import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 2 slice 5g exit proof — WebSocket connection admission as crash-safe slot LEASES (Phase 0 doc 04 §8 / §7.2).
 * Proves, against a live Postgres, that acquire_ws_slot admits at most engagement.max_ws_connections LIVE connection
 * slots per engagement, atomically under the per-engagement runtime lock (concurrent handshakes never over-admit); that
 * the lease lifetime is derived from ws_max_duration_s (not caller-supplied) and self-heals on expiry (a crashed owner's
 * slot never wedges the engagement); that a cap of 0 disables WS; that release frees a slot; that sweep_expired_ws_slots
 * reclaims only expired leases; and that RLS scopes every function to the broker tenant. Mirrors the pure
 * evaluateWsAdmission logic in @pentest/broker. DB-gated.
 */

const url = process.env.DATABASE_URL;
const silent: Logger = createLogger({ level: 'error', events: DB_EVENTS, sink: () => {} });

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const EA = 'aaaaaaaa-0000-0000-0000-000000000001';
const U = '99999999-9999-9999-9999-999999999999';

async function q(c: pg.Client, sql: string, params: unknown[] = []): Promise<pg.QueryResult> {
  return c.query(sql, params);
}
async function rejects(
  c: pg.Client,
  sql: string,
  params: unknown[] = [],
  match?: RegExp,
): Promise<void> {
  try {
    await c.query(sql, params);
  } catch (e) {
    if (match) expect((e as Error).message).toMatch(match);
    return;
  }
  throw new Error(`expected rejection but it succeeded: ${sql.slice(0, 80)}`);
}

/** Acquire a WS connection slot; returns the (caller-minted) lease id so the test can release it. */
const acquire = (c: pg.Client, owner = 'broker-1', slotId = randomUUID()): Promise<string> =>
  q(c, `SELECT acquire_ws_slot($1,$2,$3,$4)`, [T_A, EA, owner, slotId]).then(() => slotId);

const release = (c: pg.Client, slotId: string): Promise<pg.QueryResult> =>
  q(c, `SELECT release_ws_slot($1,$2,$3)`, [T_A, EA, slotId]);

/** Count only the LIVE (unexpired) connection slots — what acquire enforces against the cap. */
const liveCount = async (c: pg.Client): Promise<number> =>
  Number(
    (
      await q(
        c,
        `SELECT count(*)::int AS n FROM ws_slot WHERE engagement_id=$1 AND expires_at > now()`,
        [EA],
      )
    ).rows[0].n,
  );

const rowCount = async (c: pg.Client): Promise<number> =>
  Number((await q(c, `SELECT count(*)::int AS n FROM ws_slot`)).rows[0].n);

/** Seed the tenant + engagement with the given max_ws_connections and ws_max_duration_s. */
async function seed(c: pg.Client, maxWs: number, durS: number): Promise<void> {
  await q(c, `INSERT INTO tenant (id, name) VALUES ($1,'A'),($2,'B')`, [T_A, T_B]);
  await q(
    c,
    `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone, max_ws_connections,
       ws_max_duration_s)
     VALUES ($1,$2,'E',$3,$3,'UTC',$4,$5)`,
    [EA, T_A, U, maxWs, durS],
  );
}

describe.skipIf(!url)('slice 5g — WebSocket connection admission slots (§8/§7.2)', () => {
  let client: pg.Client;

  beforeAll(async () => {
    client = new pg.Client({ connectionString: url });
    await client.connect();
  });
  afterAll(async () => {
    if (client) {
      await client.query('RESET ROLE').catch(() => {});
      await client.query('DROP OWNED BY app_test').catch(() => {});
      await client.query('DROP ROLE IF EXISTS app_test').catch(() => {});
      await client.end();
    }
  });

  beforeEach(async () => {
    await client.query('RESET ROLE');
    await client.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    await up(client, silent);
    await client.query('DROP ROLE IF EXISTS app_test').catch(() => {});
    await client.query('CREATE ROLE app_test NOLOGIN');
    await client.query('GRANT USAGE ON SCHEMA public TO app_test');
    await client.query(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_test',
    );
  });

  it('admits up to max_ws_connections live slots, then DENY ws_connection_limit', async () => {
    await seed(client, 3, 300);
    await acquire(client);
    await acquire(client);
    await acquire(client);
    await rejects(
      client,
      `SELECT acquire_ws_slot($1,$2,$3,$4)`,
      [T_A, EA, 'broker-1', randomUUID()],
      /ws_connection_limit/,
    );
    expect(await liveCount(client)).toBe(3); // never over-admits
  });

  it('a cap of 0 disables WebSockets entirely — every acquire is refused, with no side effect', async () => {
    await seed(client, 0, 300);
    await rejects(
      client,
      `SELECT acquire_ws_slot($1,$2,$3,$4)`,
      [T_A, EA, 'broker-1', randomUUID()],
      /ws_connection_limit/,
    );
    expect(await rowCount(client)).toBe(0);
    // the ws_connection_limit RAISE rolls the whole call back — the serialization get-or-create of the runtime-counter
    // row (reached before the cap check) must NOT survive the refusal.
    expect(
      Number(
        (await q(client, `SELECT count(*)::int AS n FROM engagement_runtime_counter`)).rows[0].n,
      ),
    ).toBe(0);
  });

  it('release frees a slot: after a release the engagement admits again', async () => {
    await seed(client, 1, 300);
    const s = await acquire(client);
    await rejects(
      client,
      `SELECT acquire_ws_slot($1,$2,$3,$4)`,
      [T_A, EA, 'broker-1', randomUUID()],
      /ws_connection_limit/,
    );
    await release(client, s);
    expect(await liveCount(client)).toBe(0);
    await acquire(client);
    expect(await liveCount(client)).toBe(1);
  });

  it('release is idempotent: releasing an already-gone slot is a harmless no-op', async () => {
    await seed(client, 1, 300);
    await release(client, randomUUID());
    expect(await rowCount(client)).toBe(0);
  });

  it('derives the lease lifetime from ws_max_duration_s + the pre-open grace (not a caller value)', async () => {
    await seed(client, 2, 5); // 5s max connection lifetime
    await acquire(client);
    const s = Number(
      (
        await q(
          client,
          `SELECT extract(epoch FROM (expires_at - acquired_at)) AS s FROM ws_slot LIMIT 1`,
        )
      ).rows[0].s,
    );
    // expires_at = acquired_at + ws_max_duration_s + 60s grace (both stamped from the same now()), so the counted
    // lease always outlives the connection's governed end (t_open + ws_max_duration_s).
    expect(s).toBeCloseTo(65, 3);
  });

  it('CRASH-SAFE: an expired lease is excluded from the count, so a crashed owner never wedges the engagement', async () => {
    await seed(client, 1, 300);
    // simulate a broker that crashed holding a connection: a lease already past its deadline.
    await q(
      client,
      `INSERT INTO ws_slot (id, engagement_id, tenant_id, owner, expires_at)
       VALUES ($1,$2,$3,'crashed', now()-interval '1 second')`,
      [randomUUID(), EA, T_A],
    );
    expect(await rowCount(client)).toBe(1); // the stale row is still physically present (not yet swept)
    expect(await liveCount(client)).toBe(0); // …but not live, so it does not occupy the cap
    await acquire(client); // capacity self-healed WITHOUT the sweeper
    expect(await liveCount(client)).toBe(1);
    await rejects(
      client,
      `SELECT acquire_ws_slot($1,$2,$3,$4)`,
      [T_A, EA, 'broker-1', randomUUID()],
      /ws_connection_limit/,
    );
  });

  it('TTL self-heal: once an acquire-minted lease passes its deadline it leaves the live count, freeing the seat', async () => {
    await seed(client, 1, 300);
    const s = await acquire(client); // a REAL acquire-minted lease (deadline now() + ws_max_duration_s + grace)
    expect(await liveCount(client)).toBe(1);
    // fast-forward THIS acquire-minted lease past its deadline (its connection's lifetime elapsing / the broker crashing)
    // — deterministic, since the real deadline is minutes out. A hand-INSERTed row is covered by the crash-safe test;
    // here the lease under test was produced by acquire_ws_slot itself.
    await q(client, `UPDATE ws_slot SET expires_at = now() - interval '1 second' WHERE id=$1`, [s]);
    expect(await liveCount(client)).toBe(0); // no longer live ⇒ does not occupy the cap
    await acquire(client); // the cap-1 engagement admits again
    expect(await liveCount(client)).toBe(1);
  });

  it('sweep_expired_ws_slots reclaims ONLY expired leases and returns the count removed', async () => {
    await seed(client, 8, 300);
    await acquire(client); // live
    await acquire(client); // live
    await q(
      client,
      `INSERT INTO ws_slot (id, engagement_id, tenant_id, owner, expires_at)
       VALUES ($1,$2,$3,'crashed', now()-interval '5 seconds'),
              ($4,$2,$3,'crashed', now()-interval '5 seconds')`,
      [randomUUID(), EA, T_A, randomUUID()],
    );
    expect(await rowCount(client)).toBe(4);
    expect(Number((await q(client, `SELECT sweep_expired_ws_slots() AS n`)).rows[0].n)).toBe(2);
    expect(await rowCount(client)).toBe(2); // the two live leases survive
    expect(Number((await q(client, `SELECT sweep_expired_ws_slots() AS n`)).rows[0].n)).toBe(0);
  });

  it('DENY unknown_engagement for a missing engagement (fail-closed, no side effect)', async () => {
    await seed(client, 2, 300);
    await rejects(
      client,
      `SELECT acquire_ws_slot($1,$2,$3,$4)`,
      [T_A, 'aaaaaaaa-0000-0000-0000-0000000000ff', 'broker-1', randomUUID()],
      /unknown_engagement/,
    );
    expect(await rowCount(client)).toBe(0);
  });

  it('concurrent handshakes SERIALISE on the runtime lock — cap=1 admits exactly one, never over-admits', async () => {
    await seed(client, 1, 300);
    const clientB = new pg.Client({ connectionString: url });
    await clientB.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT acquire_ws_slot($1,$2,$3,$4)`, [
        T_A,
        EA,
        'broker-A',
        randomUUID(),
      ]);

      await clientB.query('BEGIN');
      const bPromise = clientB.query(`SELECT acquire_ws_slot($1,$2,$3,$4)`, [
        T_A,
        EA,
        'broker-B',
        randomUUID(),
      ]);
      const settled = bPromise.then(
        () => 'resolved',
        () => 'rejected',
      );
      const raced = await Promise.race([
        settled,
        new Promise<string>((r) => setTimeout(() => r('pending'), 500)),
      ]);
      expect(raced).toBe('pending'); // B is genuinely blocked while A holds the lock

      await client.query('COMMIT');
      await expect(bPromise).rejects.toThrow(/ws_connection_limit/);
      await clientB.query('ROLLBACK');

      expect(await liveCount(client)).toBe(1);
      expect(await rowCount(client)).toBe(1);
    } finally {
      await client.query('ROLLBACK').catch(() => {});
      await clientB.query('ROLLBACK').catch(() => {});
      await clientB.end();
    }
  });

  it('RLS: the acquire runs under the broker tenant role; a tenant-B session sees no slots', async () => {
    await seed(client, 2, 300);
    await client.query('SET ROLE app_test');
    await client.query(`SET app.tenant_id = '${T_A}'`);
    await client.query(`SELECT acquire_ws_slot('${T_A}','${EA}','broker-1','${randomUUID()}')`);
    expect((await q(client, `SELECT count(*)::int AS n FROM ws_slot`)).rows[0].n).toBe(1);
    await client.query(`SET app.tenant_id = '${T_B}'`);
    expect((await q(client, `SELECT count(*)::int AS n FROM ws_slot`)).rows[0].n).toBe(0);
    await client.query('RESET ROLE');
    await client.query('RESET app.tenant_id');
  });

  it('RLS fail-closed: with app.tenant_id unset the engagement read is hidden ⇒ acquire refuses (unknown_engagement)', async () => {
    await seed(client, 2, 300);
    await client.query('SET ROLE app_test');
    await client.query('RESET app.tenant_id');
    // the engagement row is RLS-hidden under the unset GUC, so the cap lookup NOT FOUND ⇒ unknown_engagement, before
    // ws_slot is ever touched. (ws_slot's OWN write policy is proven by the dedicated own-policy test below.)
    await rejects(
      client,
      `SELECT acquire_ws_slot('${T_A}','${EA}','broker-1','${randomUUID()}')`,
      [],
      /unknown_engagement/,
    );
    await client.query('RESET ROLE');
    expect(await rowCount(client)).toBe(0);
  });

  it("RLS (ws_slot's OWN policy): under an unset GUC a bare SELECT is hidden and a bare INSERT is denied", async () => {
    await seed(client, 2, 300);
    const held = await acquire(client); // one real tenant-A slot (as superuser)
    await client.query('SET ROLE app_test');
    await client.query('RESET app.tenant_id'); // predicate becomes NULL ⇒ USING hides, WITH CHECK denies
    expect((await q(client, `SELECT count(*)::int AS n FROM ws_slot`)).rows[0].n).toBe(0);
    await rejects(
      client,
      `INSERT INTO ws_slot (id, engagement_id, tenant_id, owner, expires_at)
       VALUES ($1,$2,$3,'rogue', now()+interval '1 minute')`,
      [randomUUID(), EA, T_A],
      /row-level security/,
    );
    await client.query('RESET ROLE');
    expect(await rowCount(client)).toBe(1); // nothing smuggled in
    await release(client, held);
  });

  it('RLS scopes release_ws_slot: a tenant-B session cannot delete a tenant-A slot', async () => {
    await seed(client, 2, 300);
    await acquire(client); // tenant-A slot (as superuser)
    const held = (await q(client, `SELECT id FROM ws_slot LIMIT 1`)).rows[0].id as string;
    await client.query('SET ROLE app_test');
    await client.query(`SET app.tenant_id = '${T_B}'`);
    await client.query(`SELECT release_ws_slot('${T_A}','${EA}','${held}')`);
    await client.query('RESET ROLE');
    await client.query('RESET app.tenant_id');
    expect(await rowCount(client)).toBe(1); // the tenant-A slot survived the foreign release
  });

  it('RLS write-forgery guard: a tenant-B session cannot MINT a tenant-A slot by passing p_tenant=T_A', async () => {
    await seed(client, 2, 300);
    await client.query('SET ROLE app_test');
    await client.query(`SET app.tenant_id = '${T_B}'`); // a DIFFERENT tenant's broker session
    // the engagement is invisible under the T_B GUC ⇒ unknown_engagement; even had it been read, the ws_slot WITH CHECK
    // would reject a T_A row under a T_B session. Either way no cross-tenant slot is forged.
    await rejects(
      client,
      `SELECT acquire_ws_slot('${T_A}','${EA}','broker-B','${randomUUID()}')`,
      [],
      /unknown_engagement|row-level security/,
    );
    await client.query('RESET ROLE');
    await client.query('RESET app.tenant_id');
    expect(await rowCount(client)).toBe(0);
  });

  it('release under the MATCHING tenant role frees the slot (positive RLS path)', async () => {
    await seed(client, 1, 300);
    const held = await acquire(client); // tenant-A slot (as superuser)
    await client.query('SET ROLE app_test');
    await client.query(`SET app.tenant_id = '${T_A}'`); // the broker's OWN tenant
    await client.query(`SELECT release_ws_slot('${T_A}','${EA}','${held}')`);
    await client.query('RESET ROLE');
    await client.query('RESET app.tenant_id');
    expect(await rowCount(client)).toBe(0); // the own-tenant release succeeded (the DELETE is visible under RLS)
  });
});
