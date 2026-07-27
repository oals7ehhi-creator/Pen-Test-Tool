import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 2 slice 5e exit proof — per-host concurrency as crash-safe slot LEASES (Phase 0 doc 04 §8). Proves, against a
 * live Postgres, that acquire_host_slot admits at most engagement.per_host_concurrency LIVE slots per (engagement,
 * host), atomically under the per-engagement runtime lock (concurrent draws never over-admit); that an EXPIRED lease is
 * excluded from the count (a crashed owner self-heals capacity WITHOUT the sweeper); that release frees a slot; that
 * sweep_expired_slots reclaims only expired leases; and that RLS scopes every function to the broker tenant. Mirrors the
 * pure evaluateHostSlot logic in @pentest/broker. DB-gated.
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

/** Acquire a per-host slot; returns the (caller-minted) lease id so the test can release it. */
const acquire = (
  c: pg.Client,
  host: string,
  owner = 'broker-1',
  ttlMs = 60_000,
  slotId = randomUUID(),
): Promise<string> =>
  q(c, `SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`, [T_A, EA, host, owner, slotId, ttlMs]).then(
    () => slotId,
  );

const release = (c: pg.Client, slotId: string): Promise<pg.QueryResult> =>
  q(c, `SELECT release_host_slot($1,$2,$3)`, [T_A, EA, slotId]);

/** Count only the LIVE (unexpired) slots for a host — what acquire enforces against the cap. */
const liveCount = async (c: pg.Client, host: string): Promise<number> =>
  Number(
    (
      await q(
        c,
        `SELECT count(*)::int AS n FROM host_slot
           WHERE engagement_id=$1 AND host=$2 AND expires_at > now()`,
        [EA, host],
      )
    ).rows[0].n,
  );

const rowCount = async (c: pg.Client): Promise<number> =>
  Number((await q(c, `SELECT count(*)::int AS n FROM host_slot`)).rows[0].n);

/** Seed the tenant + engagement with the given global / per-host concurrency caps. */
async function seed(c: pg.Client, maxConc: number, perHostConc: number): Promise<void> {
  await q(c, `INSERT INTO tenant (id, name) VALUES ($1,'A'),($2,'B')`, [T_A, T_B]);
  await q(
    c,
    `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone, max_concurrency,
       per_host_concurrency)
     VALUES ($1,$2,'E',$3,$3,'UTC',$4,$5)`,
    [EA, T_A, U, maxConc, perHostConc],
  );
}

describe.skipIf(!url)('slice 5e — per-host concurrency slot leases (§8)', () => {
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

  it('admits up to per_host_concurrency live slots, then DENY host_concurrency_exceeded', async () => {
    await seed(client, 4, 2); // per-host cap 2 (global ample)
    await acquire(client, 'a.example'); // 1/2
    await acquire(client, 'a.example'); // 2/2
    await rejects(
      client,
      `SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`,
      [T_A, EA, 'a.example', 'broker-1', randomUUID(), 60_000],
      /host_concurrency_exceeded/,
    );
    expect(await liveCount(client, 'a.example')).toBe(2); // never over-admits
  });

  it('per-host buckets are independent: a full host does not block a different host', async () => {
    await seed(client, 4, 1); // per-host cap 1
    await acquire(client, 'a.example'); // hostA full
    await rejects(
      client,
      `SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`,
      [T_A, EA, 'a.example', 'broker-1', randomUUID(), 60_000],
      /host_concurrency_exceeded/,
    );
    await acquire(client, 'b.example'); // a DIFFERENT host still has its own slot
    expect(await liveCount(client, 'a.example')).toBe(1);
    expect(await liveCount(client, 'b.example')).toBe(1);
  });

  it('release frees a slot: after a release the host admits again', async () => {
    await seed(client, 4, 1);
    const s = await acquire(client, 'a.example');
    await rejects(
      client,
      `SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`,
      [T_A, EA, 'a.example', 'broker-1', randomUUID(), 60_000],
      /host_concurrency_exceeded/,
    );
    await release(client, s); // frees the slot
    expect(await liveCount(client, 'a.example')).toBe(0);
    await acquire(client, 'a.example'); // admits again
    expect(await liveCount(client, 'a.example')).toBe(1);
  });

  it('release is idempotent: releasing an already-gone slot is a harmless no-op', async () => {
    await seed(client, 4, 1);
    // a lease id that was never held (or already swept) — release must not error and must change nothing.
    await release(client, randomUUID());
    expect(await rowCount(client)).toBe(0);
  });

  it('CRASH-SAFE: an expired lease is excluded from the count, so a crashed owner never wedges the host', async () => {
    await seed(client, 4, 1); // per-host cap 1
    // simulate a broker that crashed holding a slot: a lease already past its deadline.
    await q(
      client,
      `INSERT INTO host_slot (id, engagement_id, tenant_id, host, owner, expires_at)
       VALUES ($1,$2,$3,'a.example','crashed', now()-interval '1 second')`,
      [randomUUID(), EA, T_A],
    );
    expect(await rowCount(client)).toBe(1); // the stale row still physically present (not yet swept)
    expect(await liveCount(client, 'a.example')).toBe(0); // …but it is NOT live, so it does not occupy the cap
    // the cap-1 host therefore still admits — capacity self-healed WITHOUT the sweeper running.
    await acquire(client, 'a.example');
    expect(await liveCount(client, 'a.example')).toBe(1);
    // and once a LIVE slot holds the single seat, the next draw is refused.
    await rejects(
      client,
      `SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`,
      [T_A, EA, 'a.example', 'broker-1', randomUUID(), 60_000],
      /host_concurrency_exceeded/,
    );
  });

  it('sweep_expired_slots reclaims ONLY expired leases and returns the count removed', async () => {
    await seed(client, 8, 4);
    await acquire(client, 'a.example', 'broker-1', 60_000); // live
    await acquire(client, 'b.example', 'broker-1', 60_000); // live
    await q(
      client,
      `INSERT INTO host_slot (id, engagement_id, tenant_id, host, owner, expires_at)
       VALUES ($1,$2,$3,'c.example','crashed', now()-interval '5 seconds'),
              ($4,$2,$3,'d.example','crashed', now()-interval '5 seconds')`,
      [randomUUID(), EA, T_A, randomUUID()],
    );
    expect(await rowCount(client)).toBe(4);
    const swept = Number((await q(client, `SELECT sweep_expired_slots() AS n`)).rows[0].n);
    expect(swept).toBe(2); // only the two expired leases
    expect(await rowCount(client)).toBe(2); // the two live leases survive
    // a second sweep (nothing expired) reclaims nothing.
    expect(Number((await q(client, `SELECT sweep_expired_slots() AS n`)).rows[0].n)).toBe(0);
  });

  it('DENY unknown_engagement for a missing engagement (fail-closed, no side effect)', async () => {
    await seed(client, 4, 1);
    await rejects(
      client,
      `SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`,
      [T_A, 'aaaaaaaa-0000-0000-0000-0000000000ff', 'h', 'broker-1', randomUUID(), 60_000],
      /unknown_engagement/,
    );
    expect(await rowCount(client)).toBe(0);
  });

  it('concurrent draws SERIALISE on the runtime lock — cap=1 admits exactly one, never over-admits', async () => {
    await seed(client, 4, 1); // per-host capacity ONE
    const clientB = new pg.Client({ connectionString: url });
    await clientB.connect();
    try {
      // tx A: acquire host a.example and HOLD the tx open (owns the runtime-counter row + its FOR UPDATE lock).
      await client.query('BEGIN');
      await client.query(`SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`, [
        T_A,
        EA,
        'a.example',
        'broker-A',
        randomUUID(),
        60_000,
      ]);

      // tx B on a second connection: the SAME (engagement, host) draw must BLOCK on A's lock (get-or-create / FOR UPDATE).
      await clientB.query('BEGIN');
      const bPromise = clientB.query(`SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`, [
        T_A,
        EA,
        'a.example',
        'broker-B',
        randomUUID(),
        60_000,
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

      // A commits (slot 1/1 taken). B unblocks, re-reads live=1 >= cap=1 ⇒ host_concurrency_exceeded.
      await client.query('COMMIT');
      await expect(bPromise).rejects.toThrow(/host_concurrency_exceeded/);
      await clientB.query('ROLLBACK');

      // exactly one slot landed; the cap was never exceeded.
      expect(await liveCount(client, 'a.example')).toBe(1);
      expect(await rowCount(client)).toBe(1);
    } finally {
      await client.query('ROLLBACK').catch(() => {});
      await clientB.query('ROLLBACK').catch(() => {});
      await clientB.end();
    }
  });

  it('RLS: the draw runs under the broker tenant role; a tenant-B session sees no slots', async () => {
    await seed(client, 4, 2);
    await client.query('SET ROLE app_test');
    await client.query(`SET app.tenant_id = '${T_A}'`);
    await client.query(
      `SELECT acquire_host_slot('${T_A}','${EA}','h.example','broker-1','${randomUUID()}',60000)`,
    );
    expect((await q(client, `SELECT count(*)::int AS n FROM host_slot`)).rows[0].n).toBe(1);
    await client.query(`SET app.tenant_id = '${T_B}'`);
    expect((await q(client, `SELECT count(*)::int AS n FROM host_slot`)).rows[0].n).toBe(0);
    await client.query('RESET ROLE');
    await client.query('RESET app.tenant_id');
  });

  it('RLS fail-closed: with app.tenant_id unset the draw is refused and creates no slot', async () => {
    await seed(client, 4, 2);
    await client.query('SET ROLE app_test');
    await client.query('RESET app.tenant_id'); // no tenant GUC ⇒ the engagement is invisible ⇒ fail closed
    await rejects(
      client,
      `SELECT acquire_host_slot('${T_A}','${EA}','h.example','broker-1','${randomUUID()}',60000)`,
      [],
      /row-level security|unknown_engagement/,
    );
    await client.query('RESET ROLE');
    expect(await rowCount(client)).toBe(0); // superuser bypasses RLS to confirm nothing was inserted
  });

  it('DENY invalid_lease_ttl for a non-positive TTL — never mints a born-expired phantom slot', async () => {
    await seed(client, 4, 1);
    // ttl <= 0 would make expires_at <= now(): the row would report success yet hold no LIVE slot (fail-open). Refuse it.
    for (const badTtl of [0, -1]) {
      await rejects(
        client,
        `SELECT acquire_host_slot($1,$2,$3,$4,$5,$6)`,
        [T_A, EA, 'a.example', 'broker-1', randomUUID(), badTtl],
        /invalid_lease_ttl/,
      );
    }
    expect(await rowCount(client)).toBe(0); // no phantom lease inserted
    // a positive TTL still admits normally.
    await acquire(client, 'a.example', 'broker-1', 60_000);
    expect(await liveCount(client, 'a.example')).toBe(1);
  });

  it('TTL self-heal end-to-end: an acquire-minted short lease expires on its OWN deadline, freeing the seat', async () => {
    await seed(client, 4, 1); // per-host cap 1
    // acquire through acquire_host_slot with a short TTL, exercising its now() + (p_ttl_ms||' ms')::interval math
    // (NOT a hand-inserted timestamp): a unit regression (seconds instead of ms) would keep the slot live for minutes.
    await acquire(client, 'a.example', 'broker-1', 120);
    const deadline = Date.now() + 3000;
    // poll until the lease self-expires out of the LIVE count.
    while ((await liveCount(client, 'a.example')) > 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(await liveCount(client, 'a.example')).toBe(0); // the ~120ms lease is no longer live
    // the cap-1 host therefore admits again (the expired row does not occupy the seat).
    await acquire(client, 'a.example', 'broker-1', 60_000);
    expect(await liveCount(client, 'a.example')).toBe(1);
  });

  it("RLS (host_slot's OWN policy): under an unset GUC a bare SELECT is hidden and a bare INSERT is denied", async () => {
    await seed(client, 4, 2);
    const held = await acquire(client, 'h.example'); // one real tenant-A slot (as superuser)
    await client.query('SET ROLE app_test');
    await client.query('RESET app.tenant_id'); // policy predicate becomes NULL ⇒ USING hides, WITH CHECK denies
    // USING: the tenant-A row is invisible to a session with no tenant GUC.
    expect((await q(client, `SELECT count(*)::int AS n FROM host_slot`)).rows[0].n).toBe(0);
    // WITH CHECK: a direct INSERT (engagement FK satisfied) is refused by host_slot's own policy, not the engagement gate.
    await rejects(
      client,
      `INSERT INTO host_slot (id, engagement_id, tenant_id, host, owner, expires_at)
       VALUES ($1,$2,$3,'h.example','rogue', now()+interval '1 minute')`,
      [randomUUID(), EA, T_A],
      /row-level security/,
    );
    await client.query('RESET ROLE');
    expect(await rowCount(client)).toBe(1); // still just the one real slot — nothing smuggled in
    await release(client, held);
  });

  it('RLS scopes release_host_slot: a tenant-B session cannot delete a tenant-A slot', async () => {
    await seed(client, 4, 2);
    const held = await acquire(client, 'h.example'); // tenant-A slot (as superuser)
    await client.query('SET ROLE app_test');
    await client.query(`SET app.tenant_id = '${T_B}'`); // a DIFFERENT tenant's broker session
    // the DELETE runs under RLS: tenant-A's row is invisible ⇒ release is a no-op, not a cross-tenant delete.
    await client.query(`SELECT release_host_slot('${T_A}','${EA}','${held}')`);
    await client.query('RESET ROLE');
    await client.query('RESET app.tenant_id');
    expect(await rowCount(client)).toBe(1); // the tenant-A slot survived the foreign release
  });
});
