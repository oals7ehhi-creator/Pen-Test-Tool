import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 2 slice 5c exit proof — the egress-slot throttle (Phase 0 doc 04 §8): concurrency + min-spacing + circuit
 * breaker, atomically over engagement_runtime_counter under its FOR UPDATE lock. Proves, against a live Postgres, that
 * acquire_egress_slot enforces circuit → concurrency → spacing (only a full allow reserves a slot), and
 * release_egress_slot frees the slot + drives the breaker (success closes; threshold failures open; a failed half-open
 * probe re-opens). Mirrors the pure evaluateAcquire / recordResult logic in @pentest/broker. DB-gated (DATABASE_URL).
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

const acquire = (c: pg.Client, cooldownMs = 30_000): Promise<pg.QueryResult> =>
  q(c, `SELECT acquire_egress_slot($1,$2,$3)`, [T_A, EA, cooldownMs]);
const release = (c: pg.Client, success: boolean, threshold = 3): Promise<pg.QueryResult> =>
  q(c, `SELECT release_egress_slot($1,$2,$3,$4)`, [T_A, EA, success, threshold]);

/** Seed the tenant + engagement with a given concurrency cap and spacing. */
async function seed(c: pg.Client, maxConcurrency: number, minIntervalMs: number): Promise<void> {
  await q(c, `INSERT INTO tenant (id, name) VALUES ($1,'A'),($2,'B')`, [T_A, T_B]);
  await q(
    c,
    `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone, max_concurrency,
       min_request_interval_ms)
     VALUES ($1,$2,'E',$3,$3,'UTC',$4,$5)`,
    [EA, T_A, U, maxConcurrency, minIntervalMs],
  );
}

/** Directly upsert the runtime counter (so circuit-state paths can be tested without a prior acquire). */
async function counter(
  c: pg.Client,
  over: { inFlight?: number; circuit?: string; errors?: number; openedAt?: string | null } = {},
): Promise<void> {
  await q(
    c,
    `INSERT INTO engagement_runtime_counter
       (engagement_id, tenant_id, window_started_at, in_flight, circuit_state, consecutive_errors, circuit_opened_at)
     VALUES ($1,$2, now(), $3, $4, $5, ${over.openedAt ?? 'NULL'})
     ON CONFLICT (engagement_id) DO UPDATE
       SET in_flight=$3, circuit_state=$4, consecutive_errors=$5, circuit_opened_at=${over.openedAt ?? 'NULL'}`,
    [EA, T_A, over.inFlight ?? 0, over.circuit ?? 'closed', over.errors ?? 0],
  );
}

const state = async (c: pg.Client): Promise<pg.QueryResultRow> =>
  (
    await q(
      c,
      `SELECT in_flight, circuit_state, consecutive_errors, circuit_opened_at FROM engagement_runtime_counter`,
    )
  ).rows[0];

describe.skipIf(!url)('slice 5c — egress-slot throttle (§8)', () => {
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

  describe('concurrency', () => {
    it('reserves up to max_concurrency, then DENY concurrency_exceeded; a release frees a slot', async () => {
      await seed(client, 2, 0);
      await acquire(client);
      await acquire(client);
      expect((await state(client)).in_flight).toBe(2);
      await rejects(
        client,
        `SELECT acquire_egress_slot($1,$2,$3)`,
        [T_A, EA, 30],
        /concurrency_exceeded/,
      );

      // release one (success) → a slot frees and the acquire now succeeds.
      await release(client, true);
      expect((await state(client)).in_flight).toBe(1);
      await acquire(client);
      expect((await state(client)).in_flight).toBe(2);
    });

    it('in_flight never goes negative — a release at zero stays zero', async () => {
      await seed(client, 2, 0);
      await counter(client, { inFlight: 0 });
      await release(client, true);
      expect((await state(client)).in_flight).toBe(0);
    });

    it('concurrent acquires SERIALISE on the counter lock — cap=1 admits exactly one, never over-admits', async () => {
      await seed(client, 1, 0); // capacity of ONE
      const clientB = new pg.Client({ connectionString: url });
      await clientB.connect();
      try {
        // tx A: acquire and HOLD the transaction open (owns the runtime-counter row + its FOR UPDATE lock).
        await client.query('BEGIN');
        await client.query(`SELECT acquire_egress_slot($1,$2,$3)`, [T_A, EA, 0]);

        // tx B on a second connection: the same acquire must BLOCK on A's lock (via the ON CONFLICT / FOR UPDATE).
        await clientB.query('BEGIN');
        const bPromise = clientB.query(`SELECT acquire_egress_slot($1,$2,$3)`, [T_A, EA, 0]);
        const settled = bPromise.then(
          () => 'resolved',
          () => 'rejected',
        );
        const raced = await Promise.race([
          settled,
          new Promise<string>((r) => setTimeout(() => r('pending'), 500)),
        ]);
        expect(raced).toBe('pending'); // B is genuinely blocked while A holds the lock

        // A commits (in_flight -> 1). B unblocks, re-reads in_flight=1 >= cap=1 ⇒ concurrency_exceeded.
        await client.query('COMMIT');
        await expect(bPromise).rejects.toThrow(/concurrency_exceeded/);
        await clientB.query('ROLLBACK');

        // exactly one acquire landed; the counter never exceeded the cap.
        expect((await state(client)).in_flight).toBe(1);
      } finally {
        await client.query('ROLLBACK').catch(() => {});
        await clientB.query('ROLLBACK').catch(() => {});
        await clientB.end();
      }
    });
  });

  describe('min-spacing', () => {
    it('DENY min_interval when a second acquire arrives inside the interval — and reserves nothing', async () => {
      await seed(client, 8, 5000); // 5s spacing, ample concurrency
      await acquire(client);
      const before = await state(client);
      await rejects(
        client,
        `SELECT acquire_egress_slot($1,$2,$3)`,
        [T_A, EA, 30_000],
        /min_interval/,
      );
      const after = await state(client);
      // a denied acquire is a no-op: it bumps neither in_flight nor last_request_at.
      expect(after.in_flight).toBe(before.in_flight);
      expect(after.last_request_at).toEqual(before.last_request_at);
    });
  });

  describe('release robustness', () => {
    it('release on an engagement with no counter row raises unknown_engagement (fail-closed defensive branch)', async () => {
      await seed(client, 2, 0); // engagement exists; no runtime-counter row (no prior acquire)
      await rejects(
        client,
        `SELECT release_egress_slot($1,$2,$3,$4)`,
        [T_A, EA, true, 3],
        /unknown_engagement/,
      );
    });
  });

  describe('circuit breaker', () => {
    it('opens after threshold failures, DENY circuit_open during cooldown, half-open probe after, closes on success', async () => {
      await seed(client, 8, 0);
      await counter(client, { circuit: 'closed', errors: 0, inFlight: 0 });
      // three failures (threshold 3) trip the breaker open.
      await release(client, false);
      await release(client, false);
      await release(client, false);
      let s = await state(client);
      expect(s.circuit_state).toBe('open');
      expect(s.consecutive_errors).toBe(3);
      expect(s.circuit_opened_at).not.toBeNull();

      // an acquire within the cooldown (30s) is refused.
      await rejects(
        client,
        `SELECT acquire_egress_slot($1,$2,$3)`,
        [T_A, EA, 30_000],
        /circuit_open/,
      );

      // once the cooldown has elapsed (cooldown 0), exactly one probe is let through: open → half_open.
      await acquire(client, 0);
      s = await state(client);
      expect(s.circuit_state).toBe('half_open');
      expect(s.in_flight).toBe(1);

      // a SECOND acquire while half_open is refused — exactly one probe is outstanding, no flood.
      await rejects(client, `SELECT acquire_egress_slot($1,$2,$3)`, [T_A, EA, 0], /circuit_open/);
      expect((await state(client)).in_flight).toBe(1); // the refusal reserved nothing

      // the probe SUCCEEDS → breaker closes and the error run clears.
      await release(client, true);
      s = await state(client);
      expect(s.circuit_state).toBe('closed');
      expect(s.consecutive_errors).toBe(0);
      expect(s.in_flight).toBe(0);
    });

    it('a FAILED half-open probe re-opens the breaker immediately', async () => {
      await seed(client, 8, 0);
      await counter(client, { circuit: 'half_open', errors: 3, inFlight: 1 });
      await release(client, false);
      const s = await state(client);
      expect(s.circuit_state).toBe('open');
      expect(s.consecutive_errors).toBe(4);
      expect(s.circuit_opened_at).not.toBeNull();
      expect(s.in_flight).toBe(0);
    });

    it('a closed breaker accumulates below the threshold without opening', async () => {
      await seed(client, 8, 0);
      await counter(client, { circuit: 'closed', errors: 0 });
      await release(client, false);
      await release(client, false); // 2 < threshold 3
      const s = await state(client);
      expect(s.circuit_state).toBe('closed');
      expect(s.consecutive_errors).toBe(2);
    });
  });

  describe('RLS', () => {
    it('acquire runs under the broker tenant role; unset/wrong tenant GUC fails closed and writes nothing', async () => {
      await seed(client, 8, 0);
      await client.query('SET ROLE app_test');

      // (a) with the tenant GUC set, the legitimate acquire succeeds and writes exactly its own counter row.
      await client.query(`SET app.tenant_id = '${T_A}'`);
      await client.query(`SELECT acquire_egress_slot('${T_A}','${EA}',0)`);
      expect(
        (await q(client, `SELECT count(*)::int AS n FROM engagement_runtime_counter`)).rows[0].n,
      ).toBe(1);

      // (b) a tenant-B session sees none of tenant A's counter (RLS isolation).
      await client.query(`SET app.tenant_id = '${T_B}'`);
      expect(
        (await q(client, `SELECT count(*)::int AS n FROM engagement_runtime_counter`)).rows[0].n,
      ).toBe(0);
      // and a T_B-GUC acquire targeting T_A fails closed (the WITH CHECK / row invisibility refuses the write).
      await rejects(
        client,
        `SELECT acquire_egress_slot('${T_A}','${EA}',0)`,
        [],
        /row-level security|unknown_engagement/,
      );

      // (c) with the GUC unset entirely, the acquire fails closed too.
      await client.query(`RESET app.tenant_id`);
      await rejects(
        client,
        `SELECT acquire_egress_slot('${T_A}','${EA}',0)`,
        [],
        /row-level security|unknown_engagement/,
      );

      await client.query('RESET ROLE');
      await client.query('RESET app.tenant_id');
      // none of the fail-closed attempts moved tenant A's slot.
      expect((await state(client)).in_flight).toBe(1);
    });
  });
});
