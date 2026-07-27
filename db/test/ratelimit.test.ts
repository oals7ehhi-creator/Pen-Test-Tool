import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 2 slice 5d exit proof — the request-rate token buckets (Phase 0 doc 04 §8). Proves, against a live Postgres,
 * that take_rate_tokens draws from BOTH the engagement-global bucket (global_max_rps) and the per-host bucket
 * (per_host_max_rps) atomically under their FOR UPDATE lock: a bucket refills at its rate up to capacity; a request
 * only consumes a token from each when BOTH can satisfy it (no token leak); an empty bucket RAISEs a fixed reason and
 * persists nothing. Mirrors the pure evaluateRateLimit / refillAndTake logic in @pentest/broker. DB-gated.
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

const take = (c: pg.Client, host: string): Promise<pg.QueryResult> =>
  q(c, `SELECT take_rate_tokens($1,$2,$3)`, [T_A, EA, host]);

/** Seed the tenant + engagement with the given global / per-host rps. */
async function seed(c: pg.Client, globalRps: number, hostRps: number): Promise<void> {
  await q(c, `INSERT INTO tenant (id, name) VALUES ($1,'A'),($2,'B')`, [T_A, T_B]);
  await q(
    c,
    `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone, global_max_rps,
       per_host_max_rps)
     VALUES ($1,$2,'E',$3,$3,'UTC',$4,$5)`,
    [EA, T_A, U, globalRps, hostRps],
  );
}

const tokensOf = async (c: pg.Client, scope: string): Promise<number> =>
  Number(
    (await q(c, `SELECT tokens FROM rate_bucket WHERE engagement_id=$1 AND scope=$2`, [EA, scope]))
      .rows[0].tokens,
  );

describe.skipIf(!url)('slice 5d — request-rate token buckets (§8)', () => {
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

  it('draws from a fresh (full) bucket and refuses once the global bucket empties', async () => {
    await seed(client, 2, 2); // global cap 2 is the binding limit (per-host cap 2 doesn't bind across 2 hosts)
    await take(client, 'a.example'); // global 2 -> 1
    await take(client, 'b.example'); // global 1 -> 0
    await rejects(
      client,
      `SELECT take_rate_tokens($1,$2,$3)`,
      [T_A, EA, 'c.example'],
      /rate_limited_global/,
    );
    expect(await tokensOf(client, 'global')).toBeLessThan(1);
  });

  it('per-host buckets are independent: one host exhausts its own without blocking another', async () => {
    await seed(client, 50, 1); // ample global (max allowed), per-host cap 1
    await take(client, 'a.example'); // hostA 1 -> 0
    await rejects(
      client,
      `SELECT take_rate_tokens($1,$2,$3)`,
      [T_A, EA, 'a.example'],
      /rate_limited_host/,
    );
    // a DIFFERENT host still has its own full bucket.
    await take(client, 'b.example');
    expect(await tokensOf(client, 'a.example')).toBeLessThan(1);
    expect(await tokensOf(client, 'b.example')).toBeLessThan(1);
  });

  it('check-both-consume-both: a host-denied draw does NOT consume a global token', async () => {
    await seed(client, 50, 1); // per-host cap 1
    await take(client, 'a.example'); // hostA -> 0; global -> 99
    const globalBefore = await tokensOf(client, 'global');
    await rejects(
      client,
      `SELECT take_rate_tokens($1,$2,$3)`,
      [T_A, EA, 'a.example'],
      /rate_limited_host/,
    );
    // the failed (host-empty) draw rolled back ⇒ the global bucket is untouched (no leak).
    expect(await tokensOf(client, 'global')).toBe(globalBefore);
  });

  it('refills by elapsed time: an empty bucket admits again after enough seconds accrue', async () => {
    await seed(client, 2, 1);
    // pre-seed BOTH buckets empty with a refill point 2s in the past.
    await q(
      client,
      `INSERT INTO rate_bucket (engagement_id, tenant_id, scope, tokens, refill_at)
       VALUES ($1,$2,'global',0, now()-interval '2 seconds'),($1,$2,'h.example',0, now()-interval '2 seconds')`,
      [EA, T_A],
    );
    // global accrues 2*2=4 (cap 2), host accrues 1*2=2 (cap 1) ⇒ both ≥ 1 ⇒ the draw succeeds.
    await take(client, 'h.example');
    expect((await q(client, `SELECT count(*)::int AS n FROM rate_bucket`)).rows[0].n).toBe(2);
  });

  it('DENY invalid_host for the reserved scope key, and unknown_engagement for a missing engagement', async () => {
    await seed(client, 2, 1);
    await rejects(client, `SELECT take_rate_tokens($1,$2,$3)`, [T_A, EA, 'global'], /invalid_host/);
    await rejects(
      client,
      `SELECT take_rate_tokens($1,$2,$3)`,
      [T_A, 'aaaaaaaa-0000-0000-0000-0000000000ff', 'h'],
      /unknown_engagement/,
    );
  });

  it('RLS: the draw runs under the broker tenant role; a tenant-B session sees no buckets', async () => {
    await seed(client, 2, 1);
    await client.query('SET ROLE app_test');
    await client.query(`SET app.tenant_id = '${T_A}'`);
    await client.query(`SELECT take_rate_tokens('${T_A}','${EA}','h.example')`);
    expect((await q(client, `SELECT count(*)::int AS n FROM rate_bucket`)).rows[0].n).toBe(2); // global + host
    await client.query(`SET app.tenant_id = '${T_B}'`);
    expect((await q(client, `SELECT count(*)::int AS n FROM rate_bucket`)).rows[0].n).toBe(0);
    await client.query('RESET ROLE');
    await client.query('RESET app.tenant_id');
  });
});
