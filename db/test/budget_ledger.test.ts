import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 2 slice 5a exit proof — the budget CHARGE-BEFORE-SEND ledger + durable intent (Phase 0 doc 04 §8 / §8.1,
 * §7.1 step 10). Proves, against a live Postgres, the conservative charge-before-send state machine that makes
 * "sent ⇒ charged" hold and sent-but-uncharged traffic impossible (SI-017, SI-055, SI-062):
 *   - budget_charge_and_intent(): atomic availability check → fence allocation → claim → charge (used += 1) →
 *     durable hash-chained 'request.intent' — all one transaction, BEFORE any egress; e-stop + exhaustion fail closed;
 *   - budget_reservation_transition(): terminal 'charged'; owner + fence-token gating; write-once charged_at; no
 *     release/expire after charge; live-claim theft rejected; fenced takeover of an expired claim;
 *   - audit_append(): tamper-evident chaining (monotonic seq, prev_hash link, advancing head, chain identity);
 *   - RLS isolation, the composite spec FK, jti-uniqueness, and DELETE-revocation.
 * DB-gated (DATABASE_URL); runs for real in CI.
 */

const url = process.env.DATABASE_URL;
const silent: Logger = createLogger({ level: 'error', events: DB_EVENTS, sink: () => {} });

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const EA = 'aaaaaaaa-0000-0000-0000-000000000001';
const SPEC = 'eeeeeeee-0000-0000-0000-000000000001';
const U = '99999999-9999-9999-9999-999999999999';
const SCOPE_HASH = 'a'.repeat(64);
const SPEC_SHA = 'f'.repeat(64);

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

/** Call budget_charge_and_intent; returns { reservation_id, fence_token, intent_event_id }. */
async function charge(
  c: pg.Client,
  over: { jti?: string; owner?: string; ttl?: number; engagement?: string; spec?: string } = {},
): Promise<{ reservation_id: string; fence_token: string; intent_event_id: string }> {
  const r = await q(c, `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`, [
    T_A,
    over.engagement ?? EA,
    over.spec ?? SPEC,
    over.jti ?? 'jti-1',
    over.owner ?? 'broker-A',
    'https://example.com/api',
    over.ttl ?? 30,
  ]);
  return r.rows[0];
}

/** Seed a tenant/engagement/scope/authorization/header-template/request_spec so the ledger FKs are satisfiable. */
async function seed(c: pg.Client, budgetTotal: number): Promise<void> {
  await q(c, `INSERT INTO tenant (id, name) VALUES ($1,'A'),($2,'B')`, [T_A, T_B]);
  await q(
    c,
    `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone, request_budget_total)
     VALUES ($1,$2,'E',$3,$3,'UTC',$4)`,
    [EA, T_A, U, budgetTotal],
  );
  await q(
    c,
    `INSERT INTO scope_version (id, tenant_id, engagement_id, version_number, scope_hash, entry_count, host_count,
       ipv4_equiv_addresses, cidr_entry_count, created_by)
     VALUES ('cccccccc-0000-0000-0000-000000000001',$1,$2,1,$3,0,0,0,0,$4)`,
    [T_A, EA, SCOPE_HASH, U],
  );
  await q(
    c,
    `INSERT INTO "authorization" (id, tenant_id, engagement_id, authorization_reference, authorizing_party_name,
       authorizing_party_org, engagement_owner_user_id, effective_from, expires_at, allowed_modes, scope_version_id,
       scope_hash, record_hash)
     VALUES ('dddddddd-0000-0000-0000-000000000001',$1,$2,'ref','p','o',$3, now(), now()+interval '10 days',
             ARRAY['passive'],'cccccccc-0000-0000-0000-000000000001',$4,$5)`,
    [T_A, EA, U, SCOPE_HASH, 'r'.repeat(64)],
  );
  const h = await q(
    c,
    `INSERT INTO catalog_template (digest, kind, name, version, content, safety_class)
     VALUES (encode(digest(convert_to(jsonb_build_object('kind','header_set','name','h','version','v1',
       'content','{"a":1}'::jsonb,'safety_class','inert')::text,'utf8'),'sha256'),'hex'),
       'header_set','h','v1','{"a":1}'::jsonb,'inert') RETURNING digest`,
  );
  await q(
    c,
    `INSERT INTO request_spec (id, tenant_id, engagement_id, run_id, job_id, scope_hash, authorization_id,
       request_class, kind, header_set_digest, method, canonical_url, canonical_host, port, scheme, canonical_path,
       mode, spec_sha256)
     VALUES ($1,$2,$3,$4,$4,$5,'dddddddd-0000-0000-0000-000000000001','native','http',$6,'GET',
             'https://example.com/api','example.com',443,'https','/api','passive',$7)`,
    [SPEC, T_A, EA, U, SCOPE_HASH, h.rows[0].digest, SPEC_SHA],
  );
}

/** Insert a budget_reservation LEASE directly (owner path), to drive the transition trigger under test. */
async function lease(
  c: pg.Client,
  over: { jti: string; owner?: string; fence?: number; state?: string; expiresSql?: string },
): Promise<string> {
  const r = await q(
    c,
    `INSERT INTO budget_reservation (tenant_id, engagement_id, spec_id, grant_jti, state, owner, fence_token, expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7, ${over.expiresSql ?? `now()+interval '30 seconds'`}) RETURNING id`,
    [T_A, EA, SPEC, over.jti, over.state ?? 'claimed', over.owner ?? 'broker-A', over.fence ?? 1],
  );
  return r.rows[0].id as string;
}

describe.skipIf(!url)('slice 5a — budget charge-before-send ledger + intent (§8.1)', () => {
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

  describe('atomic charge + intent (happy path)', () => {
    beforeEach(() => seed(client, 5));

    it('charges before send: lease→charged, used += 1, fence allocated, intent appended', async () => {
      const c1 = await charge(client, { jti: 'j1' });
      expect(c1.reservation_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(Number(c1.fence_token)).toBe(1);

      // the lease is terminal 'charged' with a charged_at.
      const l = await q(
        client,
        `SELECT state, charged_at, fence_token FROM budget_reservation WHERE id=$1`,
        [c1.reservation_id],
      );
      expect(l.rows[0].state).toBe('charged');
      expect(l.rows[0].charged_at).not.toBeNull();

      // the ONE increment landed on the engagement counter.
      const e = await q(client, `SELECT request_budget_used FROM engagement WHERE id=$1`, [EA]);
      expect(e.rows[0].request_budget_used).toBe(1);

      // the runtime counter fence advanced.
      const rc = await q(
        client,
        `SELECT fence_seq FROM engagement_runtime_counter WHERE engagement_id=$1`,
        [EA],
      );
      expect(Number(rc.rows[0].fence_seq)).toBe(1);

      // the durable 'request.intent' event exists on the engagement chain, hash-chained from genesis.
      const ev = await q(
        client,
        `SELECT event_type, seq, prev_hash, event_hash, payload FROM audit_event WHERE id=$1`,
        [c1.intent_event_id],
      );
      expect(ev.rows[0].event_type).toBe('request.intent');
      expect(Number(ev.rows[0].seq)).toBe(1);
      expect(ev.rows[0].prev_hash).toBe('0'.repeat(64)); // genesis sentinel
      expect(ev.rows[0].event_hash).toMatch(/^[0-9a-f]{64}$/);
      // the redacted payload records the binding identifiers (no secret/body).
      expect(ev.rows[0].payload).toMatchObject({
        spec_sha256: SPEC_SHA,
        grant_jti: 'j1',
        reservation_id: c1.reservation_id,
        canonical_target: 'https://example.com/api',
      });
    });

    it('a second charge chains the audit: seq monotonic, prev_hash links, head advances', async () => {
      const c1 = await charge(client, { jti: 'j1' });
      const c2 = await charge(client, { jti: 'j2' });
      expect(Number(c2.fence_token)).toBe(2);

      const e1 = await q(client, `SELECT seq, event_hash FROM audit_event WHERE id=$1`, [
        c1.intent_event_id,
      ]);
      const e2 = await q(client, `SELECT seq, prev_hash, event_hash FROM audit_event WHERE id=$1`, [
        c2.intent_event_id,
      ]);
      expect(Number(e2.rows[0].seq)).toBe(2);
      expect(e2.rows[0].prev_hash).toBe(e1.rows[0].event_hash); // links to the prior event
      const head = await q(
        client,
        `SELECT head_seq, head_hash FROM audit_chain WHERE stream='engagement'`,
      );
      expect(Number(head.rows[0].head_seq)).toBe(2);
      expect(head.rows[0].head_hash).toBe(e2.rows[0].event_hash); // head == last event hash
      // used reached 2.
      const eng = await q(client, `SELECT request_budget_used FROM engagement WHERE id=$1`, [EA]);
      expect(eng.rows[0].request_budget_used).toBe(2);
    });
  });

  describe('fail-closed gates', () => {
    it('DENY budget_exhausted when total - used - live claims <= 0', async () => {
      await seed(client, 1);
      await charge(client, { jti: 'j1' }); // used -> 1 == total
      await rejects(
        client,
        `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`,
        [T_A, EA, SPEC, 'j2', 'broker-A', 'https://example.com/api', 30],
        /budget_exhausted/,
      );
      // nothing charged for j2; used stays 1, no j2 lease exists.
      const eng = await q(client, `SELECT request_budget_used FROM engagement WHERE id=$1`, [EA]);
      expect(eng.rows[0].request_budget_used).toBe(1);
      const n = await q(
        client,
        `SELECT count(*)::int AS n FROM budget_reservation WHERE grant_jti='j2'`,
      );
      expect(n.rows[0].n).toBe(0);
    });

    it('a live claimed lease reserves capacity (availability counts it) even before it charges', async () => {
      await seed(client, 1);
      await lease(client, { jti: 'held', state: 'claimed' }); // one live claim consumes the single unit
      await rejects(
        client,
        `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`,
        [T_A, EA, SPEC, 'j1', 'broker-A', 'https://example.com/api', 30],
        /budget_exhausted/,
      );
    });

    it('an EXPIRED claimed lease does NOT reserve capacity (only live claims count)', async () => {
      await seed(client, 1);
      await lease(client, {
        jti: 'stale',
        state: 'claimed',
        expiresSql: `now()-interval '1 second'`,
      });
      // the stale claim is past its deadline ⇒ excluded from availability ⇒ the charge succeeds.
      const c1 = await charge(client, { jti: 'j1' });
      expect(c1.reservation_id).toMatch(/^[0-9a-f-]{36}$/);
    });

    it('DENY emergency_stop under the lock (hard gate, fail-closed)', async () => {
      await seed(client, 100);
      await q(client, `UPDATE engagement SET emergency_stop=TRUE WHERE id=$1`, [EA]);
      await rejects(
        client,
        `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`,
        [T_A, EA, SPEC, 'j1', 'broker-A', 'https://example.com/api', 30],
        /emergency_stop/,
      );
      const eng = await q(client, `SELECT request_budget_used FROM engagement WHERE id=$1`, [EA]);
      expect(eng.rows[0].request_budget_used).toBe(0); // never charged
    });

    it('DENY invalid_lease_ttl for a non-positive TTL', async () => {
      await seed(client, 5);
      await rejects(
        client,
        `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`,
        [T_A, EA, SPEC, 'j1', 'broker-A', 'https://example.com/api', 0],
        /invalid_lease_ttl/,
      );
    });

    it('DENY unknown_spec (fixed reason, before the composite spec FK) for a spec not in this engagement', async () => {
      await seed(client, 5);
      // the spec digest is resolved BEFORE the lease INSERT, so a bad spec_id gives the fixed reason, not a raw FK error.
      await rejects(
        client,
        `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`,
        [
          T_A,
          EA,
          '00000000-0000-0000-0000-000000000000',
          'j1',
          'broker-A',
          'https://example.com/api',
          30,
        ],
        /unknown_spec/,
      );
      const n = await q(client, `SELECT count(*)::int AS n FROM budget_reservation`);
      expect(n.rows[0].n).toBe(0); // nothing claimed/charged
    });

    it('a terminal charged lease is EXCLUDED from availability — at total=2 two charges both succeed (used=2)', async () => {
      await seed(client, 2);
      const c1 = await charge(client, { jti: 'j1' }); // used 0->1; availability 2-1-0 = 1 > 0
      const c2 = await charge(client, { jti: 'j2' }); // the first (charged) lease must NOT count as a live claim
      expect(c1.reservation_id).not.toBe(c2.reservation_id);
      const eng = await q(client, `SELECT request_budget_used FROM engagement WHERE id=$1`, [EA]);
      expect(eng.rows[0].request_budget_used).toBe(2);
    });
  });

  describe('state-machine transition trigger', () => {
    beforeEach(() => seed(client, 100));

    it('a lease cannot be BORN in a terminal state — the INSERT guard forces state=claimed, charged_at/resolved_at NULL', async () => {
      // Without this guard, a directly-inserted 'charged' row would be a terminal charged lease that never ran the
      // claimed->charged transition, so it would never increment request_budget_used — bypassing the sole meter.
      const born = (cols: string, vals: string): string =>
        `INSERT INTO budget_reservation (tenant_id, engagement_id, spec_id, grant_jti, owner, fence_token, expires_at${cols})
         VALUES ($1,$2,$3,$4,'b',1, now()+interval '30 s'${vals})`;
      const cases: Array<[string, string]> = [
        [`, state, charged_at`, `, 'charged', now()`], // born charged
        [`, state`, `, 'released'`], // born released
        [`, state`, `, 'expired'`], // born expired
        [`, state, charged_at`, `, 'claimed', now()`], // claimed but with a charged_at
        [`, resolved_at`, `, now()`], // claimed but with a resolved_at
      ];
      let i = 0;
      for (const [cols, vals] of cases) {
        await rejects(client, born(cols, vals), [T_A, EA, SPEC, `jti-born-${i++}`], /born claimed/);
      }
    });

    it("'charged' is terminal — no release / expire / re-claim", async () => {
      const c1 = await charge(client, { jti: 'j1' });
      const id = c1.reservation_id;
      await rejects(
        client,
        `UPDATE budget_reservation SET state='released' WHERE id=$1`,
        [id],
        /terminal/,
      );
      await rejects(
        client,
        `UPDATE budget_reservation SET state='expired' WHERE id=$1`,
        [id],
        /terminal/,
      );
      await rejects(
        client,
        `UPDATE budget_reservation SET state='claimed' WHERE id=$1`,
        [id],
        /terminal/,
      );
    });

    it('charged_at is write-once (cannot be cleared or altered)', async () => {
      const c1 = await charge(client, { jti: 'j1' });
      // any UPDATE of a 'charged' row is blocked by terminality (which also protects charged_at).
      await rejects(
        client,
        `UPDATE budget_reservation SET charged_at=NULL WHERE id=$1`,
        [c1.reservation_id],
        /terminal/,
      );
    });

    it('charge requires the current owner AND fence_token (stale/wrong fence rejected)', async () => {
      const id = await lease(client, { jti: 'j1', owner: 'broker-A', fence: 7 });
      // wrong owner
      await rejects(
        client,
        `UPDATE budget_reservation SET state='charged', charged_at=now(), owner='broker-B' WHERE id=$1`,
        [id],
        /current owner/,
      );
      // wrong fence token
      await rejects(
        client,
        `UPDATE budget_reservation SET state='charged', charged_at=now(), fence_token=8 WHERE id=$1`,
        [id],
        /current owner AND the current fence_token/,
      );
      // correct owner + fence + charged_at succeeds and bumps used once.
      await q(
        client,
        `UPDATE budget_reservation SET state='charged', charged_at=now() WHERE id=$1`,
        [id],
      );
      const eng = await q(client, `SELECT request_budget_used FROM engagement WHERE id=$1`, [EA]);
      expect(eng.rows[0].request_budget_used).toBe(1);
    });

    it('a charge transition MUST set charged_at (write-once on the transition)', async () => {
      const id = await lease(client, { jti: 'j1' });
      await rejects(
        client,
        `UPDATE budget_reservation SET state='charged' WHERE id=$1`,
        [id],
        /charge must set charged_at/,
      );
    });

    it('release before charge frees capacity; release/expire after charge is impossible', async () => {
      await q(client, `UPDATE engagement SET request_budget_total=1 WHERE id=$1`, [EA]);
      const id = await lease(client, { jti: 'held', state: 'claimed' });
      // with the claim live, the single unit is reserved ⇒ a charge is denied.
      await rejects(
        client,
        `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`,
        [T_A, EA, SPEC, 'j1', 'broker-A', 'https://example.com/api', 30],
        /budget_exhausted/,
      );
      // release the claim → capacity freed, resolved_at stamped.
      await q(client, `UPDATE budget_reservation SET state='released' WHERE id=$1`, [id]);
      const rel = await q(client, `SELECT resolved_at FROM budget_reservation WHERE id=$1`, [id]);
      expect(rel.rows[0].resolved_at).not.toBeNull();
      // now the charge succeeds.
      const ok = await charge(client, { jti: 'j1' });
      expect(ok.reservation_id).toMatch(/^[0-9a-f-]{36}$/);
    });

    it('renew (same owner) keeps the fence and extends the deadline; expire only past the deadline', async () => {
      const id = await lease(client, {
        jti: 'j1',
        owner: 'broker-A',
        fence: 3,
        expiresSql: `now()-interval '1 s'`,
      });
      // renew must not change fence_token.
      await rejects(
        client,
        `UPDATE budget_reservation SET fence_token=4, expires_at=now()+interval '60 s' WHERE id=$1`,
        [id],
        /renew must not change fence_token/,
      );
      // a legit renew (same fence, later deadline) is accepted, and the now-future deadline blocks expiry.
      await q(
        client,
        `UPDATE budget_reservation SET expires_at=now()+interval '60 s' WHERE id=$1`,
        [id],
      );
      await rejects(
        client,
        `UPDATE budget_reservation SET state='expired' WHERE id=$1`,
        [id],
        /cannot expire a claim before its deadline/,
      );
    });

    it('a fenced takeover needs the claim EXPIRED and a strictly-advancing fence; a live claim cannot be stolen', async () => {
      // live claim: takeover before the deadline is rejected regardless of fence.
      const live = await lease(client, { jti: 'j1', owner: 'broker-A', fence: 1 });
      await rejects(
        client,
        `UPDATE budget_reservation SET owner='broker-B', fence_token=2 WHERE id=$1`,
        [live],
        /take over a live claim/,
      );
      // expired claim: takeover must strictly advance the fence.
      const stale = await lease(client, {
        jti: 'j2',
        owner: 'broker-A',
        fence: 5,
        expiresSql: `now()-interval '1 s'`,
      });
      await rejects(
        client,
        `UPDATE budget_reservation SET owner='broker-B', fence_token=5 WHERE id=$1`,
        [stale],
        /strictly advance fence_token/,
      );
      await q(client, `UPDATE budget_reservation SET owner='broker-B', fence_token=6 WHERE id=$1`, [
        stale,
      ]);
      const t = await q(client, `SELECT owner, fence_token FROM budget_reservation WHERE id=$1`, [
        stale,
      ]);
      expect(t.rows[0].owner).toBe('broker-B');
      expect(Number(t.rows[0].fence_token)).toBe(6);
    });

    it('the sweeper expires only a past-deadline claim; a live claim cannot be expired', async () => {
      const live = await lease(client, { jti: 'j1', expiresSql: `now()+interval '60 s'` });
      await rejects(
        client,
        `UPDATE budget_reservation SET state='expired' WHERE id=$1`,
        [live],
        /cannot expire a claim before its deadline/,
      );
      const stale = await lease(client, { jti: 'j2', expiresSql: `now()-interval '1 s'` });
      await q(client, `UPDATE budget_reservation SET state='expired' WHERE id=$1`, [stale]);
      const s = await q(client, `SELECT state, resolved_at FROM budget_reservation WHERE id=$1`, [
        stale,
      ]);
      expect(s.rows[0].state).toBe('expired');
      expect(s.rows[0].resolved_at).not.toBeNull();
    });
  });

  describe('integrity: jti-uniqueness, DELETE-revocation, composite FK, RLS', () => {
    beforeEach(() => seed(client, 100));

    it('one lease per grant jti — a second lease for the same jti is rejected', async () => {
      await charge(client, { jti: 'dup' });
      await rejects(
        client,
        `INSERT INTO budget_reservation (tenant_id, engagement_id, spec_id, grant_jti, owner, fence_token, expires_at)
         VALUES ($1,$2,$3,'dup','broker-A',9, now()+interval '30 s')`,
        [T_A, EA, SPEC],
        /duplicate key|unique/i,
      );
    });

    it('DELETE is revoked on budget_reservation', async () => {
      const c1 = await charge(client, { jti: 'j1' });
      await rejects(
        client,
        `DELETE FROM budget_reservation WHERE id=$1`,
        [c1.reservation_id],
        /not permitted|append-only/,
      );
    });

    it('a lease binding a spec from a DIFFERENT engagement is a composite-FK violation', async () => {
      // create engagement B in tenant A with its own spec.
      const EB = 'bbbbbbbb-0000-0000-0000-000000000002';
      await q(
        client,
        `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone)
         VALUES ($1,$2,'EB',$3,$3,'UTC')`,
        [EB, T_A, U],
      );
      // spec_id belongs to EA, but the lease claims engagement EB ⇒ (spec_id, tenant, engagement) FK fails.
      await rejects(
        client,
        `INSERT INTO budget_reservation (tenant_id, engagement_id, spec_id, grant_jti, owner, fence_token, expires_at)
         VALUES ($1,$2,$3,'x','broker-A',1, now()+interval '30 s')`,
        [T_A, EB, SPEC],
        /foreign key/i,
      );
    });

    it('RLS: a tenant-B session sees none of tenant A ledger/counter rows', async () => {
      await charge(client, { jti: 'j1' });
      await client.query('SET ROLE app_test');
      await client.query(`SET app.tenant_id = '${T_B}'`);
      for (const t of ['budget_reservation', 'engagement_runtime_counter']) {
        const none = await q(client, `SELECT count(*)::int AS n FROM ${t}`);
        expect(none.rows[0].n, t).toBe(0);
      }
      await client.query(`SET app.tenant_id = '${T_A}'`);
      const some = await q(client, `SELECT count(*)::int AS n FROM budget_reservation`);
      expect(some.rows[0].n).toBe(1);
      await client.query('RESET ROLE');
      await client.query('RESET app.tenant_id');
    });

    it('the charge runs under the broker RLS role with app.tenant_id set, and fails closed when it is unset', async () => {
      // (a) as the non-superuser role WITH the tenant GUC: the full write path (runtime counter, lease, engagement
      // used-increment, audit chain + intent) passes every WITH CHECK ⇒ the legitimate charge succeeds.
      await client.query('SET ROLE app_test');
      await client.query(`SET app.tenant_id = '${T_A}'`);
      const ok = await q(client, `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`, [
        T_A,
        EA,
        SPEC,
        'jr1',
        'broker-A',
        'https://example.com/api',
        30,
      ]);
      expect(ok.rows[0].reservation_id).toMatch(/^[0-9a-f-]{36}$/);

      // (b) with the GUC UNSET the charge fails closed and writes nothing — the runtime-counter WITH CHECK rejects the
      // write (or, had the row been invisible, the FOR UPDATE would see no row ⇒ unknown_engagement). Either denies.
      await client.query('RESET app.tenant_id');
      await rejects(
        client,
        `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`,
        [T_A, EA, SPEC, 'jr2', 'broker-A', 'https://example.com/api', 30],
        /row-level security|unknown_engagement/,
      );
      await client.query('RESET ROLE');
      await client.query('RESET app.tenant_id');
      // exactly one charge landed (the GUC-set one); the unset attempt changed nothing.
      const eng = await q(client, `SELECT request_budget_used FROM engagement WHERE id=$1`, [EA]);
      expect(eng.rows[0].request_budget_used).toBe(1);
    });
  });

  // The whole no-over-commit story rests on the per-engagement engagement_runtime_counter FOR UPDATE lock + the
  // under-lock availability re-read. These run for real on two concurrent connections so the serialisation is proven,
  // not assumed: removing the FOR UPDATE (or hoisting the availability read above it) would make this test fail.
  describe('concurrency — serialised charges (no over-commit)', () => {
    it('two concurrent charges at total=1 serialise: exactly one succeeds, the other DENIES budget_exhausted', async () => {
      await seed(client, 1); // the engagement_runtime_counter row does NOT exist yet (first-ever-charge race)
      const clientB = new pg.Client({ connectionString: url });
      await clientB.connect();
      try {
        // tx A: charge and HOLD the transaction open — it owns the runtime-counter row + its FOR UPDATE lock.
        await client.query('BEGIN');
        const a = await q(client, `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`, [
          T_A,
          EA,
          SPEC,
          'jA',
          'broker-A',
          'https://example.com/api',
          30,
        ]);
        expect(a.rows[0].reservation_id).toMatch(/^[0-9a-f-]{36}$/);

        // tx B (second connection): the same charge must BLOCK on A's lock (the ON CONFLICT insert / FOR UPDATE).
        await clientB.query('BEGIN');
        const bPromise = clientB.query(
          `SELECT * FROM budget_charge_and_intent($1,$2,$3,$4,$5,$6,$7)`,
          [T_A, EA, SPEC, 'jB', 'broker-B', 'https://example.com/api', 30],
        );
        const settled = bPromise.then(
          () => 'resolved',
          () => 'rejected',
        );
        const raced = await Promise.race([
          settled,
          new Promise<string>((r) => setTimeout(() => r('pending'), 500)),
        ]);
        expect(raced).toBe('pending'); // B is genuinely blocked while A holds the lock

        // A commits (used -> 1). B now unblocks, re-reads used=1 under the lock ⇒ availability 1-1-0 = 0 ⇒ DENY.
        await client.query('COMMIT');
        await expect(bPromise).rejects.toThrow(/budget_exhausted/);
        await clientB.query('ROLLBACK');

        // exactly one of the two concurrent charges landed; the counter never over-committed.
        const eng = await q(client, `SELECT request_budget_used FROM engagement WHERE id=$1`, [EA]);
        expect(eng.rows[0].request_budget_used).toBe(1);
        const charged = await q(
          client,
          `SELECT count(*)::int AS n FROM budget_reservation WHERE state='charged'`,
        );
        expect(charged.rows[0].n).toBe(1);
      } finally {
        await client.query('ROLLBACK').catch(() => {});
        await clientB.query('ROLLBACK').catch(() => {});
        await clientB.end();
      }
    });
  });

  describe('audit identity + tamper evidence', () => {
    beforeEach(() => seed(client, 100));

    it('the intent event carries the engagement chain identity (tenant + engagement)', async () => {
      const c1 = await charge(client, { jti: 'j1' });
      const ev = await q(
        client,
        `SELECT ae.tenant_id, ae.engagement_id, ac.stream
         FROM audit_event ae JOIN audit_chain ac ON ac.id = ae.chain_id WHERE ae.id=$1`,
        [c1.intent_event_id],
      );
      expect(ev.rows[0].tenant_id).toBe(T_A);
      expect(ev.rows[0].engagement_id).toBe(EA);
      expect(ev.rows[0].stream).toBe('engagement');
    });

    it('audit_event remains append-only (the chained intent cannot be rewritten)', async () => {
      const c1 = await charge(client, { jti: 'j1' });
      await rejects(
        client,
        `UPDATE audit_event SET event_type='x' WHERE id=$1`,
        [c1.intent_event_id],
        /append-only/,
      );
    });
  });

  describe('lease sweeper (§8.1) — reclaim crashed claims', () => {
    beforeEach(() => seed(client, 100));

    it('expires ONLY past-deadline claimed leases; leaves live / charged / released untouched', async () => {
      const stale = await lease(client, {
        jti: 'stale',
        state: 'claimed',
        expiresSql: `now()-interval '1 second'`,
      });
      const live = await lease(client, {
        jti: 'live',
        state: 'claimed',
        expiresSql: `now()+interval '60 seconds'`,
      });
      const chargedId = (await charge(client, { jti: 'chg' })).reservation_id; // terminal 'charged'
      const rel = await lease(client, { jti: 'rel', state: 'claimed' });
      await q(client, `UPDATE budget_reservation SET state='released' WHERE id=$1`, [rel]);

      const n = await q(client, `SELECT sweep_expired_leases() AS n`);
      expect(n.rows[0].n).toBe(1); // exactly the one past-deadline claim

      const rows = await q(
        client,
        `SELECT id, state, resolved_at FROM budget_reservation ORDER BY grant_jti`,
      );
      const byId = new Map(rows.rows.map((r) => [r.id, r]));
      expect(byId.get(stale)!.state).toBe('expired');
      expect(byId.get(stale)!.resolved_at).not.toBeNull(); // the trigger stamped it
      expect(byId.get(live)!.state).toBe('claimed'); // future deadline ⇒ not swept
      expect(byId.get(chargedId)!.state).toBe('charged'); // terminal ⇒ never swept
      expect(byId.get(rel)!.state).toBe('released'); // terminal ⇒ never swept
    });

    it('is idempotent: a second sweep (and an empty ledger) reclaims nothing', async () => {
      await lease(client, {
        jti: 'stale',
        state: 'claimed',
        expiresSql: `now()-interval '1 second'`,
      });
      expect((await q(client, `SELECT sweep_expired_leases() AS n`)).rows[0].n).toBe(1);
      expect((await q(client, `SELECT sweep_expired_leases() AS n`)).rows[0].n).toBe(0);
    });
  });
});
