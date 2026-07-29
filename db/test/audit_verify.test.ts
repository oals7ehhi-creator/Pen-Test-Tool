import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 2 slice 5i exit proof — audit-chain VERIFICATION (Phase 0 doc 04 §9). audit_append (0004) makes the log
 * tamper-EVIDENT; this proves the evidence is actually READABLE: verify_audit_chain re-derives every digest from the
 * stored payload and reports a fixed reason on the first break.
 *
 * The tamper battery below writes to audit_event with its append-only triggers DISABLED — that is not a workaround,
 * it IS the threat model: the triggers stop the application from rewriting history, and the hash chain exists to catch
 * the actor with direct database privileges who can step around them. Each mutation must be caught, with the right
 * reason. DB-gated.
 */

const url = process.env.DATABASE_URL;
const silent: Logger = createLogger({ level: 'error', events: DB_EVENTS, sink: () => {} });

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const EA = 'aaaaaaaa-0000-0000-0000-000000000001';
const U = '99999999-9999-9999-9999-999999999999';
const CHAIN = 'dddddddd-0000-0000-0000-0000000000c1';

async function q(c: pg.Client, sql: string, params: unknown[] = []): Promise<pg.QueryResult> {
  return c.query(sql, params);
}

interface Verdict {
  ok: boolean;
  events_checked: number;
  bad_seq: number | null;
  reason: string;
}
const verify = async (c: pg.Client, chain = CHAIN): Promise<Verdict> => {
  const r = (await q(c, `SELECT * FROM verify_audit_chain($1)`, [chain])).rows[0];
  return {
    ok: r.ok,
    events_checked: Number(r.events_checked),
    bad_seq: r.bad_seq === null ? null : Number(r.bad_seq),
    reason: r.reason,
  };
};

/** Append one event through the real primitive (the only sanctioned writer). */
const append = (
  c: pg.Client,
  type: string,
  payload: unknown = { k: 'v' },
): Promise<pg.QueryResult> =>
  q(c, `SELECT audit_append($1,'user',$2,'operator',$3,'request',NULL,NULL,$4::jsonb) AS id`, [
    CHAIN,
    U,
    type,
    JSON.stringify(payload),
  ]);

/** Write to audit_event stepping around the append-only triggers — the privileged-attacker threat model. */
async function tamper(c: pg.Client, sql: string, params: unknown[] = []): Promise<void> {
  await q(c, `ALTER TABLE audit_event DISABLE TRIGGER USER`);
  try {
    await q(c, sql, params);
  } finally {
    await q(c, `ALTER TABLE audit_event ENABLE TRIGGER USER`);
  }
}

/** Seed the tenant + engagement + an engagement audit chain, then append `n` events. */
async function seed(c: pg.Client, n = 3): Promise<void> {
  await q(c, `INSERT INTO tenant (id, name) VALUES ($1,'A'),($2,'B')`, [T_A, T_B]);
  await q(
    c,
    `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone)
     VALUES ($1,$2,'E',$3,$3,'UTC')`,
    [EA, T_A, U],
  );
  await q(
    c,
    `INSERT INTO audit_chain (id, stream, tenant_id, engagement_id) VALUES ($1,'engagement',$2,$3)`,
    [CHAIN, T_A, EA],
  );
  for (let i = 0; i < n; i++) await append(c, `request.step${i}`, { step: i });
}

describe.skipIf(!url)('slice 5i — audit-chain verification (§9)', () => {
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

  describe('an untampered chain verifies', () => {
    it('verifies a multi-event chain built by audit_append', async () => {
      await seed(client, 5);
      expect(await verify(client)).toEqual({
        ok: true,
        events_checked: 5,
        bad_seq: null,
        reason: 'ok',
      });
    });

    it('verifies a brand-new EMPTY chain (genesis head, no events)', async () => {
      await seed(client, 0);
      expect(await verify(client)).toEqual({
        ok: true,
        events_checked: 0,
        bad_seq: null,
        reason: 'ok',
      });
    });

    it('reports unknown_chain for a chain id that does not exist', async () => {
      await seed(client, 1);
      expect(await verify(client, 'dddddddd-0000-0000-0000-0000000000ff')).toMatchObject({
        ok: false,
        reason: 'unknown_chain',
      });
    });
  });

  describe('the tamper battery — every edit is caught, with the right reason', () => {
    it('detects a MUTATED PAYLOAD (payload_sha256 no longer covers the stored payload)', async () => {
      await seed(client, 3);
      await tamper(client, `UPDATE audit_event SET payload='{"k":"evil"}'::jsonb WHERE seq=2`);
      expect(await verify(client)).toMatchObject({
        ok: false,
        bad_seq: 2,
        reason: 'payload_tampered',
      });
    });

    it('detects a payload rewritten WITH its digest recomputed (event_hash still binds it)', async () => {
      await seed(client, 3);
      // a smarter attacker fixes payload_sha256 too — but event_hash binds that digest, so the chain still breaks.
      await tamper(
        client,
        `UPDATE audit_event
            SET payload='{"k":"evil"}'::jsonb,
                payload_sha256=encode(digest(convert_to('{"k": "evil"}','utf8'),'sha256'),'hex')
          WHERE seq=2`,
      );
      const v = await verify(client);
      expect(v.ok).toBe(false);
      expect(v.bad_seq).toBe(2);
      expect(['payload_tampered', 'event_hash_mismatch']).toContain(v.reason);
    });

    it('detects a FLIPPED event_type (the type is bound into event_hash)', async () => {
      await seed(client, 3);
      await tamper(client, `UPDATE audit_event SET event_type='request.benign' WHERE seq=2`);
      expect(await verify(client)).toMatchObject({
        ok: false,
        bad_seq: 2,
        reason: 'event_hash_mismatch',
      });
    });

    it('detects a CUT LINK (prev_hash repointed)', async () => {
      await seed(client, 3);
      await tamper(client, `UPDATE audit_event SET prev_hash=repeat('a',64) WHERE seq=3`);
      expect(await verify(client)).toMatchObject({
        ok: false,
        bad_seq: 3,
        reason: 'chain_broken',
      });
    });

    it('detects a forged GENESIS (the first event no longer starts from the zero head)', async () => {
      await seed(client, 2);
      await tamper(client, `UPDATE audit_event SET prev_hash=repeat('b',64) WHERE seq=1`);
      expect(await verify(client)).toMatchObject({
        ok: false,
        bad_seq: 1,
        reason: 'genesis_mismatch',
      });
    });

    it('detects a DELETED MIDDLE event (seq is no longer contiguous)', async () => {
      await seed(client, 4);
      await tamper(client, `DELETE FROM audit_event WHERE seq=2`);
      expect(await verify(client)).toMatchObject({ ok: false, bad_seq: 3, reason: 'seq_gap' });
    });

    it('detects a TRUNCATED TAIL — the case a prefix-only check would MISS', async () => {
      await seed(client, 4);
      // events 1..2 remain a perfectly valid chain: genesis, links, digests all still check out. Only the stored head
      // (still naming seq 4) reveals that two events were lopped off the end.
      await tamper(client, `DELETE FROM audit_event WHERE seq > 2`);
      expect(await verify(client)).toMatchObject({
        ok: false,
        events_checked: 2,
        reason: 'head_mismatch',
      });
    });

    it('LIMIT (documented, not a detection): a truncation whose HEAD is also forged back verifies clean', async () => {
      await seed(client, 4);
      await tamper(client, `DELETE FROM audit_event WHERE seq > 2`);
      // the attacker also rewrites the chain head to match the surviving prefix — audit_chain is NOT append-only, so
      // this succeeds and the chain now verifies. That is the honest limit of a self-contained chain: detecting it
      // requires an EXTERNAL anchor (a witnessed/exported head), which §9's external attestation provides.
      await q(
        client,
        `UPDATE audit_chain SET head_seq=2, head_hash=(SELECT event_hash FROM audit_event WHERE seq=2) WHERE id=$1`,
        [CHAIN],
      );
      expect(await verify(client)).toMatchObject({ ok: true, events_checked: 2, reason: 'ok' });
    });

    it('detects a REORDER (two events swap their seq)', async () => {
      await seed(client, 3);
      // UNIQUE (chain_id, seq) already forces the attacker through a temporary slot — a single CASE swap is rejected
      // outright — so the reorder has to be staged. Verification must still catch the result.
      await tamper(
        client,
        `UPDATE audit_event SET seq=999 WHERE seq=2;
         UPDATE audit_event SET seq=2   WHERE seq=3;
         UPDATE audit_event SET seq=3   WHERE seq=999;`,
      );
      const v = await verify(client);
      expect(v.ok).toBe(false);
      expect(['chain_broken', 'event_hash_mismatch', 'seq_gap']).toContain(v.reason);
    });

    it('detects an APPENDED forgery (a fabricated event past the head)', async () => {
      await seed(client, 2);
      await tamper(
        client,
        `INSERT INTO audit_event (chain_id, tenant_id, engagement_id, seq, actor_type, actor_id, actor_role,
           event_type, subject_type, payload, payload_sha256, prev_hash, event_hash)
         SELECT $1,$2,$3,3,'user',$4,'operator','request.forged','request','{}'::jsonb,
                repeat('c',64), repeat('d',64), repeat('e',64)`,
        [CHAIN, T_A, EA, U],
      );
      const v = await verify(client);
      expect(v.ok).toBe(false);
      expect(v.bad_seq).toBe(3);
      expect(['chain_broken', 'payload_tampered', 'event_hash_mismatch']).toContain(v.reason);
    });
  });

  describe('verification is read-only and RLS-scoped', () => {
    it('writes NOTHING — verifying cannot itself alter the evidence', async () => {
      await seed(client, 3);
      const before = (
        await q(
          client,
          `SELECT count(*)::int AS n, max(seq)::int AS s, string_agg(event_hash,',' ORDER BY seq) AS h
             FROM audit_event`,
        )
      ).rows[0];
      await verify(client);
      await verify(client);
      const after = (
        await q(
          client,
          `SELECT count(*)::int AS n, max(seq)::int AS s, string_agg(event_hash,',' ORDER BY seq) AS h
             FROM audit_event`,
        )
      ).rows[0];
      expect(after).toEqual(before);
      const head = (
        await q(client, `SELECT head_seq, head_hash FROM audit_chain WHERE id=$1`, [CHAIN])
      ).rows[0];
      expect(Number(head.head_seq)).toBe(3);
    });

    it('RLS: the owning tenant verifies its chain; a tenant-B session cannot see it at all', async () => {
      await seed(client, 3);
      await client.query('SET ROLE app_test');
      await client.query(`SET app.tenant_id = '${T_A}'`);
      expect(await verify(client)).toMatchObject({ ok: true, reason: 'ok' });
      // tenant B: the chain row is invisible ⇒ fail closed (you cannot attest to what you cannot read).
      await client.query(`SET app.tenant_id = '${T_B}'`);
      expect(await verify(client)).toMatchObject({ ok: false, reason: 'unknown_chain' });
      await client.query('RESET ROLE');
      await client.query('RESET app.tenant_id');
    });

    it('RLS fail-closed: with app.tenant_id unset the chain is invisible ⇒ unknown_chain', async () => {
      await seed(client, 2);
      await client.query('SET ROLE app_test');
      await client.query('RESET app.tenant_id');
      expect(await verify(client)).toMatchObject({ ok: false, reason: 'unknown_chain' });
      await client.query('RESET ROLE');
    });
  });
});
