import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 2 slice 4b exit proof — the request_spec + catalog_template + operator_session + operator_query_value
 * schema (Phase 0 §7.0). Proves content-address verification, the DERIVED approval gate (never trusting the mode),
 * append-only immutability, the GENERATED non-secret bindings + their FK binding into request_spec, RLS, and the
 * query-path constraints. DB-gated (DATABASE_URL); runs for real in CI.
 */

const url = process.env.DATABASE_URL;
const silent: Logger = createLogger({ level: 'error', events: DB_EVENTS, sink: () => {} });

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const EA = 'aaaaaaaa-0000-0000-0000-000000000001';
const U = '99999999-9999-9999-9999-999999999999';
const SCOPE_HASH = 'a'.repeat(64);

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

/** Compute a catalog_template digest exactly as the DB trigger does, then insert it; returns the digest. */
async function mkTemplate(
  c: pg.Client,
  kind: string,
  name: string,
  version: string,
  content: string,
  safety: string,
): Promise<string> {
  const d = await q(
    c,
    `SELECT encode(digest($1 || E'\\x1f' || $2 || E'\\x1f' || $3 || E'\\x1f' || ($4::jsonb)::text || E'\\x1f' || $5, 'sha256'), 'hex') AS h`,
    [kind, name, version, content, safety],
  );
  const digest = d.rows[0].h as string;
  await q(
    c,
    `INSERT INTO catalog_template (digest, kind, name, version, content, safety_class)
     VALUES ($1,$2,$3,$4,$5::jsonb,$6)`,
    [digest, kind, name, version, content, safety],
  );
  return digest;
}

/** A GET/native/http request_spec with the given header-set template; returns its id. */
async function insertSpec(
  c: pg.Client,
  headerDigest: string,
  over: Record<string, unknown> = {},
): Promise<string> {
  const cols: Record<string, unknown> = {
    tenant_id: T_A,
    engagement_id: EA,
    run_id: U,
    job_id: U,
    scope_hash: SCOPE_HASH,
    authorization_id: over.authorization_id,
    request_class: 'native',
    kind: 'http',
    header_set_digest: headerDigest,
    method: 'GET',
    canonical_url: 'https://example.com/api',
    canonical_host: 'example.com',
    port: 443,
    scheme: 'https',
    canonical_path: '/api',
    mode: 'passive',
    spec_sha256: 'f'.repeat(64),
    ...over,
  };
  const keys = Object.keys(cols);
  const vals = keys.map((_, i) => `$${i + 1}`).join(',');
  const res = await q(
    c,
    `INSERT INTO request_spec (${keys.join(',')}) VALUES (${vals}) RETURNING id, approval_required`,
    keys.map((k) => cols[k]),
  );
  return res.rows[0].id as string;
}

describe.skipIf(!url)('slice 4b — request_spec / catalog / operator secrets (§7.0)', () => {
  let client: pg.Client;
  let authId: string;

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
    await client.query(`INSERT INTO tenant (id, name) VALUES ($1,'A'),($2,'B')`, [T_A, T_B]);
    await client.query(
      `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone)
       VALUES ($1,$2,'EngA',$3,$3,'UTC')`,
      [EA, T_A, U],
    );
    await client.query(
      `INSERT INTO scope_version (id, tenant_id, engagement_id, version_number, scope_hash,
         entry_count, host_count, ipv4_equiv_addresses, cidr_entry_count, created_by)
       VALUES ('cccccccc-0000-0000-0000-000000000001',$1,$2,1,$3,0,0,0,0,$4)`,
      [T_A, EA, SCOPE_HASH, U],
    );
    const a = await client.query(
      `INSERT INTO "authorization" (tenant_id, engagement_id, authorization_reference, authorizing_party_name,
         authorizing_party_org, engagement_owner_user_id, effective_from, expires_at, allowed_modes,
         scope_version_id, scope_hash, record_hash)
       VALUES ($1,$2,'ref','p','o',$3, now(), now()+interval '10 days', ARRAY['passive','safe_active'],
               'cccccccc-0000-0000-0000-000000000001',$4,$5) RETURNING id`,
      [T_A, EA, U, SCOPE_HASH, 'r'.repeat(64)],
    );
    authId = a.rows[0].id as string;
  });

  describe('catalog_template content-addressing', () => {
    it('accepts a correctly-addressed template and rejects a wrong digest', async () => {
      const d = await mkTemplate(client, 'header_set', 'safe-headers', 'v1', '{"h":1}', 'inert');
      expect(d).toMatch(/^[0-9a-f]{64}$/);
      await rejects(
        client,
        `INSERT INTO catalog_template (digest, kind, name, version, content, safety_class)
         VALUES ($1,'payload','p','v1','{"x":1}'::jsonb,'inert')`,
        ['0'.repeat(64)],
        /does not match the content address/,
      );
    });

    it('is append-only (UPDATE/DELETE rejected)', async () => {
      const d = await mkTemplate(client, 'header_set', 'h', 'v1', '{"a":1}', 'inert');
      await rejects(
        client,
        `UPDATE catalog_template SET name='x' WHERE digest=$1`,
        [d],
        /append-only/,
      );
      await rejects(client, `DELETE FROM catalog_template WHERE digest=$1`, [d], /append-only/);
    });
  });

  describe('request_spec derived approval gate (§7.0/§10)', () => {
    it('a GET with only inert templates derives approval_required=FALSE', async () => {
      const h = await mkTemplate(client, 'header_set', 'h', 'v1', '{"a":1}', 'inert');
      const id = await insertSpec(client, h, { authorization_id: authId });
      const r = await q(client, `SELECT approval_required FROM request_spec WHERE id=$1`, [id]);
      expect(r.rows[0].approval_required).toBe(false);
    });

    it('a state-changing method derives approval_required=TRUE (and then needs an approval_ref)', async () => {
      const h = await mkTemplate(client, 'header_set', 'h', 'v1', '{"a":1}', 'inert');
      const payload = await mkTemplate(client, 'payload', 'p', 'v1', '{"b":2}', 'inert');
      // POST without an approval_ref ⇒ the derived approval_required=TRUE trips approval_present.
      await rejects(
        client,
        `INSERT INTO request_spec (tenant_id, engagement_id, run_id, job_id, scope_hash, authorization_id,
           request_class, kind, header_set_digest, payload_digest, method, canonical_url, canonical_host, port,
           scheme, canonical_path, mode, spec_sha256)
         VALUES ($1,$2,$3,$3,$4,$5,'native','http',$6,$7,'POST','https://example.com/api','example.com',443,
                 'https','/api','passive',$8)`,
        [T_A, EA, U, SCOPE_HASH, authId, h, payload, 'f'.repeat(64)],
        /approval_present/,
      );
    });

    it('a requires_approval template derives approval_required=TRUE even for a GET', async () => {
      const h = await mkTemplate(client, 'header_set', 'h', 'v1', '{"a":1}', 'requires_approval');
      await rejects(
        client,
        `INSERT INTO request_spec (tenant_id, engagement_id, run_id, job_id, scope_hash, authorization_id,
           request_class, kind, header_set_digest, method, canonical_url, canonical_host, port, scheme,
           canonical_path, mode, spec_sha256)
         VALUES ($1,$2,$3,$3,$4,$5,'native','http',$6,'GET','https://example.com/api','example.com',443,'https',
                 '/api','passive',$7)`,
        [T_A, EA, U, SCOPE_HASH, authId, h, 'f'.repeat(64)],
        /approval_present/,
      );
    });
  });

  describe('operator_session / operator_query_value', () => {
    it('generates a non-secret session_digest and is append-only', async () => {
      const s = await q(
        client,
        `INSERT INTO operator_session (tenant_id, engagement_id, account_id, secret_ref, designated_hosts)
         VALUES ($1,$2,'acct-1','lease://s1', ARRAY['example.com']) RETURNING id, session_digest`,
        [T_A, EA],
      );
      expect(s.rows[0].session_digest).toMatch(/^[0-9a-f]{64}$/);
      await rejects(
        client,
        `UPDATE operator_session SET secret_ref='x' WHERE id=$1`,
        [s.rows[0].id],
        /append-only/,
      );
    });

    it('a request_spec session_digest that does not match the referenced session is rejected (FK)', async () => {
      const h = await mkTemplate(client, 'header_set', 'h', 'v1', '{"a":1}', 'inert');
      const s = await q(
        client,
        `INSERT INTO operator_session (tenant_id, engagement_id, account_id, secret_ref, designated_hosts)
         VALUES ($1,$2,'acct-1','lease://s1', ARRAY['example.com']) RETURNING id, session_digest`,
        [T_A, EA],
      );
      const sid = s.rows[0].id as string;
      // wrong session_digest for the referenced session ⇒ the (session_ref, session_digest) FK fails.
      await rejects(
        client,
        `INSERT INTO request_spec (tenant_id, engagement_id, run_id, job_id, scope_hash, authorization_id,
           request_class, kind, header_set_digest, method, canonical_url, canonical_host, port, scheme,
           canonical_path, session_ref, session_digest, mode, spec_sha256)
         VALUES ($1,$2,$3,$3,$4,$5,'native','http',$6,'GET','https://example.com/api','example.com',443,'https',
                 '/api',$7,$8,'passive',$9)`,
        [T_A, EA, U, SCOPE_HASH, authId, h, sid, 'b'.repeat(64), 'f'.repeat(64)],
        /foreign key/i,
      );
      // the matching digest is accepted.
      const ok = await insertSpec(client, h, {
        authorization_id: authId,
        session_ref: sid,
        session_digest: s.rows[0].session_digest,
      });
      expect(ok).toMatch(/^[0-9a-f-]+$/);
    });
  });

  describe('request_spec immutability, isolation, query paths', () => {
    it('is append-only (UPDATE/DELETE rejected)', async () => {
      const h = await mkTemplate(client, 'header_set', 'h', 'v1', '{"a":1}', 'inert');
      const id = await insertSpec(client, h, { authorization_id: authId });
      await rejects(client, `UPDATE request_spec SET port=8443 WHERE id=$1`, [id], /append-only/);
      await rejects(client, `DELETE FROM request_spec WHERE id=$1`, [id], /append-only/);
    });

    it('cannot mix a curated query template with the secret query path', async () => {
      const h = await mkTemplate(client, 'header_set', 'h', 'v1', '{"a":1}', 'inert');
      const qt = await mkTemplate(client, 'query_template', 'qt', 'v1', '{"q":1}', 'inert');
      const ov = await q(
        client,
        `INSERT INTO operator_query_value (tenant_id, engagement_id, value_set_name, value_version, secret_ref)
         VALUES ($1,$2,'vs',1,'lease://v1') RETURNING id, value_binding`,
        [T_A, EA],
      );
      await rejects(
        client,
        `INSERT INTO request_spec (tenant_id, engagement_id, run_id, job_id, scope_hash, authorization_id,
           request_class, kind, header_set_digest, method, canonical_url, canonical_host, port, scheme,
           canonical_path, query_template_digest, query_value_ref, query_value_binding, query_value_digest,
           mode, spec_sha256)
         VALUES ($1,$2,$3,$3,$4,$5,'native','http',$6,'GET','https://example.com/api','example.com',443,'https',
                 '/api',$7,$8,$9,$10,'passive',$11)`,
        [
          T_A,
          EA,
          U,
          SCOPE_HASH,
          authId,
          h,
          qt,
          ov.rows[0].id,
          ov.rows[0].value_binding,
          'd'.repeat(64),
          'f'.repeat(64),
        ],
        /query_values_one_path/,
      );
    });

    it('RLS: a tenant-B session sees none of tenant A request_specs', async () => {
      const h = await mkTemplate(client, 'header_set', 'h', 'v1', '{"a":1}', 'inert');
      await insertSpec(client, h, { authorization_id: authId });
      await client.query('SET ROLE app_test');
      await client.query(`SET app.tenant_id = '${T_B}'`);
      const none = await q(client, 'SELECT count(*)::int AS n FROM request_spec');
      expect(none.rows[0].n).toBe(0);
      await client.query(`SET app.tenant_id = '${T_A}'`);
      const some = await q(client, 'SELECT count(*)::int AS n FROM request_spec');
      expect(some.rows[0].n).toBe(1);
      await client.query('RESET ROLE');
      await client.query('RESET app.tenant_id');
    });
  });
});
