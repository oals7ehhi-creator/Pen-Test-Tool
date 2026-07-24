import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 2 slice 3 exit proof — the authorization/scope/approval/audit schema enforces its safety invariants at the
 * STORAGE layer (Phase 0 doc 04). Requires a database (DATABASE_URL); skipped otherwise so `pnpm -r run test` still
 * runs without one. In CI (build-test) DATABASE_URL points at the Postgres service, so this runs for real.
 *
 * RLS note: superusers BYPASS row-level security even under FORCE. To prove tenant isolation we create a
 * non-superuser role and `SET ROLE` to it (the app connects as such a role in production, doc 03).
 */

const url = process.env.DATABASE_URL;
const silent: Logger = createLogger({ level: 'error', events: DB_EVENTS, sink: () => {} });

const T_A = '11111111-1111-1111-1111-111111111111';
const T_B = '22222222-2222-2222-2222-222222222222';
const U = '99999999-9999-9999-9999-999999999999';
const ADMIN = '00000000-0000-0000-0000-000000000000';

async function q(c: pg.Client, sql: string, params: unknown[] = []): Promise<pg.QueryResult> {
  return c.query(sql, params);
}
/** Assert a statement rejects, and (optionally) that the error message matches. */
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
  throw new Error(`expected statement to be rejected but it succeeded: ${sql.slice(0, 80)}`);
}

describe.skipIf(!url)(
  'slice 3 schema — authority isolation, RLS, immutability, approval integrity',
  () => {
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
      // Re-apply all migrations (0001 baseline + 0002 under test) onto the clean schema.
      await up(client, silent);
      // A non-superuser role that RLS actually applies to.
      await client.query('DROP ROLE IF EXISTS app_test').catch(() => {});
      await client.query('CREATE ROLE app_test NOLOGIN');
      await client.query('GRANT USAGE ON SCHEMA public TO app_test');
      await client.query(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_test',
      );
      // Two tenants + one engagement each (as superuser; RLS bypassed for setup).
      await client.query(`INSERT INTO tenant (id, name) VALUES ($1,'TenantA'),($2,'TenantB')`, [
        T_A,
        T_B,
      ]);
      await client.query(
        `INSERT INTO engagement (id, tenant_id, name, owner_user_id, created_by, timezone)
       VALUES ('aaaaaaaa-0000-0000-0000-000000000001',$1,'EngA',$2,$2,'UTC'),
              ('bbbbbbbb-0000-0000-0000-000000000001',$3,'EngB',$2,$2,'UTC')`,
        [T_A, U, T_B],
      );
    });

    it('seeds exactly one current approval_policy per request_type (6 total)', async () => {
      const all = await q(client, 'SELECT count(*)::int AS n FROM approval_policy');
      expect(all.rows[0].n).toBe(6);
      const current = await q(
        client,
        'SELECT count(*)::int AS n FROM approval_policy WHERE superseded = FALSE',
      );
      expect(current.rows[0].n).toBe(6);
      const floor = await q(
        client,
        `SELECT required_approvals FROM approval_policy WHERE request_type='authorization_attestation'`,
      );
      expect(floor.rows[0].required_approvals).toBe(2);
    });

    describe('RLS tenant isolation (non-superuser role)', () => {
      it('a tenant-A session sees only tenant-A engagements, and none with the GUC unset', async () => {
        await client.query('SET ROLE app_test');
        await client.query(`SET app.tenant_id = '${T_A}'`);
        const a = await q(client, 'SELECT count(*)::int AS n FROM engagement');
        expect(a.rows[0].n).toBe(1);
        const nameRes = await q(client, 'SELECT name FROM engagement');
        expect(nameRes.rows[0].name).toBe('EngA');
        // Unset GUC ⇒ fail-closed (no rows).
        await client.query('RESET app.tenant_id');
        const none = await q(client, 'SELECT count(*)::int AS n FROM engagement');
        expect(none.rows[0].n).toBe(0);
        await client.query('RESET ROLE');
      });

      it('a tenant-A session cannot INSERT a row for tenant B (WITH CHECK)', async () => {
        await client.query('SET ROLE app_test');
        await client.query(`SET app.tenant_id = '${T_A}'`);
        await rejects(
          client,
          `INSERT INTO engagement (tenant_id, name, owner_user_id, created_by, timezone)
         VALUES ($1,'Sneaky',$2,$2,'UTC')`,
          [T_B, U],
          /row-level security/i,
        );
        await client.query('RESET ROLE');
      });
    });

    describe('composite (id, tenant_id, engagement_id) authority isolation', () => {
      it('an authorization cannot bind a scope_version from another engagement/tenant', async () => {
        await q(
          client,
          `INSERT INTO scope_version (id, tenant_id, engagement_id, version_number, scope_hash,
           entry_count, host_count, ipv4_equiv_addresses, cidr_entry_count, created_by)
         VALUES ('cccccccc-0000-0000-0000-000000000001',$1,'aaaaaaaa-0000-0000-0000-000000000001',1,$2,0,0,0,0,$3)`,
          [T_A, 'a'.repeat(64), U],
        );
        // authorization in Eng B (tenant B) binding Eng A's scope_version ⇒ composite FK violation.
        await rejects(
          client,
          `INSERT INTO "authorization" (tenant_id, engagement_id, authorization_reference, authorizing_party_name,
           authorizing_party_org, engagement_owner_user_id, effective_from, expires_at, allowed_modes,
           scope_version_id, scope_hash, record_hash)
         VALUES ($1,'bbbbbbbb-0000-0000-0000-000000000001','ref','p','o',$2, now(), now()+interval '1 day',
                 ARRAY['passive'],'cccccccc-0000-0000-0000-000000000001',$3,$4)`,
          [T_B, U, 'a'.repeat(64), 'b'.repeat(64)],
          /foreign key/i,
        );
      });
    });

    describe('immutability / append-only', () => {
      async function makeChainEvent(): Promise<void> {
        await q(
          client,
          `INSERT INTO audit_chain (id, stream, tenant_id, engagement_id)
         VALUES ('dddddddd-0000-0000-0000-000000000001','engagement',$1,'aaaaaaaa-0000-0000-0000-000000000001')`,
          [T_A],
        );
        await q(
          client,
          `INSERT INTO audit_event (id, chain_id, tenant_id, engagement_id, seq, actor_type, event_type,
           payload, payload_sha256, prev_hash, event_hash)
         VALUES ('eeeeeeee-0000-0000-0000-000000000001','dddddddd-0000-0000-0000-000000000001',$1,
                 'aaaaaaaa-0000-0000-0000-000000000001',1,'system','test','{}'::jsonb,$2,$3,$4)`,
          [T_A, '0'.repeat(64), '0'.repeat(64), '1'.repeat(64)],
        );
      }

      it('audit_event rejects UPDATE and DELETE (append-only)', async () => {
        await makeChainEvent();
        await rejects(
          client,
          `UPDATE audit_event SET event_type='x' WHERE seq=1`,
          [],
          /append-only/,
        );
        await rejects(client, `DELETE FROM audit_event WHERE seq=1`, [], /append-only/);
      });

      it('audit_event identity must match its chain (null-safe)', async () => {
        await q(
          client,
          `INSERT INTO audit_chain (id, stream, tenant_id, engagement_id)
         VALUES ('dddddddd-0000-0000-0000-000000000002','engagement',$1,'aaaaaaaa-0000-0000-0000-000000000001')`,
          [T_A],
        );
        // event claims tenant B but the chain is tenant A ⇒ rejected by the identity trigger.
        await rejects(
          client,
          `INSERT INTO audit_event (chain_id, tenant_id, engagement_id, seq, actor_type, event_type,
           payload, payload_sha256, prev_hash, event_hash)
         VALUES ('dddddddd-0000-0000-0000-000000000002',$1,'aaaaaaaa-0000-0000-0000-000000000001',1,'system','t',
                 '{}'::jsonb,$2,$3,$4)`,
          [T_B, '0'.repeat(64), '0'.repeat(64), '2'.repeat(64)],
          /identity/,
        );
      });

      it('scope_entry cannot be added once its scope_version is frozen', async () => {
        await q(
          client,
          `INSERT INTO scope_version (id, tenant_id, engagement_id, version_number, scope_hash,
           entry_count, host_count, ipv4_equiv_addresses, cidr_entry_count, created_by)
         VALUES ('cccccccc-0000-0000-0000-000000000002',$1,'aaaaaaaa-0000-0000-0000-000000000001',1,$2,0,0,0,0,$3)`,
          [T_A, 'a'.repeat(64), U],
        );
        // an entry is fine while unfrozen…
        await q(
          client,
          `INSERT INTO scope_entry (tenant_id, scope_version_id, entry_class, raw_value, canonical_value,
           host_ascii, wildcard, include_subdomains)
         VALUES ($1,'cccccccc-0000-0000-0000-000000000002','domain','x.example','x.example','x.example',false,false)`,
          [T_A],
        );
        await q(
          client,
          `UPDATE scope_version SET frozen=TRUE WHERE id='cccccccc-0000-0000-0000-000000000002'`,
        );
        // …and rejected once frozen.
        await rejects(
          client,
          `INSERT INTO scope_entry (tenant_id, scope_version_id, entry_class, raw_value, canonical_value,
           host_ascii, wildcard, include_subdomains)
         VALUES ($1,'cccccccc-0000-0000-0000-000000000002','domain','y.example','y.example','y.example',false,false)`,
          [T_A],
          /frozen/,
        );
      });

      it('scope_version frozen flag is monotonic (cannot revert TRUE->FALSE)', async () => {
        await q(
          client,
          `INSERT INTO scope_version (id, tenant_id, engagement_id, version_number, scope_hash,
           entry_count, host_count, ipv4_equiv_addresses, cidr_entry_count, created_by, frozen)
         VALUES ('cccccccc-0000-0000-0000-000000000003',$1,'aaaaaaaa-0000-0000-0000-000000000001',1,$2,0,0,0,0,$3,TRUE)`,
          [T_A, 'a'.repeat(64), U],
        );
        await rejects(
          client,
          `UPDATE scope_version SET frozen=FALSE WHERE id='cccccccc-0000-0000-0000-000000000003'`,
          [],
          /cannot revert/,
        );
      });
    });

    describe('approval_policy strength (immutable, non-decreasing)', () => {
      it('content is immutable; only superseded FALSE->TRUE is allowed', async () => {
        await rejects(
          client,
          `UPDATE approval_policy SET required_approvals=3 WHERE request_type='scope_expansion'`,
          [],
          /immutable/,
        );
        // the permitted transition succeeds
        await q(
          client,
          `UPDATE approval_policy SET superseded=TRUE WHERE request_type='scope_expansion' AND version=1`,
        );
      });

      it('a new version may not weaken required_approvals below the prior version', async () => {
        await q(
          client,
          `UPDATE approval_policy SET superseded=TRUE WHERE request_type='scope_expansion' AND version=1`,
        );
        await rejects(
          client,
          `INSERT INTO approval_policy (policy_digest, request_type, required_approvals, approver_roles, role_quorum, version, created_by)
         VALUES ($1,'scope_expansion',1,ARRAY['Engagement Manager','Reviewer'],'{}'::jsonb,2,$2)`,
          ['d'.repeat(64), ADMIN],
          /weakens required_approvals/,
        );
      });

      it('a new version may not broaden approver_roles beyond the prior allowlist', async () => {
        await q(
          client,
          `UPDATE approval_policy SET superseded=TRUE WHERE request_type='scope_expansion' AND version=1`,
        );
        await rejects(
          client,
          `INSERT INTO approval_policy (policy_digest, request_type, required_approvals, approver_roles, role_quorum, version, created_by)
         VALUES ($1,'scope_expansion',2,ARRAY['Engagement Manager','Reviewer','Administrator'],'{}'::jsonb,2,$2)`,
          ['d'.repeat(64), ADMIN],
          /broadens approver_roles/,
        );
      });

      it('role_quorum must be satisfiable (sum <= required_approvals)', async () => {
        await rejects(
          client,
          `INSERT INTO approval_policy (policy_digest, request_type, required_approvals, approver_roles, role_quorum, version, created_by)
         VALUES ($1,'mode_elevation',2,ARRAY['Engagement Manager','Reviewer'],'{"Engagement Manager":2,"Reviewer":2}'::jsonb,99,$2)`,
          ['e'.repeat(64), ADMIN],
          /unsatisfiable/,
        );
      });
    });

    describe('approval decision + manifest integrity', () => {
      // Build an intrusive_validation request with a frozen single-entry manifest, then exercise decision pins.
      async function makeFrozenIntrusive(): Promise<{
        reqId: string;
        policyDigest: string;
        manifest: string;
      }> {
        const spec = 'f'.repeat(64);
        const pol = await q(
          client,
          `SELECT id, policy_digest FROM approval_policy WHERE request_type='intrusive_validation'`,
        );
        const policyId = pol.rows[0].id as string;
        const policyDigest = pol.rows[0].policy_digest as string;
        // manifest_sha256 = sha256 of the sorted single-digest set = digest(spec).
        const mh = await q(client, `SELECT encode(digest($1,'sha256'),'hex') AS h`, [spec]);
        const manifest = mh.rows[0].h as string;
        const req = await q(
          client,
          `INSERT INTO approval_request (tenant_id, engagement_id, request_type, approval_policy_id, requested_by,
           justification, proposed_action, manifest_sha256, potential_impact, target_summary, scope_check_result,
           evidence_plan, stop_conditions, expires_at)
         VALUES ($1,'aaaaaaaa-0000-0000-0000-000000000001','intrusive_validation',$2,$3,'j','{}'::jsonb,$4,'imp','t',
                 '{"decision":"pass"}'::jsonb,'ev','stop', now()+interval '1 day') RETURNING id`,
          [T_A, policyId, U, manifest],
        );
        const reqId = req.rows[0].id as string;
        await q(
          client,
          `INSERT INTO approval_manifest_entry (tenant_id, approval_request_id, spec_sha256) VALUES ($1,$2,$3)`,
          [T_A, reqId, spec],
        );
        await q(client, `UPDATE approval_request SET manifest_frozen=TRUE WHERE id=$1`, [reqId]);
        return { reqId, policyDigest, manifest };
      }

      it('freezing a manifest whose hash disagrees with its entries is rejected', async () => {
        const pol = await q(
          client,
          `SELECT id FROM approval_policy WHERE request_type='intrusive_validation'`,
        );
        const req = await q(
          client,
          `INSERT INTO approval_request (tenant_id, engagement_id, request_type, approval_policy_id, requested_by,
           justification, proposed_action, manifest_sha256, potential_impact, target_summary, scope_check_result,
           evidence_plan, stop_conditions, expires_at)
         VALUES ($1,'aaaaaaaa-0000-0000-0000-000000000001','intrusive_validation',$2,$3,'j','{}'::jsonb,$4,'imp','t',
                 '{"decision":"pass"}'::jsonb,'ev','stop', now()+interval '1 day') RETURNING id`,
          [T_A, pol.rows[0].id, U, 'a'.repeat(64)],
        );
        await q(
          client,
          `INSERT INTO approval_manifest_entry (tenant_id, approval_request_id, spec_sha256) VALUES ($1,$2,$3)`,
          [T_A, req.rows[0].id, 'f'.repeat(64)],
        );
        await rejects(
          client,
          `UPDATE approval_request SET manifest_frozen=TRUE WHERE id=$1`,
          [req.rows[0].id],
          /!= recomputed digest/,
        );
      });

      it('an approve decision must pin the manifest hash and policy digest (NULL never bypasses)', async () => {
        const { reqId, policyDigest, manifest } = await makeFrozenIntrusive();
        // NULL manifest pin ⇒ rejected.
        await rejects(
          client,
          `INSERT INTO approval_decision (tenant_id, approval_request_id, approver_user_id, approver_role, decision,
           approved_policy_digest) VALUES ($1,$2,$3,'Engagement Manager','approve',$4)`,
          [T_A, reqId, '00000000-0000-0000-0000-0000000000a1', policyDigest],
          /approved_manifest_sha256/,
        );
        // correct pins ⇒ accepted.
        await q(
          client,
          `INSERT INTO approval_decision (tenant_id, approval_request_id, approver_user_id, approver_role, decision,
           approved_manifest_sha256, approved_policy_digest) VALUES ($1,$2,$3,'Engagement Manager','approve',$4,$5)`,
          [T_A, reqId, '00000000-0000-0000-0000-0000000000a1', manifest, policyDigest],
        );
        const n = await q(
          client,
          `SELECT count(*)::int AS n FROM approval_decision WHERE approval_request_id=$1`,
          [reqId],
        );
        expect(n.rows[0].n).toBe(1);
      });

      it('manifest entries are forbidden on empty-manifest request types', async () => {
        const pol = await q(
          client,
          `SELECT id FROM approval_policy WHERE request_type='mode_elevation'`,
        );
        const req = await q(
          client,
          `INSERT INTO approval_request (tenant_id, engagement_id, request_type, approval_policy_id, requested_by,
           justification, proposed_action, manifest_sha256, potential_impact, target_summary, scope_check_result,
           evidence_plan, stop_conditions, expires_at)
         VALUES ($1,'aaaaaaaa-0000-0000-0000-000000000001','mode_elevation',$2,$3,'j','{}'::jsonb,
                 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855','imp','t',
                 '{"decision":"pass"}'::jsonb,'ev','stop', now()+interval '1 day') RETURNING id`,
          [T_A, pol.rows[0].id, U],
        );
        await rejects(
          client,
          `INSERT INTO approval_manifest_entry (tenant_id, approval_request_id, spec_sha256) VALUES ($1,$2,$3)`,
          [T_A, req.rows[0].id, 'f'.repeat(64)],
          /forbidden on empty-manifest/,
        );
      });
    });

    describe('authorization activation (dual-control attestation)', () => {
      it('an authorization cannot go active without an approved matching attestation approval', async () => {
        await q(
          client,
          `INSERT INTO scope_version (id, tenant_id, engagement_id, version_number, scope_hash,
           entry_count, host_count, ipv4_equiv_addresses, cidr_entry_count, created_by)
         VALUES ('cccccccc-0000-0000-0000-000000000009',$1,'aaaaaaaa-0000-0000-0000-000000000001',1,$2,0,0,0,0,$3)`,
          [T_A, 'a'.repeat(64), U],
        );
        // Directly inserting an ACTIVE authorization without an approval ⇒ rejected by the trigger. (Shape CHECK
        // requires the attestation columns to be non-null in a non-draft state; supply them, point at a missing approval.)
        await rejects(
          client,
          `INSERT INTO "authorization" (tenant_id, engagement_id, authorization_reference, authorizing_party_name,
           authorizing_party_org, engagement_owner_user_id, written_auth_attested, attested_by_user_id, attested_at,
           attestation_statement, document_sha256, attestation_approval_id, effective_from, expires_at, allowed_modes,
           scope_version_id, scope_hash, record_hash, status)
         VALUES ($1,'aaaaaaaa-0000-0000-0000-000000000001','ref','p','o',$2, TRUE, $2, now(), 'stmt', $3,
                 '00000000-0000-0000-0000-0000000000ff', now(), now()+interval '1 day', ARRAY['passive'],
                 'cccccccc-0000-0000-0000-000000000009', $4, $5, 'active')`,
          [T_A, U, 'c'.repeat(64), 'a'.repeat(64), 'b'.repeat(64)],
          /attestation approval/,
        );
      });

      it('a valid authorization CAN go active with an approved matching attestation (positive path)', async () => {
        const scopeHash = 'a'.repeat(64);
        const docHash = 'c'.repeat(64);
        await q(
          client,
          `INSERT INTO scope_version (id, tenant_id, engagement_id, version_number, scope_hash,
             entry_count, host_count, ipv4_equiv_addresses, cidr_entry_count, created_by)
           VALUES ('cccccccc-0000-0000-0000-00000000000a',$1,'aaaaaaaa-0000-0000-0000-000000000001',1,$2,0,0,0,0,$3)`,
          [T_A, scopeHash, U],
        );
        // Build an authorization_attestation approval that is approved and pins the document hash.
        const pol = await q(
          client,
          `SELECT id FROM approval_policy WHERE request_type='authorization_attestation'`,
        );
        const req = await q(
          client,
          `INSERT INTO approval_request (tenant_id, engagement_id, request_type, approval_policy_id, requested_by,
             justification, proposed_action, manifest_sha256, document_sha256, potential_impact, target_summary,
             scope_check_result, evidence_plan, stop_conditions, expires_at)
           VALUES ($1,'aaaaaaaa-0000-0000-0000-000000000001','authorization_attestation',$2,$3,'j','{}'::jsonb,
                   'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',$4,'imp','t',
                   '{}'::jsonb,'ev','stop', now()+interval '1 day') RETURNING id`,
          [T_A, pol.rows[0].id, U, docHash],
        );
        // Freeze the (empty) manifest and mark the approval approved (app-layer status transition).
        await q(client, `UPDATE approval_request SET manifest_frozen=TRUE WHERE id=$1`, [
          req.rows[0].id,
        ]);
        await q(
          client,
          `UPDATE approval_request SET status='approved', resolved_at=now() WHERE id=$1`,
          [req.rows[0].id],
        );
        // The authorization activates: matching document hash, scope binding, same engagement, unexpired approval.
        await q(
          client,
          `INSERT INTO "authorization" (tenant_id, engagement_id, authorization_reference, authorizing_party_name,
             authorizing_party_org, engagement_owner_user_id, written_auth_attested, attested_by_user_id, attested_at,
             attestation_statement, document_sha256, attestation_approval_id, effective_from, expires_at, allowed_modes,
             scope_version_id, scope_hash, record_hash, status)
           VALUES ($1,'aaaaaaaa-0000-0000-0000-000000000001','ref','p','o',$2, TRUE, $2, now(), 'stmt', $3, $4,
                   now(), now()+interval '30 days', ARRAY['passive'],
                   'cccccccc-0000-0000-0000-00000000000a', $5, $6, 'active')`,
          [T_A, U, docHash, req.rows[0].id, scopeHash, 'r'.repeat(64)],
        );
        const n = await q(
          client,
          `SELECT count(*)::int AS n FROM "authorization" WHERE status='active' AND engagement_id='aaaaaaaa-0000-0000-0000-000000000001'`,
        );
        expect(n.rows[0].n).toBe(1);
      });

      it('the authorization scope_hash must equal the bound scope_version scope_hash', async () => {
        await q(
          client,
          `INSERT INTO scope_version (id, tenant_id, engagement_id, version_number, scope_hash,
           entry_count, host_count, ipv4_equiv_addresses, cidr_entry_count, created_by)
         VALUES ('cccccccc-0000-0000-0000-000000000010',$1,'aaaaaaaa-0000-0000-0000-000000000001',1,$2,0,0,0,0,$3)`,
          [T_A, 'a'.repeat(64), U],
        );
        await rejects(
          client,
          `INSERT INTO "authorization" (tenant_id, engagement_id, authorization_reference, authorizing_party_name,
           authorizing_party_org, engagement_owner_user_id, effective_from, expires_at, allowed_modes,
           scope_version_id, scope_hash, record_hash)
         VALUES ($1,'aaaaaaaa-0000-0000-0000-000000000001','ref','p','o',$2, now(), now()+interval '1 day',
                 ARRAY['passive'],'cccccccc-0000-0000-0000-000000000010',$3,$4)`,
          [T_A, U, 'b'.repeat(64) /* != scope_version.scope_hash */, 'r'.repeat(64)],
          /scope_hash does not match/,
        );
      });
    });
  },
);
