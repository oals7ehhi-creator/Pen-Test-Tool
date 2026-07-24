-- 0002 authorization & scope schema (down). Exact inverse of 0002_...up.sql.
--   * `tenant` pre-existed 0002 (created by 0001), so its RLS additions are REVERSED, not dropped.
--   * The 11 tables 0002 created are dropped with CASCADE, which also removes their triggers, RLS policies,
--     constraints, indexes, and the deferred cyclic FKs (breaking the engagement<->authorization<->approval cycle).
--   * The standalone trigger FUNCTIONS are not owned by any table, so they are dropped explicitly.
--   * pgcrypto is dropped last (0002 created it).

-- Reverse the RLS added to the pre-existing tenant table (restores its exact 0001 state).
DROP POLICY IF EXISTS tenant_isolation ON tenant;
ALTER TABLE tenant NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant DISABLE ROW LEVEL SECURITY;

-- Drop the 0002 tables (CASCADE clears the cyclic deferred FKs, plus each table's triggers/policies/constraints).
DROP TABLE IF EXISTS approval_decision CASCADE;
DROP TABLE IF EXISTS approval_manifest_entry CASCADE;
DROP TABLE IF EXISTS approval_request CASCADE;
DROP TABLE IF EXISTS approval_policy CASCADE;
DROP TABLE IF EXISTS audit_event CASCADE;
DROP TABLE IF EXISTS audit_chain CASCADE;
DROP TABLE IF EXISTS "authorization" CASCADE;
DROP TABLE IF EXISTS scope_entry CASCADE;
DROP TABLE IF EXISTS scope_version CASCADE;
DROP TABLE IF EXISTS testing_window CASCADE;
DROP TABLE IF EXISTS engagement CASCADE;

-- Drop the standalone trigger functions (their triggers went with the tables above).
DROP FUNCTION IF EXISTS approval_decision_shape();
DROP FUNCTION IF EXISTS approval_request_freeze_guard();
DROP FUNCTION IF EXISTS approval_manifest_entry_guard();
DROP FUNCTION IF EXISTS approval_request_policy_match();
DROP FUNCTION IF EXISTS approval_policy_validity();
DROP FUNCTION IF EXISTS approval_policy_supersede_only();
DROP FUNCTION IF EXISTS audit_event_identity();
DROP FUNCTION IF EXISTS auth_active_requires_approved_attestation();
DROP FUNCTION IF EXISTS scope_entry_frozen_guard();
DROP FUNCTION IF EXISTS scope_version_freeze_guard();
DROP FUNCTION IF EXISTS reject_mutation();

DROP EXTENSION IF EXISTS pgcrypto;
