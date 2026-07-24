-- 0002 authorization & scope schema (up). Phase 2 slice 3: the core Engagement / Authorization / Scope /
-- Approval / Audit persistence from Phase 0 doc 04 (§2, §3, §4, §9, §10). Implements:
--   * composite (id, tenant_id[, engagement_id]) uniqueness + FKs so a cross-tenant / cross-engagement authority
--     reference is a hard constraint violation, not merely an application check (§0.8, §1);
--   * DEFERRABLE composite FKs to break the engagement <-> authorization <-> scope_version and
--     authorization -> attestation-approval cycles (verified at COMMIT);
--   * Row-Level Security (FORCE) binding every tenant-scoped row to `current_setting('app.tenant_id')` (doc 03);
--   * append-only / immutability + behavioural triggers (approval policy strength, manifest freeze, decision pins,
--     audit chain identity, scope-freeze) exactly as the design specifies.
--
-- request_spec / catalog_template / operator_session / operator_query_value (§7) and the budget_reservation ledger
-- (§8.1) are deliberately NOT created here — they are Phase 2 slices 4 (two-stage flow) and 5 (interlocks).
--
-- pgcrypto is provisioned here because it is the first migration to need digest() (approval manifest freeze +
-- seeded approval_policy digests). Its down drops it, keeping 0002 an exact inverse of itself.

CREATE EXTENSION pgcrypto;

-- The well-known SHA-256 of the empty string — the canonical "empty manifest" digest (§10 manifest_shape).
-- (Kept inline as a literal where needed: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'.)

-- =============================================================================================================
-- 2. Engagement (§2.1). Created WITHOUT its two cyclic FKs (to authorization / scope_version); those are added by
--    ALTER at the end once the target tables exist.
-- =============================================================================================================
CREATE TABLE engagement (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               UUID NOT NULL,
  name                    TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  description             TEXT CHECK (char_length(description) <= 4000),

  owner_user_id           UUID NOT NULL,
  created_by              UUID NOT NULL,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

  status                  TEXT NOT NULL DEFAULT 'draft'
                          CHECK (status IN ('draft','pending_authorization','authorized',
                                            'active','paused','suspended','expired',
                                            'completed','archived','emergency_stopped')),

  timezone                TEXT NOT NULL,
  default_mode            TEXT NOT NULL DEFAULT 'passive'
                          CHECK (default_mode IN ('passive','safe_active','approval_gated')),
  allowed_modes           TEXT[] NOT NULL DEFAULT ARRAY['passive'],

  active_authorization_id UUID,
  active_scope_version_id UUID,
  active_scope_hash       CHAR(64),

  max_concurrency         INT  NOT NULL DEFAULT 2  CHECK (max_concurrency BETWEEN 1 AND 32),
  per_host_concurrency    INT  NOT NULL DEFAULT 1  CHECK (per_host_concurrency BETWEEN 1 AND 8),
  global_max_rps          NUMERIC(6,2) NOT NULL DEFAULT 2.0  CHECK (global_max_rps > 0 AND global_max_rps <= 50),
  per_host_max_rps        NUMERIC(6,2) NOT NULL DEFAULT 1.0  CHECK (per_host_max_rps > 0),
  min_request_interval_ms INT NOT NULL DEFAULT 250 CHECK (min_request_interval_ms >= 0),
  request_budget_total    INT NOT NULL DEFAULT 5000 CHECK (request_budget_total >= 0),
  request_budget_used     INT NOT NULL DEFAULT 0    CHECK (request_budget_used >= 0),
  max_response_body_bytes INT NOT NULL DEFAULT 2097152 CHECK (max_response_body_bytes > 0),

  max_scope_hosts          INT NOT NULL DEFAULT 1024 CHECK (max_scope_hosts BETWEEN 1 AND 65536),
  max_ipv4_equiv_addresses BIGINT NOT NULL DEFAULT 65536 CHECK (max_ipv4_equiv_addresses >= 1),
  max_cidr_entries         INT NOT NULL DEFAULT 64 CHECK (max_cidr_entries BETWEEN 1 AND 4096),
  min_ipv4_prefix          INT NOT NULL DEFAULT 24 CHECK (min_ipv4_prefix BETWEEN 8 AND 32),
  min_ipv6_prefix          INT NOT NULL DEFAULT 48 CHECK (min_ipv6_prefix BETWEEN 32 AND 128),

  max_ws_connections       INT NOT NULL DEFAULT 4 CHECK (max_ws_connections BETWEEN 0 AND 64),
  ws_max_duration_s        INT NOT NULL DEFAULT 300 CHECK (ws_max_duration_s BETWEEN 1 AND 3600),
  ws_max_messages          INT NOT NULL DEFAULT 500 CHECK (ws_max_messages BETWEEN 1 AND 100000),
  ws_max_message_bytes     INT NOT NULL DEFAULT 65536 CHECK (ws_max_message_bytes BETWEEN 1 AND 1048576),

  raw_quarantine_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
  evidence_retention_days INT NOT NULL DEFAULT 90 CHECK (evidence_retention_days BETWEEN 1 AND 3650),
  dek_key_ref             TEXT,

  emergency_stop          BOOLEAN NOT NULL DEFAULT FALSE,
  emergency_stop_reason   TEXT CHECK (char_length(emergency_stop_reason) <= 1000),
  emergency_stopped_at    TIMESTAMPTZ,
  emergency_stopped_by    UUID,

  UNIQUE (id, tenant_id),
  FOREIGN KEY (tenant_id) REFERENCES tenant(id),
  CONSTRAINT draft_no_active CHECK (
     status <> 'draft' OR (active_authorization_id IS NULL AND active_scope_version_id IS NULL
                           AND active_scope_hash IS NULL)),
  CONSTRAINT rps_host_le_global   CHECK (per_host_max_rps <= global_max_rps),
  CONSTRAINT conc_host_le_global  CHECK (per_host_concurrency <= max_concurrency),
  CONSTRAINT budget_used_le_total CHECK (request_budget_used <= request_budget_total),
  CONSTRAINT engagement_allowed_modes_ok CHECK (
     allowed_modes <@ ARRAY['passive','safe_active','approval_gated'] AND array_length(allowed_modes,1) >= 1)
);

-- =============================================================================================================
-- 2.3 Testing windows (§2.3)
-- =============================================================================================================
CREATE TABLE testing_window (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  engagement_id UUID NOT NULL,
  tenant_id     UUID NOT NULL,
  kind          TEXT NOT NULL CHECK (kind IN ('recurring_weekly','one_off','blackout')),
  days_of_week  INT[]  CHECK (days_of_week <@ ARRAY[0,1,2,3,4,5,6]),   -- 0=Mon
  start_local   TIME,
  end_local     TIME,
  start_at      TIMESTAMPTZ,
  end_at        TIMESTAMPTZ,
  note          TEXT CHECK (char_length(note) <= 500),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id),
  CONSTRAINT window_shape CHECK (
     (kind='recurring_weekly' AND days_of_week IS NOT NULL AND start_local IS NOT NULL AND end_local IS NOT NULL
      AND start_local <> end_local)
     OR (kind IN ('one_off','blackout') AND start_at IS NOT NULL AND end_at IS NOT NULL AND start_at < end_at)
  )
);

-- =============================================================================================================
-- 4.1 Scope version (§4.1)
-- =============================================================================================================
CREATE TABLE scope_version (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  engagement_id  UUID NOT NULL,
  version_number INT  NOT NULL,
  scope_hash     CHAR(64) NOT NULL,
  entry_count          INT NOT NULL,
  host_count           INT NOT NULL,
  ipv4_equiv_addresses BIGINT NOT NULL,
  cidr_entry_count     INT NOT NULL,
  ipv6_min_prefix      INT,
  created_by     UUID NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  note           TEXT CHECK (char_length(note) <= 1000),
  frozen         BOOLEAN NOT NULL DEFAULT FALSE,
  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),
  UNIQUE (engagement_id, version_number),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);

-- =============================================================================================================
-- 4.2 Scope entry (§4.2) — strict per-class shape
-- =============================================================================================================
CREATE TABLE scope_entry (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL,
  scope_version_id UUID NOT NULL,

  entry_class      TEXT NOT NULL CHECK (entry_class IN
                     ('domain','ip','cidr','port','protocol','path_prefix','api_resource')),
  is_exclusion     BOOLEAN NOT NULL DEFAULT FALSE,
  elevated         BOOLEAN NOT NULL DEFAULT FALSE,

  raw_value        TEXT NOT NULL,
  canonical_value  TEXT NOT NULL,

  host_ascii         TEXT,
  wildcard           BOOLEAN,
  include_subdomains BOOLEAN,

  ip_version       INT CHECK (ip_version IN (4,6)),
  ip_start         INET,
  ip_end           INET,
  prefix_len       INT,

  port_low         INT CHECK (port_low  BETWEEN 1 AND 65535),
  port_high        INT CHECK (port_high BETWEEN 1 AND 65535),

  scheme           TEXT CHECK (scheme IN ('https','http','wss','ws')),

  bound_host_ascii    TEXT,
  bound_host_wildcard BOOLEAN,
  path_prefix         TEXT,
  api_doc_ref         TEXT,
  api_doc_sha256      CHAR(64),
  api_operations      TEXT[],

  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

  FOREIGN KEY (scope_version_id, tenant_id) REFERENCES scope_version(id, tenant_id),

  CONSTRAINT port_range_ok   CHECK (port_low IS NULL OR port_high IS NULL OR port_low <= port_high),
  CONSTRAINT elevated_only_where_allowed CHECK (
     elevated = FALSE OR entry_class IN ('ip','cidr','domain')),
  CONSTRAINT elevated_domain_wildcard CHECK (
     NOT (entry_class='domain' AND elevated=TRUE) OR wildcard = TRUE),
  CONSTRAINT exclusion_not_elevated CHECK (is_exclusion = FALSE OR elevated = FALSE),
  CONSTRAINT cidr_absolute_floor CHECK (
     entry_class <> 'cidr'
     OR (ip_version = 4 AND prefix_len >= 16)
     OR (ip_version = 6 AND prefix_len >= 32)),

  CONSTRAINT shape_domain CHECK (entry_class <> 'domain' OR (
     host_ascii IS NOT NULL AND wildcard IS NOT NULL AND include_subdomains IS NOT NULL
     AND ip_version IS NULL AND ip_start IS NULL AND ip_end IS NULL AND prefix_len IS NULL
     AND port_low IS NULL AND port_high IS NULL AND scheme IS NULL
     AND bound_host_ascii IS NULL AND path_prefix IS NULL AND api_doc_sha256 IS NULL)),
  CONSTRAINT shape_ip CHECK (entry_class <> 'ip' OR (
     ip_version IS NOT NULL AND ip_start IS NOT NULL AND ip_end = ip_start AND prefix_len IS NULL
     AND host_ascii IS NULL AND port_low IS NULL AND scheme IS NULL
     AND bound_host_ascii IS NULL AND path_prefix IS NULL)),
  CONSTRAINT shape_cidr CHECK (entry_class <> 'cidr' OR (
     ip_version IS NOT NULL AND ip_start IS NOT NULL AND ip_end IS NOT NULL AND prefix_len IS NOT NULL
     AND host_ascii IS NULL AND port_low IS NULL AND scheme IS NULL
     AND bound_host_ascii IS NULL AND path_prefix IS NULL)),
  CONSTRAINT shape_port CHECK (entry_class <> 'port' OR (
     port_low IS NOT NULL AND port_high IS NOT NULL
     AND host_ascii IS NULL AND ip_start IS NULL AND scheme IS NULL AND bound_host_ascii IS NULL)),
  CONSTRAINT shape_protocol CHECK (entry_class <> 'protocol' OR (
     scheme IS NOT NULL
     AND host_ascii IS NULL AND ip_start IS NULL AND port_low IS NULL AND bound_host_ascii IS NULL)),
  CONSTRAINT shape_path CHECK (entry_class <> 'path_prefix' OR (
     bound_host_ascii IS NOT NULL AND bound_host_wildcard IS NOT NULL
     AND path_prefix IS NOT NULL AND left(path_prefix,1) = '/'
     AND host_ascii IS NULL AND ip_start IS NULL AND api_doc_sha256 IS NULL)),
  CONSTRAINT shape_api CHECK (entry_class <> 'api_resource' OR (
     bound_host_ascii IS NOT NULL AND bound_host_wildcard IS NOT NULL
     AND api_doc_sha256 IS NOT NULL AND api_operations IS NOT NULL
     AND host_ascii IS NULL AND ip_start IS NULL AND path_prefix IS NULL))
);

-- =============================================================================================================
-- 10. Approval policy (§10) — IMMUTABLE, Administrator-managed source of threshold + eligible roles
-- =============================================================================================================
CREATE TABLE approval_policy (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_digest      CHAR(64) NOT NULL,
  request_type       TEXT NOT NULL CHECK (request_type IN
                       ('authorization_attestation','scope_expansion','restricted_range_allow',
                        'mode_elevation','intrusive_validation','business_logic_test')),
  required_approvals INT NOT NULL CHECK (required_approvals BETWEEN 1 AND 5),
  approver_roles     TEXT[] NOT NULL,
  role_quorum        JSONB NOT NULL DEFAULT '{}',
  version            INT NOT NULL,
  effective_from     TIMESTAMPTZ NOT NULL DEFAULT now(),
  superseded         BOOLEAN NOT NULL DEFAULT FALSE,
  created_by         UUID NOT NULL,
  UNIQUE (policy_digest),
  UNIQUE (request_type, version),
  CONSTRAINT approver_roles_allowlisted CHECK (
     array_length(approver_roles, 1) >= 1
     AND approver_roles <@ ARRAY['Engagement Manager','Reviewer','Administrator']),
  CONSTRAINT threshold_floor CHECK (
     (request_type = 'intrusive_validation' AND required_approvals >= 1)
     OR required_approvals >= 2)
);
CREATE UNIQUE INDEX one_current_policy ON approval_policy (request_type) WHERE superseded = FALSE;

-- =============================================================================================================
-- 3. Authorization (§3). Quoted because AUTHORIZATION is a reserved SQL keyword. The DEFERRABLE FK to
--    approval_request is added by ALTER at the end (approval_request is created later).
-- =============================================================================================================
CREATE TABLE "authorization" (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                UUID NOT NULL,
  engagement_id            UUID NOT NULL,

  authorization_reference  TEXT NOT NULL CHECK (char_length(authorization_reference) BETWEEN 1 AND 200),

  authorizing_party_name   TEXT NOT NULL CHECK (char_length(authorizing_party_name) <= 200),
  authorizing_party_org    TEXT NOT NULL CHECK (char_length(authorizing_party_org)  <= 200),
  authorizing_party_role   TEXT           CHECK (char_length(authorizing_party_role) <= 120),
  authorizing_party_email  TEXT           CHECK (authorizing_party_email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),

  engagement_owner_user_id UUID NOT NULL,

  written_auth_attested    BOOLEAN NOT NULL DEFAULT FALSE,
  attested_by_user_id      UUID,
  attested_at              TIMESTAMPTZ,
  attestation_statement    TEXT CHECK (attestation_statement IS NULL OR char_length(attestation_statement) <= 2000),
  document_ref             TEXT,
  document_sha256          CHAR(64),
  attestation_approval_id  UUID,

  effective_from           TIMESTAMPTZ NOT NULL,
  expires_at               TIMESTAMPTZ NOT NULL,

  allowed_modes            TEXT[] NOT NULL
                           CHECK (allowed_modes <@ ARRAY['passive','safe_active','approval_gated']
                                  AND array_length(allowed_modes,1) >= 1),

  internal_testing_granted BOOLEAN NOT NULL DEFAULT FALSE,

  scope_version_id         UUID NOT NULL,
  scope_hash               CHAR(64) NOT NULL,

  record_hash              CHAR(64) NOT NULL,
  signature                TEXT,

  status                   TEXT NOT NULL DEFAULT 'draft'
                           CHECK (status IN ('draft','active','revoked','expired','superseded')),
  revoked_at               TIMESTAMPTZ,
  revoked_by               UUID,
  revocation_reason        TEXT CHECK (char_length(revocation_reason) <= 1000),
  superseded_by            UUID,

  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),

  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),
  FOREIGN KEY (engagement_id, tenant_id)  REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (scope_version_id, tenant_id, engagement_id) REFERENCES scope_version(id, tenant_id, engagement_id),
  FOREIGN KEY (superseded_by, tenant_id, engagement_id)    REFERENCES "authorization"(id, tenant_id, engagement_id),
  CONSTRAINT auth_dates_valid CHECK (expires_at > effective_from),
  CONSTRAINT authorization_status_shape CHECK (
     (status = 'draft'
        AND written_auth_attested = FALSE
        AND attested_by_user_id     IS NULL
        AND attested_at             IS NULL
        AND attestation_statement   IS NULL
        AND document_sha256         IS NULL
        AND attestation_approval_id IS NULL)
     OR
     (status IN ('active','revoked','expired','superseded')
        AND written_auth_attested = TRUE
        AND attested_by_user_id     IS NOT NULL
        AND attested_at             IS NOT NULL
        AND attestation_statement   IS NOT NULL
        AND document_sha256         IS NOT NULL
        AND attestation_approval_id IS NOT NULL))
);

-- =============================================================================================================
-- 9. Immutable audit — chains + events (§9)
-- =============================================================================================================
CREATE TABLE audit_chain (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stream        TEXT NOT NULL CHECK (stream IN ('engagement','tenant','global')),
  tenant_id     UUID,
  engagement_id UUID,
  chain_key     TEXT GENERATED ALWAYS AS (
                  CASE stream WHEN 'global' THEN 'global'
                              WHEN 'tenant' THEN 'tenant:'||tenant_id::text
                              ELSE 'engagement:'||engagement_id::text END) STORED,
  head_seq      BIGINT NOT NULL DEFAULT 0,
  head_hash     CHAR(64) NOT NULL DEFAULT repeat('0',64),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (chain_key),
  UNIQUE (id, tenant_id, engagement_id),
  CONSTRAINT stream_keys CHECK (
     (stream='engagement' AND engagement_id IS NOT NULL AND tenant_id IS NOT NULL)
     OR (stream='tenant'  AND engagement_id IS NULL     AND tenant_id IS NOT NULL)
     OR (stream='global'  AND engagement_id IS NULL     AND tenant_id IS NULL))
);

CREATE TABLE audit_event (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  chain_id        UUID NOT NULL,
  tenant_id       UUID,
  engagement_id   UUID,
  seq             BIGINT NOT NULL,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  actor_type      TEXT NOT NULL CHECK (actor_type IN ('user','system','worker','scheduler','broker')),
  actor_id        UUID,
  actor_role      TEXT,

  event_type      TEXT NOT NULL,
  subject_type    TEXT,
  subject_id      UUID,
  related_event_id UUID,

  payload         JSONB NOT NULL,
  payload_sha256  CHAR(64) NOT NULL,

  prev_hash       CHAR(64) NOT NULL,
  event_hash      CHAR(64) NOT NULL,
  signature       TEXT,

  FOREIGN KEY (chain_id) REFERENCES audit_chain(id),
  FOREIGN KEY (related_event_id, chain_id) REFERENCES audit_event(id, chain_id),
  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),
  UNIQUE (id, chain_id),
  UNIQUE (chain_id, seq),
  UNIQUE (chain_id, event_hash)
);

-- =============================================================================================================
-- 10. Approval request / manifest / decision (§10)
-- =============================================================================================================
CREATE TABLE approval_request (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          UUID NOT NULL,
  engagement_id      UUID NOT NULL,

  request_type       TEXT NOT NULL CHECK (request_type IN
                       ('authorization_attestation','scope_expansion','restricted_range_allow',
                        'mode_elevation','intrusive_validation','business_logic_test')),
  approval_policy_id UUID NOT NULL,

  requested_by       UUID NOT NULL,
  requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  justification      TEXT NOT NULL CHECK (char_length(justification) BETWEEN 1 AND 4000),

  proposed_action    JSONB NOT NULL,
  manifest_sha256    CHAR(64),
  document_sha256    CHAR(64),
  potential_impact   TEXT NOT NULL CHECK (char_length(potential_impact) <= 4000),
  target_summary     TEXT NOT NULL,
  scope_check_result JSONB NOT NULL,
  required_account   TEXT,
  expected_response  TEXT,
  evidence_plan      TEXT NOT NULL,
  cleanup_action     TEXT,
  stop_conditions    TEXT NOT NULL,

  status             TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','approved','rejected','expired','withdrawn')),
  resolved_at        TIMESTAMPTZ,
  expires_at         TIMESTAMPTZ NOT NULL,
  manifest_frozen    BOOLEAN NOT NULL DEFAULT FALSE,
  manifest_frozen_at TIMESTAMPTZ,

  linked_scope_version_id UUID,
  linked_audit_event_id   UUID,

  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (approval_policy_id) REFERENCES approval_policy(id),
  FOREIGN KEY (linked_scope_version_id, tenant_id, engagement_id) REFERENCES scope_version(id, tenant_id, engagement_id),
  FOREIGN KEY (linked_audit_event_id, tenant_id, engagement_id)   REFERENCES audit_event(id, tenant_id, engagement_id),
  CONSTRAINT scope_preverdict_pass CHECK (
     request_type IN ('scope_expansion','restricted_range_allow','authorization_attestation')
     OR (scope_check_result->>'decision') = 'pass'),
  CONSTRAINT manifest_shape CHECK (
     (request_type IN ('intrusive_validation','business_logic_test') AND manifest_sha256 IS NOT NULL)
     OR (request_type NOT IN ('intrusive_validation','business_logic_test')
         AND manifest_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')),
  CONSTRAINT attestation_needs_document CHECK (
     request_type <> 'authorization_attestation' OR document_sha256 IS NOT NULL),
  CONSTRAINT document_only_for_attestation CHECK (
     request_type = 'authorization_attestation' OR document_sha256 IS NULL),
  CONSTRAINT scope_change_needs_linked_scope CHECK (
     request_type NOT IN ('scope_expansion','restricted_range_allow') OR linked_scope_version_id IS NOT NULL),
  CONSTRAINT linked_scope_only_for_scope_change CHECK (
     request_type IN ('scope_expansion','restricted_range_allow') OR linked_scope_version_id IS NULL)
);

CREATE TABLE approval_manifest_entry (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           UUID NOT NULL,
  approval_request_id UUID NOT NULL,
  spec_sha256         CHAR(64) NOT NULL,
  UNIQUE (approval_request_id, spec_sha256),
  FOREIGN KEY (approval_request_id, tenant_id) REFERENCES approval_request(id, tenant_id)
);

CREATE TABLE approval_decision (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id            UUID NOT NULL,
  approval_request_id  UUID NOT NULL,
  approver_user_id     UUID NOT NULL,
  approver_role        TEXT NOT NULL,
  decision             TEXT NOT NULL CHECK (decision IN ('approve','reject')),
  decided_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  decision_reason      TEXT CHECK (char_length(decision_reason) <= 2000),
  approved_manifest_sha256 CHAR(64),
  approved_document_sha256 CHAR(64),
  approved_policy_digest   CHAR(64) NOT NULL,
  FOREIGN KEY (approval_request_id, tenant_id) REFERENCES approval_request(id, tenant_id),
  UNIQUE (approval_request_id, approver_user_id)
);

-- =============================================================================================================
-- Deferred cyclic FKs (added now that every target table exists). All DEFERRABLE INITIALLY DEFERRED so a
-- consistent set of engagement/authorization/scope_version/approval rows can be written in one transaction and is
-- verified at COMMIT (§1, §2.1, §3).
-- =============================================================================================================
ALTER TABLE engagement
  ADD CONSTRAINT engagement_active_authorization_fk
  FOREIGN KEY (active_authorization_id, tenant_id, id)
  REFERENCES "authorization"(id, tenant_id, engagement_id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE engagement
  ADD CONSTRAINT engagement_active_scope_version_fk
  FOREIGN KEY (active_scope_version_id, tenant_id, id)
  REFERENCES scope_version(id, tenant_id, engagement_id) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE "authorization"
  ADD CONSTRAINT authorization_attestation_approval_fk
  FOREIGN KEY (attestation_approval_id, tenant_id, engagement_id)
  REFERENCES approval_request(id, tenant_id, engagement_id) DEFERRABLE INITIALLY DEFERRED;

-- =============================================================================================================
-- Behavioural + immutability triggers (§3, §4.1/§4.2, §9, §10). Enforced at the storage layer, not in prose.
-- =============================================================================================================

-- Generic append-only guard: reject UPDATE/DELETE on strictly append-only tables.
CREATE FUNCTION reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION '% is append-only; % is not permitted', TG_TABLE_NAME, TG_OP;
END; $$ LANGUAGE plpgsql;

-- scope_version: `frozen` is monotonic (FALSE->TRUE); once frozen, no security-relevant column may change (§4.1).
CREATE FUNCTION scope_version_freeze_guard() RETURNS trigger AS $$
BEGIN
  IF OLD.frozen AND NOT NEW.frozen THEN
    RAISE EXCEPTION 'scope_version.frozen cannot revert TRUE->FALSE';
  END IF;
  IF OLD.frozen THEN
    IF NEW.scope_hash <> OLD.scope_hash OR NEW.entry_count <> OLD.entry_count
       OR NEW.host_count <> OLD.host_count OR NEW.ipv4_equiv_addresses <> OLD.ipv4_equiv_addresses
       OR NEW.cidr_entry_count <> OLD.cidr_entry_count
       OR NEW.ipv6_min_prefix IS DISTINCT FROM OLD.ipv6_min_prefix
       OR NEW.version_number <> OLD.version_number OR NEW.engagement_id <> OLD.engagement_id THEN
      RAISE EXCEPTION 'scope_version is frozen; its scope/breadth columns are immutable';
    END IF;
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER scope_version_freeze_guard_t BEFORE UPDATE ON scope_version
  FOR EACH ROW EXECUTE FUNCTION scope_version_freeze_guard();

-- scope_entry: once its parent scope_version is frozen, no entry may be added, edited, or removed (§4.1).
CREATE FUNCTION scope_entry_frozen_guard() RETURNS trigger AS $$
DECLARE is_frozen BOOLEAN; svid UUID;
BEGIN
  svid := CASE WHEN TG_OP = 'DELETE' THEN OLD.scope_version_id ELSE NEW.scope_version_id END;
  SELECT frozen INTO is_frozen FROM scope_version WHERE id = svid;
  IF is_frozen THEN
    RAISE EXCEPTION 'scope_version % is frozen; scope entries are immutable (% rejected)', svid, TG_OP;
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER scope_entry_frozen_guard_t BEFORE INSERT OR UPDATE OR DELETE ON scope_entry
  FOR EACH ROW EXECUTE FUNCTION scope_entry_frozen_guard();

-- authorization: a transition to 'active' requires an approved, matching attestation approval; and the row's
-- scope_hash must equal the bound scope_version's scope_hash (scope binding, §3).
CREATE FUNCTION auth_active_requires_approved_attestation() RETURNS trigger AS $$
DECLARE ar approval_request%ROWTYPE; sv_hash CHAR(64);
BEGIN
  SELECT scope_hash INTO sv_hash FROM scope_version WHERE id = NEW.scope_version_id;
  IF sv_hash IS NULL THEN
    RAISE EXCEPTION 'authorization.scope_version_id % references no scope_version', NEW.scope_version_id;
  END IF;
  IF NEW.scope_hash <> sv_hash THEN
    RAISE EXCEPTION 'authorization.scope_hash does not match the bound scope_version.scope_hash';
  END IF;
  IF NEW.status = 'active' THEN
    SELECT * INTO ar FROM approval_request WHERE id = NEW.attestation_approval_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'active authorization requires an attestation approval_request';
    END IF;
    IF ar.request_type <> 'authorization_attestation' THEN
      RAISE EXCEPTION 'attestation approval must be of type authorization_attestation';
    END IF;
    IF ar.status <> 'approved' THEN
      RAISE EXCEPTION 'attestation approval is not approved';
    END IF;
    IF ar.tenant_id <> NEW.tenant_id OR ar.engagement_id <> NEW.engagement_id THEN
      RAISE EXCEPTION 'attestation approval belongs to a different engagement';
    END IF;
    IF ar.expires_at <= now() THEN
      RAISE EXCEPTION 'attestation approval is expired';
    END IF;
    IF ar.document_sha256 IS DISTINCT FROM NEW.document_sha256 THEN
      RAISE EXCEPTION 'attestation approval document_sha256 does not match the authorization document_sha256';
    END IF;
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER auth_active_requires_approved_attestation_t BEFORE INSERT OR UPDATE ON "authorization"
  FOR EACH ROW EXECUTE FUNCTION auth_active_requires_approved_attestation();

-- audit_event: NULL-safe chain-identity check (structural fix for the MATCH SIMPLE gap, §9).
CREATE FUNCTION audit_event_identity() RETURNS trigger AS $$
DECLARE ch audit_chain%ROWTYPE;
BEGIN
  SELECT * INTO ch FROM audit_chain WHERE id = NEW.chain_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit_event.chain_id % references no chain', NEW.chain_id;
  END IF;
  IF NEW.tenant_id IS DISTINCT FROM ch.tenant_id
     OR NEW.engagement_id IS DISTINCT FROM ch.engagement_id THEN
    RAISE EXCEPTION 'audit_event identity does not match its chain identity';
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_event_identity_t BEFORE INSERT OR UPDATE ON audit_event
  FOR EACH ROW EXECUTE FUNCTION audit_event_identity();
-- audit_event is append-only: UPDATE/DELETE are rejected (§9).
CREATE TRIGGER audit_event_append_only_t BEFORE UPDATE OR DELETE ON audit_event
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- approval_policy: content immutable; only superseded FALSE->TRUE is a permitted UPDATE; DELETE rejected (§10).
CREATE FUNCTION approval_policy_supersede_only() RETURNS trigger AS $$
BEGIN
  IF NEW.request_type <> OLD.request_type OR NEW.required_approvals <> OLD.required_approvals
     OR NEW.approver_roles <> OLD.approver_roles OR NEW.role_quorum <> OLD.role_quorum
     OR NEW.version <> OLD.version OR NEW.policy_digest <> OLD.policy_digest
     OR NEW.effective_from <> OLD.effective_from OR NEW.created_by <> OLD.created_by THEN
    RAISE EXCEPTION 'approval_policy content is immutable; only superseded FALSE->TRUE is permitted';
  END IF;
  IF OLD.superseded AND NOT NEW.superseded THEN
    RAISE EXCEPTION 'superseded cannot revert TRUE->FALSE';
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER approval_policy_supersede_only_t BEFORE UPDATE ON approval_policy
  FOR EACH ROW EXECUTE FUNCTION approval_policy_supersede_only();
CREATE TRIGGER approval_policy_no_delete_t BEFORE DELETE ON approval_policy
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- approval_policy: role_quorum validity + NON-DECREASING strength vs the immediately-prior version (§10).
CREATE FUNCTION approval_policy_validity() RETURNS trigger AS $$
DECLARE k TEXT; v INT; total INT := 0; prev approval_policy%ROWTYPE; pk TEXT; pv INT;
BEGIN
  FOR k, v IN SELECT key, value::int FROM jsonb_each_text(NEW.role_quorum) LOOP
    IF NOT (k = ANY(NEW.approver_roles)) THEN RAISE EXCEPTION 'role_quorum role % not in approver_roles', k; END IF;
    IF v <= 0 THEN RAISE EXCEPTION 'role_quorum value for % must be a positive integer', k; END IF;
    total := total + v;
  END LOOP;
  IF total > NEW.required_approvals THEN
    RAISE EXCEPTION 'role_quorum sum (%) exceeds required_approvals (%) — unsatisfiable', total, NEW.required_approvals;
  END IF;
  SELECT * INTO prev FROM approval_policy
    WHERE request_type = NEW.request_type AND id <> NEW.id
    ORDER BY version DESC LIMIT 1;
  IF FOUND THEN
    IF NEW.required_approvals < prev.required_approvals THEN
      RAISE EXCEPTION 'new policy weakens required_approvals (% < %)', NEW.required_approvals, prev.required_approvals;
    END IF;
    IF NOT (NEW.approver_roles <@ prev.approver_roles) THEN
      RAISE EXCEPTION 'new policy broadens approver_roles (allowlist may only tighten)';
    END IF;
    FOR pk, pv IN SELECT key, value::int FROM jsonb_each_text(prev.role_quorum) LOOP
      IF coalesce((NEW.role_quorum->>pk)::int, 0) < pv THEN
        RAISE EXCEPTION 'new policy lowers role_quorum for % (% < %)', pk, coalesce((NEW.role_quorum->>pk)::int,0), pv;
      END IF;
    END LOOP;
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER approval_policy_validity_t BEFORE INSERT ON approval_policy
  FOR EACH ROW EXECUTE FUNCTION approval_policy_validity();

-- approval_request: must pin the CURRENT (non-superseded) policy of the matching request_type (§10).
CREATE FUNCTION approval_request_policy_match() RETURNS trigger AS $$
DECLARE pol approval_policy%ROWTYPE;
BEGIN
  SELECT * INTO pol FROM approval_policy WHERE id = NEW.approval_policy_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'approval_policy_id references no policy'; END IF;
  IF pol.request_type <> NEW.request_type THEN
    RAISE EXCEPTION 'policy request_type % <> request %', pol.request_type, NEW.request_type;
  END IF;
  IF pol.superseded THEN
    RAISE EXCEPTION 'approval_request must pin the CURRENT (non-superseded) policy for its type';
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER approval_request_policy_match_t BEFORE INSERT ON approval_request
  FOR EACH ROW EXECUTE FUNCTION approval_request_policy_match();

-- approval_manifest_entry: allowed only on manifest-bearing types and only before freeze; append-only (§10).
CREATE FUNCTION approval_manifest_entry_guard() RETURNS trigger AS $$
DECLARE rt TEXT; frz BOOLEAN;
BEGIN
  SELECT request_type, manifest_frozen INTO rt, frz FROM approval_request WHERE id = NEW.approval_request_id;
  IF rt NOT IN ('intrusive_validation','business_logic_test') THEN
    RAISE EXCEPTION 'manifest entries forbidden on empty-manifest request_type %', rt;
  END IF;
  IF frz THEN RAISE EXCEPTION 'manifest is frozen; no further entries'; END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER approval_manifest_entry_guard_t BEFORE INSERT ON approval_manifest_entry
  FOR EACH ROW EXECUTE FUNCTION approval_manifest_entry_guard();
CREATE TRIGGER approval_manifest_entry_append_only_t BEFORE UPDATE OR DELETE ON approval_manifest_entry
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- approval_request: manifest freeze is monotonic and, on freeze, manifest_sha256 must equal the recomputed digest
-- of the sorted entry set (empty types verify against the canonical empty digest) (§10).
CREATE FUNCTION approval_request_freeze_guard() RETURNS trigger AS $$
DECLARE n INT; computed CHAR(64);
BEGIN
  IF OLD.manifest_frozen AND NOT NEW.manifest_frozen THEN
    RAISE EXCEPTION 'manifest_frozen cannot revert TRUE->FALSE';
  END IF;
  IF NEW.manifest_frozen AND NOT OLD.manifest_frozen THEN
    SELECT count(*),
           encode(digest(coalesce(string_agg(spec_sha256, '' ORDER BY spec_sha256), ''), 'sha256'), 'hex')
      INTO n, computed
      FROM approval_manifest_entry WHERE approval_request_id = NEW.id;
    IF NEW.request_type IN ('intrusive_validation','business_logic_test') THEN
      IF n = 0 THEN RAISE EXCEPTION 'cannot freeze an EMPTY manifest on a manifest-bearing request'; END IF;
      IF computed <> NEW.manifest_sha256 THEN
        RAISE EXCEPTION 'manifest_sha256 (%) != recomputed digest of the frozen entry set (%)', NEW.manifest_sha256, computed;
      END IF;
    ELSE
      IF n <> 0 THEN RAISE EXCEPTION 'empty-manifest request must have ZERO entries'; END IF;
      IF computed <> NEW.manifest_sha256 THEN
        RAISE EXCEPTION 'empty manifest digest mismatch (expected the canonical empty digest)';
      END IF;
    END IF;
    NEW.manifest_frozen_at := now();
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER approval_request_freeze_guard_t BEFORE UPDATE ON approval_request
  FOR EACH ROW EXECUTE FUNCTION approval_request_freeze_guard();

-- approval_decision: every APPROVE pins the required digests with a NON-NULL EQUAL value (NULL never bypasses),
-- and no decision may be recorded before the manifest is frozen; append-only (§10).
CREATE FUNCTION approval_decision_shape() RETURNS trigger AS $$
DECLARE rt TEXT; frz BOOLEAN; m CHAR(64); d CHAR(64); pol CHAR(64);
BEGIN
  SELECT ar.request_type, ar.manifest_frozen, ar.manifest_sha256, ar.document_sha256, ap.policy_digest
    INTO rt, frz, m, d, pol
    FROM approval_request ar JOIN approval_policy ap ON ap.id = ar.approval_policy_id
    WHERE ar.id = NEW.approval_request_id;
  IF NEW.decision = 'approve' THEN
    IF NOT frz THEN RAISE EXCEPTION 'no decision may be recorded before the manifest is frozen'; END IF;
    IF NEW.approved_policy_digest IS NULL OR NEW.approved_policy_digest <> pol THEN
      RAISE EXCEPTION 'decision must pin the CURRENT policy digest (NULL never bypasses)';
    END IF;
    IF rt IN ('intrusive_validation','business_logic_test') THEN
      IF NEW.approved_manifest_sha256 IS NULL OR NEW.approved_manifest_sha256 <> m THEN
        RAISE EXCEPTION 'manifest approval requires approved_manifest_sha256 = manifest_sha256 (NULL never bypasses)';
      END IF;
    ELSIF rt = 'authorization_attestation' THEN
      IF NEW.approved_document_sha256 IS NULL OR NEW.approved_document_sha256 <> d THEN
        RAISE EXCEPTION 'attestation approval requires approved_document_sha256 = document_sha256 (NULL never bypasses)';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER approval_decision_shape_t BEFORE INSERT ON approval_decision
  FOR EACH ROW EXECUTE FUNCTION approval_decision_shape();
CREATE TRIGGER approval_decision_append_only_t BEFORE UPDATE OR DELETE ON approval_decision
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- =============================================================================================================
-- Row-Level Security (doc 03: SET LOCAL app.tenant_id per request). FORCED so even the table owner is subject,
-- making tenant isolation provable in tests. Unset GUC => current_setting(...,true) is NULL => policy is false
-- => no rows (fail-closed). approval_policy has NO tenant_id (global, Administrator-managed) and is not RLS-scoped.
-- Global/tenant audit rows (tenant_id NULL) are intentionally invisible to a tenant session; platform/global audit
-- access is a separate admin path (later slice).
-- =============================================================================================================
ALTER TABLE tenant           ENABLE ROW LEVEL SECURITY; ALTER TABLE tenant           FORCE ROW LEVEL SECURITY;
ALTER TABLE engagement       ENABLE ROW LEVEL SECURITY; ALTER TABLE engagement       FORCE ROW LEVEL SECURITY;
ALTER TABLE testing_window   ENABLE ROW LEVEL SECURITY; ALTER TABLE testing_window   FORCE ROW LEVEL SECURITY;
ALTER TABLE scope_version    ENABLE ROW LEVEL SECURITY; ALTER TABLE scope_version    FORCE ROW LEVEL SECURITY;
ALTER TABLE scope_entry      ENABLE ROW LEVEL SECURITY; ALTER TABLE scope_entry      FORCE ROW LEVEL SECURITY;
ALTER TABLE "authorization"  ENABLE ROW LEVEL SECURITY; ALTER TABLE "authorization"  FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_chain      ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_chain      FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_event      ENABLE ROW LEVEL SECURITY; ALTER TABLE audit_event      FORCE ROW LEVEL SECURITY;
ALTER TABLE approval_request ENABLE ROW LEVEL SECURITY; ALTER TABLE approval_request FORCE ROW LEVEL SECURITY;
ALTER TABLE approval_manifest_entry ENABLE ROW LEVEL SECURITY; ALTER TABLE approval_manifest_entry FORCE ROW LEVEL SECURITY;
ALTER TABLE approval_decision ENABLE ROW LEVEL SECURITY; ALTER TABLE approval_decision FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenant
  USING (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON engagement
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON testing_window
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON scope_version
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON scope_entry
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON "authorization"
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON audit_chain
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON audit_event
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON approval_request
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON approval_manifest_entry
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON approval_decision
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- =============================================================================================================
-- Seed the baseline (version 1) approval_policy per request_type (§10 table). Administrator-managed thereafter.
-- policy_digest = sha256 over canonical(request_type | required_approvals | sort(approver_roles) | role_quorum |
-- version); the exact serialization is internal — the value only needs to be stable + unique + pinned by decisions.
-- =============================================================================================================
INSERT INTO approval_policy (policy_digest, request_type, required_approvals, approver_roles, role_quorum, version, created_by)
SELECT encode(digest(request_type || '|' || required_approvals::text || '|' ||
                     array_to_string(ARRAY(SELECT unnest(approver_roles) ORDER BY 1), ',') || '|' ||
                     role_quorum::text || '|' || version::text, 'sha256'), 'hex'),
       request_type, required_approvals, approver_roles, role_quorum, version, created_by
FROM (VALUES
  ('authorization_attestation', 2, ARRAY['Administrator','Engagement Manager','Reviewer'], '{"Engagement Manager": 1}'::jsonb, 1, '00000000-0000-0000-0000-000000000000'::uuid),
  ('scope_expansion',           2, ARRAY['Engagement Manager','Reviewer'], '{}'::jsonb, 1, '00000000-0000-0000-0000-000000000000'::uuid),
  ('restricted_range_allow',    2, ARRAY['Engagement Manager','Reviewer'], '{}'::jsonb, 1, '00000000-0000-0000-0000-000000000000'::uuid),
  ('mode_elevation',            2, ARRAY['Engagement Manager','Reviewer'], '{}'::jsonb, 1, '00000000-0000-0000-0000-000000000000'::uuid),
  ('business_logic_test',       2, ARRAY['Engagement Manager','Reviewer'], '{}'::jsonb, 1, '00000000-0000-0000-0000-000000000000'::uuid),
  ('intrusive_validation',      1, ARRAY['Engagement Manager','Reviewer'], '{}'::jsonb, 1, '00000000-0000-0000-0000-000000000000'::uuid)
) AS seed(request_type, required_approvals, approver_roles, role_quorum, version, created_by);
