-- 0003 request_spec + secret-manager reference tables (up). Phase 2 slice 4b: the immutable, content-addressed
-- queued object (§7.0) plus the curated-template catalog and the append-only, versioned secret-manager references.
--
--   * catalog_template     — GLOBAL, content-addressed, immutable store of CURATED, NON-SECRET templates. Its
--                            digest is trigger-verified against the content; UPDATE/DELETE rejected.
--   * operator_session     — append-only, versioned operator auth session; the VALUE lives in the secret manager.
--                            The NON-secret session_digest is GENERATED (tenant+engagement+account+version).
--   * operator_query_value — append-only, versioned SECRET query-value reference; NON-secret value_binding GENERATED.
--   * request_spec         — the immutable, content-addressed wire request. approval_required is DERIVED by trigger
--                            (never trusted from the self-declared mode); every security/context reference is an
--                            immutable content digest into catalog_template; the secret session / query values are
--                            bound by their NON-secret digests and FK-verified.
--
-- spec_sha256 integrity (§7.1 step A "recompute spec_sha256; MUST equal the stored value") is enforced by the Scope
-- Authority at dispatch (application layer, @pentest/spec) — NOT re-derived in SQL, to avoid a second, divergent
-- canonical-JSON implementation. The DB instead FK-binds the non-secret session_digest / query_value_binding so a
-- spec can never be repointed to another engagement's / version's secret. pgcrypto + reject_mutation() are provided
-- by migration 0002 and reused here (this migration's down drops only what it created).

-- =============================================================================================================
-- catalog_template — global, content-addressed, immutable (§7.0 / §10)
-- =============================================================================================================
CREATE TABLE catalog_template (
  digest       CHAR(64) PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('check','tool_template','header_set','payload','ws_frame_set',
                                             'query_template')),
  name         TEXT NOT NULL,
  version      TEXT NOT NULL,
  content      JSONB NOT NULL,
  safety_class TEXT NOT NULL CHECK (safety_class IN ('inert','non_destructive','requires_approval')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (kind, name, version),
  UNIQUE (digest, kind)
);

-- Content-address verification: the digest MUST equal sha256 over a deterministic serialization of the
-- content-determining fields (kind, name, version, content, safety_class). A unit-separator delimiter avoids
-- field-boundary ambiguity; jsonb::text is deterministic for a given jsonb value (normalized key order).
CREATE FUNCTION catalog_template_digest_verify() RETURNS trigger AS $$
DECLARE computed CHAR(64);
BEGIN
  -- Pre-image is a jsonb object (proper JSON escaping) rather than a delimiter-joined string, so distinct field
  -- tuples can never collide by smuggling the delimiter into a free-text name/version. jsonb::text is deterministic.
  computed := encode(digest(convert_to(
    jsonb_build_object('kind', NEW.kind, 'name', NEW.name, 'version', NEW.version,
                       'content', NEW.content, 'safety_class', NEW.safety_class)::text, 'utf8'),
    'sha256'), 'hex');
  IF NEW.digest <> computed THEN
    RAISE EXCEPTION 'catalog_template.digest does not match the content address of its fields';
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER catalog_template_digest_verify_t BEFORE INSERT ON catalog_template
  FOR EACH ROW EXECUTE FUNCTION catalog_template_digest_verify();
-- Immutable: UPDATE/DELETE rejected (a new version is a new row with a new digest).
CREATE TRIGGER catalog_template_append_only_t BEFORE UPDATE OR DELETE ON catalog_template
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- =============================================================================================================
-- operator_session — append-only, versioned; session_digest GENERATED (§7.0)
-- =============================================================================================================
CREATE TABLE operator_session (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL,
  engagement_id    UUID NOT NULL,
  account_id       TEXT NOT NULL,
  session_version  INT  NOT NULL DEFAULT 1,
  secret_ref       TEXT NOT NULL,
  designated_hosts TEXT[] NOT NULL,
  session_digest   CHAR(64) GENERATED ALWAYS AS (
                     encode(digest(tenant_id::text || ':' || engagement_id::text || ':' ||
                                   account_id || ':' || session_version::text, 'sha256'), 'hex')) STORED,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),
  UNIQUE (id, session_digest),
  UNIQUE (tenant_id, engagement_id, account_id, session_version),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);
CREATE TRIGGER operator_session_append_only_t BEFORE UPDATE OR DELETE ON operator_session
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- =============================================================================================================
-- operator_query_value — append-only, versioned; value_binding GENERATED (§7.0)
-- =============================================================================================================
CREATE TABLE operator_query_value (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  engagement_id  UUID NOT NULL,
  value_set_name TEXT NOT NULL,
  value_version  INT  NOT NULL,
  secret_ref     TEXT NOT NULL,
  value_binding  CHAR(64) GENERATED ALWAYS AS (
                     encode(digest(tenant_id::text || ':' || engagement_id::text || ':' ||
                                   value_set_name || ':' || value_version::text, 'sha256'), 'hex')) STORED,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (id, tenant_id, engagement_id),
  UNIQUE (id, value_binding),
  UNIQUE (tenant_id, engagement_id, value_set_name, value_version),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);
CREATE TRIGGER operator_query_value_append_only_t BEFORE UPDATE OR DELETE ON operator_query_value
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- =============================================================================================================
-- request_spec — the immutable, content-addressed queued object (§7.0)
-- =============================================================================================================
CREATE TABLE request_spec (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          UUID NOT NULL,
  engagement_id      UUID NOT NULL,
  run_id             UUID NOT NULL,
  job_id             UUID NOT NULL,
  scope_hash         CHAR(64) NOT NULL,
  authorization_id   UUID NOT NULL,
  request_class      TEXT NOT NULL CHECK (request_class IN ('native','tool_driven','browser')),
  kind               TEXT NOT NULL CHECK (kind IN ('http','websocket')),

  check_digest         CHAR(64),
  tool_template_digest CHAR(64),
  header_set_digest    CHAR(64) NOT NULL,
  payload_digest       CHAR(64),
  ws_frame_set_digest  CHAR(64),
  check_kind         TEXT GENERATED ALWAYS AS ('check')         STORED,
  tool_template_kind TEXT GENERATED ALWAYS AS ('tool_template') STORED,
  header_set_kind    TEXT GENERATED ALWAYS AS ('header_set')    STORED,
  payload_kind       TEXT GENERATED ALWAYS AS ('payload')       STORED,
  ws_frame_kind      TEXT GENERATED ALWAYS AS ('ws_frame_set')  STORED,

  method             TEXT NOT NULL CHECK (method IN ('GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE')),
  canonical_url      TEXT NOT NULL,
  canonical_host     TEXT NOT NULL,
  port               INT  NOT NULL CHECK (port BETWEEN 1 AND 65535),
  scheme             TEXT NOT NULL CHECK (scheme IN ('https','http','wss','ws')),
  canonical_path     TEXT NOT NULL,
  query_keys_canonical TEXT,

  query_template_digest CHAR(64),
  query_template_kind   TEXT GENERATED ALWAYS AS ('query_template') STORED,
  query_value_ref       UUID,
  query_value_binding   CHAR(64),
  query_value_digest    CHAR(64),

  session_ref        UUID,
  session_digest     CHAR(64),
  mode               TEXT NOT NULL CHECK (mode IN ('passive','safe_active','approval_gated')),
  approval_ref       UUID,
  approval_required  BOOLEAN NOT NULL DEFAULT FALSE,
  spec_sha256        CHAR(64) NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  frozen             BOOLEAN NOT NULL DEFAULT TRUE,

  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),
  FOREIGN KEY (engagement_id, tenant_id)    REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (authorization_id, tenant_id, engagement_id) REFERENCES "authorization"(id, tenant_id, engagement_id),
  FOREIGN KEY (approval_ref, tenant_id, engagement_id)     REFERENCES approval_request(id, tenant_id, engagement_id),
  FOREIGN KEY (session_ref, tenant_id, engagement_id) REFERENCES operator_session(id, tenant_id, engagement_id),
  FOREIGN KEY (session_ref, session_digest) REFERENCES operator_session(id, session_digest),
  FOREIGN KEY (query_template_digest, query_template_kind) REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (query_value_ref, tenant_id, engagement_id) REFERENCES operator_query_value(id, tenant_id, engagement_id),
  FOREIGN KEY (query_value_ref, query_value_binding)       REFERENCES operator_query_value(id, value_binding),
  FOREIGN KEY (check_digest, check_kind)                 REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (tool_template_digest, tool_template_kind) REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (header_set_digest, header_set_kind)       REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (payload_digest, payload_kind)             REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (ws_frame_set_digest, ws_frame_kind)       REFERENCES catalog_template(digest, kind),
  CONSTRAINT kind_scheme CHECK (
     (kind='http')      = (scheme IN ('http','https'))
     AND (kind='websocket') = (scheme IN ('ws','wss'))),
  CONSTRAINT ws_is_get       CHECK (kind <> 'websocket' OR method = 'GET'),
  CONSTRAINT ws_needs_frames CHECK (kind <> 'websocket' OR ws_frame_set_digest IS NOT NULL),
  CONSTRAINT tool_needs_tmpl CHECK (request_class <> 'tool_driven' OR tool_template_digest IS NOT NULL),
  CONSTRAINT approval_present CHECK (approval_required = FALSE OR approval_ref IS NOT NULL),
  CONSTRAINT query_values_one_path CHECK (
     NOT (query_template_digest IS NOT NULL AND query_value_ref IS NOT NULL)),
  CONSTRAINT query_secret_shape CHECK (
     (query_value_ref IS NULL AND query_value_binding IS NULL AND query_value_digest IS NULL)
     OR (query_value_ref IS NOT NULL AND query_value_binding IS NOT NULL AND query_value_digest IS NOT NULL)),
  -- The operator-session path is all-or-nothing too (mirrors query_secret_shape). Without this, MATCH SIMPLE would
  -- SKIP the (session_ref, session_digest) binding FK whenever session_digest IS NULL, so a spec could name a live
  -- session without pinning its version, or fold a made-up session_digest into spec_sha256 with no backing row
  -- (SI-065). This makes the invalid state unrepresentable at the storage layer.
  CONSTRAINT session_binding_shape CHECK (
     (session_ref IS NULL AND session_digest IS NULL)
     OR (session_ref IS NOT NULL AND session_digest IS NOT NULL))
);

-- Derived approval gate (§7.0/§10): approval_required is set from the request itself — TRUE for a state-changing
-- method OR when ANY referenced catalog template is safety_class='requires_approval'. The self-declared `mode` is
-- NEVER trusted. The approval_present CHECK then forces an approval_ref whenever this derives TRUE. The spec's
-- separate "state-changing check action class" trigger is subsumed here: a state-changing check MUST carry
-- safety_class='requires_approval' in its immutable catalog_template, so this same safety_class path gates it.
CREATE FUNCTION request_spec_derive_approval() RETURNS trigger AS $$
DECLARE needs BOOLEAN := FALSE; hit INT;
BEGIN
  IF NEW.method IN ('POST','PUT','PATCH','DELETE') THEN
    needs := TRUE;
  END IF;
  SELECT count(*) INTO hit FROM catalog_template
    WHERE safety_class = 'requires_approval'
      AND digest IN (NEW.check_digest, NEW.tool_template_digest, NEW.header_set_digest,
                     NEW.payload_digest, NEW.ws_frame_set_digest, NEW.query_template_digest);
  IF hit > 0 THEN
    needs := TRUE;
  END IF;
  NEW.approval_required := needs;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER request_spec_derive_approval_t BEFORE INSERT ON request_spec
  FOR EACH ROW EXECUTE FUNCTION request_spec_derive_approval();
-- Immutable: a spec is created once, never mutated (§7.0). UPDATE/DELETE rejected.
CREATE TRIGGER request_spec_append_only_t BEFORE UPDATE OR DELETE ON request_spec
  FOR EACH ROW EXECUTE FUNCTION reject_mutation();

-- =============================================================================================================
-- Row-Level Security (doc 03). request_spec / operator_session / operator_query_value are tenant-scoped and FORCED;
-- catalog_template is GLOBAL (curated, non-secret, no tenant_id) and, like approval_policy, is not RLS-scoped.
-- =============================================================================================================
ALTER TABLE request_spec         ENABLE ROW LEVEL SECURITY; ALTER TABLE request_spec         FORCE ROW LEVEL SECURITY;
ALTER TABLE operator_session     ENABLE ROW LEVEL SECURITY; ALTER TABLE operator_session     FORCE ROW LEVEL SECURITY;
ALTER TABLE operator_query_value ENABLE ROW LEVEL SECURITY; ALTER TABLE operator_query_value FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON request_spec
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON operator_session
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE POLICY tenant_isolation ON operator_query_value
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
