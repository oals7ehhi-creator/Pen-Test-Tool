> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

# Authorization & Scope Schema — Phase 0 Design

**Component:** Engagement / Authorization / Scope Engine (backbone for Phase 2)
**Status:** Design/analysis only — no implementation. Pseudo-DDL and JSON/YAML snippets are illustrative.
**Design posture:** deny-by-default, authorization-first, exclusions-always-win, tamper-evident, dual-control on legal gates.

> **Canonical component names (used in every Phase 0 document):**
> - **Scope Authority** — the single control-plane service that decides *"is this permitted?"*. It evaluates the ordered decision procedure over the frozen scope and mints signed **Stage-1 egress grants**. It performs **no target I/O** and does **no DNS resolution of targets**.
> - **Guarded Egress Broker** — the single data-plane enforcer and the **only component that opens a socket to a target**. It authenticates each per-job request, resolves DNS, validates and **pins** every resolved IP at broker time, connects, re-validates redirects, applies rate/window/expiry/e-stop gates, and emits audit events.
>
> These two names supersede the earlier "scope-validation service" / "ScopeGuard" terminology used in draft notes.

---

## 0. Design principles that constrain every table below

1. **No scope, no request.** Every outbound request is gated by a *live* Scope Authority decision. Absence of a matching allowlist entry is a DENY, not a soft warning.
2. **Authorization binds to an exact scope snapshot.** An `authorization` record is cryptographically bound to an immutable `scope_version` via a `scope_hash` (§4.1 defines exactly which fields the hash covers). Editing scope *invalidates* authorization and forces re-attestation under dual control.
3. **Exclusions are absolute and evaluated first.** Any candidate matching an exclusion is denied even if it also matches an allow entry, and even if it is the apex of an allowed wildcard.
4. **The network guard is not overridable by ordinary allowlisting.** Tier A ranges — cloud-metadata, loopback, unspecified, multicast, broadcast, and reserved/future — are **permanently hard-denied and can never be reached by any means**. Tier B ranges — RFC1918, ULA, link-local, and CGNAT — are denied **unless** an explicit `elevated` scope entry names them **and** a dual-approved elevated approval exists (§6, §10). Metadata addresses remain Tier A even though they sit inside link-local space.
5. **Immutability > editability.** Scope versions, authorization records, audit events, and approval records/decisions are append-only. "Changes" are new versions/events, never in-place mutation.
6. **Canonicalize before you compare.** All matching is performed on a single canonical form for host, IP, port, scheme, and path. Raw operator input is preserved separately for audit but is never the thing matched against.
7. **Dual control on the legal gate.** Authorization attestation and any scope expansion require two distinct approvers (§10); no single actor can broaden what may be tested.
8. **Composite tenant *and engagement* integrity.** Every child row references its parent by a composite foreign key carrying `tenant_id`, and **every security-authority reference also carries `engagement_id`** — `(id, tenant_id, engagement_id)` — so a request can never bind an authorization, approval, scope version, session, or budget lease from another engagement, even within the same tenant and even with an identical `scope_hash` (§1). Stage-1 re-verifies engagement-identity equality at dispatch as defense in depth (§7.1 precondition a0).
9. **The queued object is immutable and hashed.** Work is queued as an immutable, fully-hashed `request_spec`; short-lived egress grants are minted **just-in-time** at dispatch and bound to the spec's hash, so no grant ever waits in the queue (§7).

---

## 1. Common conventions

| Convention | Rule |
|---|---|
| Primary keys | `UUID` (prefer UUIDv7 for time-ordered inserts). Never expose sequential integer PKs across tenants. |
| Tenancy | Every row carries `tenant_id UUID NOT NULL`. Every parent table declares `UNIQUE (id, tenant_id)`; every child FK is **composite** — `FOREIGN KEY (parent_id, tenant_id) REFERENCES parent(id, tenant_id)` — so a cross-tenant reference is a hard constraint violation, not merely an application check. Postgres Row-Level Security additionally scopes every read/write to the caller's `tenant_id`. |
| Timestamps | `TIMESTAMPTZ`, stored UTC. Human-facing windows are interpreted in the engagement `timezone`. |
| Enums | Constrained text (`CHECK (col IN (...))`) or native enum types; values stable, lowercase, snake_case. |
| Soft delete | **Not used** for authorization/scope/audit/approval. These are immutable; lifecycle is status + new versions. Deletion of engagement *data* is by cryptographic erasure (see `11-data-retention-and-deletion.md`), never by mutating immutable rows. |
| Hashing | SHA-256, lowercase hex, over a **canonical JSON** serialization (sorted keys, no insignificant whitespace, UTF-8, explicit null handling). |
| Text limits | All free-text fields have explicit max lengths (noted per field) to bound storage and log volume. |

---

## 2. Engagement entity

The engagement is the top-level container and the runtime "kill switch" surface. It holds operating posture (mode, rate/concurrency, windows, timezone, scope-breadth ceilings) but **not** the legal authority to test — that lives in `authorization`.

### 2.1 Pseudo-DDL

```sql
TABLE engagement (
  id                    UUID PRIMARY KEY,               -- UUIDv7
  tenant_id             UUID NOT NULL,
  name                  TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  description           TEXT CHECK (char_length(description) <= 4000),

  owner_user_id         UUID NOT NULL,                  -- Engagement Manager / accountable owner
  created_by            UUID NOT NULL,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

  status                TEXT NOT NULL DEFAULT 'draft'
                        CHECK (status IN ('draft','pending_authorization','authorized',
                                          'active','paused','suspended','expired',
                                          'completed','archived','emergency_stopped')),

  timezone              TEXT NOT NULL,                  -- IANA tz; validated against tz DB
  default_mode          TEXT NOT NULL DEFAULT 'passive'
                        CHECK (default_mode IN ('passive','safe_active','approval_gated')),
  allowed_modes         TEXT[] NOT NULL DEFAULT ARRAY['passive'],  -- subset of authorization.allowed_modes

  -- Active scope/authorization pointers (denormalized for fast gate checks)
  active_authorization_id UUID,
  active_scope_version_id UUID,
  active_scope_hash       CHAR(64),                     -- must equal authorization.scope_hash when authorized

  -- Rate / concurrency posture (see §8)
  max_concurrency         INT  NOT NULL DEFAULT 2  CHECK (max_concurrency BETWEEN 1 AND 32),
  per_host_concurrency    INT  NOT NULL DEFAULT 1  CHECK (per_host_concurrency BETWEEN 1 AND 8),
  global_max_rps          NUMERIC(6,2) NOT NULL DEFAULT 2.0  CHECK (global_max_rps > 0 AND global_max_rps <= 50),
  per_host_max_rps        NUMERIC(6,2) NOT NULL DEFAULT 1.0  CHECK (per_host_max_rps > 0),
  min_request_interval_ms INT NOT NULL DEFAULT 250 CHECK (min_request_interval_ms >= 0),
  request_budget_total    INT NOT NULL DEFAULT 5000 CHECK (request_budget_total >= 0),
  request_budget_used     INT NOT NULL DEFAULT 0    CHECK (request_budget_used >= 0),
  max_response_body_bytes INT NOT NULL DEFAULT 2097152 CHECK (max_response_body_bytes > 0), -- 2 MiB

  -- Scope-breadth ceilings (see §4.6) — bound how broad a scope may get before elevated approval
  max_scope_hosts          INT NOT NULL DEFAULT 1024 CHECK (max_scope_hosts BETWEEN 1 AND 65536),
  max_ipv4_equiv_addresses BIGINT NOT NULL DEFAULT 65536 CHECK (max_ipv4_equiv_addresses >= 1),
  max_cidr_entries         INT NOT NULL DEFAULT 64 CHECK (max_cidr_entries BETWEEN 1 AND 4096),
  min_ipv4_prefix          INT NOT NULL DEFAULT 24 CHECK (min_ipv4_prefix BETWEEN 8 AND 32),
  min_ipv6_prefix          INT NOT NULL DEFAULT 48 CHECK (min_ipv6_prefix BETWEEN 32 AND 128),

  -- WebSocket caps (see §7.2): established ws/wss connections are bounded, not per-message scoped
  max_ws_connections       INT NOT NULL DEFAULT 4 CHECK (max_ws_connections BETWEEN 0 AND 64),
  ws_max_duration_s        INT NOT NULL DEFAULT 300 CHECK (ws_max_duration_s BETWEEN 1 AND 3600),
  ws_max_messages          INT NOT NULL DEFAULT 500 CHECK (ws_max_messages BETWEEN 1 AND 100000),
  ws_max_message_bytes     INT NOT NULL DEFAULT 65536 CHECK (ws_max_message_bytes BETWEEN 1 AND 1048576),

  -- Data-handling posture (see 11-data-retention-and-deletion.md)
  raw_quarantine_enabled  BOOLEAN NOT NULL DEFAULT FALSE,   -- off by default (SI-057)
  evidence_retention_days INT NOT NULL DEFAULT 90 CHECK (evidence_retention_days BETWEEN 1 AND 3650),
  dek_key_ref             TEXT,                             -- secret-manager ref to per-engagement DEK

  -- Emergency controls
  emergency_stop          BOOLEAN NOT NULL DEFAULT FALSE,
  emergency_stop_reason   TEXT CHECK (char_length(emergency_stop_reason) <= 1000),
  emergency_stopped_at    TIMESTAMPTZ,
  emergency_stopped_by    UUID,

  UNIQUE (id, tenant_id),                                    -- target of composite child FKs
  -- Deferred composite FKs break the engagement<->authorization<->scope_version cycle while still
  -- guaranteeing SAME-TENANT-AND-ENGAGEMENT references (verified at COMMIT, not per-statement). The engagement's
  -- OWN id is the engagement identity, so the active authorization/scope_version must carry engagement_id = this.id:
  -- a valid authorization/scope_version from another engagement (even same tenant, identical scope_hash) is a hard
  -- constraint violation, not merely an application check.
  FOREIGN KEY (active_authorization_id, tenant_id, id)
        REFERENCES authorization(id, tenant_id, engagement_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (active_scope_version_id, tenant_id, id)
        REFERENCES scope_version(id, tenant_id, engagement_id) DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT draft_no_active CHECK (
     status <> 'draft' OR (active_authorization_id IS NULL AND active_scope_version_id IS NULL
                           AND active_scope_hash IS NULL)),
  CONSTRAINT rps_host_le_global   CHECK (per_host_max_rps <= global_max_rps),
  CONSTRAINT conc_host_le_global  CHECK (per_host_concurrency <= max_concurrency),
  CONSTRAINT budget_used_le_total CHECK (request_budget_used <= request_budget_total)
);
```

**Validation rules & notes**

- `allowed_modes` on the engagement must always be a **subset** of the active authorization's `allowed_modes`. A DB trigger + application check enforce this.
- `active_scope_hash` **must equal** `authorization.scope_hash` whenever `status ∈ {authorized, active, paused}`. If they diverge, the engagement is forced to `pending_authorization` and all requests are denied.
- Concurrency, RPS, budget, and scope-breadth ceilings are capped in schema so no operator input can request abusive volume/breadth even by typo.
- `dek_key_ref` points at the per-engagement data-encryption key in the secret manager; destroying that key is the cryptographic-erasure delete path (§11 doc).

### 2.2 Status machine (allowed transitions)

```
draft ─▶ pending_authorization ─▶ authorized ─▶ active ⇄ paused
                                     │              │       │
                                     ▼              ▼       ▼
                                 (revoke)      emergency_stopped / suspended
                                     │
   authorized|active|paused ─────▶ expired          (ONLY on authorization expiry / revocation)
   active|paused|authorized ─────▶ completed ─▶ archived
```

- Transitions are recorded as audit events (§9). Illegal transitions are rejected.
- `expired`, `suspended`, `emergency_stopped` are **terminal for testing**: no request may be scheduled or executed. Recovery requires an explicit human transition and (for expiry) a fresh authorization.
- **Closing a testing window is NOT an engagement state transition.** A `recurring_weekly`/`one_off` window ending, or a `blackout` window opening, only **blocks/stops execution**: the engagement stays `active`, and requests are simply denied at the gate (`DENY(outside_testing_window)`) until a window re-opens. Only **authorization expiry** (`now ≥ authorization.expires_at`) or **revocation** may transition the engagement to terminal `expired`. Window state and authorization validity are independent axes — a window close never expires the engagement (SI-011/SI-013).

### 2.3 Testing windows

```sql
TABLE testing_window (
  id             UUID PRIMARY KEY,
  engagement_id  UUID NOT NULL,
  tenant_id      UUID NOT NULL,
  kind           TEXT NOT NULL CHECK (kind IN ('recurring_weekly','one_off','blackout')),
  days_of_week   INT[]  CHECK (days_of_week <@ ARRAY[0,1,2,3,4,5,6]),  -- 0=Mon
  start_local    TIME,                          -- interpreted in engagement.timezone
  end_local      TIME,
  start_at       TIMESTAMPTZ,
  end_at         TIMESTAMPTZ,
  note           TEXT CHECK (char_length(note) <= 500),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id),
  CONSTRAINT window_shape CHECK (
     (kind='recurring_weekly' AND days_of_week IS NOT NULL AND start_local IS NOT NULL AND end_local IS NOT NULL
      AND start_local <> end_local)
     OR (kind IN ('one_off','blackout') AND start_at IS NOT NULL AND end_at IS NOT NULL AND start_at < end_at)
  )
);
```

**Effective-window rule (runtime):** a request is allowed *only if*, evaluated at request time:
`now ∈ (authorization.effective_from, authorization.expires_at)` **AND** `now` falls inside at least one `recurring_weekly`/`one_off` window **AND** `now` falls inside **no** `blackout` window. Blackout always wins over allow. Windows crossing midnight and DST transitions are resolved in the engagement timezone before conversion to UTC. All time comparisons use the trusted-clock rule of SI-049 (monotonic + authenticated wall-clock; unverifiable time fails closed).

---

## 3. Authorization record

The legal-authority object. Activation is a **dual-control** event (§10): a complete `authorization` row cannot become `active` until an `approval_request` of type `authorization_attestation` reaches its approval threshold.

### 3.1 Pseudo-DDL

```sql
TABLE authorization (
  id                       UUID PRIMARY KEY,
  tenant_id                UUID NOT NULL,
  engagement_id            UUID NOT NULL,

  authorization_reference  TEXT NOT NULL CHECK (char_length(authorization_reference) BETWEEN 1 AND 200),

  authorizing_party_name   TEXT NOT NULL CHECK (char_length(authorizing_party_name) <= 200),
  authorizing_party_org    TEXT NOT NULL CHECK (char_length(authorizing_party_org)  <= 200),
  authorizing_party_role   TEXT           CHECK (char_length(authorizing_party_role) <= 120),
  authorizing_party_email  TEXT           CHECK (authorizing_party_email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),

  engagement_owner_user_id UUID NOT NULL,

  -- Written-authorization attestation (dual-controlled via approval, §10).
  -- ALL of these are NULL/FALSE while status='draft' and ALL present while status is non-draft — see the single
  -- authorization_status_shape CHECK below (there is NO global "always attested" rule; a draft is genuinely incomplete).
  written_auth_attested    BOOLEAN NOT NULL DEFAULT FALSE,
  attested_by_user_id      UUID,                   -- the requester of the attestation approval (NULL in draft)
  attested_at              TIMESTAMPTZ,            -- (NULL in draft)
  attestation_statement    TEXT CHECK (attestation_statement IS NULL OR char_length(attestation_statement) <= 2000),
  document_ref             TEXT,                   -- pointer/URI to stored authorization doc (not the doc)
  document_sha256          CHAR(64),               -- hash of the authorization artifact (pinned at both approvals; NULL in draft)
  attestation_approval_id  UUID,                   -- FK -> approval_request(id) of type authorization_attestation (NULL in draft)

  effective_from           TIMESTAMPTZ NOT NULL,
  expires_at               TIMESTAMPTZ NOT NULL,

  allowed_modes            TEXT[] NOT NULL
                           CHECK (allowed_modes <@ ARRAY['passive','safe_active','approval_gated']
                                  AND array_length(allowed_modes,1) >= 1),

  internal_testing_granted BOOLEAN NOT NULL DEFAULT FALSE,  -- does the authorizing party permit Tier B internal testing?

  scope_version_id         UUID NOT NULL,
  scope_hash               CHAR(64) NOT NULL,      -- MUST equal scope_version.scope_hash at sign-off

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
  UNIQUE (id, tenant_id, engagement_id),         -- target of engagement-scoped authority FKs (engagement.active_
                                                 --   authorization_id, request_spec.authorization_id)
  FOREIGN KEY (engagement_id, tenant_id)  REFERENCES engagement(id, tenant_id),
  -- scope_version, superseding authorization, and the attestation approval MUST all belong to THIS engagement:
  FOREIGN KEY (scope_version_id, tenant_id, engagement_id) REFERENCES scope_version(id, tenant_id, engagement_id),
  FOREIGN KEY (superseded_by, tenant_id, engagement_id)    REFERENCES authorization(id, tenant_id, engagement_id),
  FOREIGN KEY (attestation_approval_id, tenant_id, engagement_id)
        REFERENCES approval_request(id, tenant_id, engagement_id) DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT auth_dates_valid CHECK (expires_at > effective_from),
  -- ONE complete status-shape rule replaces the old contradictory trio (attest_true / active_needs_dual_approval /
  -- draft_not_attested). A draft is genuinely incomplete and NON-attested; every non-draft status carries the
  -- complete, opposite shape AND a resolved attestation approval. draft_not_attested is SUBSUMED here.
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
-- TRIGGER auth_active_requires_approved_attestation (BEFORE INSERT OR UPDATE): a transition to status='active' is
-- REJECTED unless attestation_approval_id references an approval_request of type 'authorization_attestation' that is
-- status='approved', same (tenant_id, engagement_id), unexpired, whose approved document_sha256 EQUALS this row's
-- document_sha256 and whose pinned scope_hash EQUALS this row's scope_hash. The shape CHECK guarantees the columns
-- are non-null in that state; the trigger guarantees the approval actually exists and matches (cross-table).
```

**Validation rules & notes**

- **Attestation is dual-controlled.** Reaching `status='active'` requires a linked `approval_request` (`authorization_attestation`) that has met its `required_approvals` threshold from two distinct approvers, neither of whom is the executing tester, each pinning the same `document_sha256` and `scope_hash` (§10, SI-047).
- **Scope binding is enforced.** At sign-off, `scope_hash` is copied from `scope_version.scope_hash` and a trigger recomputes it (§4.1) to reject a hash that does not correspond to stored rows.
- **Internal testing is opt-in twice.** Tier B (RFC1918/ULA/link-local/CGNAT) targets are reachable only when `internal_testing_granted = TRUE` **and** the specific range has an `elevated` scope entry approved via dual control (§6).
- **Immutability / auto-expiry / revocation** as before: rows never edited; a background evaluator flips `active→expired` at `expires_at`; every request independently re-derives validity; revocation halts all testing immediately.

---

## 4. Scope model

Scope is an **immutable version** (`scope_version`) of typed **entries** (`scope_entry`), each `allow` or `exclude`. The `scope_hash` over the canonicalized entry set (§4.1) is what authorization binds to.

### 4.1 Scope version & the canonical scope hash

```sql
TABLE scope_version (
  id             UUID PRIMARY KEY,
  tenant_id      UUID NOT NULL,
  engagement_id  UUID NOT NULL,
  version_number INT  NOT NULL,
  scope_hash     CHAR(64) NOT NULL,       -- canonical hash defined below
  entry_count          INT NOT NULL,
  host_count           INT NOT NULL,      -- distinct allow domain host-families (a wildcard = its own family), §4.6
  ipv4_equiv_addresses BIGINT NOT NULL,   -- Σ over allow IPv4 ip/cidr of 2^(32 - prefix); a single ip = 1
  cidr_entry_count     INT NOT NULL,      -- count of allow ip/cidr entries (both families)
  ipv6_min_prefix      INT,               -- broadest (numerically smallest) allow IPv6 prefix present, or NULL
  created_by     UUID NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  note           TEXT CHECK (char_length(note) <= 1000),
  frozen         BOOLEAN NOT NULL DEFAULT FALSE,  -- TRUE once bound by an authorization
  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),           -- target of engagement-scoped authority FKs (authorization,
                                                   --   engagement.active_scope_version_id, approval linkage)
  UNIQUE (engagement_id, version_number),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);
```

- Once `frozen = TRUE`, **no entries may be added, edited, or removed.** Any change clones a new `scope_version`.
- **Canonical `scope_hash` (blocker 5).** The hash MUST cover **every security-relevant semantic field** of every entry, so two scopes that differ in *any* dimension that changes what may be contacted produce different hashes. For each entry, form the tuple:

  ```
  ( entry_class, is_exclusion, elevated,
    host_ascii, wildcard, include_subdomains,
    ip_version, ip_start, ip_end, prefix_len,
    port_low, port_high,
    scheme,
    path_prefix, bound_host_ascii, bound_host_wildcard,
    api_doc_sha256, sort(api_operations) )
  ```

  Null out fields not applicable to the class, serialize each tuple as canonical JSON, sort the tuples lexicographically, concatenate, and `SHA-256`. The hash is therefore independent of insertion order and cosmetic input but sensitive to any host/range/port/scheme/path/operation/exclusion/elevation change. `entry_count`, `host_count`, `ipv4_equiv_addresses`, `cidr_entry_count`, and `ipv6_min_prefix` are computed deterministically at freeze time and included as a trailer in the hashed document, so breadth cannot drift under a fixed hash. Breadth reflects **allow-entry worst case**; **exclusions are not subtracted** — an exclusion must never be a way to smuggle a broader allow past a ceiling.

### 4.2 Scope entry (supertype + typed value, strict per-class shape)

```sql
TABLE scope_entry (
  id               UUID PRIMARY KEY,
  tenant_id        UUID NOT NULL,
  scope_version_id UUID NOT NULL,

  entry_class      TEXT NOT NULL CHECK (entry_class IN
                     ('domain','ip','cidr','port','protocol','path_prefix','api_resource')),
  is_exclusion     BOOLEAN NOT NULL DEFAULT FALSE,   -- exclusions always win
  elevated         BOOLEAN NOT NULL DEFAULT FALSE,   -- deliberately allows a Tier B range or a broad/wildcard entry

  raw_value        TEXT NOT NULL,                    -- exactly what the operator typed (audit)
  canonical_value  TEXT NOT NULL,                    -- normalized form used for matching (§5)

  -- domain
  host_ascii         TEXT,        -- punycode/ToASCII, lowercase, no trailing dot
  wildcard           BOOLEAN,     -- TRUE if leftmost-label wildcard '*.'
  include_subdomains BOOLEAN,

  -- ip / cidr
  ip_version       INT CHECK (ip_version IN (4,6)),
  ip_start         INET,
  ip_end           INET,
  prefix_len       INT,

  -- port
  port_low         INT CHECK (port_low  BETWEEN 1 AND 65535),
  port_high        INT CHECK (port_high BETWEEN 1 AND 65535),

  -- protocol / path_prefix / api_resource
  scheme           TEXT CHECK (scheme IN ('https','http','wss','ws')),

  -- path_prefix / api_resource — MUST be bound to a host (blocker 5)
  bound_host_ascii    TEXT,       -- the host this path/API is scoped to (canonical)
  bound_host_wildcard BOOLEAN,    -- TRUE if the bound host is a leftmost-label wildcard
  path_prefix         TEXT,       -- canonical path, must start with '/'
  api_doc_ref         TEXT,
  api_doc_sha256      CHAR(64),
  api_operations      TEXT[],     -- allowed operationIds / "METHOD /path" pairs

  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

  FOREIGN KEY (scope_version_id, tenant_id) REFERENCES scope_version(id, tenant_id),

  CONSTRAINT port_range_ok   CHECK (port_low IS NULL OR port_high IS NULL OR port_low <= port_high),
  CONSTRAINT elevated_only_where_allowed CHECK (
     elevated = FALSE OR entry_class IN ('ip','cidr','domain')),  -- Tier B nets, or broad/wildcard domains
  CONSTRAINT elevated_domain_wildcard CHECK (
     NOT (entry_class='domain' AND elevated=TRUE) OR wildcard = TRUE),  -- an elevated domain must be a wildcard (§4.4)
  CONSTRAINT exclusion_not_elevated CHECK (is_exclusion = FALSE OR elevated = FALSE),  -- exclusions never elevate (§4.5)
  CONSTRAINT cidr_absolute_floor CHECK (        -- absolute floors, enforceable regardless of approval (§4.6)
     entry_class <> 'cidr'
     OR (ip_version = 4 AND prefix_len >= 16)
     OR (ip_version = 6 AND prefix_len >= 32)),

  -- STRICT PER-CLASS SHAPE: each class populates exactly its fields and nulls the rest.
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
```

**Explicit host binding (blocker 5).** `path_prefix` and `api_resource` entries **must** name the host they apply to via `bound_host_ascii` (+ `bound_host_wildcard`). A path or API operation never "floats" across hosts: it constrains only requests whose canonical host matches the bound host. A path entry with no matching allowed host entry is rejected at validation.

### 4.3 Per-type semantics

| `entry_class` | What it constrains | Match semantics |
|---|---|---|
| `domain` | A hostname family | Exact host match on `host_ascii`; if `wildcard`, `*.example.com` matches subdomains but **not** the apex unless `include_subdomains=TRUE` or the apex is listed. Wildcard domains are `elevated` (§4.6). |
| `ip` | A single literal address | Exact canonical IP equality; `ip_end = ip_start`. |
| `cidr` | An address range | Containment: candidate IP ∈ `[ip_start, ip_end]`; range materialized for index-friendly checks. |
| `port` | Allowed port(s) | Candidate port ∈ `[port_low, port_high]`. |
| `protocol` | Allowed URL schemes | Default allowed = `{https}`; `http`/`ws` require explicit entry. |
| `path_prefix` | A URL sub-tree **on a bound host** | Canonical candidate host matches `bound_host_ascii` AND path starts with `path_prefix` at a segment boundary. |
| `api_resource` | Operations from a spec **on a bound host** | Candidate host matches `bound_host_ascii` AND `(method, path)` ∈ `api_operations`; bound to the spec via `api_doc_sha256`. |

### 4.4 Wildcard rules (precise)

- Only a **leftmost-label** wildcard: `*.example.com`. Reject `foo.*.com`, `*.*.example.com`, `ex*ple.com`, bare `*`.
- **Wildcard domain entries are `elevated` and require dual approval** (§4.6, §10) — they authorize a whole subtree and are a common over-broadening vector.
- A wildcard never matches the registrable apex unless the apex is separately allowlisted or `include_subdomains=TRUE`.
- Public-suffix guard: reject wildcard entries at or above a public suffix (`*.co.uk`, `*.com`) outright — not even elevated approval permits them.

### 4.5 Exclusions (always win)

- An `is_exclusion=TRUE` entry of any class removes matching candidates **regardless of any allow match**.
- Precedence at evaluation (§7): **exclusions first**. Any exclusion match ⇒ DENY.
- Exclusions cannot be `elevated` and never *grant*; they only subtract (enforced by `exclusion_not_elevated`, §4.2).

### 4.6 Scope-breadth limits & elevated approval (blocker 10)

Broad scope is the quiet path from an authorized assessment to an unauthorized one. Breadth is bounded technically and gated by elevated dual approval:

| Breadth dimension | Enforced limit | Consequence when exceeded |
|---|---|---|
| IPv4 CIDR prefix | `prefix_len` must be ≥ `engagement.min_ipv4_prefix` (default `/24`) | Broader than the engagement floor ⇒ entry must be `elevated` + dual-approved; below the **absolute floor** `/16` ⇒ **hard reject** regardless of approval — enforced by the `cidr_absolute_floor` CHECK (§4.2). |
| IPv6 CIDR prefix | `prefix_len` ≥ `engagement.min_ipv6_prefix` (default `/48`) | Same pattern; absolute floor `/32` ⇒ hard reject. |
| Wildcard domain | Any `*.host` entry | Must be `elevated` + dual-approved; PSL/apex wildcards hard-rejected. |
| Distinct hosts | `scope_version.host_count` ≤ `engagement.max_scope_hosts` (default 1024) | Above ceiling ⇒ elevated dual approval required to raise the ceiling. |
| IPv4-equivalent addresses | `scope_version.ipv4_equiv_addresses` ≤ `engagement.max_ipv4_equiv_addresses` (default 65536) | Above ceiling ⇒ elevated dual approval. Computed as Σ `2^(32-prefix)` over allow IPv4 ip/cidr entries (a single ip = 1). |
| CIDR entry count | `scope_version.cidr_entry_count` ≤ `engagement.max_cidr_entries` (default 64) | Above ceiling ⇒ elevated dual approval. |
| IPv6 breadth | `ipv6_min_prefix` ≥ `engagement.min_ipv6_prefix` | Governed **solely** by the per-entry prefix floor + elevated approval — **never** an address sum (an IPv6 /64 already holds 2^64 addresses, so summing addresses is meaningless). |
| **Scope expansion** | Any new host/domain/IP/range vs the currently-authorized `scope_version` | Requires an `approval_request` of type `scope_expansion` at threshold **and** re-attestation (new authorization). |

`host_count`, `ipv4_equiv_addresses`, `cidr_entry_count`, and `ipv6_min_prefix` are computed at freeze and bound into the hashed document (§4.1); IPv4 breadth is an exact worst-case address budget while IPv6 breadth is bounded by prefix floors (address counting is deliberately avoided for IPv6). The Scope Authority refuses to mint grants for a `scope_version` whose breadth exceeds ceilings without the corresponding approved elevation.

---

## 5. Canonicalization rules

All matching operates on canonical forms. Raw input is preserved for audit but never compared directly.

### 5.1 Host / domain
1. Trim whitespace; reject embedded control chars, spaces, NUL.
2. Strip a single trailing dot.
3. Lowercase (ASCII).
4. **IDN → punycode (ToASCII, IDNA2008/UTS-46).** Reject labels failing IDNA validation, forbidden confusables, or over length.
5. Reject hostnames that are IP literals here — those must be `ip`/`cidr` (defeats `http://0x7f000001/` style bypasses; numeric/hex/octal forms are normalized to IPs in §5.2).
6. Trailing-dot, case, punycode normalized identically for scope entries and candidates ⇒ byte-exact `host_ascii` comparison.

### 5.2 IP address (IPv4 + IPv6)
1. Parse obfuscated IPv4 (decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f.0.0.1`, mixed, short forms) → canonical dotted-quad, then re-check the network guard.
2. IPv6: expand then compress to RFC 5952 canonical form.
3. **Transition/embedding forms are decoded and the embedded IPv4 re-classified** against all guard ranges: IPv4-mapped (`::ffff:a.b.c.d`), deprecated IPv4-compatible (`::a.b.c.d`), **6to4 (`2002::/16`)**, **Teredo (`2001::/32`)**, **NAT64 (`64:ff9b::/96`)**. A form decoding to a Tier A range is hard-denied; to a Tier B range, the Tier B rules apply.
4. **IPv6 zone IDs** (`fe80::1%eth0`) rejected everywhere (link-local only; Tier B and only via elevated).
5. Canonical value stored as normalized string; range checks use numeric `INET`.

### 5.3 Port
- Missing port ⇒ apply scheme default (`https`→443, `http`→80, `wss`→443, `ws`→80) **before** the port check. Explicit `:443` on https == default. No entry bypass by adding/removing a default port.

### 5.4 Scheme
- Lowercase. Only `{https, http, ws, wss}` recognized; everything else (`file`, `gopher`, `ftp`, `data`, `javascript`, …) rejected at parse time.

### 5.5 Path
- Percent-decode only unreserved; re-encode reserved/unsafe consistently. Reject invalid percent-encodings and encoded NUL/CR/LF.
- Resolve `.`/`..` (RFC 3986 remove-dot-segments) so `/api/../admin` → `/admin` before the prefix check.
- Paths are **case-sensitive**; `path_prefix` matching is segment-boundary aware (`/api` matches `/api`, `/api/`, `/api/v1`, never `/apiv2`).

### 5.6 Full candidate URL canonical order
`scheme (lower) → host (ToASCII, lower, no trailing dot) → port (explicit, default-normalized) → path (dot-segment resolved) → [query/fragment ignored for scope]`. Userinfo (`user:pass@`) is stripped, flagged, and redacted from audit; it never influences scope.

---

## 6. Deny-by-default network guard (two-tier, one consistent policy)

Applied to **every resolved IP** and every IP literal by the Guarded Egress Broker (and pre-checked by the Scope Authority for IP-literal targets), independent of allowlist matching. Ranges are enumerated so nothing depends on library defaults.

### Tier A — PERMANENT HARD DENY (never reachable by any means — no allowlist entry, no `elevated` flag, no approval)

| Category | IPv4 | IPv6 |
|---|---|---|
| Loopback | `127.0.0.0/8` | `::1/128` |
| Unspecified | `0.0.0.0/8`, `0.0.0.0` | `::/128` |
| Cloud/link-local **metadata** | `169.254.169.254`, `169.254.170.2` (ECS) | `fd00:ec2::254` and known provider metadata endpoints |
| Multicast | `224.0.0.0/4` | `ff00::/8` |
| Broadcast | `255.255.255.255/32` | — |
| Reserved / future-use | `240.0.0.0/4`, `192.0.0.0/24` (IETF protocol assignments) | `2001:20::/28` (ORCHIDv2), `::/96` (deprecated IPv4-compatible) |
| Documentation / benchmark | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15` | `2001:db8::/32`, `100::/64` (discard) |

**Metadata is Tier A even though it is technically link-local.** An `elevated` link-local entry (Tier B) never re-permits any metadata address; the classifier subtracts Tier A from any Tier B grant.

### Tier B — RESTRICTED (denied unless ALL of: an explicit `elevated=TRUE` `ip`/`cidr` scope entry names the range · a dual-approved `restricted_range_allow` approval exists · the active authorization has `internal_testing_granted = TRUE`)

| Category | IPv4 | IPv6 |
|---|---|---|
| Private (RFC1918) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | ULA `fc00::/7` |
| Carrier-grade NAT | `100.64.0.0/10` | — |
| Link-local (minus Tier A metadata) | `169.254.0.0/16` | `fe80::/10` |

**Decision (explicit, per blocker 1): authorized internal RFC1918/ULA/link-local/CGNAT applications ARE supported — exclusively through elevated dual approval.** Absent the full Tier B condition, all of this space is denied exactly like Tier A. **No entry, elevated or not, can ever override Tier A.**

---

## 7. Request authorization — immutable request spec + just-in-time two-stage flow

Every outbound request passes a **two-stage** flow. **The object placed on the queue is an immutable, fully-hashed `request_spec` — never a grant.** Egress grants are short-lived (TTL in seconds) and single-use, so they are **minted just-in-time at dispatch**, not at enqueue; a grant's lifetime only has to cover *dispatch → send*, never the (possibly long) queue dwell time. Full token/ingress design: `10-request-authorization-flow.md`.

### 7.0 The queued object — immutable `request_spec`

```sql
TABLE request_spec (               -- the IMMUTABLE, CONTENT-ADDRESSED queued object
  id                 UUID PRIMARY KEY,
  tenant_id          UUID NOT NULL,
  engagement_id      UUID NOT NULL,
  run_id             UUID NOT NULL,            -- INSTANCE identity; EXCLUDED from spec_sha256
  job_id             UUID NOT NULL,            -- INSTANCE identity; EXCLUDED from spec_sha256
  scope_hash         CHAR(64) NOT NULL,        -- digest of the frozen scope_version this spec was specced against
  authorization_id   UUID NOT NULL,
  request_class      TEXT NOT NULL CHECK (request_class IN ('native','tool_driven','browser')),
  kind               TEXT NOT NULL CHECK (kind IN ('http','websocket')),

  -- Every security/request-context reference is an IMMUTABLE CONTENT DIGEST (sha256) into catalog_template,
  -- so nothing can be silently repointed; each digest is part of spec_sha256.
  check_digest         CHAR(64),   -- native: digest of the immutable check definition
  tool_template_digest CHAR(64),   -- tool_driven: digest of the pinned tool template
  header_set_digest    CHAR(64) NOT NULL,  -- digest of the FIXED safe header-set template
  payload_digest       CHAR(64),   -- digest of the INERT request payload (curated catalog), or NULL
  ws_frame_set_digest  CHAR(64),   -- websocket: digest of the APPROVED inert outbound-frame set (§7.2, SI-063)
  -- Fixed template KINDS (generated) so each digest FK enforces the referenced template's kind:
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
  query_keys_canonical TEXT,                  -- canonical, sorted query PARAMETER NAMES only (structure; never values)
  -- QUERY VALUES — TWO SEPARATE PATHS (never both); parameter NAMES are always the non-secret query_keys_canonical.
  -- Path 1 — CURATED, NON-SECRET values may be content-addressed globally (a 'query_template' catalog_template):
  query_template_digest CHAR(64),             -- FK -> catalog_template(digest, kind='query_template'); folded into spec_sha256
  query_template_kind   TEXT GENERATED ALWAYS AS ('query_template') STORED,
  -- Path 2 — SECRET / OPERATOR-SUPPLIED values live ONLY in the secret manager under an engagement-scoped,
  --   immutable, versioned reference (operator_query_value). NEVER content-addressed, NEVER in any global store:
  query_value_ref       UUID,                 -- FK -> operator_query_value(id); BROKER-RESOLVED; EXCLUDED from spec_sha256
  query_value_binding   CHAR(64),             -- = operator_query_value.value_binding (NON-secret, GENERATED: hashes
                                              --   tenant+engagement+name+version, NOT the values); BOUND INTO spec_sha256, FK-verified
  query_value_digest    CHAR(64),             -- KEYED HMAC over the canonical ACTUAL injected values, keyed with the
                                              --   engagement-scoped MAC key held ONLY in the secret manager; BOUND INTO spec_sha256.
                                              --   The broker fetches the EXACT pinned version, recomputes this HMAC, compares in
                                              --   CONSTANT TIME, and DENIES before any egress on mismatch (§7.1 step 8).
  session_ref        UUID,                    -- FK to an immutable operator_session lease; the SECRET is injected by
                                              --   the broker and never stored; session_ref itself is EXCLUDED from spec_sha256
  session_digest     CHAR(64),                -- NON-SECRET binding = the referenced operator_session's IMMUTABLE,
                                              --   GENERATED session_digest (sha256(tenant_id, engagement_id, account_id,
                                              --   session_version) — never collides across tenants/engagements);
                                              --   BOUND INTO spec_sha256 and FK-verified to equal the session's digest,
                                              --   so a spec is tied to one tenant+engagement+account+version (rotation invalidates)
  mode               TEXT NOT NULL CHECK (mode IN ('passive','safe_active','approval_gated')),  -- advisory display only
  approval_ref       UUID,                    -- present iff approval_required (below)
  approval_required  BOOLEAN NOT NULL,        -- DERIVED by trigger from referenced templates' safety_class and
                                              --   request_class — NOT trusted from the self-declared `mode`
  spec_sha256        CHAR(64) NOT NULL,       -- CONTENT digest over ALL request-determining fields (below)
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  frozen             BOOLEAN NOT NULL DEFAULT TRUE,   -- specs are immutable from creation

  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),    -- target of budget_reservation's engagement-scoped spec FK
  -- NO UNIQUE(tenant_id, spec_sha256): spec_sha256 is a REUSABLE content digest, so the SAME logical request
  --   may recur across jobs/runs. Each recurrence is a distinct INSTANCE (own id/run_id/job_id + own single-use
  --   JIT grant) — a legitimate repeat, NOT a replay (replay is prevented by the single-use jti + job binding).
  FOREIGN KEY (engagement_id, tenant_id)    REFERENCES engagement(id, tenant_id),
  -- Authorization AND approval MUST belong to THIS engagement: a valid authorization/approval from engagement B
  -- can never authorize engagement A even in the same tenant with an identical scope_hash (engagement_id is in the FK).
  FOREIGN KEY (authorization_id, tenant_id, engagement_id) REFERENCES authorization(id, tenant_id, engagement_id),
  FOREIGN KEY (approval_ref, tenant_id, engagement_id)     REFERENCES approval_request(id, tenant_id, engagement_id),
  FOREIGN KEY (session_ref, tenant_id, engagement_id) REFERENCES operator_session(id, tenant_id, engagement_id),
  FOREIGN KEY (session_ref, session_digest) REFERENCES operator_session(id, session_digest),  -- digest MUST match the session
  -- Path-1 curated query template: content-addressed, kind-checked.
  FOREIGN KEY (query_template_digest, query_template_kind) REFERENCES catalog_template(digest, kind),
  -- Path-2 secret query values: BOTH engagement-scoping AND exact-version binding (defeats cross-engagement theft
  -- and version confusion). query_value_ref resolves ONLY to an operator_query_value row of THIS engagement.
  FOREIGN KEY (query_value_ref, tenant_id, engagement_id) REFERENCES operator_query_value(id, tenant_id, engagement_id),
  FOREIGN KEY (query_value_ref, query_value_binding)       REFERENCES operator_query_value(id, value_binding),
  FOREIGN KEY (check_digest, check_kind)                 REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (tool_template_digest, tool_template_kind) REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (header_set_digest, header_set_kind)       REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (payload_digest, payload_kind)             REFERENCES catalog_template(digest, kind),
  FOREIGN KEY (ws_frame_set_digest, ws_frame_kind)       REFERENCES catalog_template(digest, kind),
  CONSTRAINT kind_scheme CHECK (          -- HTTP<->http/https and WebSocket<->ws/wss, BIDIRECTIONAL
     (kind='http')      = (scheme IN ('http','https'))
     AND (kind='websocket') = (scheme IN ('ws','wss'))),
  CONSTRAINT ws_is_get       CHECK (kind <> 'websocket' OR method = 'GET'),
  CONSTRAINT ws_needs_frames CHECK (kind <> 'websocket' OR ws_frame_set_digest IS NOT NULL),
  CONSTRAINT tool_needs_tmpl CHECK (request_class <> 'tool_driven' OR tool_template_digest IS NOT NULL),
  CONSTRAINT approval_present CHECK (approval_required = FALSE OR approval_ref IS NOT NULL),
  -- At most ONE query-value path: a spec never mixes a curated content-addressed template with secret values.
  CONSTRAINT query_values_one_path CHECK (
     NOT (query_template_digest IS NOT NULL AND query_value_ref IS NOT NULL)),
  -- The secret path is all-or-nothing: ref + non-secret version binding + keyed value digest travel together.
  CONSTRAINT query_secret_shape CHECK (
     (query_value_ref IS NULL AND query_value_binding IS NULL AND query_value_digest IS NULL)
     OR (query_value_ref IS NOT NULL AND query_value_binding IS NOT NULL AND query_value_digest IS NOT NULL))
);
-- Immutability: UPDATE/DELETE revoked; a spec is created once, never mutated.
-- spec_sha256 = SHA-256 over canonical JSON of
--   (engagement_id, scope_hash, authorization_id, request_class, kind,
--    check_digest, tool_template_digest, header_set_digest, payload_digest, ws_frame_set_digest,
--    method, canonical_url, canonical_host, port, scheme, canonical_path,
--    query_keys_canonical, query_template_digest, query_value_binding, query_value_digest,
--    session_digest, approval_required).
--   approval_ref, session_ref, query_value_ref, run_id, job_id, and the ADVISORY `mode` are EXCLUDED: query_value_ref
--   (like session_ref) is a broker-resolved instance pointer to an engagement-scoped secret; the hash instead binds the
--   NON-secret query_value_binding (tenant+engagement+name+version) and the KEYED query_value_digest of the actual values.
--   approval_ref is INSTANCE
--   linkage — excluding it breaks the spec↔approval circularity for dynamic requests: the manifest binds the STABLE
--   content digest, and approval_ref merely links this instance to the approval that authorized it. The secret
--   session is resolved at the broker; run/job are INSTANCE identity (so the same digest can recur across jobs/runs);
--   and the approval gate is driven by the DERIVED approval_required, never by the self-declared mode.

TABLE catalog_template (           -- GLOBAL, content-addressed, immutable store of CURATED, NON-SECRET templates ONLY
  digest       CHAR(64) PRIMARY KEY,          -- sha256 of canonical(kind,name,version,content,safety_class)
  kind         TEXT NOT NULL CHECK (kind IN ('check','tool_template','header_set','payload','ws_frame_set',
                                             'query_template')),  -- 'query_template' = curated NON-SECRET query values
  name         TEXT NOT NULL,
  version      TEXT NOT NULL,
  content      JSONB NOT NULL,                -- immutable body: inert payloads / safe header-set / WS frame set /
                                              --   curated NON-SECRET query templates. SECRET/operator-supplied values
                                              --   MUST NEVER be a catalog_template row — content-addressing a secret makes
                                              --   the digest an offline confirmation oracle; secrets live in the secret
                                              --   manager via operator_query_value / operator_session (never here).
  safety_class TEXT NOT NULL CHECK (safety_class IN ('inert','non_destructive','requires_approval')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (kind, name, version),
  UNIQUE (digest, kind)                       -- composite target so request_spec FKs can enforce the KIND
);
-- Content-addressed & immutable: digest MUST equal sha256(canonical(...)) (trigger-verified); UPDATE/DELETE
-- revoked. A new version is a new row with a new digest. Curated/pinned like tool images (SI-031, SI-065).
-- Derived-approval gate: a BEFORE trigger on request_spec sets approval_required from EVERY relevant semantic input —
-- TRUE when the HTTP method / action class is state-changing (POST/PUT/PATCH/DELETE, or a state-changing check action
-- class) OR the MAX safety_class over ALL referenced catalog templates (check, tool_template, header_set, payload,
-- ws_frame_set, query_template) is 'requires_approval'. The self-declared `mode` is NEVER trusted for the approval gate.

TABLE operator_session (           -- operator-supplied auth session; the VALUE lives in the secret manager.
  -- APPEND-ONLY & VERSIONED: each row is ONE immutable version. UPDATE and DELETE are REVOKED — rotation INSERTs a
  -- NEW row (new id, session_version+1) and NEVER mutates this row's GENERATED session_digest, so specs pinned to the
  -- old (session_ref, session_digest) stay valid and the new secret is reachable ONLY by specs that reference the new id.
  id               UUID PRIMARY KEY,          -- one row PER VERSION; a new session_ref is minted on every rotation
  tenant_id        UUID NOT NULL,
  engagement_id    UUID NOT NULL,
  account_id       TEXT NOT NULL,             -- NON-SECRET account identifier (bound via session_digest)
  session_version  INT  NOT NULL DEFAULT 1,   -- IMMUTABLE per row; rotation creates a new row with version+1
  secret_ref       TEXT NOT NULL,             -- secret-manager lease id PINNED TO THIS VERSION (value NEVER stored in the DB)
  designated_hosts TEXT[] NOT NULL,           -- the in-scope hosts this session may be used against
  session_digest   CHAR(64) GENERATED ALWAYS AS (   -- IMMUTABLE, generated; request_spec.session_digest FK-binds THIS.
                     -- Binds tenant + engagement + account + version so it can NEVER collide across tenants/engagements
                     -- (two accounts named the same in different tenants have DIFFERENT digests). No secret is hashed.
                     encode(digest(tenant_id::text || ':' || engagement_id::text || ':' ||
                                   account_id || ':' || session_version::text, 'sha256'), 'hex')) STORED,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),      -- target of request_spec's same-tenant-AND-engagement session FK
  UNIQUE (id, session_digest),                -- target of request_spec's session-digest binding FK
  UNIQUE (tenant_id, engagement_id, account_id, session_version),  -- one row per (account, version) per engagement
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);
-- Rotation is INSERT-only (append a new version row); UPDATE/DELETE revoked. session_digest is GENERATED (no secret
-- hashed) and immutable; because request_spec FK-binds (session_ref,
-- session_digest), a spec is tied to one tenant+engagement+account+version. A rotation creates a NEW row with a new
-- session_ref; old specs stay pinned to the old row/version (never silently repointed to the new secret).

TABLE operator_query_value (       -- engagement-scoped, immutable, versioned reference to SECRET/operator query values
  id             UUID PRIMARY KEY,          -- one row PER VERSION; rotation INSERTs a new row (new id) + version+1
  tenant_id      UUID NOT NULL,
  engagement_id  UUID NOT NULL,
  value_set_name TEXT NOT NULL,             -- NON-secret logical name of the value set
  value_version  INT  NOT NULL,             -- IMMUTABLE per row; rotation appends value_version+1
  secret_ref     TEXT NOT NULL,             -- secret-manager lease id PINNED TO THIS IMMUTABLE VERSION; the ACTUAL
                                            --   values live ONLY in the secret manager, never in the DB or any global store
  value_binding  CHAR(64) GENERATED ALWAYS AS (   -- NON-secret binding (no value hashed): tenant+engagement+name+version
                     encode(digest(tenant_id::text || ':' || engagement_id::text || ':' ||
                                   value_set_name || ':' || value_version::text, 'sha256'), 'hex')) STORED,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (id, tenant_id, engagement_id),    -- target of request_spec's same-tenant-AND-engagement query FK
  UNIQUE (id, value_binding),               -- target of request_spec's exact-version binding FK
  UNIQUE (tenant_id, engagement_id, value_set_name, value_version),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);
-- APPEND-ONLY & VERSIONED: UPDATE/DELETE revoked; rotation = INSERT a new row/version, never mutate. The broker
-- resolves query_value_ref -> secret_ref at the EXACT version, fetches the actual values from the secret manager,
-- recomputes the KEYED HMAC (engagement-scoped MAC key, never in the DB) over the canonical values, compares it in
-- CONSTANT TIME to spec.query_value_digest, and DENIES before any egress on mismatch or a withdrawn version (§7.1 step 8).
```

- **Content-addressed & immutable.** A `request_spec` is created once — by the check engine for native checks, or by the broker for tool/browser requests (§7.2) — and never mutated. Every security/request-context reference (check, tool template, header-set, payload, WS frame-set) is an **immutable content digest** into `catalog_template`, and all digests are folded into `spec_sha256`, so nothing can be silently repointed. **The queue stores only `(spec_id, tenant_id)`**, not a grant.
- **Repeatable across jobs/runs.** `spec_sha256` is a reusable **content** digest (it excludes `run_id`/`job_id`/`session_ref`), so the same logical request may legitimately recur in different jobs or runs; there is no `UNIQUE(spec_sha256)`. Each recurrence is a distinct instance with its own single-use JIT grant — a repeat, not a replay.
- **No free-form request; protected values.** `method`, the `canonical_*` fields, a fixed `header_set_digest`, an inert `payload_digest`, the query **keys** + (curated `query_template_digest` **or** the secret path's non-secret `query_value_binding` + **keyed** `query_value_digest`), and a non-secret `session_digest` fully determine the wire request and are all bound into `spec_sha256`; the raw query values and the session secret live only in the secret manager and are injected at the broker (never stored, never content-addressed). A worker cannot hand the broker an arbitrary serialized request. Approval is **derived** from a referenced template's `safety_class` (`approval_required`), never trusted from `mode`.

### 7.1 The two-stage procedure

```
STAGE 1 — SCOPE AUTHORITY (control plane; no target I/O). Called JUST-IN-TIME at dispatch. Mints a grant or DENIES.
INPUT: spec_id (the immutable request_spec)

 A. LOAD spec; recompute spec_sha256; MUST equal the stored value            else DENY(spec_tampered)
 0. PRECONDITIONS (re-evaluated against CURRENT state, on the trusted clock):
    a0. ENGAGEMENT-IDENTITY EQUALITY (authority isolation, §1): let E = the engagement being dispatched. Require
        spec.engagement_id = E.id, authorization.engagement_id = E.id, and — if spec.approval_ref present —
        approval.engagement_id = E.id; AND E.active_authorization_id = spec.authorization_id AND
        E.active_scope_version_id = the scope_version whose scope_hash = spec.scope_hash. Any mismatch ⇒
        DENY(engagement_mismatch). A valid authorization/approval from another engagement — even same tenant,
        identical scope_hash — is refused here AND is already a hard FK violation at write (composite
        (id, tenant_id, engagement_id) FKs, §1/§3/§7.0/§10).
    a. engagement.status ∈ {authorized, active}                              else DENY(engagement_not_active)
    b. engagement.emergency_stop = FALSE                                     else DENY(emergency_stop)
    c. authorization active, effective_from ≤ now < expires_at               else DENY(authorization_invalid/expired)
    d. engagement.active_scope_hash == spec.scope_hash == authorization.scope_hash  else DENY(scope_binding_broken)
    e. now inside a testing window AND not blackout                          else DENY(outside_testing_window)
    f. spec.mode ∈ authorization.allowed_modes ∩ engagement.allowed_modes    else DENY(mode_not_authorized)
    g. budget available (total − used − live 'claimed' leases, from the ledger §8.1) > 0  else DENY(budget_exhausted)
    h. approval_gated/intrusive class: spec.approval_ref resolves to an APPROVED, unexpired approval whose
       immutable MANIFEST CONTAINS spec.spec_sha256 (policy threshold met, §10)  else DENY(approval_missing)
 1-5. PARSE/CANONICALIZE, SCHEME, IP-LITERAL NETWORK GUARD (§6), EXCLUSIONS, ALLOWLIST — over the spec's
      canonical fields, against the frozen scope_version identified by spec.scope_hash. Any fail ⇒ DENY.
 → ON PASS: check budget availability (advisory) and MINT a short-TTL (≤30s), single-use grant bound to
   {iss, aud=broker, run_id, job_id, jti, iat/nbf/exp, tenant_id, engagement_id, authorization_id, scope_hash,
   SPEC_SHA256, request_class, approval_ref?}. NO resolved IP and NO request line are in the grant — the request
   line lives in the immutable spec. THE RESERVATION IS NOT CREATED HERE — the broker creates it atomically with
   the intent, before DNS (§8.1, Stage-2 step 10). Emit audit scope.decision.allow. If window/expiry/budget/e-stop
   fails, NO grant is minted and the spec remains queued for a later dispatch — a stale grant can never sit in the queue.

STAGE 2 — GUARDED EGRESS BROKER (data-plane enforcer; the ONLY socket creator).
 6. INGRESS AUTH: authenticate the calling job's per-job identity/capability; NOT a generic CONNECT proxy.
 7. VERIFY GRANT: signature, iss, aud==self, nbf/exp, jti unused (consume single-use). AND
    grant.spec_sha256 == sha256(presented spec) — the spec is exactly the one authorized.  Mismatch ⇒ DENY.
 8. RECONSTRUCT + NORMALIZE the outbound request DETERMINISTICALLY from the immutable spec: method, URL
    (canonical_url + query_keys_canonical + query VALUES by path — CURATED: the non-secret query_template_digest
    catalog body; SECRET: resolve query_value_ref -> operator_query_value at the version pinned by query_value_binding,
    fetch the actual values from the secret manager, recompute the KEYED HMAC and CONSTANT-TIME compare it to
    query_value_digest — mismatch or withdrawn version ⇒ DENY(query_value_mismatch) BEFORE any egress), headers (from
    the header_set_digest template only), body (from the inert payload_digest catalog only), operator session (secret
    injected from the lease named by session_ref, whose tenant/engagement/account/version digest MUST equal
    session_digest). The broker NEVER sends a worker-serialized request; it re-canonicalizes and asserts the
    reconstructed request equals the spec's fields                             else DENY(reconstruction_mismatch)
 9. RE-CHECK LIVE STATE (fail-closed, SI-046): auth not expired/revoked, window open, e-stop clear,
    rate/concurrency slot. Any unknown ⇒ DENY (any pre-charge claim is released).
10. ATOMIC CHARGE + INTENT — ONE TRANSACTION, BEFORE ANY EGRESS (no DNS/TCP/TLS yet): SELECT the engagement
    budget row FOR UPDATE; verify availability > 0; write the fenced budget_reservation and TRANSITION it to
    'charged' (request_budget_used += 1, IRREVERSIBLE) with fence_token = (fence_seq += 1) and owner = this broker;
    AND durably commit request.intent (spec_sha256, grant jti, reservation id, canonical target). All one
    transaction — the budget is charged BEFORE any byte is sent (§8.1). Any failure ⇒ DENY (any claim is released).
11. DNS RESOLUTION + RESOLVED-IP RE-CHECK (rebinding) — the FIRST egress: resolve canonical_host; EVERY
    resolved IP must pass the network guard (§6) AND the frozen scope_version; PIN a validated IP.
12. CONNECT to the pinned IP (TCP + TLS; cert host == canonical_host); SEND the reconstructed request.
13. REDIRECT: never auto-follow. On 3xx, canonicalize Location → form a NEW request_spec → request a FRESH
    JIT grant. Out-of-scope ⇒ STOP, record. Bounded hop depth; each hop independently specced + granted.
14. COMPLETE: request.completed/failed is INFORMATIONAL — it records the resolved+pinned IP, status, and byte
    counts (redacted) but does NOT change the charge, which was applied at step 10 before any send. A pre-charge
    denial released the claim; a post-charge crash leaves a 'charged' lease (conservative over-charge, §8.1). So
    "sent ⇒ charged" always holds and the sent count never exceeds request_budget_total.
```

### 7.2 Tool / browser (broker-mediated) and WebSocket semantics

- **Tool-driven / browser requests are not pre-enqueued per subrequest.** A headless browser or a self-driving tool is an autonomous request engine; the broker is its mediating proxy (`10` §4). For **each** intercepted request line the broker **forms a `request_spec` on the fly**, computes `spec_sha256`, and requests a **JIT grant** from the Scope Authority (Stage 1 over the frozen scope). Only if a grant is minted does it proceed to Stage 2. A browser that fetches an out-of-scope subresource, or follows a redirect off-scope, simply gets **no grant → the request is blocked**. The Scope Authority remains the sole minter and the broker the sole socket creator even for autonomous engines.
- **WebSocket (`ws`/`wss`).** A `kind='websocket'` spec authorizes the **HTTP Upgrade handshake** (a `GET` to the canonical WS path); the handshake is scoped, resolved, IP-pinned, and connected **exactly like an HTTP request**. Scope is fixed at the pinned handshake — an established socket can never change target. The established connection is bounded by per-connection caps (§8: `ws_max_duration_s`, `ws_max_messages`, `ws_max_message_bytes`) and counts against `max_ws_connections` (`ws_in_flight`); **e-stop, window close, or authorization expiry terminate active connections**. Redirects do not apply to an established WS; a handshake redirect is re-authorized like any HTTP redirect (new spec + JIT grant). **Outbound frames are drawn ONLY from the approved, content-addressed inert frame set named by `ws_frame_set_digest`** (a `ws_frame_set` catalog_template); the broker cannot emit a frame outside that set, frame count/size are bounded (§8), and any non-catalog frame requires an approval manifest — never destructive fuzzing (SI-063).
- **Pause / approve / resume (dynamic requests).** When a broker-mediated (tool/browser) request needs approval — a referenced template's `safety_class = 'requires_approval'`, or a new scope element is required — the broker **PAUSES** the dynamic session (holds it, emits no further requests, consumes no budget), obtains a **scope-only pre-verdict** (distinct from Stage-1, §10), raises an `approval_request` whose **frozen manifest** contains that spec's `spec_sha256` (non-circular because `approval_ref` is excluded from `spec_sha256`), and **RESUMES** only once the approval reaches its policy threshold and role quorum; otherwise it **ABORTS** and records `dynamic.rejected`. A paused session remains subject to e-stop / window / expiry.

### 7.3 Key protections baked in
- **Immutable spec + JIT grant:** the queued object is hash-frozen; grants are minted just-in-time bound to `spec_sha256`, so no grant sits in the queue and a tampered spec is rejected at mint (SI-001, SI-060).
- **Broker reconstruction:** the wire request is rebuilt deterministically from the signed spec and must equal it; a worker cannot inject a deviation (SI-061).
- **DNS rebinding / redirects:** resolve → validate → pin at the broker; every redirect is a new spec + grant (SI-003, SI-004, SI-005).
- **Budget correctness (conservative charge-before-send):** an identifiable `budget_reservation` per grant `jti`; the broker transitions the lease to **`charged`** (`request_budget_used += 1`, IRREVERSIBLE) **before any byte is sent**, so `sent ⇒ charged` always holds and sent-but-uncharged traffic is impossible. A pre-charge denial releases the claim; a crashed `claimed` lease is swept and its capacity freed; a `charged` lease is terminal (never released, never expired) — a crash around the send is a conservative over-charge, never an under-charge (SI-017, SI-062).
- **Intent before egress:** the durable `request.intent` is committed **before any DNS/TCP/TLS action**, in the **same transaction** that transitions the lease to `charged`, so nothing is ever contacted without a prior durable record and the budget is already irreversibly charged (SI-055).
- **Fail-closed & double-checkpoint:** any non-affirmative state at either stage denies; window/expiry/e-stop re-checked at JIT mint and Stage 2 (SI-002, SI-046, SI-049).

## 8. Rate-limit, testing-window & expiry enforcement (runtime fields)

```sql
TABLE engagement_runtime_counter (
  engagement_id        UUID PRIMARY KEY,
  tenant_id            UUID NOT NULL,
  window_started_at    TIMESTAMPTZ NOT NULL,
  requests_in_window   INT NOT NULL DEFAULT 0,
  in_flight            INT NOT NULL DEFAULT 0,     -- HTTP requests currently on the wire
  ws_in_flight         INT NOT NULL DEFAULT 0,     -- established ws/wss connections (<= engagement.max_ws_connections)
  fence_seq            BIGINT NOT NULL DEFAULT 0,  -- AUTHORITATIVE monotonic fence source; advanced under the §7.1
                                                   --   FOR UPDATE lock — every reservation/claim takes fence_seq += 1
  last_request_at      TIMESTAMPTZ,
  circuit_state        TEXT NOT NULL DEFAULT 'closed' CHECK (circuit_state IN ('closed','open','half_open')),
  circuit_opened_at    TIMESTAMPTZ,
  consecutive_errors   INT NOT NULL DEFAULT 0,
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id)
);
```

| Control | Field(s) | Enforcement |
|---|---|---|
| Global / per-host RPS | `global_max_rps`, `per_host_max_rps` | Token buckets per engagement/host (broker send path); excess queued, not dropped. |
| Concurrency | `max_concurrency`, `per_host_concurrency`, `in_flight` | Distributed semaphore consulted before every request. |
| Min spacing | `min_request_interval_ms` | Enforced against `last_request_at`. |
| Request budget | `request_budget_total`, `request_budget_used`, **`budget_reservation` ledger (§8.1)** | **Conservative charge-before-send (§8.1):** availability = `total − used − count(live 'claimed' leases)`; checked under a `SELECT … FOR UPDATE` lock. In that same locked transaction the broker transitions the lease to **`charged`** (`used += 1`, IRREVERSIBLE) and commits the durable intent **before any byte is sent**, so `sent ⇒ charged` always holds. A pre-charge denial releases the claim; a crashed `claimed` lease is swept (capacity freed); a `charged` lease is terminal. Sent count never exceeds `request_budget_total`; the only crash residue is a conservative over-charge, never sent-but-uncharged traffic. Exhaustion auto-pauses. |
| Body cap | `max_response_body_bytes` | Response reading truncates; oversize bodies never fully buffered. |
| WebSocket | `max_ws_connections`, `ws_in_flight`, `ws_max_duration_s`, `ws_max_messages`, `ws_max_message_bytes` | Handshake scoped/pinned like HTTP (§7.2); established connection bounded by duration / message-count / message-size; `ws_in_flight <= max_ws_connections`; e-stop / window-close / expiry terminate active connections. |
| Testing window / expiry | `testing_window`, `authorization.expires_at` | Re-evaluated at Stage-1 (**JIT grant-mint**) **and** Stage-2, on the trusted clock (SI-049); a spec that waits in the queue past the window simply gets no grant. |
| Circuit breaker / emergency stop | `circuit_state`, `engagement.emergency_stop` | Breaker auto-pauses on error/latency thresholds; e-stop halts immediately, audited. |

**Auto-expiration invariant:** expiry/window are *pure functions of the trusted clock*, re-derived at Stage 2 on every request, never a cached status flag alone.

### 8.1 Budget reservation ledger

Budget is accounted by an **identifiable ledger**, not a bare counter, running a **conservative charge-before-send state machine** so that no request is ever sent without its budget already irreversibly charged, and a crashed worker can neither send-uncharged nor strand a unit:

```sql
TABLE budget_reservation (               -- CONSERVATIVE charge-before-send lease (no sent-but-uncharged traffic)
  id             UUID PRIMARY KEY,
  tenant_id      UUID NOT NULL,
  engagement_id  UUID NOT NULL,
  spec_id        UUID NOT NULL,
  grant_jti      TEXT NOT NULL,              -- ties the lease to exactly one single-use grant
  state          TEXT NOT NULL DEFAULT 'claimed'
                 CHECK (state IN ('claimed','charged','released','expired')),
  owner          TEXT NOT NULL,              -- the broker instance holding this LEASE
  fence_token    BIGINT NOT NULL,            -- from engagement_runtime_counter.fence_seq (authoritative, monotonic)
  claimed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  charged_at     TIMESTAMPTZ,                -- set when claimed->charged (WITH the intent commit, BEFORE any send)
  expires_at     TIMESTAMPTZ NOT NULL,       -- CLAIM deadline; renewable while 'claimed'
  resolved_at    TIMESTAMPTZ,                -- when released/expired
  UNIQUE (id, tenant_id),
  UNIQUE (tenant_id, grant_jti),             -- one lease per grant (also blocks JTI reuse across leases)
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (spec_id, tenant_id, engagement_id) REFERENCES request_spec(id, tenant_id, engagement_id),
  CONSTRAINT charged_has_time        CHECK (state <> 'charged' OR charged_at IS NOT NULL),
  CONSTRAINT no_release_after_charge CHECK (NOT (state='released' AND charged_at IS NOT NULL)),
  CONSTRAINT no_expire_after_charge  CHECK (NOT (state='expired'  AND charged_at IS NOT NULL))
);
-- CONSERVATIVE charge-before-send state machine — NO sent-but-uncharged traffic:
--   claimed --(atomic WITH the durable intent commit, BEFORE any send)--> charged  [request_budget_used += 1, IRREVERSIBLE]
--   claimed --(denied before charge)---------------------------------> released    [capacity freed]
--   claimed --(deadline, sweeper)------------------------------------> expired      [capacity freed]
-- 'charged' is TERMINAL: never released, never expired, never uncharged. Bytes are sent ONLY when state='charged',
-- so "sent => charged" ALWAYS holds. A DB/network crash around the send may leave a 'charged' lease whose bytes never
-- left (a conservative OVER-charge, acceptable per "ambiguous sends may consume budget"); the inverse (sent-but-
-- uncharged) is IMPOSSIBLE. request.completed/failed is INFORMATIONAL and does NOT change the charge.
-- FENCE TOKENS: fence_token comes from the authoritative per-engagement fence_seq (advanced under the §7.1 FOR UPDATE
-- lock). Only the `owner` may transition a lease and MUST present the current fence_token. RENEW extends expires_at
-- (same token, only while 'claimed'). CLAIM takes over an EXPIRED 'claimed' lease by writing a NEW fence_token (fencing
-- off the old owner, whose token is now stale) and becoming owner — a 'charged' lease is NEVER claimable. The SWEEPER
-- expires ONLY 'claimed' leases past expires_at and outside the renewal grace window; it MUST EXCLUDE 'charged' and
-- 'released' leases.

-- ============================================================================================================
-- EXPLICIT STATE-TRANSITION TRIGGER (behavioral enforcement, not prose). Rejects every illegal transition, the
-- clearing/altering of charged_at, release/expiry after charge, non-owner or stale-fence transitions, and any
-- second increment of request_budget_used. Terminal states are immutable. This trigger — not a CHECK alone —
-- carries the charge-before-send guarantee.
CREATE FUNCTION budget_reservation_transition() RETURNS trigger AS $$
BEGIN
  -- (0) Terminal states are immutable: charged / released / expired can never be transitioned again.
  IF OLD.state IN ('charged','released','expired') THEN
    RAISE EXCEPTION 'budget lease % is terminal (state=%): no further transition (blocks charged->claimed, re-release, etc.)',
      OLD.id, OLD.state;
  END IF;
  -- OLD.state is now 'claimed'. (1) Immutable identity/anchor columns may never change on any transition:
  IF NEW.id <> OLD.id OR NEW.tenant_id <> OLD.tenant_id OR NEW.engagement_id <> OLD.engagement_id
     OR NEW.spec_id <> OLD.spec_id OR NEW.grant_jti <> OLD.grant_jti OR NEW.claimed_at <> OLD.claimed_at THEN
    RAISE EXCEPTION 'immutable budget-lease identity column changed';
  END IF;
  -- (2) charged_at is write-once: NULL while 'claimed'; set ONLY by the charge transition; never cleared/altered.
  IF OLD.charged_at IS NOT NULL THEN
    RAISE EXCEPTION 'charged_at already set on a claimed lease (invariant violation)';  -- unreachable: claimed => NULL
  END IF;

  IF NEW.state = 'claimed' THEN
    -- RENEW (same owner: fence_token unchanged, only expires_at may extend) OR fenced takeover (new owner AFTER
    -- expiry, strictly advancing fence_token to fence off the stale owner). A live claim can never be stolen.
    IF NEW.owner = OLD.owner THEN
      IF NEW.fence_token <> OLD.fence_token THEN RAISE EXCEPTION 'renew must not change fence_token'; END IF;
    ELSE
      IF OLD.expires_at > now()      THEN RAISE EXCEPTION 'cannot take over a live claim before its deadline'; END IF;
      IF NEW.fence_token <= OLD.fence_token THEN RAISE EXCEPTION 'takeover must strictly advance fence_token'; END IF;
    END IF;
    IF NEW.charged_at IS NOT NULL THEN RAISE EXCEPTION 'a claimed lease has no charged_at'; END IF;
    RETURN NEW;

  ELSIF NEW.state = 'charged' THEN
    -- (3) CHARGE: only the current owner presenting the CURRENT fence_token; sets charged_at; increments used ONCE.
    IF NEW.owner <> OLD.owner OR NEW.fence_token <> OLD.fence_token THEN
      RAISE EXCEPTION 'charge requires the current owner AND the current fence_token (stale/incorrect fence rejected)';
    END IF;
    IF NEW.charged_at IS NULL THEN RAISE EXCEPTION 'charge must set charged_at (write-once)'; END IF;
    -- The ONE increment of request_budget_used is performed HERE, bound to this single claimed->charged transition.
    -- Because 'charged' is terminal, this transition fires exactly once per lease => used cannot be double-incremented.
    UPDATE engagement SET request_budget_used = request_budget_used + 1
      WHERE id = NEW.engagement_id AND tenant_id = NEW.tenant_id;
    RETURN NEW;

  ELSIF NEW.state = 'released' THEN
    IF NEW.owner <> OLD.owner OR NEW.fence_token <> OLD.fence_token THEN
      RAISE EXCEPTION 'release requires the current owner AND fence_token';
    END IF;
    IF NEW.charged_at IS NOT NULL THEN RAISE EXCEPTION 'cannot release after charge'; END IF;  -- also a CHECK
    NEW.resolved_at := now();
    RETURN NEW;

  ELSIF NEW.state = 'expired' THEN
    -- SWEEPER: only a claim past its deadline may expire; never after charge. (Owner-agnostic: the sweeper is system.)
    IF OLD.expires_at > now()     THEN RAISE EXCEPTION 'cannot expire a claim before its deadline'; END IF;
    IF NEW.charged_at IS NOT NULL THEN RAISE EXCEPTION 'cannot expire after charge'; END IF;   -- also a CHECK
    NEW.resolved_at := now();
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'unknown target budget-lease state %', NEW.state;
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER budget_reservation_transition_t
  BEFORE UPDATE ON budget_reservation
  FOR EACH ROW EXECUTE FUNCTION budget_reservation_transition();
-- UPDATE-only: the CHECK constraints already bound the INSERT shape (a lease is born 'claimed', charged_at NULL).
-- DELETE is revoked. grant_jti reuse is impossible: UNIQUE(tenant_id, grant_jti) rejects a second lease for a jti,
-- and the grant itself is single-use (jti consumed at the broker, §7.1 step 7).

-- CHARGE PROCEDURE (§7.1 Stage-2 step 10), one transaction, BEFORE any DNS/TCP/TLS:
--   BEGIN;
--     SELECT fence_seq FROM engagement_runtime_counter WHERE engagement_id = :E FOR UPDATE;   -- lock the runtime row
--     -- availability = request_budget_total - request_budget_used - count(claimed & not-expired); MUST be > 0
--     UPDATE engagement_runtime_counter SET fence_seq = fence_seq + 1 WHERE engagement_id = :E RETURNING fence_seq
--       INTO :ftoken;                                                                          -- allocate fence_token
--     INSERT INTO budget_reservation(id, tenant_id, engagement_id, spec_id, grant_jti, state, owner, fence_token,
--                                    expires_at) VALUES (..., 'claimed', :self, :ftoken, now()+lease_ttl);
--     UPDATE budget_reservation SET state='charged', charged_at=now()                          -- fires the trigger:
--       WHERE id=:lease AND owner=:self AND fence_token=:ftoken AND state='claimed';           --   used += 1 (once)
--     INSERT INTO audit_event(... 'request.intent' ...);                                        -- durable intent
--   COMMIT;                                                                                     -- THEN resolve DNS
```

- **Charge before send (conservative).** In the atomic `SELECT ... FOR UPDATE` transaction that commits the durable intent, the broker transitions the lease to **`charged`** and does `request_budget_used += 1` **IRREVERSIBLY, before any egress**. Bytes are sent ONLY when the lease is `charged`, so **sent => charged** always holds; the inverse — sent-but-uncharged traffic — is impossible.
- **Crash boundary.** A crash before the charge commits leaves a `claimed` (or no) lease => nothing was sent => the sweeper reclaims it. A crash around/after the send leaves a `charged` lease whose bytes may or may not have left — a conservative **over-charge**, never an under-charge. `request.completed`/`failed` is informational and does not alter the charge.
- **Availability** = `request_budget_total - request_budget_used - count(state='claimed' AND expires_at > now)`; `used` counts `charged` leases. A grant is minted only when availability > 0, checked under the same `FOR UPDATE` lock so the check and the charge cannot race.
- **Owned / fenced lease.** Each lease has one `owner` and a `fence_token` from the authoritative per-engagement `fence_seq`. Only the owner may transition it, presenting the current token. **RENEW** extends `expires_at` while `claimed`; **CLAIM** takes over an *expired* `claimed` lease by writing a new fence token (fencing the old owner); a **`charged`** lease is never claimable or releasable.
- **Sweeper exclusions.** The sweeper expires only `claimed` leases past `expires_at` outside the renewal grace window; it **never touches `charged` or `released`** leases (charged is terminal and irreversible).

---

## 9. Immutable audit — split request events, multiple streams (blocker 7)

Append-only, hash-chained, tamper-evident. Redaction happens **before** any write (SI-045). Three **streams**, each an independent hash chain so events that have no engagement still get tamper-evident logging:

- **`engagement`** — scope decisions, request intent/completion, approvals, mode switches, e-stop, lifecycle. Keyed by `(engagement_id)`.
- **`tenant`** — tenant-level events with no single engagement: user/role changes, login/logout, tenant retention-policy changes. Keyed by `(tenant_id)`.
- **`global`** — platform-level events with no tenant: global emergency stop, tool-inventory/version-pin changes, feed ingestion, key rotation. Keyed by the platform singleton.

```sql
TABLE audit_chain (                -- one row per chain → gives every chain a NON-NULL identity
  id            UUID PRIMARY KEY,
  chain_key     TEXT GENERATED ALWAYS AS (   -- NON-NULL, GENERATED per scope → exactly one chain per scope
                  CASE stream WHEN 'global' THEN 'global'
                              WHEN 'tenant' THEN 'tenant:'||tenant_id::text
                              ELSE 'engagement:'||engagement_id::text END) STORED,
  stream        TEXT NOT NULL CHECK (stream IN ('engagement','tenant','global')),
  tenant_id     UUID,                          -- NULL only for the global chain
  engagement_id UUID,                          -- NOT NULL iff stream='engagement'
  head_seq      BIGINT NOT NULL DEFAULT 0,
  head_hash     CHAR(64) NOT NULL DEFAULT repeat('0',64),   -- genesis sentinel
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (chain_key),                          -- chain_key is NON-NULL, so this uniqueness ACTUALLY holds
  UNIQUE (id, tenant_id, engagement_id),       -- target of audit_event's tenant/engagement<->chain binding FK
  CONSTRAINT stream_keys CHECK (
     (stream='engagement' AND engagement_id IS NOT NULL AND tenant_id IS NOT NULL)
     OR (stream='tenant'  AND engagement_id IS NULL     AND tenant_id IS NOT NULL)
     OR (stream='global'  AND engagement_id IS NULL     AND tenant_id IS NULL))
);

TABLE audit_event (
  id              UUID PRIMARY KEY,
  chain_id        UUID NOT NULL,                 -- NON-NULL chain identity → the uniqueness below is real
  tenant_id       UUID,                          -- denormalized for RLS/query; NULL only for global
  engagement_id   UUID,
  seq             BIGINT NOT NULL,               -- monotonic per chain; gap = tampering signal
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  actor_type      TEXT NOT NULL CHECK (actor_type IN ('user','system','worker','scheduler','broker')),
  actor_id        UUID,
  actor_role      TEXT,                          -- RBAC role snapshot at event time (doc 09)

  event_type      TEXT NOT NULL,                 -- see catalog below
  subject_type    TEXT,
  subject_id      UUID,
  related_event_id UUID,                         -- completion → its intent event (same chain)

  payload         JSONB NOT NULL,                -- REDACTED structured detail (no secrets/PII/tokens/bodies)
  payload_sha256  CHAR(64) NOT NULL,             -- hash of canonical(payload) AFTER redaction

  prev_hash       CHAR(64) NOT NULL,             -- the chain's head_hash at insert time
  event_hash      CHAR(64) NOT NULL,
  signature       TEXT,                          -- periodic-anchor signature (write-only signing svc, SI-051)

  FOREIGN KEY (chain_id) REFERENCES audit_chain(id),   -- chain_id is NON-NULL, so THIS FK always validates
  -- NOTE: a composite FK (chain_id, tenant_id, engagement_id) REFERENCES audit_chain(...) is DELIBERATELY NOT relied
  -- upon for identity: PostgreSQL MATCH SIMPLE SKIPS the whole FK when ANY referencing column is NULL, so for tenant
  -- (engagement_id NULL) and global (both NULL) chains it would validate NOTHING — a tenant event could point at
  -- another tenant's chain. Identity is enforced by the NULL-SAFE trigger below instead (see audit_event_identity).
  FOREIGN KEY (related_event_id, chain_id) REFERENCES audit_event(id, chain_id),  -- related event MUST be same chain
                                                 -- (both columns non-null when related_event_id is present => validated;
                                                 --  a cross-chain related_event_id is rejected here)
  UNIQUE (id, tenant_id),                        -- target of composite child FKs (e.g. approval linkage)
  UNIQUE (id, tenant_id, engagement_id),         -- target of approval_request.linked_audit_event_id (same-engagement)
  UNIQUE (id, chain_id),                         -- target of the same-chain related-event FK
  UNIQUE (chain_id, seq),                        -- NON-NULL columns ⇒ REAL per-chain seq uniqueness
  UNIQUE (chain_id, event_hash)
  -- (The earlier UNIQUE(stream, tenant_id, engagement_id, seq) was VOID for tenant/global chains: Postgres
  --  treats the NULL tenant_id/engagement_id as distinct, so seq uniqueness was not enforced. chain_id fixes this.)
);

-- NULL-SAFE audit identity (structural fix for the MATCH SIMPLE gap). audit_event.tenant_id/engagement_id are kept
-- only for RLS/query convenience; they are NOT authoritative and NOT operator-trusted — this trigger derives the
-- authoritative identity from the event's chain and REJECTS any mismatch using IS DISTINCT FROM (NULL-safe), which,
-- unlike the skipped FK, catches a tenant/global event whose (tenant_id, engagement_id) disagrees with its chain.
CREATE FUNCTION audit_event_identity() RETURNS trigger AS $$
DECLARE ch audit_chain%ROWTYPE;
BEGIN
  SELECT * INTO ch FROM audit_chain WHERE id = NEW.chain_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'audit_event.chain_id % references no chain', NEW.chain_id;
  END IF;
  -- IS DISTINCT FROM treats NULL as a comparable value, so NULL=NULL passes and NULL<>value fails. A global chain
  -- (tenant NULL, engagement NULL) or a tenant chain (engagement NULL) can no longer be paired with a mismatched event.
  IF NEW.tenant_id IS DISTINCT FROM ch.tenant_id
     OR NEW.engagement_id IS DISTINCT FROM ch.engagement_id THEN
    RAISE EXCEPTION 'audit_event identity (tenant=%, engagement=%) != chain % identity (stream=%, tenant=%, engagement=%)',
      NEW.tenant_id, NEW.engagement_id, ch.id, ch.stream, ch.tenant_id, ch.engagement_id;
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER audit_event_identity_t
  BEFORE INSERT OR UPDATE ON audit_event
  FOR EACH ROW EXECUTE FUNCTION audit_event_identity();
-- (UPDATE is otherwise revoked on this append-only table; the trigger also covers the theoretical UPDATE path.)
```

**Event-type catalog (illustrative).**
- *engagement stream:* `scope.decision.allow`, `scope.decision.deny`, `request.spec_created`, `request.intent`, `request.completed`, `request.failed`, `redirect.blocked`, `ws.opened`, `ws.closed`, `auth.attested`, `approval.requested`, `approval.decided`, `approval.threshold_met`, `scope.version.created`, `engagement.mode_changed`, `engagement.emergency_stop`, `engagement.expired`, `evidence.stored`, `dek.destroyed`.
- *tenant stream:* `auth.login`, `auth.login_failed`, `auth.logout`, `user.role_changed`, `tenant.retention_changed`.
- *global stream:* `platform.emergency_stop.global`, `tool.inventory.updated`, `tool.pinned`, `feed.ingested`, `key.rotated`.

**Integrity rules**
- **Genesis & non-null chain identity.** Each chain is an `audit_chain` row with a NON-NULL `chain_key`/`id`; genesis `head_hash = 0*64`. Each event's `prev_hash` = the chain's current `head_hash`, and committing an event advances the chain's `head_seq`/`head_hash`. Uniqueness of `seq` and `event_hash` is enforced on the NON-NULL `chain_id` — closing the earlier gap where NULL tenant/engagement keys made the constraint vacuous for tenant/global chains. Any altered/removed/reordered event breaks that chain from that point.
- **Request intent precedes ANY egress (SI-055):** the `request.intent` event — recording the `spec_sha256`, the grant `jti`, and the `budget_reservation` id — is durably committed **before any DNS query, TCP connect, or TLS handshake**, in the **same transaction** that transitions the lease to `charged` (`request_budget_used += 1`, §8.1), so a target is never contacted without a prior durable record AND the budget is already irreversibly charged before any byte is sent. The `request.completed`/`request.failed` event references it via `related_event_id` (same chain) and is **informational only** — it does not change the charge. A crash after intent leaves a durable "attempted" record and a `charged` lease (conservative over-charge), never sent-but-uncharged traffic.
- **Redaction before hashing (SI-045):** secrets, cookies, `Authorization` headers, tokens, credentials-in-URL, PII, and raw bodies are stripped/omitted first; `payload_sha256` covers the redacted form. Raw target auth material and bodies are **never** written to any stream.
- **Append-only:** `UPDATE`/`DELETE` revoked at the grant level and rejected by triggers.
- **Anchoring & key custody (SI-051):** each chain head is periodically signed by a **write-only** signing service (whose key Administrators cannot read) and anchored to WORM/external notary; the residual rewrite window between anchors is documented in `11-data-retention-and-deletion.md`.

---

## 10. Approval — dual control with per-approver decisions (blocker 3)

Backs Mode 3 (approval-gated validation), authorization attestation, scope expansion, restricted-range (Tier B) allows, and mode elevation. The single-`decided_by` model is replaced by an **N-of-M** model: an `approval_request` plus one `approval_decision` row per approver. **The threshold and eligible approver roles are NOT fields the requester supplies** — they are read from an **immutable, Administrator-managed `approval_policy`** referenced by `approval_policy_id`. For intrusive/business-logic requests the approval authorizes an **explicit manifest of approved `request_spec` content digests** (`approval_manifest_entry`), not a free-form plan. Per-decision hash binding and separation of duties still apply.

```sql
TABLE approval_request (
  id                 UUID PRIMARY KEY,
  tenant_id          UUID NOT NULL,
  engagement_id      UUID NOT NULL,

  request_type       TEXT NOT NULL CHECK (request_type IN
                       ('authorization_attestation','scope_expansion','restricted_range_allow',
                        'mode_elevation','intrusive_validation','business_logic_test')),
  approval_policy_id UUID NOT NULL,   -- FK -> immutable approval_policy in force; threshold + roles come from HERE

  requested_by       UUID NOT NULL,
  requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  justification      TEXT NOT NULL CHECK (char_length(justification) BETWEEN 1 AND 4000),

  proposed_action    JSONB NOT NULL,   -- human-readable description of the request (NOT the authorization anchor)
  manifest_sha256    CHAR(64),         -- intrusive/business-logic: hash over the sorted approved-spec digest set
  document_sha256    CHAR(64),         -- authorization_attestation: hash of the authorization artifact
  potential_impact   TEXT NOT NULL CHECK (char_length(potential_impact) <= 4000),
  target_summary     TEXT NOT NULL,
  scope_check_result JSONB NOT NULL,   -- snapshot of the SCOPE-ONLY pre-verdict (§10, no approval check) — must be PASS;
                                       --   NOT the full Stage-1 approval validation (that would be circular, §10)
  required_account   TEXT,
  expected_response  TEXT,
  evidence_plan      TEXT NOT NULL,
  cleanup_action     TEXT,
  stop_conditions    TEXT NOT NULL,

  status             TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','approved','rejected','expired','withdrawn')),
  resolved_at        TIMESTAMPTZ,
  expires_at         TIMESTAMPTZ NOT NULL,
  manifest_frozen    BOOLEAN NOT NULL DEFAULT FALSE,   -- TRUE once the manifest is frozen (required before any decision)
  manifest_frozen_at TIMESTAMPTZ,

  linked_scope_version_id UUID,
  linked_audit_event_id   UUID,

  UNIQUE (id, tenant_id),
  UNIQUE (id, tenant_id, engagement_id),   -- target of authorization.attestation_approval_id + request_spec.approval_ref
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (approval_policy_id) REFERENCES approval_policy(id),
  -- Linked scope-version and audit event MUST belong to THIS engagement (no cross-engagement linkage):
  FOREIGN KEY (linked_scope_version_id, tenant_id, engagement_id) REFERENCES scope_version(id, tenant_id, engagement_id),
  FOREIGN KEY (linked_audit_event_id, tenant_id, engagement_id)   REFERENCES audit_event(id, tenant_id, engagement_id),
  -- SCOPE-ONLY PRE-VERDICT (never the full Stage-1 approval validation — that would be circular). Within-scope
  -- types must pass the SCOPE-ONLY pre-verdict; scope-CHANGING types target something not-yet-in-scope so no pass
  -- is required. scope_check_result holds ONLY the scope-only pre-verdict snapshot.
  CONSTRAINT scope_preverdict_pass CHECK (
     request_type IN ('scope_expansion','restricted_range_allow','authorization_attestation')
     OR (scope_check_result->>'decision') = 'pass'),
  -- ONE MANIFEST RULE. Manifest-bearing types carry a non-null manifest_sha256 (non-empty + freeze enforced by
  -- trigger). EVERY other type carries the CANONICAL EMPTY manifest digest (= sha256 of the empty entry set) and
  -- may hold NO manifest_entry rows (forbidden by trigger). EMPTY_MANIFEST_SHA256 is the well-known sha256 of the
  -- empty string, which is exactly what the freeze trigger computes for a zero-row manifest (string_agg -> '').
  CONSTRAINT manifest_shape CHECK (
     (request_type IN ('intrusive_validation','business_logic_test') AND manifest_sha256 IS NOT NULL)
     OR (request_type NOT IN ('intrusive_validation','business_logic_test')
         AND manifest_sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')),
  -- REQUEST-TYPE SHAPE: each type carries exactly its authority anchor and NULLs the anchors it must not use.
  CONSTRAINT attestation_needs_document CHECK (
     request_type <> 'authorization_attestation' OR document_sha256 IS NOT NULL),
  CONSTRAINT document_only_for_attestation CHECK (
     request_type = 'authorization_attestation' OR document_sha256 IS NULL),
  CONSTRAINT scope_change_needs_linked_scope CHECK (
     request_type NOT IN ('scope_expansion','restricted_range_allow') OR linked_scope_version_id IS NOT NULL),
  CONSTRAINT linked_scope_only_for_scope_change CHECK (
     request_type IN ('scope_expansion','restricted_range_allow') OR linked_scope_version_id IS NULL)
);
-- required_approvals + approver_roles are NOT columns here — they are read from the immutable approval_policy
-- referenced by approval_policy_id, so a requester can never set their own threshold or eligible roles. The behavioral
-- rules above are enforced by the explicit triggers defined AFTER approval_decision (approval_request_policy_match,
-- approval_manifest_entry_guard, approval_request_freeze_guard, approval_decision_shape) — not by prose.

TABLE approval_policy (             -- IMMUTABLE, Administrator-managed, versioned policy (the source of truth)
  id                 UUID PRIMARY KEY,
  policy_digest      CHAR(64) NOT NULL,       -- sha256 of canonical(request_type, required_approvals, sort(approver_roles), role_quorum, version)
  request_type       TEXT NOT NULL CHECK (request_type IN
                       ('authorization_attestation','scope_expansion','restricted_range_allow',
                        'mode_elevation','intrusive_validation','business_logic_test')),
  required_approvals INT NOT NULL CHECK (required_approvals BETWEEN 1 AND 5),
  approver_roles     TEXT[] NOT NULL,
  role_quorum        JSONB NOT NULL DEFAULT '{}',  -- minimum approvals PER role, e.g. {"Engagement Manager": 1}
  version            INT NOT NULL,
  effective_from     TIMESTAMPTZ NOT NULL DEFAULT now(),
  superseded         BOOLEAN NOT NULL DEFAULT FALSE,
  created_by         UUID NOT NULL,           -- Administrator only (doc 09); recorded in the global audit stream
  UNIQUE (policy_digest),
  UNIQUE (request_type, version),
  -- ELIGIBLE-ROLE ALLOWLIST: only these roles may ever approve; Tester and Read-only Auditor are NEVER eligible
  -- (doc 09). An arbitrary/unknown role string is rejected at write.
  CONSTRAINT approver_roles_allowlisted CHECK (
     array_length(approver_roles, 1) >= 1
     AND approver_roles <@ ARRAY['Engagement Manager','Reviewer','Administrator']),
  CONSTRAINT threshold_floor CHECK (
     (request_type = 'intrusive_validation' AND required_approvals >= 1)
     OR required_approvals >= 2)
);
-- EXACTLY ONE current policy per request_type — a REAL partial unique index (not a comment):
CREATE UNIQUE INDEX one_current_policy ON approval_policy (request_type) WHERE superseded = FALSE;
-- Content columns are IMMUTABLE; DELETE is revoked. The ONLY permitted UPDATE is superseded FALSE->TRUE (retiring a
-- version so a new one can become current) — enforced by approval_policy_supersede_only. Introducing a new version is
-- an INSERT whose role-quorum validity and NON-DECREASING strength vs the current version are enforced by
-- approval_policy_validity. Together these resolve the old contradiction (a blanket "UPDATE revoked" made it
-- impossible to flip superseded, which the one-current-policy index requires).

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

CREATE FUNCTION approval_policy_validity() RETURNS trigger AS $$
DECLARE k TEXT; v INT; total INT := 0; prev approval_policy%ROWTYPE; pk TEXT; pv INT;
BEGIN
  -- role_quorum validity: every key is an eligible role; every value is a POSITIVE integer; the sum is SATISFIABLE.
  FOR k, v IN SELECT key, value::int FROM jsonb_each_text(NEW.role_quorum) LOOP
    IF NOT (k = ANY(NEW.approver_roles)) THEN RAISE EXCEPTION 'role_quorum role % not in approver_roles', k; END IF;
    IF v <= 0 THEN RAISE EXCEPTION 'role_quorum value for % must be a positive integer', k; END IF;
    total := total + v;
  END LOOP;
  IF total > NEW.required_approvals THEN
    RAISE EXCEPTION 'role_quorum sum (%) exceeds required_approvals (%) — unsatisfiable', total, NEW.required_approvals;
  END IF;
  -- NON-DECREASING strength vs the IMMEDIATELY-PRIOR version of this request_type: threshold may only rise, the
  -- eligible-role allowlist may only tighten (subset), and no existing per-role quorum minimum may fall.
  -- The predecessor is the HIGHEST existing version (regardless of superseded): a new version is inserted only AFTER
  -- the old current row was flipped superseded=TRUE (one_current_policy allows just one non-superseded row), so a
  -- `superseded = FALSE` filter here would find NOTHING at insert time and silently DISABLE the downgrade guard.
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

TABLE approval_manifest_entry (     -- the EXPLICIT set of approved request_spec content digests
  id                  UUID PRIMARY KEY,
  tenant_id           UUID NOT NULL,
  approval_request_id UUID NOT NULL,
  spec_sha256         CHAR(64) NOT NULL,       -- an approved request_spec (or spec-template) content digest
  UNIQUE (approval_request_id, spec_sha256),
  FOREIGN KEY (approval_request_id, tenant_id) REFERENCES approval_request(id, tenant_id)
);
-- manifest_sha256 on approval_request = SHA-256 over the sorted set of these spec_sha256 digests. §7 Stage-1
-- mints a grant ONLY IF spec.spec_sha256 EXISTS as a manifest entry of the referenced, approved request.

TABLE approval_decision (
  id                   UUID PRIMARY KEY,
  tenant_id            UUID NOT NULL,
  approval_request_id  UUID NOT NULL,
  approver_user_id     UUID NOT NULL,
  approver_role        TEXT NOT NULL,          -- verified against the policy's approver_roles at decision time
  decision             TEXT NOT NULL CHECK (decision IN ('approve','reject')),
  decided_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  decision_reason      TEXT CHECK (char_length(decision_reason) <= 2000),
  approved_manifest_sha256 CHAR(64),           -- intrusive/business-logic: the manifest hash THIS approver pinned (= request.manifest_sha256)
  approved_document_sha256 CHAR(64),           -- attestation: the doc hash this approver pinned
  approved_policy_digest   CHAR(64) NOT NULL,  -- the approval_policy version this approver decided under

  FOREIGN KEY (approval_request_id, tenant_id) REFERENCES approval_request(id, tenant_id),
  UNIQUE (approval_request_id, approver_user_id)          -- one decision per approver
);

-- (F) BEHAVIORAL TRIGGERS — approval integrity is enforced here, not in prose.

-- 1. The request MUST pin the CURRENT (non-superseded) policy whose request_type MATCHES.
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

-- 2. Manifest entries are ALLOWED ONLY on manifest-bearing types and ONLY before freeze (forbids entries on the
--    empty-manifest types; a scope_expansion/attestation can never smuggle a manifest entry).
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

-- 3. Freeze is MONOTONIC (FALSE->TRUE) and on freeze the manifest_sha256 MUST equal the recomputed digest of the
--    sorted entry set. Manifest-bearing types must be NON-EMPTY; empty-manifest types must have ZERO entries (and
--    manifest_shape already pins their manifest_sha256 to the canonical empty digest — which is exactly the digest
--    this trigger computes for a zero-row manifest, so the verify is uniform).
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
      IF computed <> NEW.manifest_sha256 THEN   -- computed = sha256('') = the canonical empty digest
        RAISE EXCEPTION 'empty manifest digest mismatch (expected the canonical empty digest)';
      END IF;
    END IF;
    NEW.manifest_frozen_at := now();
  END IF;
  RETURN NEW;
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER approval_request_freeze_guard_t BEFORE UPDATE ON approval_request
  FOR EACH ROW EXECUTE FUNCTION approval_request_freeze_guard();

-- 4. Every APPROVE decision MUST pin the required digests with a NON-NULL EQUAL value — NULL never bypasses. It is
--    also rejected before the manifest is frozen. Reject decisions are recorded but pin nothing.
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
```

**Decision rules (enforced in app + trigger, tested as SI-047 / SI-018 / SI-020):**

1. **Threshold, role quorum & frozen manifest (from the immutable policy).** **For manifest-bearing types** (`intrusive_validation`, `business_logic_test`) decisions are accepted only when `manifest_frozen = TRUE` and the frozen manifest hashes to `manifest_sha256` (trigger-verified); non-manifest types (attestation/scope-change) carry no manifest (or the canonical empty-set digest) and skip that check. `approval_request` becomes `approved` **iff** the count of *distinct* `approval_decision` rows with `decision='approve'`, `approver_role ∈ approval_policy.approver_roles`, `approved_policy_digest = the referenced policy's digest` (a NON-NULL equal pin — NULL never counts), and — for **manifest-bearing** types a NON-NULL `approved_manifest_sha256 = manifest_sha256`, for **attestation** a NON-NULL `approved_document_sha256 = document_sha256` (the `approval_decision_shape` trigger rejects any approve-decision whose required pin is NULL or unequal) — is **≥ `approval_policy.required_approvals`**, **every per-role minimum in `approval_policy.role_quorum` is met**, **and** no `reject` decision exists. Any `reject` ⇒ `rejected`. The threshold, eligible roles, and role quorum all come from the current, non-superseded `approval_policy` pinned at request time — never from the request.
2. **Separation of duties.** No approver may equal `requested_by`; no approver may be the tester executing the action; approvers must be distinct users; each approver must hold a role in the **policy's** `approver_roles`; a user may not hold two SoD-conflicting roles on the same engagement (doc 09).
3. **Manifest/document-hash binding.** Each approver pins the exact `manifest_sha256` (and `document_sha256` for attestation) and the `approved_policy_digest`. If the manifest, document, or policy version changes, prior decisions are void and the threshold must be re-met — an approval can never be moved onto a different manifest or a weaker policy.
4. **Scope-only pre-verdict precondition (conditional; NON-circular).** For *within-scope* request types (`intrusive_validation`, `business_logic_test`, `mode_elevation`) an approval cannot be created unless its target passes the **scope-only pre-verdict** (scheme/exclusion/allowlist/network-guard, with **no** approval check) — the DDL `scope_preverdict_pass` CHECK requires `scope_check_result.decision = 'pass'`, and `scope_check_result` holds ONLY that pre-verdict. It is **never** the full §7 Stage-1 approval validation: Stage-1 mints a grant only from an *already-approved* manifest, so requiring "passes Stage-1" to *create* the approval would be circular. The manifest binds the stable `spec_sha256` (`approval_ref` is excluded from it, §7.0), so the pre-verdict and the approval never wait on each other. For *scope-changing* types (`scope_expansion`, `restricted_range_allow`, `authorization_attestation`) the target is by definition **not yet in scope**, so the CHECK deliberately does **not** require a pass; these approvals gate a *new* `scope_version` that becomes the in-scope set only once re-attested.
5. **Manifest binds the exact request(s).** For `intrusive_validation`/`business_logic_test`, the approval's `approval_manifest_entry` rows are the exhaustive set of authorized `request_spec` content digests, and `manifest_sha256` hashes that set; §7 Stage-1 step (h) mints a grant only if `spec.spec_sha256` EXISTS as a manifest entry of the referenced approved request. An approval can never authorize a spec whose digest is not in its manifest.
6. **Time-boxed & audited.** Requests and each decision emit audit events (`approval.requested`, `approval.decided`, `approval.threshold_met`). Expired approvals authorize nothing.

**Seeded `approval_policy` content** (immutable, Administrator-managed, versioned; roles cross-checked against `09-rbac-matrix.md`; a new version may raise a threshold, never lower it below the floor). This is table *content*, not requester-supplied fields:

| `request_type` | `required_approvals` (floor) | `approver_roles` |
|---|---|---|
| `authorization_attestation` | 2 | Engagement Manager (≥1 required), then Reviewer / Administrator |
| `scope_expansion` | 2 | Engagement Manager, Reviewer |
| `restricted_range_allow` (Tier B) | 2 | Engagement Manager, Reviewer |
| `mode_elevation` | 2 | Engagement Manager, Reviewer |
| `business_logic_test` | 2 | Engagement Manager, Reviewer |
| `intrusive_validation` | 1 | Engagement Manager, Reviewer |

**Scope-only pre-verdict vs Stage-1 approval validation (non-circular dynamic bootstrap).** The Scope Authority exposes two distinct verdicts over a candidate: a **scope-only pre-verdict** — scheme/exclusion/allowlist/network-guard PASS with **no** approval check — and the **Stage-1 full verdict** — the scope-only checks PLUS approval-manifest membership and policy threshold (which mints the grant, §7.1 step h). A dynamic (broker-mediated) request that turns out to need approval is bootstrapped **without circularity** because `approval_ref` is EXCLUDED from `spec_sha256` (§7.0): (1) the broker forms the spec and gets its stable `spec_sha256`; (2) a **scope-only pre-verdict** confirms it is in scope (and is what satisfies `approval_request.scope_check_result`); (3) an `approval_request` is created and its manifest **frozen** with that `spec_sha256`; (4) after approvals reach threshold + role quorum, the **Stage-1 full verdict** now finds the digest in the frozen manifest and mints the grant → the paused session resumes. The pre-verdict never depends on the approval, and the approval's manifest binds the already-stable content digest — so neither waits on the other.

---

## 11. Scope import / export format

A single, versioned, canonical document, hash-bound so an imported scope cannot silently differ from what was signed. Round-trips deterministically.

```yaml
# scope-export.yaml  (JSON equivalent canonicalizes identically)
schema_version: "1.1"
kind: scope_bundle
exported_at: "2026-07-21T09:15:00Z"
engagement:
  reference: "SOW-2026-0417"          # non-secret identifier only
  name: "Acme External Web Assessment"
  timezone: "Europe/London"
authorization_binding:
  authorization_reference: "SOW-2026-0417"
  effective_from: "2026-07-15T00:00:00Z"
  expires_at:     "2026-08-15T00:00:00Z"
  allowed_modes: ["passive","safe_active","approval_gated"]
  internal_testing_granted: false
scope:
  allow:
    - {class: domain, value: "acme.example",     wildcard: false, include_subdomains: false}
    - {class: domain, value: "*.acme.example",    wildcard: true,  include_subdomains: true, elevated: true}  # wildcard ⇒ elevated
    - {class: cidr,   value: "203.0.113.0/24",    ip_version: 4}
    - {class: port,   value: "443"}
    - {class: protocol, value: "https"}
    - {class: path_prefix,  bound_host: "api.acme.example", value: "/v1/"}                    # host-bound
    - {class: api_resource, bound_host: "api.acme.example",
       openapi_ref: "specs/acme-openapi.yaml", openapi_sha256: "0f3d...ab",
       operations: ["GET /v1/users","GET /v1/orders/{id}"]}
  exclude:                              # always win
    - {class: domain,      value: "admin.acme.example"}
    - {class: path_prefix, bound_host: "*.acme.example", value: "/logout"}
    - {class: ip,          value: "203.0.113.7"}      # carve a host out of the allowed CIDR
integrity:
  canonicalization: "sorted-keys/utf8/no-ws"
  scope_hash: "sha256:9c1e...f4"       # MUST match recomputed hash on import (§4.1 field set)
  entry_count: 9
  host_count: 3
  address_count: 257
signature:
  algo: "ed25519"
  key_id: "org-scope-signing-2026"
  value: "base64:..."
```

**Import validation (fail-closed):**
1. Reject unknown `schema_version`.
2. Re-canonicalize `scope`, recompute `scope_hash` over the full §4.1 field set, and **reject on mismatch**.
3. Re-run all per-entry validators (§4, §5, §6): IDNA, public-suffix/wildcard guard, CIDR/IP form, port ranges, path canonicalization, scheme allowlist, host-binding for path/api entries, **network-guard classification** (any Tier B entry imports as `elevated=FALSE` and cannot self-activate — it still needs §6/§10 elevated dual approval + re-attestation), and **breadth limits** (§4.6).
4. Verify `signature` if signed and the key is trusted.
5. On success, materialize a **new** `scope_version`; binding to authorization is a separate, dual-controlled attestation step.

**Export never includes secrets** — only scope structure and non-secret identifiers, consistent with the redaction posture everywhere.

---

## 12. Cross-cutting invariants → Phase 2 acceptance criteria

These are the testable guarantees this schema exists to make provable (Phase 2 "out-of-scope requests cannot be scheduled/executed" + Phase 10 property tests):

1. **No authorization ⇒ no request.** Any request on an engagement lacking an `active`, dual-attested authorization is denied and audited.
2. **Scope drift is fatal.** `engagement.active_scope_hash ≠ authorization.scope_hash` ⇒ all requests deny until re-attestation.
3. **Exclusions always win.** Any candidate matching both allow and exclude ⇒ DENY (property test over overlaps, including host-bound paths).
4. **Tier A is absolute.** No scope entry, elevated flag, or approval can reach loopback/metadata/unspecified/multicast/broadcast/reserved; obfuscated and transition IPv6 forms decode and deny (SI-006, SI-044).
5. **Tier B needs full elevation.** RFC1918/ULA/link-local/CGNAT reachable only with an `elevated` entry **and** a dual-approved `restricted_range_allow` **and** `internal_testing_granted` (SI-047, SI-059).
6. **Immutable spec + JIT two-stage.** The queued object is an immutable, fully-hashed `request_spec`; JIT grants bind `spec_sha256` (never a resolved IP), are single-use (`jti`) and `aud`-bound, and are minted only at dispatch so none can sit in the queue; the broker reconstructs the wire request from the spec and rejects any mismatch (SI-001, SI-060, SI-061).
7. **Rebinding & redirects defeated.** Resolved IPs individually validated and pinned; every redirect hop needs a fresh grant (SI-003, SI-004, SI-005).
8. **Dual control on the legal gate.** Attestation and scope expansion require two distinct valid-role approvers, neither the tester, each pinning the required `manifest_sha256`/`document_sha256` and the policy digest (NULL never counts); the threshold is enforced, not advisory (SI-047).
9. **Audit is complete, split, and tamper-evident.** Every action emits an event; request intent precedes egress; three streams chain independently; recomputation detects any edit/reorder; `seq` has no gaps (SI-026, SI-055, SI-056).
10. **Breadth is bounded.** Broad CIDRs, wildcards, and excessive host/address counts are hard-capped or gated by elevated dual approval; scope expansion re-attests (SI-059).
11. **Import is hash-verified & fail-closed.** A bundle whose recomputed `scope_hash` differs is rejected; Tier B/wildcard entries never self-activate.
12. **Composite tenant *and engagement* integrity.** No child row can reference a parent in another tenant, and no security-authority reference can bind another engagement — every such FK is composite `(id, tenant_id, engagement_id)` (`request_spec`→authorization/approval/session, `budget_reservation`→spec, `engagement`→active authorization/scope, `authorization`→scope_version/attestation-approval, `approval_request`→linked scope-version/audit-event; the engagement↔authorization↔scope_version and authorization↔attestation-approval cycles use DEFERRABLE composite FKs) — Stage-1 re-verifies engagement equality at dispatch, and RLS scopes every query (SI-024).
13. **Budget is charge-before-send.** In one `FOR UPDATE`-locked transaction the broker charges the lease (`used += 1`, IRREVERSIBLE) and commits the durable intent **before any byte is sent** (availability = `total − used − live 'claimed'` checked under the same lock), so `sent ⇒ charged` always holds; a pre-charge denial releases the claim, a crashed `claimed` lease is swept, and a `charged` lease is terminal — the only crash residue is a conservative over-charge, never sent-but-uncharged traffic (SI-017, SI-062).
14. **Window/expiry/e-stop are JIT + Stage-2.** Re-evaluated at grant-mint and again at the broker; a spec that waited past the window gets no grant, and a fired e-stop/expiry aborts in-flight work including WebSockets (SI-011, SI-012, SI-013, SI-049).
15. **Approval binds the exact spec.** Intrusive approvals bind an explicit `approval_manifest_entry` set (hashed as `manifest_sha256`) containing each authorized `spec_sha256`; scope-changing approvals correctly do NOT require the not-yet-in-scope target to pass §7 (SI-018, SI-047, SI-064).
16. **Breadth accounting is computable.** An IPv4-equivalent address budget + a CIDR-entry cap are enforced; IPv6 breadth is governed by prefix floors + elevated approval (never an address sum); exclusions are not subtracted (SI-059).
17. **WebSocket is bounded and catalog-controlled.** ws/wss handshakes are scoped/pinned like HTTP; established connections are bounded by duration/message/size/count caps and terminated on e-stop/window/expiry; outbound frames come only from the approved content-addressed frame set (SI-063).
18. **Intent precedes any egress.** `request.intent` is durably committed before any DNS/TCP/TLS action, in the same transaction that charges the budget lease (SI-055).
19. **Budget leases are identifiable, owned & fenced.** One `budget_reservation` per grant `jti` with an `owner` and a monotonic `fence_token` (from `engagement_runtime_counter.fence_seq`); only the owner may transition a lease and must present the current token; a `charged` lease is terminal (never released, never claimable), the sweeper reclaims only expired `claimed` leases — sent never exceeds total, nothing strands, and no stale owner can charge after being fenced off (SI-017, SI-062).
20. **Requests are content-addressed & repeatable.** All template references are immutable digests bound into `spec_sha256`; there is no `UNIQUE(spec_sha256)`, so identical requests may recur across jobs/runs as distinct instances (SI-065).
21. **Approval policy is immutable; approval binds a manifest.** Threshold + roles come from an immutable, Admin-versioned `approval_policy`, never requester fields; intrusive approvals authorize only the explicit set of `spec_sha256` digests in their manifest (SI-064).
22. **Audit chains have non-null identity.** Every chain is an `audit_chain` row with a NON-NULL `chain_id`; per-chain `seq`/`event_hash` uniqueness is enforced on that non-null key (SI-026).

---

**File paths:** none produced — Phase 0 design deliverable. The schema seeds the Phase 2 migration set (`engagement`, `testing_window`, `authorization`, `scope_version`, `scope_entry`, `request_spec`, `catalog_template`, `operator_session`, `operator_query_value`, `engagement_runtime_counter`, `budget_reservation`, `audit_chain`, `audit_event`, `approval_policy`, `approval_request`, `approval_manifest_entry`, `approval_decision`) and the Scope Authority / Guarded Egress Broker two-stage decision procedure (§7), network guard (§6), canonicalization (§5), breadth limits (§4.6), and dual-control approval (§10). Related: `09-rbac-matrix.md`, `10-request-authorization-flow.md`, `11-data-retention-and-deletion.md`.
