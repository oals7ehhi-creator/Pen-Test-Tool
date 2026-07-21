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
8. **Composite-tenant integrity.** Every child row references its parent by a composite `(id, tenant_id)` foreign key, so a row can never point at a parent in another tenant (§1).
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
  -- guaranteeing same-tenant references (verified at COMMIT, not per-statement).
  FOREIGN KEY (active_authorization_id, tenant_id)
        REFERENCES authorization(id, tenant_id) DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (active_scope_version_id, tenant_id)
        REFERENCES scope_version(id, tenant_id) DEFERRABLE INITIALLY DEFERRED,
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
   any state (except archived) ──▶ expired          (on auth expiry / window close)
   active|paused|authorized ─────▶ completed ─▶ archived
```

- Transitions are recorded as audit events (§9). Illegal transitions are rejected.
- `expired`, `suspended`, `emergency_stopped` are **terminal for testing**: no request may be scheduled or executed. Recovery requires an explicit human transition and (for expiry) a fresh authorization.

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
     (kind='recurring_weekly' AND days_of_week IS NOT NULL AND start_local IS NOT NULL AND end_local IS NOT NULL)
     OR (kind IN ('one_off','blackout') AND start_at IS NOT NULL AND end_at IS NOT NULL)
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

  -- Written-authorization attestation (dual-controlled via approval, §10)
  written_auth_attested    BOOLEAN NOT NULL,
  attested_by_user_id      UUID NOT NULL,          -- the requester of the attestation approval
  attested_at              TIMESTAMPTZ NOT NULL,
  attestation_statement    TEXT NOT NULL CHECK (char_length(attestation_statement) <= 2000),
  document_ref             TEXT,                   -- pointer/URI to stored authorization doc (not the doc)
  document_sha256          CHAR(64) NOT NULL,      -- hash of the authorization artifact (pinned at both approvals)
  attestation_approval_id  UUID,                   -- FK -> approval_request(id) of type authorization_attestation

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
  FOREIGN KEY (engagement_id, tenant_id)  REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (scope_version_id, tenant_id) REFERENCES scope_version(id, tenant_id),
  FOREIGN KEY (superseded_by, tenant_id)  REFERENCES authorization(id, tenant_id),
  FOREIGN KEY (attestation_approval_id, tenant_id)
        REFERENCES approval_request(id, tenant_id) DEFERRABLE INITIALLY DEFERRED,
  CONSTRAINT auth_dates_valid CHECK (expires_at > effective_from),
  CONSTRAINT attest_true      CHECK (written_auth_attested = TRUE),
  CONSTRAINT active_needs_dual_approval CHECK (          -- cannot go active without a resolved attestation approval
     status <> 'active' OR attestation_approval_id IS NOT NULL)
);
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
- Exclusions cannot be `elevated` and never *grant*; they only subtract.

### 4.6 Scope-breadth limits & elevated approval (blocker 10)

Broad scope is the quiet path from an authorized assessment to an unauthorized one. Breadth is bounded technically and gated by elevated dual approval:

| Breadth dimension | Enforced limit | Consequence when exceeded |
|---|---|---|
| IPv4 CIDR prefix | `prefix_len` must be ≥ `engagement.min_ipv4_prefix` (default `/24`) | Broader than the engagement floor ⇒ entry must be `elevated` + dual-approved; below the **absolute floor** `/16` ⇒ **hard reject** regardless of approval. |
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
TABLE request_spec (               -- the IMMUTABLE, fully-hashed queued object
  id                 UUID PRIMARY KEY,
  tenant_id          UUID NOT NULL,
  engagement_id      UUID NOT NULL,
  run_id             UUID NOT NULL,
  job_id             UUID NOT NULL,
  scope_hash         CHAR(64) NOT NULL,       -- the frozen scope_version this spec was specced against
  authorization_id   UUID NOT NULL,
  request_class      TEXT NOT NULL CHECK (request_class IN ('native','tool_driven','browser')),
  kind               TEXT NOT NULL CHECK (kind IN ('http','websocket')),  -- WS handshake vs HTTP request
  check_id           TEXT,                    -- registered check id (native)
  tool_template_id   TEXT,                    -- pinned tool/template id (tool_driven), else NULL
  method             TEXT NOT NULL CHECK (method IN ('GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE')),
  canonical_url      TEXT NOT NULL,
  canonical_host     TEXT NOT NULL,
  port               INT  NOT NULL CHECK (port BETWEEN 1 AND 65535),
  scheme             TEXT NOT NULL CHECK (scheme IN ('https','http','wss','ws')),
  canonical_path     TEXT NOT NULL,
  query_canonical    TEXT,                    -- canonical, redaction-safe query (never secrets)
  header_set_id      TEXT NOT NULL,           -- id of a FIXED safe header template (no free-form headers)
  session_ref        TEXT,                    -- ref to an operator session lease; VALUE injected by broker,
                                              --   never stored here and EXCLUDED from spec_sha256
  payload_id         TEXT,                    -- id of an INERT payload from the curated catalog (no free-form body)
  mode               TEXT NOT NULL CHECK (mode IN ('passive','safe_active','approval_gated')),
  approval_ref       UUID,                    -- required for approval_gated / intrusive class
  spec_sha256        CHAR(64) NOT NULL,       -- canonical hash over ALL request-determining fields (below)
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  frozen             BOOLEAN NOT NULL DEFAULT TRUE,   -- specs are immutable from creation

  UNIQUE (id, tenant_id),
  UNIQUE (tenant_id, spec_sha256),
  FOREIGN KEY (engagement_id, tenant_id)    REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (authorization_id, tenant_id) REFERENCES authorization(id, tenant_id),
  FOREIGN KEY (approval_ref, tenant_id)     REFERENCES approval_request(id, tenant_id),
  CONSTRAINT ws_is_get      CHECK (kind <> 'websocket' OR (method = 'GET' AND scheme IN ('ws','wss'))),
  CONSTRAINT gated_needs_ref CHECK (mode <> 'approval_gated' OR approval_ref IS NOT NULL)
);
-- Immutability: UPDATE/DELETE are revoked at the grant level; a spec is created once, never mutated.
-- spec_sha256 = SHA-256 over canonical JSON of
--   (engagement_id, scope_hash, authorization_id, request_class, kind, check_id, tool_template_id,
--    method, canonical_url, canonical_host, port, scheme, canonical_path, query_canonical,
--    header_set_id, payload_id, mode, approval_ref).   session_ref is EXCLUDED (resolved at the broker).
```

- **Immutable & hashed.** A `request_spec` is created once — by the check engine for native checks, or by the broker for tool/browser requests (§7.2) — and never mutated; `spec_sha256` is the canonical hash over every request-determining field. **The queue stores only `(spec_id, tenant_id)`**, not a grant.
- **No free-form request.** `method`, the `canonical_*` fields, a fixed `header_set_id`, an inert `payload_id`, and a `session_ref` (resolved to a secret lease at the broker, never stored) fully determine the wire request. A worker cannot hand the broker an arbitrary serialized request.

### 7.1 The two-stage procedure

```
STAGE 1 — SCOPE AUTHORITY (control plane; no target I/O). Called JUST-IN-TIME at dispatch. Mints a grant or DENIES.
INPUT: spec_id (the immutable request_spec)

 A. LOAD spec; recompute spec_sha256; MUST equal the stored value            else DENY(spec_tampered)
 0. PRECONDITIONS (re-evaluated against CURRENT state, on the trusted clock):
    a. engagement.status ∈ {authorized, active}                              else DENY(engagement_not_active)
    b. engagement.emergency_stop = FALSE                                     else DENY(emergency_stop)
    c. authorization active, effective_from ≤ now < expires_at               else DENY(authorization_invalid/expired)
    d. engagement.active_scope_hash == spec.scope_hash == authorization.scope_hash  else DENY(scope_binding_broken)
    e. now inside a testing window AND not blackout                          else DENY(outside_testing_window)
    f. spec.mode ∈ authorization.allowed_modes ∩ engagement.allowed_modes    else DENY(mode_not_authorized)
    g. budget: (request_budget_used + reserved) < request_budget_total       else DENY(budget_exhausted)
    h. approval_gated/intrusive class: spec.approval_ref resolves to an APPROVED, unexpired approval whose
       plan_sha256 COVERS spec.spec_sha256                                   else DENY(approval_missing)
 1-5. PARSE/CANONICALIZE, SCHEME, IP-LITERAL NETWORK GUARD (§6), EXCLUSIONS, ALLOWLIST — over the spec's
      canonical fields, against the frozen scope_version identified by spec.scope_hash. Any fail ⇒ DENY.
 → ON PASS: RESERVE 1 budget unit atomically (engagement_runtime_counter.reserved += 1) and MINT a
   short-TTL (≤30s), single-use grant bound to {iss, aud=broker, run_id, job_id, jti, iat/nbf/exp,
   tenant_id, engagement_id, authorization_id, scope_hash, SPEC_SHA256, mode, request_class, approval_ref?}.
   NO resolved IP and NO request line are in the grant — the request line lives in the immutable spec.
   Emit audit scope.decision.allow. If window/expiry/budget/e-stop fails, NO grant is minted and the spec
   remains queued for a later dispatch (or is dropped on hard failure) — a stale grant can never sit in the queue.

STAGE 2 — GUARDED EGRESS BROKER (data-plane enforcer; the ONLY socket creator).
 6. INGRESS AUTH: authenticate the calling job's per-job identity/capability; NOT a generic CONNECT proxy.
 7. VERIFY GRANT: signature, iss, aud==self, nbf/exp, jti unused (consume single-use). AND
    grant.spec_sha256 == sha256(presented spec) — the spec is exactly the one authorized.  Mismatch ⇒ DENY.
 8. RECONSTRUCT + NORMALIZE the outbound request DETERMINISTICALLY from the immutable spec: method,
    URL (canonical_url + query_canonical), headers (from header_set_id template only), body (from the inert
    payload_id catalog only), operator session (injected from the secret lease named by session_ref). The
    broker NEVER sends a worker-serialized request; it re-canonicalizes and asserts the reconstructed
    request equals the spec's fields                                          else DENY(reconstruction_mismatch)
 9. RE-CHECK LIVE STATE (fail-closed, SI-046): auth not expired/revoked, window open, e-stop clear,
    rate/concurrency slot. Any unknown ⇒ DENY (and RELEASE the reservation).
10. DNS RESOLUTION + RESOLVED-IP RE-CHECK (rebinding): resolve canonical_host; EVERY resolved IP must pass
    the network guard (§6) AND the frozen scope_version; PIN a validated IP; connect ONLY to the pin.
11. AUDIT INTENT (SI-055): durably commit request.intent (records spec_sha256, grant jti, reserved unit)
    BEFORE the socket opens — this commit and the budget reservation are ONE transaction.
12. CONNECT to the pinned IP (TLS cert host == canonical_host); SEND the reconstructed request.
13. REDIRECT: never auto-follow. On 3xx, canonicalize Location → form a NEW request_spec → request a FRESH
    JIT grant. Out-of-scope ⇒ STOP, record. Bounded hop depth; each hop independently specced + granted.
14. COMPLETE: request.completed/failed records the resolved+pinned IP, status, byte counts (redacted).
    On send COMMIT the reserved unit (reserved -= 1; used += 1). On any pre-send DENY/failure RELEASE it
    (reserved -= 1; used unchanged). Sent count never exceeds request_budget_total.
```

### 7.2 Tool / browser (broker-mediated) and WebSocket semantics

- **Tool-driven / browser requests are not pre-enqueued per subrequest.** A headless browser or a self-driving tool is an autonomous request engine; the broker is its mediating proxy (`10` §4). For **each** intercepted request line the broker **forms a `request_spec` on the fly**, computes `spec_sha256`, and requests a **JIT grant** from the Scope Authority (Stage 1 over the frozen scope). Only if a grant is minted does it proceed to Stage 2. A browser that fetches an out-of-scope subresource, or follows a redirect off-scope, simply gets **no grant → the request is blocked**. The Scope Authority remains the sole minter and the broker the sole socket creator even for autonomous engines.
- **WebSocket (`ws`/`wss`).** A `kind='websocket'` spec authorizes the **HTTP Upgrade handshake** (a `GET` to the canonical WS path); the handshake is scoped, resolved, IP-pinned, and connected **exactly like an HTTP request**. Scope is fixed at the pinned handshake — an established socket can never change target. The established connection is bounded by per-connection caps (§8: `ws_max_duration_s`, `ws_max_messages`, `ws_max_message_bytes`) and counts against `max_ws_connections` (`ws_in_flight`); **e-stop, window close, or authorization expiry terminate active connections**. Redirects do not apply to an established WS; a handshake redirect is re-authorized like any HTTP redirect (new spec + JIT grant). Only inert/observation frames per the check contract are sent — never destructive fuzzing.

### 7.3 Key protections baked in
- **Immutable spec + JIT grant:** the queued object is hash-frozen; grants are minted just-in-time bound to `spec_sha256`, so no grant sits in the queue and a tampered spec is rejected at mint (SI-001, SI-060).
- **Broker reconstruction:** the wire request is rebuilt deterministically from the signed spec and must equal it; a worker cannot inject a deviation (SI-061).
- **DNS rebinding / redirects:** resolve → validate → pin at the broker; every redirect is a new spec + grant (SI-003, SI-004, SI-005).
- **Budget correctness:** reserve at mint, commit on send, release on denial — never double-spent, never spent on a request that is not sent (SI-017, SI-062).
- **Fail-closed & double-checkpoint:** any non-affirmative state at either stage denies; window/expiry/e-stop re-checked at JIT mint and Stage 2 (SI-002, SI-046, SI-049).

## 8. Rate-limit, testing-window & expiry enforcement (runtime fields)

```sql
TABLE engagement_runtime_counter (
  engagement_id        UUID PRIMARY KEY,
  tenant_id            UUID NOT NULL,
  window_started_at    TIMESTAMPTZ NOT NULL,
  requests_in_window   INT NOT NULL DEFAULT 0,
  in_flight            INT NOT NULL DEFAULT 0,     -- HTTP requests currently on the wire
  reserved             INT NOT NULL DEFAULT 0,     -- budget units reserved at JIT grant-mint, not yet sent
  ws_in_flight         INT NOT NULL DEFAULT 0,     -- established ws/wss connections (<= engagement.max_ws_connections)
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
| Request budget | `request_budget_total`, `request_budget_used`, `reserved` | **Reserve-at-mint / commit-on-send / release-on-denial:** a JIT grant-mint atomically reserves a unit (`reserved += 1`) only if `used + reserved < request_budget_total`; a sent request commits (`reserved -= 1; used += 1`); a pre-send denial/failure releases (`reserved -= 1`). Sent count never exceeds `request_budget_total`, and no unit is spent on a request that is never sent. Exhaustion auto-pauses. |
| Body cap | `max_response_body_bytes` | Response reading truncates; oversize bodies never fully buffered. |
| WebSocket | `max_ws_connections`, `ws_in_flight`, `ws_max_duration_s`, `ws_max_messages`, `ws_max_message_bytes` | Handshake scoped/pinned like HTTP (§7.2); established connection bounded by duration / message-count / message-size; `ws_in_flight <= max_ws_connections`; e-stop / window-close / expiry terminate active connections. |
| Testing window / expiry | `testing_window`, `authorization.expires_at` | Re-evaluated at Stage-1 (**JIT grant-mint**) **and** Stage-2, on the trusted clock (SI-049); a spec that waits in the queue past the window simply gets no grant. |
| Circuit breaker / emergency stop | `circuit_state`, `engagement.emergency_stop` | Breaker auto-pauses on error/latency thresholds; e-stop halts immediately, audited. |

**Auto-expiration invariant:** expiry/window are *pure functions of the trusted clock*, re-derived at Stage 2 on every request, never a cached status flag alone.

---

## 9. Immutable audit — split request events, multiple streams (blocker 7)

Append-only, hash-chained, tamper-evident. Redaction happens **before** any write (SI-045). Three **streams**, each an independent hash chain so events that have no engagement still get tamper-evident logging:

- **`engagement`** — scope decisions, request intent/completion, approvals, mode switches, e-stop, lifecycle. Keyed by `(engagement_id)`.
- **`tenant`** — tenant-level events with no single engagement: user/role changes, login/logout, tenant retention-policy changes. Keyed by `(tenant_id)`.
- **`global`** — platform-level events with no tenant: global emergency stop, tool-inventory/version-pin changes, feed ingestion, key rotation. Keyed by the platform singleton.

```sql
TABLE audit_event (
  id              UUID PRIMARY KEY,
  stream          TEXT NOT NULL CHECK (stream IN ('engagement','tenant','global')),
  tenant_id       UUID,                          -- NULL only when stream='global'
  engagement_id   UUID,                          -- NOT NULL iff stream='engagement'
  seq             BIGINT NOT NULL,               -- monotonic per chain; gap = tampering signal
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  actor_type      TEXT NOT NULL CHECK (actor_type IN ('user','system','worker','scheduler','broker')),
  actor_id        UUID,
  actor_role      TEXT,                          -- RBAC role snapshot at event time (doc 09)

  event_type      TEXT NOT NULL,                 -- see catalog below
  subject_type    TEXT,
  subject_id      UUID,

  -- Request events split into intent (pre-send) and completion (post-send)
  related_event_id UUID,                         -- completion → its intent event

  payload         JSONB NOT NULL,                -- REDACTED structured detail (no secrets/PII/tokens/bodies)
  payload_sha256  CHAR(64) NOT NULL,             -- hash of canonical(payload) AFTER redaction

  prev_hash       CHAR(64) NOT NULL,             -- previous event's event_hash in THIS chain
  event_hash      CHAR(64) NOT NULL,
  signature       TEXT,                          -- periodic-anchor signature (write-only signing svc, SI-051)

  CONSTRAINT stream_keys CHECK (
     (stream='engagement' AND engagement_id IS NOT NULL AND tenant_id IS NOT NULL)
     OR (stream='tenant'  AND engagement_id IS NULL     AND tenant_id IS NOT NULL)
     OR (stream='global'  AND engagement_id IS NULL     AND tenant_id IS NULL)),
  UNIQUE (id, tenant_id),                                    -- target of composite child FKs (e.g. approval linkage)
  UNIQUE (stream, tenant_id, engagement_id, seq),
  UNIQUE (stream, tenant_id, engagement_id, event_hash)
);
```

**Event-type catalog (illustrative).**
- *engagement stream:* `scope.decision.allow`, `scope.decision.deny`, `request.spec_created`, `request.intent`, `request.completed`, `request.failed`, `redirect.blocked`, `ws.opened`, `ws.closed`, `auth.attested`, `approval.requested`, `approval.decided`, `approval.threshold_met`, `scope.version.created`, `engagement.mode_changed`, `engagement.emergency_stop`, `engagement.expired`, `evidence.stored`, `dek.destroyed`.
- *tenant stream:* `auth.login`, `auth.login_failed`, `auth.logout`, `user.role_changed`, `tenant.retention_changed`.
- *global stream:* `platform.emergency_stop.global`, `tool.inventory.updated`, `tool.pinned`, `feed.ingested`, `key.rotated`.

**Integrity rules**
- **Genesis** per chain uses `prev_hash = 0*64`; each subsequent `prev_hash` = prior `event_hash` **within the same stream key**. Any altered/removed/reordered event breaks that chain from that point.
- **Request intent precedes egress (SI-055):** the `request.intent` event — recording the `spec_sha256`, the grant `jti`, and the reserved budget unit — is durably committed **before** the Broker opens the socket, in the **same transaction** as the budget reservation, so a crash can neither send without a record nor leak a reserved unit. The `request.completed`/`request.failed` event references it via `related_event_id` and commits or releases the reservation. A crash after intent but before completion leaves a durable, provable "attempted" record.
- **Redaction before hashing (SI-045):** secrets, cookies, `Authorization` headers, tokens, credentials-in-URL, PII, and raw bodies are stripped/omitted first; `payload_sha256` covers the redacted form. Raw target auth material and bodies are **never** written to any stream.
- **Append-only:** `UPDATE`/`DELETE` revoked at the grant level and rejected by triggers.
- **Anchoring & key custody (SI-051):** each chain head is periodically signed by a **write-only** signing service (whose key Administrators cannot read) and anchored to WORM/external notary; the residual rewrite window between anchors is documented in `11-data-retention-and-deletion.md`.

---

## 10. Approval — dual control with per-approver decisions (blocker 3)

Backs Mode 3 (approval-gated validation), authorization attestation, scope expansion, restricted-range (Tier B) allows, and mode elevation. The single-`decided_by` model is replaced by an **N-of-M** model: an `approval_request` plus one `approval_decision` row per approver, with a `required_approvals` threshold, verified approver roles (doc 09), per-decision plan/document-hash binding, and separation of duties.

```sql
TABLE approval_request (
  id                 UUID PRIMARY KEY,
  tenant_id          UUID NOT NULL,
  engagement_id      UUID NOT NULL,

  request_type       TEXT NOT NULL CHECK (request_type IN
                       ('authorization_attestation','scope_expansion','restricted_range_allow',
                        'mode_elevation','intrusive_validation','business_logic_test')),

  requested_by       UUID NOT NULL,
  requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  justification      TEXT NOT NULL CHECK (char_length(justification) BETWEEN 1 AND 4000),

  proposed_action    JSONB NOT NULL,   -- exact plan: method, url, headers(redacted), body-shape, etc.
  plan_sha256        CHAR(64) NOT NULL,-- canonical hash of the EXACT plan/document being approved
  document_sha256    CHAR(64),         -- for authorization_attestation: hash of the authorization artifact
  potential_impact   TEXT NOT NULL CHECK (char_length(potential_impact) <= 4000),
  target_summary     TEXT NOT NULL,
  scope_check_result JSONB NOT NULL,   -- snapshot of the §7 Stage-1 decision (must be PASS)
  required_account   TEXT,
  expected_response  TEXT,
  evidence_plan      TEXT NOT NULL,
  cleanup_action     TEXT,
  stop_conditions    TEXT NOT NULL,

  required_approvals INT NOT NULL CHECK (required_approvals BETWEEN 1 AND 5),  -- threshold; see policy below
  approver_roles     TEXT[] NOT NULL,  -- roles permitted to approve THIS request_type (from doc 09)

  status             TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','approved','rejected','expired','withdrawn')),
  resolved_at        TIMESTAMPTZ,
  expires_at         TIMESTAMPTZ NOT NULL,

  linked_scope_version_id UUID,
  linked_audit_event_id   UUID,

  UNIQUE (id, tenant_id),
  FOREIGN KEY (engagement_id, tenant_id) REFERENCES engagement(id, tenant_id),
  FOREIGN KEY (linked_scope_version_id, tenant_id) REFERENCES scope_version(id, tenant_id),
  FOREIGN KEY (linked_audit_event_id, tenant_id)   REFERENCES audit_event(id, tenant_id),
  -- Within-scope actions must already pass §7 Stage-1. Scope-CHANGING requests target something
  -- NOT yet in scope, so the pass requirement applies ONLY to within-scope request types.
  CONSTRAINT scope_must_pass CHECK (
     request_type IN ('scope_expansion','restricted_range_allow','authorization_attestation')
     OR (scope_check_result->>'decision') = 'pass'),
  CONSTRAINT threshold_by_type CHECK (        -- floors; may be raised per engagement, never lowered below floor
     (request_type IN ('authorization_attestation','scope_expansion','restricted_range_allow',
                       'mode_elevation','business_logic_test') AND required_approvals >= 2)
     OR (request_type = 'intrusive_validation' AND required_approvals >= 1))
);

TABLE approval_decision (
  id                   UUID PRIMARY KEY,
  tenant_id            UUID NOT NULL,
  approval_request_id  UUID NOT NULL,
  approver_user_id     UUID NOT NULL,
  approver_role        TEXT NOT NULL,          -- verified against RBAC (doc 09) at decision time
  decision             TEXT NOT NULL CHECK (decision IN ('approve','reject')),
  decided_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  decision_reason      TEXT CHECK (char_length(decision_reason) <= 2000),
  approved_plan_sha256 CHAR(64) NOT NULL,      -- the plan hash THIS approver saw; must equal request.plan_sha256
  approved_document_sha256 CHAR(64),           -- for attestation: the doc hash this approver pinned

  FOREIGN KEY (approval_request_id, tenant_id) REFERENCES approval_request(id, tenant_id),
  UNIQUE (approval_request_id, approver_user_id)          -- one decision per approver
);
```

**Decision rules (enforced in app + trigger, tested as SI-047 / SI-018 / SI-020):**

1. **Threshold.** `approval_request` becomes `approved` **iff** the count of *distinct* `approval_decision` rows with `decision='approve'`, `approver_role ∈ approver_roles`, and `approved_plan_sha256 = plan_sha256` (and `approved_document_sha256 = document_sha256` when present) is **≥ `required_approvals`**, **and** no `reject` decision exists. Any `reject` ⇒ `rejected`.
2. **Separation of duties.** No approver may equal `requested_by`; no approver may be the tester executing the action; approvers must be distinct users; each approver must hold a role in `approver_roles`; a user may not hold two SoD-conflicting roles on the same engagement (doc 09).
3. **Plan/document-hash binding.** Each approver pins the exact `plan_sha256` (and `document_sha256` for attestation). If the plan changes, prior decisions are void and the threshold must be re-met — an approval can never be moved onto a different plan.
4. **Scope precondition (conditional).** For *within-scope* request types (`intrusive_validation`, `business_logic_test`, `mode_elevation`) an approval cannot be created unless its target already passes §7 Stage-1 — the DDL `scope_must_pass` CHECK requires `scope_check_result.decision = 'pass'`. For *scope-changing* types (`scope_expansion`, `restricted_range_allow`, `authorization_attestation`) the target is by definition **not yet in scope**, so the CHECK deliberately does **not** require a pass; these approvals gate a *new* `scope_version` that becomes the in-scope set only once re-attested. (This resolves the earlier contradiction where the unconditional CHECK would have rejected every scope-expansion approval.)
5. **Plan binds the exact request(s).** For `intrusive_validation`/`business_logic_test`, `plan_sha256` MUST cover the `spec_sha256` of every `request_spec` the approval authorizes; §7 Stage-1 step (h) mints a grant only if the spec's `approval_ref` resolves to an approved request whose `plan_sha256` covers that exact spec. An approval can never authorize a request whose spec it did not pin.
6. **Time-boxed & audited.** Requests and each decision emit audit events (`approval.requested`, `approval.decided`, `approval.threshold_met`). Expired approvals authorize nothing.

**Default approval policy** (roles from `09-rbac-matrix.md`; per-engagement config may raise thresholds, never lower below the floor):

| `request_type` | `required_approvals` (floor) | `approver_roles` |
|---|---|---|
| `authorization_attestation` | 2 | Engagement Manager (≥1 required), then Reviewer / Administrator |
| `scope_expansion` | 2 | Engagement Manager, Reviewer |
| `restricted_range_allow` (Tier B) | 2 | Engagement Manager, Reviewer |
| `mode_elevation` | 2 | Engagement Manager, Reviewer |
| `business_logic_test` | 2 | Engagement Manager, Reviewer |
| `intrusive_validation` | 1 | Engagement Manager, Reviewer |

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
8. **Dual control on the legal gate.** Attestation and scope expansion require two distinct valid-role approvers, neither the tester, each pinning the plan/document hash; the threshold is enforced, not advisory (SI-047).
9. **Audit is complete, split, and tamper-evident.** Every action emits an event; request intent precedes egress; three streams chain independently; recomputation detects any edit/reorder; `seq` has no gaps (SI-026, SI-055, SI-056).
10. **Breadth is bounded.** Broad CIDRs, wildcards, and excessive host/address counts are hard-capped or gated by elevated dual approval; scope expansion re-attests (SI-059).
11. **Import is hash-verified & fail-closed.** A bundle whose recomputed `scope_hash` differs is rejected; Tier B/wildcard entries never self-activate.
12. **Composite-tenant integrity.** No child row can reference a parent in another tenant — every FK is composite `(id, tenant_id)` (the engagement↔authorization↔scope_version and authorization↔attestation-approval cycles use DEFERRABLE composite FKs) — and RLS scopes every query (SI-024).
13. **Budget is reserve/commit/release.** A unit is reserved at JIT grant-mint (only if `used + reserved < total`), committed on send, released on any pre-send denial; sent requests never exceed `request_budget_total` and no unit leaks (SI-017, SI-062).
14. **Window/expiry/e-stop are JIT + Stage-2.** Re-evaluated at grant-mint and again at the broker; a spec that waited past the window gets no grant, and a fired e-stop/expiry aborts in-flight work including WebSockets (SI-011, SI-012, SI-013, SI-049).
15. **Approval binds the exact spec.** Intrusive approvals pin `plan_sha256` covering each authorized `spec_sha256`; scope-changing approvals correctly do NOT require the not-yet-in-scope target to pass §7 (SI-018, SI-047).
16. **Breadth accounting is computable.** An IPv4-equivalent address budget + a CIDR-entry cap are enforced; IPv6 breadth is governed by prefix floors + elevated approval (never an address sum); exclusions are not subtracted (SI-059).
17. **WebSocket is bounded.** ws/wss handshakes are scoped/pinned like HTTP and established connections are bounded by duration/message/size/count caps and terminated on e-stop/window/expiry (SI-063).

---

**File paths:** none produced — Phase 0 design deliverable. The schema seeds the Phase 2 migration set (`engagement`, `testing_window`, `authorization`, `scope_version`, `scope_entry`, `request_spec`, `engagement_runtime_counter`, `audit_event`, `approval_request`, `approval_decision`) and the Scope Authority / Guarded Egress Broker two-stage decision procedure (§7), network guard (§6), canonicalization (§5), breadth limits (§4.6), and dual-control approval (§10). Related: `09-rbac-matrix.md`, `10-request-authorization-flow.md`, `11-data-retention-and-deletion.md`.
