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
  max_scope_hosts         INT NOT NULL DEFAULT 1024 CHECK (max_scope_hosts BETWEEN 1 AND 65536),
  max_scope_addresses     BIGINT NOT NULL DEFAULT 65536 CHECK (max_scope_addresses >= 1),
  min_ipv4_prefix         INT NOT NULL DEFAULT 24 CHECK (min_ipv4_prefix BETWEEN 8 AND 32),
  min_ipv6_prefix         INT NOT NULL DEFAULT 48 CHECK (min_ipv6_prefix BETWEEN 32 AND 128),

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
  entry_count    INT NOT NULL,
  host_count     INT NOT NULL,            -- distinct hosts (breadth accounting, §4.6)
  address_count  BIGINT NOT NULL,         -- sum of allow ip/cidr sizes minus exclusions (breadth accounting)
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

  Null out fields not applicable to the class, serialize each tuple as canonical JSON, sort the tuples lexicographically, concatenate, and `SHA-256`. The hash is therefore independent of insertion order and cosmetic input but sensitive to any host/range/port/scheme/path/operation/exclusion/elevation change. `entry_count`, `host_count`, and `address_count` are derived at freeze time and are part of the breadth checks (§4.6) — they are also included as a trailer in the hashed document so breadth cannot drift under a fixed hash.

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
| Total addresses | `scope_version.address_count` ≤ `engagement.max_scope_addresses` (default 65536) | Above ceiling ⇒ elevated dual approval. |
| **Scope expansion** | Any new host/domain/IP/range vs the currently-authorized `scope_version` | Requires an `approval_request` of type `scope_expansion` at threshold **and** re-attestation (new authorization). |

`entry_count`, `host_count`, and `address_count` are computed at freeze and bound into the hashed document (§4.1). The Scope Authority refuses to mint grants for a `scope_version` whose breadth exceeds ceilings without the corresponding approved elevation.

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

## 7. Request authorization — the two-stage decision procedure

Every outbound request passes a **two-stage** flow (blocker 2). The full token/ingress design is in `10-request-authorization-flow.md`; this section defines the ordered checks and which component owns each.

**Why two stages:** the resolved IP is unknown until DNS is resolved, and DNS resolution of targets is done only by the Guarded Egress Broker at connect time. Therefore the Stage-1 grant (minted by the Scope Authority at scheduling) **cannot and does not bind a resolved IP** — it binds the exact request *line*. The resolved IP is validated and pinned at Stage 2, at the broker, and recorded in the completion audit event.

```
STAGE 1 — SCOPE AUTHORITY (control plane; no target I/O). Mints a signed egress grant or DENIES.
INPUT: engagement_id, method, candidate_url, mode, request_class, actor, approval_ref?

 0. PRECONDITIONS (engagement-level gate)
    a. engagement.status ∈ {authorized, active}          else DENY(engagement_not_active)
    b. engagement.emergency_stop = FALSE                  else DENY(emergency_stop)
    c. authorization active, effective_from ≤ now < expires_at   else DENY(authorization_invalid/expired)
    d. engagement.active_scope_hash == authorization.scope_hash  else DENY(scope_binding_broken)
    e. now inside a testing window AND not blackout       else DENY(outside_testing_window)
    f. mode ∈ authorization.allowed_modes ∩ engagement.allowed_modes  else DENY(mode_not_authorized)
    g. request_budget_used < request_budget_total         else DENY(budget_exhausted)
    h. for intrusive/elevated class: approval_ref resolves to an APPROVED, unexpired approval
       whose plan hash matches this request                else DENY(approval_missing)
 1. PARSE + CANONICALIZE (§5). Malformed/bad-encoding/disallowed-scheme/zone-id ⇒ DENY.
 2. SCHEME CHECK against allowed protocol entries.        else DENY(scheme_not_in_scope)
 3. IF host is an IP literal → NETWORK GUARD (§6): Tier A ⇒ DENY(hard_denied);
    Tier B without full elevation ⇒ DENY(restricted_range).
 4. EXCLUSION CHECK (host/port/path/bound-host) — ANY match ⇒ DENY(excluded).
 5. ALLOWLIST CHECK: host ∈ domain/ip/cidr allow AND port allowed AND
    (path within an allowed path_prefix bound to this host OR no path_prefix constrains this host)
    AND (if api_resource entries bind this host, operation allowed).  No match ⇒ DENY(not_in_scope).
 → ON PASS: MINT a Stage-1 egress grant (see doc 10): signed, short-TTL, single-use (jti), bound to
   {iss, aud=broker, run_id, job_id, jti, iat/nbf/exp, tenant_id, engagement_id, scope_hash,
    authorization_id, method, canonical_url, canonical_host, port, scheme, canonical_path,
    mode, request_class, approval_ref?}.  NO resolved IP is bound here.
   Emit audit `scope.decision.allow` (engagement stream).

STAGE 2 — GUARDED EGRESS BROKER (data-plane enforcer; the ONLY socket creator).
 6. INGRESS AUTH: authenticate the calling job's per-job identity/capability (doc 10, §ingress);
    reject unauthenticated callers. This is NOT a generic CONNECT proxy.
 7. VERIFY GRANT: signature, iss, aud==this broker, nbf/exp valid, jti unused (consume single-use);
    replayed/forged/expired ⇒ DENY(grant_invalid).
 8. RE-CHECK LIVE STATE (fail-closed per SI-046): authorization not expired/revoked, window open,
    emergency_stop clear, budget remaining, rate/concurrency token available.  Any unknown ⇒ DENY.
 9. DNS RESOLUTION + RESOLVED-IP RE-CHECK (rebinding protection):
    a. Resolve canonical_host → all A/AAAA records.
    b. For EACH resolved IP: NETWORK GUARD (§6) [Tier A ⇒ DENY; Tier B w/o full elevation ⇒ DENY],
       AND the resolved IP must satisfy the frozen scope_version (in an allowed ip/cidr, or the host
       is an allowlisted domain permitted to resolve to public space).  ANY failure ⇒ DENY.
    c. PIN the validated IP set; connect ONLY to a pinned, validated IP (no re-resolution).
10. CONNECT to pinned IP; on TLS verify the certificate hostname matches canonical_host.
11. REDIRECT HANDLING: do NOT auto-follow. On 3xx, canonicalize Location and request a FRESH
    Stage-1 grant from the Scope Authority for the new request line; only proceed if minted.
    Out-of-scope ⇒ STOP, record. Bounded max-redirect depth; each hop independently authorized.
12. AUDIT: a durable `request.intent` event is committed BEFORE the socket opens (SI-055);
    a `request.completed`/`request.failed` event afterward records the resolved+pinned IP, status,
    and byte counts (redacted). Budget decremented atomically on send.
```

**Key protections baked in**
- **DNS rebinding:** resolve → validate every IP → pin → connect to the pin, all at the broker; no client-side resolution anywhere.
- **Redirect scope escape:** every hop needs a fresh Stage-1 grant; no "trusted because we started in scope."
- **Deny-by-default & fail-closed:** any non-affirmative state at either stage denies (SI-002, SI-046).
- **Double-checkpoint in time:** Stage 1 at schedule, Stage 2 at execute; expiry/e-stop/window firing between them is caught at Stage 2.
- **Replay-safe grants:** short TTL + single-use `jti` + `aud` binding + per-job ingress identity (doc 10).

---

## 8. Rate-limit, testing-window & expiry enforcement (runtime fields)

```sql
TABLE engagement_runtime_counter (
  engagement_id        UUID PRIMARY KEY,
  tenant_id            UUID NOT NULL,
  window_started_at    TIMESTAMPTZ NOT NULL,
  requests_in_window   INT NOT NULL DEFAULT 0,
  in_flight            INT NOT NULL DEFAULT 0,
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
| Request budget | `request_budget_total/used` | Hard cap; exhaustion auto-pauses and notifies. |
| Body cap | `max_response_body_bytes` | Response reading truncates; oversize bodies never fully buffered. |
| Testing window / expiry | `testing_window`, `authorization.expires_at` | Evaluated at Stage-1 step 0 **and** Stage-2 step 8, on the trusted clock (SI-049). |
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
  UNIQUE (stream, tenant_id, engagement_id, seq),
  UNIQUE (stream, tenant_id, engagement_id, event_hash)
);
```

**Event-type catalog (illustrative).**
- *engagement stream:* `scope.decision.allow`, `scope.decision.deny`, `request.intent`, `request.completed`, `request.failed`, `redirect.blocked`, `auth.attested`, `approval.requested`, `approval.decided`, `approval.threshold_met`, `scope.version.created`, `engagement.mode_changed`, `engagement.emergency_stop`, `engagement.expired`, `evidence.stored`, `dek.destroyed`.
- *tenant stream:* `auth.login`, `auth.login_failed`, `auth.logout`, `user.role_changed`, `tenant.retention_changed`.
- *global stream:* `platform.emergency_stop.global`, `tool.inventory.updated`, `tool.pinned`, `feed.ingested`, `key.rotated`.

**Integrity rules**
- **Genesis** per chain uses `prev_hash = 0*64`; each subsequent `prev_hash` = prior `event_hash` **within the same stream key**. Any altered/removed/reordered event breaks that chain from that point.
- **Request intent precedes egress (SI-055):** the `request.intent` event is durably committed **before** the Broker opens the socket; the `request.completed`/`request.failed` event references it via `related_event_id`. A crash after intent but before completion leaves a durable, provable "attempted" record.
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
  CONSTRAINT scope_must_pass CHECK ((scope_check_result->>'decision') = 'pass'),
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
4. **Scope precondition.** An approval cannot be *created* unless its target already passes §7 Stage-1 (`scope_must_pass`). Approval is never a path to out-of-scope targets — only to higher-impact actions *within* scope. (Exception: `scope_expansion`/`restricted_range_allow` approvals gate a *new* `scope_version` that itself becomes the in-scope set once re-attested.)
5. **Time-boxed & audited.** Requests and each decision emit audit events (`approval.requested`, `approval.decided`, `approval.threshold_met`). Expired approvals authorize nothing.

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
6. **Two-stage token is sound.** Stage-1 grants bind the request line but never a resolved IP; Stage-2 resolves, validates every IP, and pins; a grant is single-use (`jti`) and `aud`-bound (SI-001, SI-053).
7. **Rebinding & redirects defeated.** Resolved IPs individually validated and pinned; every redirect hop needs a fresh grant (SI-003, SI-004, SI-005).
8. **Dual control on the legal gate.** Attestation and scope expansion require two distinct valid-role approvers, neither the tester, each pinning the plan/document hash; the threshold is enforced, not advisory (SI-047).
9. **Audit is complete, split, and tamper-evident.** Every action emits an event; request intent precedes egress; three streams chain independently; recomputation detects any edit/reorder; `seq` has no gaps (SI-026, SI-055, SI-056).
10. **Breadth is bounded.** Broad CIDRs, wildcards, and excessive host/address counts are hard-capped or gated by elevated dual approval; scope expansion re-attests (SI-059).
11. **Import is hash-verified & fail-closed.** A bundle whose recomputed `scope_hash` differs is rejected; Tier B/wildcard entries never self-activate.
12. **Composite-tenant integrity.** No child row can reference a parent in another tenant (composite FK) and RLS scopes every query (SI-024).

---

**File paths:** none produced — Phase 0 design deliverable. The schema seeds the Phase 2 migration set (`engagement`, `testing_window`, `authorization`, `scope_version`, `scope_entry`, `engagement_runtime_counter`, `audit_event`, `approval_request`, `approval_decision`) and the Scope Authority / Guarded Egress Broker two-stage decision procedure (§7), network guard (§6), canonicalization (§5), breadth limits (§4.6), and dual-control approval (§10). Related: `09-rbac-matrix.md`, `10-request-authorization-flow.md`, `11-data-retention-and-deletion.md`.
