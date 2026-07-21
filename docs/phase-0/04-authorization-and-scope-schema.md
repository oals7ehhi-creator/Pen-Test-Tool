> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

# Authorization & Scope Schema — Phase 0 Design

**Component:** Engagement / Authorization / Scope Engine (backbone for Phase 2)
**Status:** Design/analysis only — no implementation. Pseudo-DDL and JSON/YAML snippets are illustrative.
**Design posture:** deny-by-default, authorization-first, exclusions-always-win, tamper-evident.

---

## 0. Design principles that constrain every table below

1. **No scope, no request.** Every outbound request is gated by a *live* scope-validation decision. Absence of a matching allowlist entry is a DENY, not a soft warning.
2. **Authorization binds to an exact scope snapshot.** An `authorization` record is cryptographically bound to an immutable `scope_version` via a `scope_hash`. Editing scope *invalidates* authorization and forces re-attestation. Scope cannot silently drift out from under a signed authorization.
3. **Exclusions are absolute and evaluated first.** Any candidate matching an exclusion is denied even if it also matches an allow entry, and even if it is the apex of an allowed wildcard.
4. **The network guard is not overridable by ordinary allowlisting.** Cloud-metadata, loopback, multicast, unspecified, and broadcast addresses are hard-denied. Private/link-local ranges are denied *unless* an explicit, separately-flagged, elevated-approval scope entry names them.
5. **Immutability > editability.** Scope versions, authorization records, audit events, and approval records are append-only. "Changes" are new versions/events, never in-place mutation.
6. **Canonicalize before you compare.** All matching is performed on a single canonical form for host, IP, port, scheme, and path. Raw operator input is preserved separately for audit but is never the thing matched against.

---

## 1. Common conventions

| Convention | Rule |
|---|---|
| Primary keys | `UUID` (prefer UUIDv7 for time-ordered inserts). Never expose sequential integer PKs across tenants. |
| Tenancy | Every row carries `tenant_id UUID NOT NULL`. All queries and all scope checks are tenant-scoped; cross-tenant reference is a hard constraint violation. |
| Timestamps | `TIMESTAMPTZ`, stored UTC. Human-facing windows are interpreted in the engagement `timezone`. |
| Enums | Modeled as constrained text (`CHECK (col IN (...))`) or native enum types; values are stable, lowercase, snake_case. |
| Soft delete | **Not used** for authorization/scope/audit. These are immutable; lifecycle is expressed by status + new versions. |
| Hashing | SHA-256, lowercase hex, over a **canonical JSON** serialization (sorted keys, no insignificant whitespace, UTF-8, explicit null handling). |
| Text limits | All free-text fields have explicit max lengths (noted per field) to bound storage and log volume. |

---

## 2. Engagement entity

The engagement is the top-level container and the runtime "kill switch" surface. It holds operating posture (mode, rate/concurrency, windows, timezone) but **not** the legal authority to test — that lives in `authorization`.

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

  timezone              TEXT NOT NULL,                  -- IANA tz, e.g. 'Europe/London'; validated against tz DB
  default_mode          TEXT NOT NULL DEFAULT 'passive'
                        CHECK (default_mode IN ('passive','safe_active','approval_gated')),
  allowed_modes         TEXT[] NOT NULL DEFAULT ARRAY['passive'],
                        -- subset of {passive,safe_active,approval_gated}; must be a subset of the
                        -- allowed_modes granted by the ACTIVE authorization (enforced in app + trigger)

  -- Active scope/authorization pointers (denormalized for fast gate checks)
  active_authorization_id UUID,                         -- FK -> authorization.id (nullable until authorized)
  active_scope_version_id UUID,                         -- FK -> scope_version.id
  active_scope_hash       CHAR(64),                     -- must equal authorization.scope_hash when authorized

  -- Rate / concurrency posture (see §10)
  max_concurrency         INT  NOT NULL DEFAULT 2  CHECK (max_concurrency BETWEEN 1 AND 32),
  per_host_concurrency    INT  NOT NULL DEFAULT 1  CHECK (per_host_concurrency BETWEEN 1 AND 8),
  global_max_rps          NUMERIC(6,2) NOT NULL DEFAULT 2.0  CHECK (global_max_rps > 0 AND global_max_rps <= 50),
  per_host_max_rps        NUMERIC(6,2) NOT NULL DEFAULT 1.0  CHECK (per_host_max_rps > 0),
  min_request_interval_ms INT NOT NULL DEFAULT 250 CHECK (min_request_interval_ms >= 0),
  request_budget_total    INT NOT NULL DEFAULT 5000 CHECK (request_budget_total >= 0),
  request_budget_used     INT NOT NULL DEFAULT 0    CHECK (request_budget_used >= 0),
  max_response_body_bytes INT NOT NULL DEFAULT 2097152 CHECK (max_response_body_bytes > 0), -- 2 MiB

  -- Emergency controls
  emergency_stop          BOOLEAN NOT NULL DEFAULT FALSE,
  emergency_stop_reason   TEXT CHECK (char_length(emergency_stop_reason) <= 1000),
  emergency_stopped_at    TIMESTAMPTZ,
  emergency_stopped_by    UUID,

  CONSTRAINT rps_host_le_global CHECK (per_host_max_rps <= global_max_rps),
  CONSTRAINT conc_host_le_global CHECK (per_host_concurrency <= max_concurrency),
  CONSTRAINT budget_used_le_total CHECK (request_budget_used <= request_budget_total),
  CONSTRAINT per_host_rps_le_global CHECK (per_host_max_rps <= global_max_rps)
);
```

**Validation rules & notes**

- `allowed_modes` on the engagement must always be a **subset** of the active authorization's `allowed_modes`. A DB trigger + application check enforce this; when authorization is downgraded/revoked, engagement modes are intersected down automatically.
- `active_scope_hash` **must equal** `authorization.scope_hash` whenever `status ∈ {authorized, active, paused}`. This is the runtime tripwire that catches scope drift. If they diverge, the engagement is forced to `pending_authorization` and all requests are denied.
- `timezone` is validated against the IANA tz database at write time; invalid tz strings are rejected.
- Concurrency and RPS ceilings are capped in schema (`<= 32`, `<= 50 rps`) so no operator input can request abusive volume even by typo. These caps are conservative and defensive.

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

- Transitions are recorded as audit events (§11). Illegal transitions are rejected.
- `expired`, `suspended`, `emergency_stopped` are **terminal for testing**: no request may be scheduled or executed. Recovery requires an explicit human transition and (for expiry) a fresh authorization.

### 2.3 Testing windows

Modeled as child rows so a window is a first-class, auditable object with recurrence + blackout support.

```sql
TABLE testing_window (
  id             UUID PRIMARY KEY,
  engagement_id  UUID NOT NULL REFERENCES engagement(id),
  tenant_id      UUID NOT NULL,
  kind           TEXT NOT NULL CHECK (kind IN ('recurring_weekly','one_off','blackout')),
  -- recurring_weekly:
  days_of_week   INT[]  CHECK (days_of_week <@ ARRAY[0,1,2,3,4,5,6]),  -- 0=Mon
  start_local    TIME,                          -- interpreted in engagement.timezone
  end_local      TIME,
  -- one_off / blackout:
  start_at       TIMESTAMPTZ,
  end_at         TIMESTAMPTZ,
  note           TEXT CHECK (char_length(note) <= 500),
  CONSTRAINT window_shape CHECK (
     (kind='recurring_weekly' AND days_of_week IS NOT NULL AND start_local IS NOT NULL AND end_local IS NOT NULL)
     OR (kind IN ('one_off','blackout') AND start_at IS NOT NULL AND end_at IS NOT NULL)
  )
);
```

**Effective-window rule (runtime):** a request is allowed *only if*, evaluated at request time:
`now ∈ (authorization.effective_from, authorization.expires_at)` **AND** `now` falls inside at least one `recurring_weekly`/`one_off` window **AND** `now` falls inside **no** `blackout` window. Blackout always wins over allow, mirroring exclusion precedence. Windows crossing midnight and DST transitions are resolved in the engagement timezone before conversion to UTC.

---

## 3. Authorization record

The legal-authority object. It is the bridge between "we are allowed" (attestation + authorizing party + document reference) and "here is exactly what we are allowed to touch" (the bound `scope_hash`).

### 3.1 Pseudo-DDL

```sql
TABLE authorization (
  id                       UUID PRIMARY KEY,
  tenant_id                UUID NOT NULL,
  engagement_id            UUID NOT NULL REFERENCES engagement(id),

  authorization_reference  TEXT NOT NULL CHECK (char_length(authorization_reference) BETWEEN 1 AND 200),
                           -- external contract / SOW / ticket id (e.g. 'SOW-2026-0417')

  -- Authorizing party (the client-side entity that granted permission)
  authorizing_party_name   TEXT NOT NULL CHECK (char_length(authorizing_party_name) <= 200),
  authorizing_party_org    TEXT NOT NULL CHECK (char_length(authorizing_party_org)  <= 200),
  authorizing_party_role   TEXT           CHECK (char_length(authorizing_party_role) <= 120),
  authorizing_party_email  TEXT           CHECK (authorizing_party_email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),

  engagement_owner_user_id UUID NOT NULL,  -- accountable owner on the testing side (snapshot at sign-off)

  -- Written-authorization attestation (operator confirms a signed document exists)
  written_auth_attested    BOOLEAN NOT NULL,
  attested_by_user_id      UUID NOT NULL,
  attested_at              TIMESTAMPTZ NOT NULL,
  attestation_statement    TEXT NOT NULL CHECK (char_length(attestation_statement) <= 2000),
  document_ref             TEXT,           -- pointer/URI to stored authorization doc (not the doc itself)
  document_sha256          CHAR(64),       -- hash of the uploaded authorization artifact, if stored

  -- Validity window
  effective_from           TIMESTAMPTZ NOT NULL,
  expires_at               TIMESTAMPTZ NOT NULL,

  -- Granted posture
  allowed_modes            TEXT[] NOT NULL
                           CHECK (allowed_modes <@ ARRAY['passive','safe_active','approval_gated']
                                  AND array_length(allowed_modes,1) >= 1),

  -- Binding to an exact scope snapshot
  scope_version_id         UUID NOT NULL REFERENCES scope_version(id),
  scope_hash               CHAR(64) NOT NULL,   -- MUST equal scope_version.scope_hash at sign-off

  -- Integrity of this record
  record_hash              CHAR(64) NOT NULL,   -- hash over canonical form of all fields above
  signature                TEXT,                -- optional detached signature (org key) over record_hash

  -- Lifecycle
  status                   TEXT NOT NULL DEFAULT 'active'
                           CHECK (status IN ('draft','active','revoked','expired','superseded')),
  revoked_at               TIMESTAMPTZ,
  revoked_by               UUID,
  revocation_reason        TEXT CHECK (char_length(revocation_reason) <= 1000),
  superseded_by            UUID REFERENCES authorization(id),

  created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT auth_dates_valid CHECK (expires_at > effective_from),
  CONSTRAINT attest_true      CHECK (written_auth_attested = TRUE),  -- cannot activate without attestation
  CONSTRAINT scope_binding    CHECK (scope_hash = <computed from scope_version>) -- enforced by trigger
);
```

**Validation rules & notes**

- **Attestation is mandatory to activate.** A record cannot reach `status='active'` unless `written_auth_attested = TRUE`, with `attested_by_user_id`, `attested_at`, and a non-empty `attestation_statement` (e.g. *"I confirm a signed authorization from AuthorizingOrg dated 2026-07-10 is on file under SOW-2026-0417"*).
- **Scope binding is enforced.** At sign-off, `scope_hash` is copied from the referenced `scope_version.scope_hash`. A trigger recomputes the hash from the scope entries and rejects the record if it does not match — you cannot bind authorization to a hash that does not correspond to real, stored scope rows.
- **Immutability.** Authorization rows are never edited after activation. A scope change ⇒ new `scope_version` ⇒ the old authorization is marked `superseded` and a *new* authorization must be attested and bound. This produces a clean legal trail of "who authorized exactly what, when."
- **Auto-expiry** (§10): a background evaluator flips `active → expired` at `expires_at`; the engagement gate independently re-checks validity on every request, so even a lagging job cannot permit an expired test.
- **Revocation is immediate.** `revoked` halts all testing regardless of window or budget.
- `document_sha256` lets the platform detect if the stored authorization artifact changes after sign-off (tamper detection on the evidence of authority itself).

---

## 4. Scope model

Scope is stored as an **immutable version** (`scope_version`) containing a set of typed **entries** (`scope_entry`), each either an `allow` or `exclude` rule. The `scope_hash` over the canonicalized entry set is what authorization binds to.

### 4.1 Scope version (immutable snapshot)

```sql
TABLE scope_version (
  id             UUID PRIMARY KEY,
  tenant_id      UUID NOT NULL,
  engagement_id  UUID NOT NULL REFERENCES engagement(id),
  version_number INT  NOT NULL,           -- monotonically increasing per engagement
  scope_hash     CHAR(64) NOT NULL,       -- SHA-256 over canonical(sorted(entries))
  created_by     UUID NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  note           TEXT CHECK (char_length(note) <= 1000),
  frozen         BOOLEAN NOT NULL DEFAULT FALSE,  -- becomes TRUE when bound by an authorization
  UNIQUE (engagement_id, version_number)
);
```

- Once `frozen = TRUE` (i.e. an authorization is bound to it), **no entries may be added, edited, or removed.** Any change requires cloning into a new `scope_version`.
- `scope_hash` is computed as: canonical JSON array of entries, each entry reduced to its `(entry_class, kind, canonical_value, is_exclusion, elevated)` tuple, sorted lexicographically, then SHA-256. This makes the hash independent of insertion order or cosmetic input differences.

### 4.2 Scope entry (supertype + typed value)

```sql
TABLE scope_entry (
  id              UUID PRIMARY KEY,
  tenant_id       UUID NOT NULL,
  scope_version_id UUID NOT NULL REFERENCES scope_version(id),

  entry_class     TEXT NOT NULL CHECK (entry_class IN
                    ('domain','ip','cidr','port','protocol','path_prefix','api_resource')),
  is_exclusion    BOOLEAN NOT NULL DEFAULT FALSE,   -- TRUE = exclusion; exclusions always win
  elevated        BOOLEAN NOT NULL DEFAULT FALSE,   -- TRUE = deliberately allows an otherwise-restricted
                                                    -- range (private/link-local). Requires elevated approval.

  raw_value       TEXT NOT NULL,                    -- exactly what the operator typed (audit)
  canonical_value TEXT NOT NULL,                    -- normalized form used for matching (see §5)

  -- Type-specific normalized fields (only the relevant ones are populated per entry_class)
  host_ascii      TEXT,        -- domain: punycode/ToASCII, lowercase, no trailing dot
  wildcard        BOOLEAN,     -- domain: TRUE if leftmost-label wildcard '*.'
  include_subdomains BOOLEAN,  -- domain: TRUE => match host and any subdomain

  ip_version      INT CHECK (ip_version IN (4,6)),  -- ip/cidr
  ip_start        INET,        -- ip: the address; cidr: network address
  ip_end          INET,        -- cidr: broadcast/last address (range materialized for fast containment)
  prefix_len      INT,         -- cidr

  port_low        INT CHECK (port_low  BETWEEN 1 AND 65535),  -- port
  port_high       INT CHECK (port_high BETWEEN 1 AND 65535),

  scheme          TEXT CHECK (scheme IN ('https','http','wss','ws')), -- protocol / path_prefix / api

  path_prefix     TEXT,        -- path_prefix: canonical path, must start with '/'
  api_doc_ref     TEXT,        -- api_resource: pointer to imported OpenAPI/Swagger doc
  api_doc_sha256  CHAR(64),    -- api_resource: hash of the imported spec
  api_operations  TEXT[],      -- api_resource: allowed operationIds / method+path pairs

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT port_range_ok   CHECK (port_low IS NULL OR port_high IS NULL OR port_low <= port_high),
  CONSTRAINT wildcard_domain CHECK (entry_class <> 'domain' OR host_ascii IS NOT NULL),
  CONSTRAINT elevated_only_for_net CHECK (elevated = FALSE OR entry_class IN ('ip','cidr'))
);
```

### 4.3 Per-type semantics

| `entry_class` | What it constrains | Match semantics |
|---|---|---|
| `domain` | A hostname family | Exact host match on `host_ascii`; if `wildcard`, `*.example.com` matches any single-or-multi-label subdomain (`a.example.com`, `a.b.example.com`) but **not** the apex `example.com` unless `include_subdomains=TRUE` or the apex is listed separately. |
| `ip` | A single literal address | Exact canonical IP equality (IPv4 or IPv6). |
| `cidr` | An address range | Containment: candidate IP ∈ `[ip_start, ip_end]`. Materializing start/end enables index-friendly range checks for both v4 and v6. |
| `port` | Allowed port(s) | Candidate port ∈ `[port_low, port_high]` (single port ⇒ low=high). |
| `protocol` | Allowed URL schemes | Candidate scheme ∈ allowed set. Default allowed = `{https}`; `http`/`ws` require explicit entry. |
| `path_prefix` | A URL sub-tree on a host | Canonical candidate path starts with `path_prefix` at a segment boundary (`/api` matches `/api/x` but not `/apixyz`). Scoped to the host/scheme of the same or a companion domain entry. |
| `api_resource` | Operations from an imported spec | Candidate `(method, path)` maps to an allowed operation in `api_operations`. Binds to the exact spec via `api_doc_sha256` so a changed spec does not silently widen scope. |

### 4.4 Wildcard rules (precise)

- Only a **leftmost-label** wildcard is permitted: `*.example.com`. Reject `foo.*.com`, `*.*.example.com`, `ex*ple.com`, bare `*`.
- Wildcard label matches **one or more** labels by default (subtree), *unless* the platform is configured single-label — recommended default is subtree match with `include_subdomains` semantics, which is the least surprising and easiest to reason about for scope, but this is documented explicitly to the operator at sign-off.
- A wildcard never matches the registrable apex unless the apex is separately allowlisted or `include_subdomains=TRUE`.
- Public-suffix guard: reject wildcard entries at or above a public suffix (`*.co.uk`, `*.com`) — these would authorize the entire internet. Validated against a bundled Public Suffix List.

### 4.5 Exclusions (always win)

- An `is_exclusion=TRUE` entry of any class removes matching candidates from scope **regardless of any allow match**, including exclusion of a host inside an allowed CIDR, a path under an allowed prefix, or the apex of an allowed wildcard.
- Precedence order at evaluation (see §9): **exclusions first**. If any exclusion matches ⇒ DENY, full stop.
- Exclusions cannot be `elevated` and never *grant* anything; they only subtract.

---

## 5. Canonicalization rules

All matching operates on canonical forms. Raw operator input and raw candidate input are preserved for audit but never compared directly.

### 5.1 Host / domain

1. Trim whitespace; reject embedded control chars, spaces, or NUL.
2. Strip a single trailing dot (`example.com.` → `example.com`).
3. Lowercase (ASCII). Reject uppercase after IDN conversion mismatch.
4. **IDN → punycode (ToASCII, IDNA2008/UTS-46).** Store `host_ascii`. Reject labels that fail IDNA validation, mixed-script confusables where the platform policy forbids them, or labels > 63 octets / names > 253 octets.
5. Reject hostnames that are actually IP literals here — those must be entered as `ip`/`cidr` (prevents `http://0x7f000001/` style bypasses; numeric/hex/octal IP-in-hostname forms are normalized to IPs before scope evaluation, see §5.2).
6. Trailing-dot, case, and punycode are normalized *identically* for both scope entries and candidate hosts, so comparison is byte-exact on `host_ascii`.

### 5.2 IP address (IPv4 + IPv6)

1. Parse the candidate host as an IP if it *is* one, including obfuscated IPv4 (decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f.0.0.1`, mixed, and short forms) — **all normalized to canonical dotted-quad** before comparison. Ambiguous/obfuscated forms are normalized then re-checked against the network guard (they frequently target loopback/metadata).
2. IPv6: expand, then compress to canonical form (RFC 5952) — lowercase hex, `::` at the longest zero run, no leading zeros.
3. **IPv4-mapped/compatible IPv6** (`::ffff:127.0.0.1`, `::ffff:a9fe:a9fe`, `0:0:0:0:0:ffff:...`, and deprecated IPv4-compatible) are unwrapped to their embedded IPv4 and re-evaluated against v4 guard ranges. NAT64 `64:ff9b::/96` is likewise decoded and the embedded v4 checked.
4. **IPv6 zone IDs** (`fe80::1%eth0`) are **rejected** in both scope entries and candidate hosts. Zone IDs only apply to link-local scope, which is denied regardless.
5. Canonical value stored as normalized string; range checks use the numeric `INET` value.

### 5.3 Port

- If the URL omits a port, apply the scheme default (`https`→443, `http`→80, `wss`→443, `ws`→80) **before** the port scope check.
- Explicit `:443` on an https URL is treated identically to the default (canonical port). No entry can be bypassed by adding/removing a default port.

### 5.4 Scheme

- Lowercase. Only `{https, http, ws, wss}` are recognized; everything else (`file`, `gopher`, `ftp`, `data`, `javascript`, …) is rejected outright at parse time.

### 5.5 Path

- Percent-decode only **unreserved** characters; re-encode reserved/unsafe consistently. Reject invalid percent-encodings and encoded NUL/CR/LF.
- Resolve `.`/`..` dot-segments (RFC 3986 remove-dot-segments) so `/api/../admin` canonicalizes to `/admin` before the prefix check — prevents traversal-style scope escape.
- Collapse duplicate slashes per policy; paths are **case-sensitive** (unlike hosts).
- Trailing-slash rule: `path_prefix` matching is segment-boundary aware, so a stored prefix `/api` matches `/api`, `/api/`, and `/api/v1` but never `/apiv2`.

### 5.6 Full candidate URL canonical order

`scheme (lower) → host (ToASCII, lower, no trailing dot) → port (explicit, default-normalized) → path (dot-segment resolved) → [query/fragment ignored for scope]`. Userinfo (`user:pass@`) is stripped and, if present, flagged (credentials in URLs are never used for scope decisions and are redacted from audit).

---

## 6. Deny-by-default network guard (two-tier)

Applied to **every resolved IP** and every IP literal, independent of allowlist matching. Ranges are enumerated so nothing depends on library defaults.

### Tier A — HARD DENY (never overridable, even by an explicit `elevated` entry)

| Category | IPv4 | IPv6 |
|---|---|---|
| Loopback | `127.0.0.0/8` | `::1/128` |
| Unspecified | `0.0.0.0/8`, `0.0.0.0` | `::/128` |
| Cloud/link-local metadata | `169.254.169.254`, `169.254.170.2` (ECS) | `fd00:ec2::254` |
| Multicast | `224.0.0.0/4` | `ff00::/8` |
| Broadcast / reserved | `255.255.255.255/32`, `240.0.0.0/4` | — |
| Documentation/benchmark | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `198.18.0.0/15` | `2001:db8::/32` |
| Discard / ORCHID / deprecated | — | `100::/64`, `2001:20::/28` |

Cloud-metadata addresses are special-cased into hard-deny even though they are technically link-local, because their compromise is the entire point of SSRF.

### Tier B — RESTRICTED (denied unless a matching `elevated=TRUE` scope entry explicitly names them, and only when the active authorization grants it)

| Category | IPv4 | IPv6 |
|---|---|---|
| Private (RFC1918) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | ULA `fc00::/7` |
| Carrier-grade NAT | `100.64.0.0/10` | — |
| Link-local | `169.254.0.0/16` (minus hard-denied metadata) | `fe80::/10` |

**Rule:** Tier B is for legitimately-authorized internal engagements. An operator must add an explicit `ip`/`cidr` scope entry with `elevated=TRUE`, and that entry — because it changes the scope — forces re-attestation and (per policy) a second-reviewer elevated approval (see §12). Absent that, all Tier B space is denied exactly like Tier A.

**No entry, elevated or not, can override Tier A.**

---

## 7. Scope-validation decision procedure

This is the single procedure **every outbound request must pass**, at scheduling time *and* re-checked at execution time (state may have changed between the two). It is deterministic and ordered; the first DENY wins.

```
INPUT: engagement_id, candidate_url, request_context(mode, check_id, actor)

0. PRECONDITIONS (engagement-level gate)
   a. engagement.status ∈ {authorized, active}          else DENY(engagement_not_active)
   b. engagement.emergency_stop = FALSE                  else DENY(emergency_stop)
   c. active authorization exists, status='active',
      effective_from ≤ now < expires_at                 else DENY(authorization_invalid/expired)
   d. engagement.active_scope_hash == authorization.scope_hash  else DENY(scope_binding_broken)
   e. now inside a testing window AND not in blackout    else DENY(outside_testing_window)
   f. request_context.mode ∈ authorization.allowed_modes ∩ engagement.allowed_modes
                                                          else DENY(mode_not_authorized)
   g. request_budget_used < request_budget_total         else DENY(budget_exhausted)
   h. rate/concurrency token available (see §10)         else THROTTLE (queue, not deny)

1. PARSE + CANONICALIZE (§5). Reject malformed URL, bad encoding,
   disallowed scheme, IP-literal-with-zone-id.            else DENY(malformed/scheme)

2. SCHEME CHECK: canonical scheme ∈ allowed protocol entries.  else DENY(scheme_not_in_scope)

3. IF host is an IP literal → run NETWORK GUARD (§6) on it now.
   Tier A match ⇒ DENY(hard_denied_range).
   Tier B match with no elevated allow ⇒ DENY(restricted_range).

4. EXCLUSION CHECK (always first among scope entries):
   evaluate host/port/path against all is_exclusion=TRUE entries.
   ANY match ⇒ DENY(excluded).                           ← exclusions win

5. ALLOWLIST CHECK: host matches a domain/ip/cidr allow entry
   AND port matches a port allow entry (or default port allowed)
   AND (path within an allowed path_prefix OR no path_prefix entries constrain this host)
   AND (if api_resource entries exist for host, operation is allowed).
   No allow match ⇒ DENY(not_in_scope).

6. DNS RESOLUTION + RESOLVED-IP RE-CHECK (rebinding protection):
   a. Resolve host → all A/AAAA records.
   b. For EACH resolved IP:
        - run NETWORK GUARD (§6): Tier A ⇒ DENY(rebinding_hard_denied);
          Tier B without elevated allow ⇒ DENY(rebinding_restricted).
        - the resolved IP must ALSO satisfy the allowlist: it must fall within an
          allowed ip/cidr entry OR the host it came from is an allowlisted domain
          whose resolution to public space is permitted by policy.
      ANY resolved IP failing ⇒ DENY(resolved_ip_out_of_scope).
   c. PIN the validated IP for the actual socket connection. The connection MUST
      use the exact pinned IP that passed the check — not a fresh resolution — so a
      TOCTOU DNS-rebind between check and connect cannot occur.

7. CONNECT to pinned IP; on TLS, verify certificate hostname matches the
   canonical host (no connecting to pinned IP while presenting an out-of-scope SNI).

8. REDIRECT HANDLING: on any 3xx, do NOT auto-follow. Extract Location,
   canonicalize (§5), and RE-RUN THIS ENTIRE PROCEDURE (steps 1–7) for the
   target. Cross-host / out-of-scope redirect ⇒ STOP, record, do not follow.
   Enforce a max-redirect depth; each hop is independently scope-validated and audited.

9. ON PASS: decrement budget, emit audit event (§11) with the decision, pinned IP,
   and matched entry ids. ON ANY DENY: emit audit event with the deny reason;
   never send the request.
```

**Key protections baked in:**
- **DNS rebinding:** resolve → validate every IP → pin the IP → connect to the pin. The DNS answer that was validated is the one used; re-resolution cannot smuggle a private IP in.
- **Redirect scope escape:** every redirect hop is a brand-new full validation; there is no "trusted because we started in scope."
- **Deny-by-default:** any step that cannot affirmatively place the candidate in scope denies.
- **Double-checkpoint:** the procedure runs at *schedule* time and again at *execute* time; an authorization expiring or an emergency stop firing between the two is caught.

---

## 8. Rate-limit, testing-window & expiry enforcement (runtime fields)

These live on the engagement (§2.1) and authorization (§3.1); this section defines how the runtime evaluates them and the supporting counters.

```sql
TABLE engagement_runtime_counter (   -- fast-moving state, separate from config
  engagement_id        UUID PRIMARY KEY REFERENCES engagement(id),
  tenant_id            UUID NOT NULL,
  window_started_at    TIMESTAMPTZ NOT NULL,   -- current rate window
  requests_in_window   INT NOT NULL DEFAULT 0,
  in_flight            INT NOT NULL DEFAULT 0,  -- current concurrency
  last_request_at      TIMESTAMPTZ,
  circuit_state        TEXT NOT NULL DEFAULT 'closed'
                       CHECK (circuit_state IN ('closed','open','half_open')),
  circuit_opened_at    TIMESTAMPTZ,
  consecutive_errors   INT NOT NULL DEFAULT 0
);
```

| Control | Field(s) | Enforcement |
|---|---|---|
| Global RPS | `global_max_rps` + `requests_in_window` | Token-bucket / sliding window per engagement; excess is queued (throttled), not dropped. |
| Per-host RPS | `per_host_max_rps` | Per-host bucket keyed by canonical host. |
| Concurrency | `max_concurrency`, `per_host_concurrency`, `in_flight` | Semaphore; new requests wait for a slot. |
| Min spacing | `min_request_interval_ms` | Enforced against `last_request_at`. |
| Request budget | `request_budget_total/used` | Hard cap; at exhaustion the engagement auto-pauses and notifies. |
| Body cap | `max_response_body_bytes` | Response reading truncates; oversize bodies never fully buffered (queue-abuse / resource protection). |
| Testing window | `testing_window` rows + `timezone` | Evaluated at step 0e; blackout wins. |
| Expiry | `authorization.expires_at` | Evaluated at step 0c on **every** request; independent background job also flips status to `expired`. |
| Circuit breaker | `circuit_state`, `consecutive_errors` | On error-rate/latency threshold, breaker opens → engagement auto-pauses; requires human/half-open probe to resume. |
| Emergency stop | `engagement.emergency_stop` | Checked at step 0b; set → immediate global halt, audited. |

**Auto-expiration invariant:** even if the background expiry job is delayed, no request can execute past `expires_at` because step 0c re-derives validity from timestamps at request time. Expiry and window logic are *pure functions of the clock*, never of a cached status flag alone.

---

## 9. Immutable audit-event schema (tamper-evident, hash-chained)

Append-only, per-engagement hash chain. Every scope decision, config change, authorization/approval action, mode switch, emergency stop, and lifecycle transition is an event. Chaining makes silent deletion or reordering detectable.

```sql
TABLE audit_event (
  id              UUID PRIMARY KEY,
  tenant_id       UUID NOT NULL,
  engagement_id   UUID NOT NULL REFERENCES engagement(id),
  seq             BIGINT NOT NULL,               -- monotonic per engagement, gap = tampering signal
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  actor_type      TEXT NOT NULL CHECK (actor_type IN ('user','system','worker','scheduler')),
  actor_id        UUID,                          -- user id when actor_type='user'
  actor_role      TEXT,                          -- snapshot of RBAC role at event time

  event_type      TEXT NOT NULL,                 -- e.g. 'scope.decision.deny','auth.attested',
                                                 -- 'engagement.emergency_stop','request.executed',
                                                 -- 'redirect.blocked','scope.version.created'
  subject_type    TEXT,                          -- 'authorization','scope_version','request','approval'
  subject_id      UUID,

  payload         JSONB NOT NULL,                -- REDACTED structured detail (no secrets/PII/tokens)
  payload_sha256  CHAR(64) NOT NULL,             -- hash of canonical(payload) AFTER redaction

  prev_hash       CHAR(64) NOT NULL,             -- hash of the previous event in this engagement's chain
  event_hash      CHAR(64) NOT NULL,             -- H( canonical( seq || occurred_at || event_type ||
                                                 --    actor || subject || payload_sha256 || prev_hash ) )
  signature       TEXT,                          -- optional per-event / periodic-anchor signature

  UNIQUE (engagement_id, seq),
  UNIQUE (engagement_id, event_hash)
);
```

**Integrity rules**

- **Genesis event** per engagement uses a fixed `prev_hash` sentinel (`0*64`). Every subsequent `prev_hash` = previous event's `event_hash`. A verifier recomputes the chain end-to-end; any altered/removed/reordered event breaks the chain from that point forward.
- `seq` is strictly monotonic with no gaps; a gap or duplicate is itself an integrity alarm.
- **Redaction happens before hashing.** Secrets, cookies, `Authorization` headers, API keys, tokens, credentials-in-URL, and PII are stripped/masked in `payload` first; `payload_sha256` covers the redacted form, so audit integrity does not depend on retaining sensitive data.
- **Append-only enforcement:** `UPDATE`/`DELETE` on `audit_event` are revoked at the DB grant level and rejected by triggers; the table is write-once.
- **Periodic anchoring:** every N events (or hourly), the current chain-head hash is signed and/or externally timestamped (`signature`) and recorded, so even a total-rewrite attempt cannot forge history predating the last anchor.

---

## 10. Approval-record schema

Backs Mode 3 (approval-gated validation) and any elevated action (scope changes that touch restricted ranges, mode elevation, intrusive validation). No intrusive/elevated action proceeds without a decided approval.

```sql
TABLE approval_request (
  id                 UUID PRIMARY KEY,
  tenant_id          UUID NOT NULL,
  engagement_id      UUID NOT NULL REFERENCES engagement(id),

  request_type       TEXT NOT NULL CHECK (request_type IN
                       ('intrusive_validation','scope_change','restricted_range_allow',
                        'mode_elevation','business_logic_test')),

  requested_by       UUID NOT NULL,
  requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  justification      TEXT NOT NULL CHECK (char_length(justification) BETWEEN 1 AND 4000),

  -- The exact plan being approved (mirrors Phase 3/7 validation-plan requirements)
  proposed_action    JSONB NOT NULL,   -- exact request(s): method, url, headers(redacted), body-shape
  potential_impact   TEXT NOT NULL CHECK (char_length(potential_impact) <= 4000),
  target_summary     TEXT NOT NULL,
  scope_check_result JSONB NOT NULL,   -- snapshot of the §7 decision for the target (must be PASS)
  required_account   TEXT,             -- operator test account to use, if any
  expected_response  TEXT,
  evidence_plan      TEXT NOT NULL,    -- what non-destructive evidence will be retained
  cleanup_action     TEXT,            -- required rollback/cleanup steps
  stop_conditions    TEXT NOT NULL,   -- when execution must halt

  status             TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','approved','rejected','expired','withdrawn')),
  decided_by         UUID,
  decided_at         TIMESTAMPTZ,
  decision_reason    TEXT CHECK (char_length(decision_reason) <= 2000),
  expires_at         TIMESTAMPTZ NOT NULL,        -- approval is time-boxed

  linked_scope_version_id UUID REFERENCES scope_version(id),  -- for scope_change/restricted_range_allow
  linked_audit_event_id   UUID REFERENCES audit_event(id),

  CONSTRAINT decided_requires_decider CHECK (
     status IN ('pending','withdrawn','expired') OR (decided_by IS NOT NULL AND decided_at IS NOT NULL)),
  CONSTRAINT scope_must_pass CHECK ( (scope_check_result->>'decision') = 'pass' )
);
```

**Rules**

- **Separation of duties:** `decided_by` must differ from `requested_by` (a requester cannot approve their own intrusive/elevated action). Enforced in app + policy; role must be Engagement Manager/Reviewer per RBAC.
- **Scope precondition:** an approval cannot even be *created* unless the target already passes §7 (`scope_must_pass`). Approval is never a way to reach out-of-scope targets — it is only for higher-impact actions *within* scope.
- **Restricted-range / scope changes** link the new `scope_version`; approving one is what permits an `elevated` Tier B entry to take effect (paired with re-attested authorization).
- **Time-boxed:** approvals expire (`expires_at`); an expired approval cannot authorize execution. Every decision emits an audit event.

---

## 11. Scope import / export format

A single, versioned, canonical document for portability and review, hash-bound so an imported scope cannot silently differ from what was signed. Round-trips deterministically (canonical serialization ⇒ identical `scope_hash`).

```yaml
# scope-export.yaml  (JSON equivalent also supported; both canonicalize identically)
schema_version: "1.0"
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
scope:
  allow:
    - {class: domain, value: "acme.example",        include_subdomains: false}
    - {class: domain, value: "*.acme.example",       wildcard: true}
    - {class: cidr,   value: "203.0.113.0/24",        ip_version: 4}
    - {class: port,   value: "443"}
    - {class: port,   value: "8443"}
    - {class: protocol, value: "https"}
    - {class: path_prefix, host: "*.acme.example",    value: "/api/"}
    - {class: api_resource, host: "api.acme.example",
       openapi_ref: "specs/acme-openapi.yaml",
       openapi_sha256: "0f3d...ab", operations: ["GET /v1/users","GET /v1/orders/{id}"]}
  exclude:                              # always win over allow
    - {class: domain,     value: "admin.acme.example"}
    - {class: path_prefix, host: "*.acme.example", value: "/logout"}
    - {class: path_prefix, host: "*.acme.example", value: "/payments/"}
    - {class: ip,         value: "203.0.113.7"}      # carve out a host inside the allowed CIDR
integrity:
  canonicalization: "sorted-keys/utf8/no-ws"
  scope_hash: "sha256:9c1e...f4"       # MUST match recomputed hash on import
signature:                             # optional, for signed bundles
  algo: "ed25519"
  key_id: "org-scope-signing-2026"
  value: "base64:..."
```

**Import validation (fail-closed):**

1. Reject unknown `schema_version`.
2. Re-canonicalize `scope` and recompute `scope_hash`; **reject if it does not match** `integrity.scope_hash`.
3. Re-run all per-entry validators (§4, §5): punycode/IDNA, public-suffix wildcard guard, CIDR/IP form, port ranges, path canonicalization, scheme allowlist, network-guard classification (any Tier B entry is imported as `elevated=FALSE` and cannot self-activate — it still requires the §12 elevated approval + re-attestation).
4. Verify `signature` if the bundle is signed and the key is trusted.
5. On success, materialize a **new** `scope_version` (never mutate an existing one); binding to authorization is a separate, explicit attestation step. Export is the inverse: serialize the frozen `scope_version` canonically, emit its stored `scope_hash`.

**Export never includes secrets:** no credentials, session material, cookies, tokens, or PII — only scope structure and non-secret identifiers, consistent with the redaction posture everywhere else.

---

## 12. Cross-cutting invariants → Phase 2 acceptance criteria

These are the testable guarantees this schema exists to make provable (feeding Phase 2 "tests proving out-of-scope requests cannot be scheduled/executed" and Phase 10 property-based scope tests):

1. **No authorization ⇒ no request.** Any request attempt on an engagement lacking an `active` authorization is denied and audited. *(Test: every engagement status except {authorized, active} denies.)*
2. **Scope drift is fatal.** If `engagement.active_scope_hash ≠ authorization.scope_hash`, all requests deny until re-attestation. *(Test: mutate scope → old authorization no longer authorizes.)*
3. **Exclusions always win.** For any candidate matching both an allow and an exclude entry (including apex-of-wildcard, host-in-CIDR, path-in-prefix), result is DENY. *(Property test over generated overlaps.)*
4. **Hard-deny is non-overridable.** No scope entry, elevated or not, permits Tier A ranges (loopback/metadata/multicast/unspecified/broadcast/reserved). *(Fuzz obfuscated IP forms → all normalize and deny.)*
5. **Rebinding is defeated.** Resolved IPs are individually validated and the validated IP is pinned for connect. *(Test: DNS answer flips public→private between resolve and connect → connect uses pinned public IP or the request is denied.)*
6. **Redirects are re-validated.** Every 3xx hop re-runs the full §7 procedure; out-of-scope Location is not followed. *(Test: in-scope → out-of-scope redirect stops and audits.)*
7. **Expiry/window are clock-derived.** No cached status can permit a request past `expires_at` or outside a window/inside a blackout. *(Test: freeze clock past expiry with status still 'active' → deny.)*
8. **Approvals cannot reach out-of-scope.** An approval requires a passing §7 result at creation and time-boxes execution; requester ≠ approver. *(Test: approval for out-of-scope target cannot be created.)*
9. **Audit chain verifies.** Recomputing the per-engagement hash chain detects any deletion/reorder/edit; `seq` has no gaps. *(Test: tamper any event → verification fails from that point.)*
10. **Import is hash-verified and fail-closed.** A bundle whose recomputed `scope_hash` differs from its declared hash is rejected; Tier B entries never self-activate on import.

---

**File paths:** none produced — this is a Phase 0 design deliverable returned inline. The schema above is intended to seed the Phase 2 migration set (`engagement`, `testing_window`, `authorization`, `scope_version`, `scope_entry`, `engagement_runtime_counter`, `audit_event`, `approval_request`) and the scope-validation service's ordered decision procedure (§7), network guard (§6), and canonicalization rules (§5).
