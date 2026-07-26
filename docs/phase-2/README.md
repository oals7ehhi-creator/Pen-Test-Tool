# Phase 2 — Engagement, Authorization & Scope Engine (in progress)

Phase 1 is **approved and merged** (PR #1 → `main`). Phase 2 implements the authoritative scope and authorization
engine that every outbound request must consult — deny-by-default, exclusions-always-win, SSRF-hardened, with a
single Scope Authority (decision) and a single Guarded Egress Broker (the only target-socket creator). It is
subordinate to the approved Phase 0 design (`docs/phase-0/03`, `04`, `06`, `10`).

Because Phase 2 is large, it is delivered in **tested, CI-green vertical slices**. This document tracks honestly
what is implemented versus what is still to come — nothing here claims a control that is not yet built and tested.

## Slice status

| Slice                             | Scope                                                                                                                                                                                                                                                                               | Status                                                                                                                                                                                        |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1 — Scope Authority pure core** | Canonicalization (§5) + two-tier SSRF network guard (§6): decode any obfuscated/transition IP form to canonical bytes and classify `hard_deny` / `restricted` / `permitted`; canonicalize full candidate URLs (scheme/host/port/path, userinfo stripped). Package `@pentest/scope`. | ✅ implemented + tested (`packages/scope`)                                                                                                                                                    |
| **2 — Scope-entry matching**      | Allow/exclude `domain`/`ip`/`cidr`/`port`/`protocol`/`path_prefix`/`api_resource` matching; exclusions-first; Tier B elevation gating; deny-by-default over a frozen `scope_version`; breadth accounting.                                                                           | ✅ implemented + tested (`packages/scope`)                                                                                                                                                    |
| **3 — Schema & persistence**      | Engagement / authorization / scope_version / scope_entry / approval / audit tables + migrations (composite tenant+engagement FKs, RLS, immutability triggers).                                                                                                                      | ✅ implemented + tested (`db/`)                                                                                                                                                               |
| 4 — Two-stage flow                | Immutable content-addressed `request_spec`; JIT single-use Stage-1 grants bound to `spec_sha256`; Guarded Egress Broker (resolve → validate → **pin** → connect → re-guard redirects).                                                                                              | 🔶 in progress — **4a** grant/spec core + **4b** schema `0003` + **4c** Broker decision core + **4d** request reconstruction done; Broker transport (mTLS ingress + DNS/TCP/TLS sockets) next |
| 5 — Interlocks                    | Budget charge-before-send ledger; testing windows / expiry / emergency-stop; per-target rate/concurrency/circuit-breakers; hash-chained audit; WebSocket bounds; approval policy + dual control.                                                                                    | ⏳                                                                                                                                                                                            |

## Slice 1 — what it proves (this commit)

`@pentest/scope` (`packages/scope`) is the pure, dependency-free SSRF / network-policy chokepoint:

- **Two-tier network guard (§6).** Every candidate address is decoded and classified. **Tier A** (loopback,
  unspecified, cloud/link-local metadata, multicast, broadcast, reserved/future, documentation/benchmark) is
  `hard_deny` and can never be reached. **Tier B** (RFC1918, ULA, link-local, CGNAT) is `restricted` (reachable
  only under full elevation, decided in slice 2). Metadata stays Tier A even inside link-local space.
- **Obfuscation & transition forms decoded (§5.2).** Decimal (`2130706433`), octal (`0177.0.0.1`), hex
  (`0x7f000001`), short forms, IPv4-mapped, deprecated-compat, 6to4, Teredo, and NAT64 all decode to the embedded
  IPv4 and are re-classified — so `::ffff:169.254.169.254` and `http://0x7f000001/` are hard-denied. Zone IDs are
  rejected.
- **Canonicalization (§5).** Host (IDNA/ToASCII, trailing-dot, case; IP-literal hosts are treated as IPs, not
  domains), scheme (only `https/http/wss/ws`), port (scheme defaults), and path (percent-decode unreserved only,
  reject encoded NUL/CR/LF, RFC 3986 dot-segment removal). Full-URL canonicalization strips `user:pass@` userinfo.
- **Fails closed.** Anything the guard cannot decode is `hard_deny`, never `permitted`.

Tests (`packages/scope/test`, coverage-thresholded 90/85/90/90): the SSRF-denial battery (127.0.0.1, `::1`,
10.0.0.0/8, 169.254.169.254, `[::ffff:169.254.169.254]`, `0177.0.0.1`, `0x7f000001`, `2130706433`), Tier A/B
classification, transition-form decoding, and canonicalization fuzz (mixed case, trailing dot, IDN homoglyphs,
`@`-embedded userinfo, encoded path traversal) proving alternate encodings cannot smuggle a different host/path.

## Slice 2 — what it proves (this commit)

The scope-matching decision engine (`packages/scope/src/model.ts`, `evaluate.ts`, `breadth.ts`) turns the pure
canonicalization/guard core into the authoritative **deny-by-default** decision, matching Phase 0 §4 + §7.1 steps 1–5:

- **The runtime scope model (§4.2).** A `ScopeVersion` is an immutable set of typed entries — `domain`, `ip`,
  `cidr`, `port`, `protocol`, `path_prefix`, `api_resource` — each optionally an exclusion and/or `elevated`.
- **The ordered decision (§7.1 steps 1–5), deny-by-default.** `evaluateScope(candidate, scope, ctx)` /
  `evaluateUrl(url, scope, …)` decide in the spec's precedence: **(1)** scheme (`https` default-allowed, others need
  a `protocol` entry) → **(2)** IP-literal network guard (Tier A is an absolute hard-deny that no allowlist entry or
  elevation can override) → **(3)** exclusions-first (any exclusion match denies, even over an allow or a wildcard
  apex) → **(4)** host allowlist (domain wildcard/subdomain/apex per §4.3–4.4; ip/cidr containment) with **Tier B
  gated** on a matching `elevated` entry **and** an elevation-granted context → **(5)** port (explicit entries define
  the set; otherwise only the scheme-default port) + host-bound path (`path_prefix` segment-boundary / `api_resource`
  `METHOD path`). No matching allow ⇒ DENY. An empty scope denies everything.
- **Breadth accounting (§4.6, §4.2 absolute floors).** `computeScopeBreadth` / `evaluateBreadth` compute host count,
  IPv4-equivalent addresses (Σ 2^(32−prefix)), CIDR-entry count, and the IPv6 prefix floor, and split violations into
  **hard rejects** (broader than the absolute `/16`/`/32` floors — no approval lifts them) and **elevation-required**
  (over a ceiling, a broader-than-floor CIDR, or a wildcard domain).

Tests (`packages/scope/test/evaluate.test.ts`, `breadth.test.ts`; coverage-thresholded 90/85/90/90): deny-by-default
over an empty scope; wildcard/subdomain/apex matching and label-boundary confusion (`example.com` ≠ `notexample.com`);
exclusions winning over allows/wildcards/apex; ip/cidr (v4+v6) containment; Tier A hard-deny even when allowlisted +
elevated; Tier B gating with/without an elevated entry and with/without granted elevation; scheme default vs explicit
`protocol`; port default vs explicit set; host-bound path segment boundaries and encoded-traversal escape attempts;
SSRF through a candidate URL (incl. userinfo-smuggled metadata) denied regardless of scope; and the breadth floors/ceilings.

## Slice 3 — what it proves (this commit)

Migration `db/migrations/0002_authorization_scope_schema.{up,down}.sql` persists the core authority model (doc 04
§2/§3/§4/§9/§10) and enforces its safety invariants **at the storage layer**, not in prose:

- **Tables.** `engagement`, `testing_window`, `scope_version`, `scope_entry`, `"authorization"`, `approval_policy`,
  `approval_request`, `approval_manifest_entry`, `approval_decision`, `audit_chain`, `audit_event` — with the full
  per-class CHECK shapes (§4.2), status machines (§2.2/§3), and breadth trailer columns (§4.6).
- **Authority isolation (§0.8/§1).** Every security-authority reference is a composite `(id, tenant_id, engagement_id)`
  FK, so an authorization/approval/scope_version from another engagement — even in the same tenant with an identical
  `scope_hash` — is a hard constraint violation. The engagement ⇄ authorization ⇄ scope_version and authorization ⇄
  attestation-approval cycles use DEFERRABLE composite FKs verified at COMMIT.
- **Row-Level Security (doc 03).** Every tenant-scoped table is `ENABLE` + `FORCE ROW LEVEL SECURITY` with a
  `current_setting('app.tenant_id')` policy; an unset/empty GUC fails closed (no rows).
- **Immutability & dual control.** append-only audit/decision/manifest tables; scope-version freeze + entry-freeze
  guards; approval-policy content immutability with a non-decreasing-strength guard; manifest-freeze digest recompute;
  approve-decision NON-NULL hash pins; NULL-safe audit chain identity; and the authorization-activation trigger that
  requires an approved, matching attestation approval + scope binding.
- **pgcrypto** is provisioned by this migration (first use of `digest()`) and dropped by its down, so up/down stays an
  exact inverse — verified by `migrate:ci`'s full-catalog snapshot round-trip.

Tests (`db/test/schema.test.ts`, 35 DB-gated cases + the migrate round-trip): RLS isolation under a **non-superuser
role** across engagement/scope_version/authorization/audit_event; same-tenant cross-engagement FK rejection; append-only
rejects; scope-freeze (insert/update/delete); approval-policy strength guards (weaken/broaden/quorum) + a positive
non-weakening version; decision hash-pin enforcement + "no decision before freeze"; the null-safe audit identity on a
tenant chain; the authorization-activation trigger (positive activation + not-approved/wrong-document/scope-mismatch
rejections); §4.2 scope-entry constraints; the status-shape CHECK; and the engagement⊆authorization allowed-modes guard.
An adversarial 4-lens review of this migration surfaced a dual-control-bypass **blocker** (approval anchors were mutable
post-approval) plus four constraint-vacuity defects; all were fixed and now have regression tests.

**Not yet implemented (do not assume present):** the `request_spec` / catalog-template / operator-session /
operator-query-value tables and the JIT-grant two-stage flow (§7), the Guarded Egress Broker (resolve→validate→**pin**→
re-guard redirects), and the budget-reservation ledger / window / e-stop / rate-limit interlocks (§8). Those are slices
4–5. DNS-rebinding defense is a Broker (slice 4) property — the guard classifies literals now, and the
resolve-validate-**pin** step lands with the Broker.

## Slice 4a — what it proves (this commit)

`@pentest/spec` (`packages/spec`) is the pure, dependency-light core of the two-stage flow (Phase 0 §7.0 + §7.1),
the foundation the DB schema (4b) and the Guarded Egress Broker (4c) build on:

- **Content-addressed `request_spec` (§7.0).** `computeSpecSha256` is the SHA-256 over the **canonical JSON**
  (sorted keys, explicit null, `undefined` rejected) of EXACTLY the 22 request-determining fields. INSTANCE identity
  (`run_id`/`job_id`), the broker-resolved secret POINTERS (`approval_ref`/`session_ref`/`query_value_ref`), and the
  advisory `mode` are **excluded** — so the same logical request may recur across jobs/runs with the same digest (a
  repeat, not a replay), and a dynamic request keeps a stable digest while `approval_ref` is attached — while the
  non-secret bindings (`query_value_binding`, `session_digest`) ARE bound in, so rotation invalidates the digest. The
  covered field set is asserted in tests so a future edit can't silently fold a field in or out.
- **Stage-1 egress grant (§7.1).** `mintGrant` / `verifyGrant` — a **short-TTL (≤ 30 s), single-use** JWT (HS256,
  pinned issuer/audience) that binds `spec_sha256` and carries **no resolved IP and no request line**. Verification
  recomputes the presented spec's digest and requires equality, consumes the `jti` exactly once (replay defense), and
  rejects a tampered / expired / not-yet-valid / wrong-audience / wrong-issuer / wrong-key grant with a fixed reason
  code — and a rejected grant never burns its `jti`.

Tests (`packages/spec/test`, coverage-thresholded 90/85/90/90): canonical-JSON determinism + `undefined`/non-finite
rejection; digest field-membership and per-field sensitivity (all 22) with the excluded fields proven absent; grant
round-trip, replay rejection, jti-not-consumed-on-failure, spec-mismatch, and the tamper/expiry/audience/issuer matrix.

**Deliberately still to come in slice 4:** persistence of `request_spec` / `catalog_template` / `operator_session` /
`operator_query_value` with the derived-`approval_required` + digest-verify + immutability triggers (**4b**, migration
`0003`), and the Guarded Egress Broker data path — reconstruct-from-spec, DNS resolve, per-resolved-IP network-guard +
frozen-scope re-check, **pin**, connect, and re-guarded redirects (**4c**). The grant here carries no socket; the
Broker is the only component that opens one.

## Slice 4b — what it proves (migration `0003`)

Migration `0003` persists the two-stage flow's data plane (Phase 0 §7.0) — the immutable, content-addressed
`request_spec` plus the catalog and operator-secret reference tables — with the integrity enforced **in the database**,
not merely in application code:

- **`catalog_template` content-addressing.** A curated header-set / query-template / body-template row stores a
  `template_sha256` that a trigger recomputes from the row's canonical pre-image (`jsonb_build_object(...)::text`) and
  rejects on mismatch — a template cannot be inserted under a digest that does not match its content. Append-only
  (`UPDATE`/`DELETE` rejected).
- **Operator secrets never stored.** `operator_session` and `operator_query_value` hold only a **non-secret**
  `GENERATED` content address (`session_digest` / `value_binding` via pgcrypto `digest()`), never the secret itself;
  both tables are append-only, and a `request_spec` that references a session must carry the **exact** generated digest
  (composite FK) — a mismatched or forged digest is rejected.
- **`request_spec` immutability + isolation + derived approval.** Rows are append-only; RLS isolates them per tenant
  (a tenant-B session sees none of tenant A); a spec binding an `authorization` from a **different** engagement in the
  same tenant is rejected (composite tenant+engagement FK); the curated-query and secret-query paths are mutually
  exclusive (shape `CHECK`); and `approval_required` is a **trigger-derived** column (the operator cannot lie about
  whether a spec needs approval). The `session_binding_shape` `CHECK` closes the `MATCH SIMPLE` NULL-skip so a
  `session_ref` without its `session_digest` (or vice-versa) cannot slip past the FK.
- **WebSocket bounds.** `kind_scheme` / `ws_is_get` / `ws_needs_frames` constraints hold a WebSocket spec to a `GET`
  upgrade with a bounded, catalog-controlled frame plan.

Tests (`db/test/request_spec.test.ts`, 18 DB-gated cases + the migrate round-trip): content-address verify + append-only
on every table; the session-digest FK (positive + mismatch); tenant RLS; cross-engagement rejection; curated-vs-secret
mutual exclusion; the derived `approval_required`; the WebSocket constraints; and the review-added `session_binding_shape`
NULL-skip regression. An adversarial 4-lens review surfaced a **HIGH** `MATCH SIMPLE` FK-evasion defect (fixed, with a
regression test) plus content-address and coverage hardening.

## Slice 4c — what it proves (this commit)

`@pentest/broker` (`packages/broker`) is the pure decision core of the **Guarded Egress Broker** — the one component
that will ever open a socket to a target (Phase 0 doc 10 §4). This slice implements its connect-time security decisions
as pure, injectable-I/O logic (the resolver and the grant-jti consumer are injected; **nothing here performs real
egress** — the mTLS ingress and the DNS/TCP/TLS sockets are the next sub-slice). It closes the gap the spec-time scope
decision structurally cannot: that decision matched a **domain**, but the broker dials a **resolved address**.

- **Authenticated per-job ingress (doc 10 §4.3 / §7.1 step 6–7).** `authorizeIngress` accepts a request only with a
  valid, unconsumed, spec-bound Stage-1 grant **and** a per-job identity whose `tenant/engagement/run/job` **equal** the
  grant's — the broker is not a generic CONNECT proxy. A grant is single-use (its `jti` is consumed on successful
  verification); a grant surfacing under a **mismatched** identity is rejected **and its `jti` burned** (defensive:
  a misdirected grant is treated as compromised, never reusable). Errors carry only fixed reason codes — never the
  token, claims, or identity values.
- **Resolve → validate → PIN (§6 + §7.1 step 11) — the DNS-rebinding / SSRF-at-connect defense.** Every resolved
  address must pass the two-tier network guard: Tier A (loopback/metadata/unspecified/…, **including** IPv4-mapped and
  other transition IPv6 forms like `::ffff:169.254.169.254`) is an **absolute** deny; Tier B (RFC1918/ULA/link-local/
  CGNAT) is denied unless a matching **elevated ip/cidr** entry exists **and** elevation is granted (an elevated
  _domain_ never suffices); any ip/cidr **exclusion** wins; anything unparseable or an empty resolution fails closed.
  A **mixed** A/AAAA set with a single forbidden record refuses the **whole** connection — never "pick the good one" —
  and one validated address is **pinned** in canonical form so the connect step dials only it and never re-resolves
  (no TOCTOU). Exclusion and elevation matching decode a resolved address on the **same** representation the guard
  classifies, so a mapped form (`::ffff:<excluded-public-ip>`) cannot evade a v4 exclusion.
- **Redirect re-guard (§7.1 step 13).** The broker **never** auto-follows a 3xx: a `Location` is re-canonicalized and
  re-decided by the same deny-by-default evaluator (so a 200-in-scope page cannot `302` to metadata/loopback/off-scope),
  the hop budget is bounded, and a followed hop is only a **new** candidate for a fresh spec + grant + resolve/pin —
  so the rebinding defense applies to every hop. Never opens a socket.

Tests (`packages/broker/test`, coverage-thresholded 90/85/90/90, currently **100%**): the ingress accept/reject matrix
incl. each mismatched identity dimension, single-use replay, and the **defensive jti-burn on identity mismatch**; the
full network-guard battery incl. Tier A absoluteness **under** an elevated/allow entry (guarding the ordering
invariant), the IPv4-mapped exclusion-evasion regression, mixed-set rebinding refusal, IPv6 pin canonicalization, and
Tier B elevation via both `cidr` and `ip`; and the redirect re-guard driven through the **network guard** (over `https`,
so the guard — not the scheme gate — refuses metadata/loopback), the last-allowed-hop boundary, exact reason codes, and
no-value-leak oracles. An adversarial 4-lens review found the mapped-exclusion bypass (**HIGH**, fixed) and the Tier A
regression-guard gap (**HIGH**, closed) plus oracle-tightening items, all landed here.

**Deliberately still to come:** the Broker **transport** — mTLS ingress termination and the actual DNS/TCP/TLS sockets
that consume these decisions — and the slice-5 interlocks (budget charge-before-send, windows, emergency-stop,
per-target rate/concurrency/circuit-breakers, hash-chained audit). (Reconstruction, the step that precedes connect,
lands in **4d** below.)

## Slice 4d — what it proves (this commit)

`reconstructRequest` (`packages/broker/src/reconstruct.ts`) is the broker's **request-reconstruction** step (Phase 0
§7.1 step 8 / doc 10 §3 step 3, **SI-061**): the broker never sends a worker-serialized request — it rebuilds the wire
request DETERMINISTICALLY from the immutable, signed spec (already proven to be the grant's spec at ingress) and refuses
any deviation **before** any egress. All I/O is injected (catalog fetch, secret resolve, the keyed-digest key); it opens
no socket.

- **Content-addressed assembly.** The fixed safe header-set, the inert payload, and a curated query template are fetched
  BY their content digest (a lookup the store content-addresses at write — the broker does not re-derive the DB's
  `jsonb::text` digest, that cross-engine canonical-JSON is deliberately avoided). The broker sets `Host` (IPv6
  bracketed, non-default port included) and `Content-Length` (octet length) **authoritatively**; a curated set — or an
  operator-session lease — that tries to carry a broker-controlled or malformed header name is refused.
- **Secret query path.** On the secret path the resolved lease's non-secret `value_binding` must equal the spec's (a
  withdrawn/rotated version is refused), and the **keyed HMAC** over the resolved values must **constant-time** equal
  `query_value_digest` (a value tamper is refused) — both BEFORE the values are used. The operator session is gated by
  its `session_digest` before the secret is injected. Every injected value is percent-encoded so it cannot alter request
  structure.
- **Re-canonicalize + assert.** The assembled URL is re-canonicalized and its scheme/host/port/path must re-derive the
  spec's canonical fields, else `DENY(reconstruction_mismatch)`; every unresolved/inconsistent dependency fails closed
  with a fixed reason code that never echoes a header/value/secret.
- **Shared bindings (`@pentest/spec`).** `operatorSessionDigest` / `operatorQueryValueBinding` mirror the DB `GENERATED`
  columns byte-for-byte (a DB-parity test asserts equality against the live column), and `computeQueryValueDigest` is
  the keyed, order-and-key-and-value-binding HMAC — the single source of truth the spec builder and broker both use.

Tests (`packages/broker/test/reconstruct.test.ts` + `packages/spec/test/bindings.test.ts`, both coverage-thresholded and
at **100%**): the full happy-path matrix (curated + secret query, session, payload, WebSocket handshake, IPv6/non-default
port); every DENY reason; the secret-path keyed-HMAC + version-binding refusals with no-value-leak oracles; and the
broker-controlled-header screen on both the curated set and the session lease. An adversarial 4-lens review found a
session-lease header-smuggling gap (**HIGH**, fixed — the session lease now gets the same screen as the curated set), a
header-name whitespace evasion, a Host-header port/IPv6 omission, and a fail-closed gap on a query path with null keys,
all fixed with regression tests.

## Dependency-advisory disposition

- **CVE-2026-14257 / GHSA-mh99-v99m-4gvg — `brace-expansion` ReDoS/DoS (high).** Published upstream after Phase 2
  slice 3 was first pushed; unrelated to any application change here. **Fixed where fixable:** a `pnpm.overrides`
  entry (`brace-expansion@5` → `>=5.0.8`) forces the current 5.x line to the patched **5.0.8**. **Recorded (accepted)
  for the residual:** two _transitive_ copies remain — `brace-expansion@1.1.16` (via `minimatch@3`, pulled by
  ESLint 9 / typescript-eslint) and `2.1.2` (via `minimatch@9`, pulled by `@vitest/coverage-v8`'s `glob@10`). Upstream
  shipped the DoS fix **only** on the 5.x line (no 1.x/2.x backport exists — the `maintenance-v1`/`maintenance-v2`
  releases predate 5.0.8), and `minimatch@3`/`@9` cannot consume brace-expansion 5.x (its module export shape changed,
  breaking `minimatch`), so no compatible fix reaches those chains without breaking the build toolchain. The exposure
  is **build-time only** (a DoS triggered by a maliciously-crafted glob pattern fed to ESLint/Vitest config) with **no
  runtime or untrusted-input path** — none of these packages ship in the API/worker runtime. It is therefore suppressed
  narrowly via `pnpm.auditConfig.ignoreGhsas` (this one advisory only; every other advisory and severity still hard-fails
  the `pnpm audit --audit-level=high` gate, proven by `ci/dependency-audit-negative-test.sh`). Revisit when ESLint /
  Vitest bump their transitive `minimatch` to a 5.x-compatible line, then drop the suppression.
