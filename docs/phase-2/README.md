# Phase 2 — Engagement, Authorization & Scope Engine (in progress)

Phase 1 is **approved and merged** (PR #1 → `main`). Phase 2 implements the authoritative scope and authorization
engine that every outbound request must consult — deny-by-default, exclusions-always-win, SSRF-hardened, with a
single Scope Authority (decision) and a single Guarded Egress Broker (the only target-socket creator). It is
subordinate to the approved Phase 0 design (`docs/phase-0/03`, `04`, `06`, `10`).

Because Phase 2 is large, it is delivered in **tested, CI-green vertical slices**. This document tracks honestly
what is implemented versus what is still to come — nothing here claims a control that is not yet built and tested.

## Slice status

| Slice                             | Scope                                                                                                                                                                                                                                                                               | Status                                                                                                                                                                                                                                                                                |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1 — Scope Authority pure core** | Canonicalization (§5) + two-tier SSRF network guard (§6): decode any obfuscated/transition IP form to canonical bytes and classify `hard_deny` / `restricted` / `permitted`; canonicalize full candidate URLs (scheme/host/port/path, userinfo stripped). Package `@pentest/scope`. | ✅ implemented + tested (`packages/scope`)                                                                                                                                                                                                                                            |
| **2 — Scope-entry matching**      | Allow/exclude `domain`/`ip`/`cidr`/`port`/`protocol`/`path_prefix`/`api_resource` matching; exclusions-first; Tier B elevation gating; deny-by-default over a frozen `scope_version`; breadth accounting.                                                                           | ✅ implemented + tested (`packages/scope`)                                                                                                                                                                                                                                            |
| **3 — Schema & persistence**      | Engagement / authorization / scope_version / scope_entry / approval / audit tables + migrations (composite tenant+engagement FKs, RLS, immutability triggers).                                                                                                                      | ✅ implemented + tested (`db/`)                                                                                                                                                                                                                                                       |
| 4 — Two-stage flow                | Immutable content-addressed `request_spec`; JIT single-use Stage-1 grants bound to `spec_sha256`; Guarded Egress Broker (resolve → validate → **pin** → connect → re-guard redirects).                                                                                              | 🔶 broker complete — **4a**–**4h** done (grant/spec core, schema `0003`, decision core, reconstruction, socket layer, send/read wire, Stage-2 orchestration, mTLS ingress auth); slice 5 interlocks next                                                                              |
| 5 — Interlocks                    | Budget charge-before-send ledger; testing windows / expiry / emergency-stop; per-target rate/concurrency/circuit-breakers; hash-chained audit; WebSocket bounds; approval policy + dual control.                                                                                    | 🔶 **5a**–**5d** done — budget ledger + intent (`0004`); live-state gate + sweeper (`0005`); concurrency/spacing/circuit slot throttle (`0006`); global + per-host RPS token buckets (`0007`); per-host concurrency, hash-chained audit wiring, WS bounds, dual control still to come |

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

## Slice 4e — what it proves (this commit)

The Broker's **outbound socket layer** (`packages/broker/src/resolver.ts`, `connect.ts`) — the concrete realization of
§7.1 step 11 (resolve) + step 12 (connect), the point where the pin becomes a real socket. All DNS/socket I/O is
injectable; the security-relevant option construction is pure and unit-tested, and a real loopback socket proves the
pinned IP is what actually gets dialed.

- **DNS resolution (§7.1 step 11).** `createResolver` resolves **A + AAAA** and merges them (deduped), feeding
  `resolveAndPin` — which guards every address and pins one. It uses `dns.resolve4/6` (NOT `dns.lookup`), so the OS
  hosts file cannot inject a loopback answer; a per-family `NODATA` does not fail the whole resolution; an empty merged
  result is returned so `resolveAndPin` fails closed with `no_resolution`.
- **Pinned connect (§7.1 step 12, SI-003/SI-004).** `connectPinned` dials **only** the pinned IP — enforced
  structurally by an IP-literal guard, so `net`/`tls` can never fall back to `dns.lookup` (no second, unguarded
  resolution / rebinding). For TLS the **SNI is the canonical host**, the certificate identity is validated against the
  **canonical host** (never the pinned IP, never a name Node would otherwise default to), and `rejectUnauthorized` is
  pinned to `true` in-code so a global TLS-verification bypass in the environment cannot silently disable chain
  validation.

Tests (`packages/broker/test/resolver.test.ts`, `connect.test.ts`; package at **100%** coverage): A/AAAA merge, per-family
NODATA tolerance, empty-resolution fail-closed, and dedup; the connect contract (dial pinned IP, SNI = canonical host,
cert bound to canonical host, `rejectUnauthorized` explicit); the non-IP-pin refusal; and a real loopback TCP round-trip
proving the pinned IP is dialed while the canonical host is only presented as identity. An adversarial 4-lens review
returned **SHIP** (no blocker/high); its three non-blocking items (explicit `rejectUnauthorized`, the structural
IP-literal guard, and a `rejectUnauthorized` assertion) are all landed here.

**Deliberately still to come in the Broker:** the **mTLS ingress** server (terminating the per-job client identity into
`authorizeIngress`) and the **Stage-2 orchestration** that threads ingress → reconstruct → resolve/pin → connect →
send → read. Then the slice-5 interlocks (budget charge-before-send, windows, emergency-stop, per-target
rate/concurrency/circuit-breakers, hash-chained audit). (The send/read wire lands in **4f** below.)

## Slice 4f — what it proves (this commit)

The Broker's **send/read wire** (`packages/broker/src/wire.ts`) — once `connectPinned` has opened the socket to the
pinned IP, this frames the reconstructed request and reads the response, safely.

- **`serializeRequest` sends EXACTLY the reconstructed request.** It frames the method/target/headers/body to HTTP/1.1
  bytes and invents nothing. Request-splitting is closed at the source: `reconstruct` now screens every curated/session
  header **value** for CR/LF/NUL (in addition to the name), so a crafted header can never inject a second header or a
  second request on the wire.
- **`readBoundedResponse` treats the target's response as hostile and bounds it.** The header section and the body each
  have a hard byte ceiling (`max_response_body_bytes`, §8); an oversize body is **truncated and flagged, and the socket
  destroyed — never fully buffered**. Content-Length, chunked (`Transfer-Encoding`), and connection-close framings are
  all capped identically, across fragmented packet delivery. A malformed status line / header / chunk, an early close,
  or a stalled response **fails closed** with a fixed reason code that never echoes response bytes.

Tests (`packages/broker/test/wire.test.ts`, package at **100%** lines / branch ≥ 90): exact request framing (with body

- query); Content-Length / chunked / close-delimited reads; 204 and HEAD bodyless handling; oversize truncation on all
  three framings and on an unterminated chunk size-line; fragmented (multi-packet) chunk reassembly; and the fail-closed
  matrix (malformed status/header, non-numeric Content-Length, bad chunk size, over-large header section, early close,
  timeout). Plus the reconstruct CR/LF/NUL header-value regression, curated and session.

An adversarial 4-lens review (request-smuggling / response-desync / correctness / test-adequacy) returned **SHIP** — the
request-smuggling vector was pre-closed by the header-value screen. Its four confirmed RFC-correctness fixes are landed
here: chunked overrides `Content-Length` (RFC 9112 §6.1, so a `Content-Length: 0` can't empty a chunked body); a
conflicting duplicate `Content-Length` fails closed; a body that exactly fills the cap is no longer mis-flagged
truncated; and an interim `1xx` head is skipped rather than mistaken for the final response — each with a regression
test (plus pipelined-after-body, fragmented-head, chunk-extension/trailer, and negative-`Content-Length` coverage).

## Slice 4g — what it proves (this commit)

`runStage2` (`packages/broker/src/stage2.ts`) is the Broker's **end-to-end orchestration** (Phase 0 §7.1 steps 7–13 /
doc 10 §3) — the single function that threads every already-reviewed step into the one procedure the broker runs per
request. Its whole job is to enforce the **order**, which is itself a security property, and to fail closed at any step:

1. **verify grant + identity** — the presented spec's `spec_sha256` is recomputed and the grant must bind it (a worker
   cannot present a spec other than the one authorized), and the grant's tenant/engagement/run/job must equal the
   calling job (single-use `jti` consumed);
2. **reconstruct** the wire request from the immutable spec (§7.1 step 8, SI-061);
3. **interlocks** — an injected `beforeEgress` hook (the slice-5 state-recheck + budget charge) runs AFTER reconstruct
   and **before any egress**, so a denial here — like the resolve/reconstruct/grant denials — opens **no socket** (the
   "no packet, not even DNS, leaves before intent/charge" property, SI-055);
4. **resolve + pin** (§6 + §7.1 step 11), **connect + send** to ONLY the pinned IP (§7.1 step 12), **bounded read**
   (§8); and
5. **redirect re-guard** — a 3xx is surfaced as a fresh-spec+grant candidate, **never auto-followed**.

Every dependency is injected (grant key/clock, catalog/secret resolvers, DNS resolver, socket connectors, the interlock
hook), so this is pure composition; any failure short-circuits with a fixed `{stage, reason}` that never carries
response/secret content.

Tests (`packages/broker/test/stage2.test.ts`, package at **100%** coverage): the happy-path thread to a bounded
response; a denial at **each** stage with a fixed `{stage, reason}`; **no socket opened** when grant / reconstruct /
interlock / resolve deny (charge-before-egress); a redirect **surfaced but not auto-followed** (exactly one connect);
spec-mismatch and identity-mismatch rejection; the scheme→transport mapping (http⇒TCP, wss⇒TLS); and the interlock hook
receiving the reconstructed request + claims (order proof).

An adversarial 4-lens review (spec-fidelity / security / correctness / test-adequacy) returned **SHIP** — the step
ordering, spec binding, and no-egress-on-denial were confirmed correct. Its three fail-closed/robustness fixes are
landed here: the `beforeEgress` interlock is now a **required** dependency (the composition cannot reach egress without
the charge slot being invoked — no silent no-op default); a rejecting DNS resolver is mapped to a fixed
`{stage: resolve}` instead of escaping unmapped; and a synchronous throw after connect destroys the socket rather than
leaking it — each with a regression test (plus interlock-runs-before-DNS, single-use-jti-across-runs, a no-leak oracle,
and the redirect hop/`maxHops` bound).

**Deliberately still to come in the Broker:** the **mTLS ingress server** — terminating the per-job client certificate
into the `JobIdentity` that `authorizeIngress` (and thus `runStage2`) consumes — lands in **4h** below. Then the
slice-5 interlocks fill the `beforeEgress` hook (budget charge-before-send, windows, emergency-stop,
rate/concurrency/circuit-breakers, hash-chained audit).

## Slice 4h — what it proves (this commit)

`ingressServer.ts` is the Broker's **mTLS ingress authentication** — its authentication boundary (Phase 0 doc 10 §4.3 /
§7.1 step 6). The broker is not a generic CONNECT proxy: each ingress connection must present a short-lived per-job
mTLS **client certificate** bound to `tenant/engagement/run/job`. This slice is the pure decision layer (the
`tls.createServer` glue is deployment I/O built on it; the handshake-time cert verification is Node's, enforced by the
options this module asserts):

- **Authentication is a handshake control.** `buildIngressServerOptions` sets `requestCert` + `rejectUnauthorized`
  (TLS ≥ 1.2) against the pinned per-job CA, so Node **refuses** at the handshake any client whose certificate is
  missing or not signed by that CA — an unauthenticated peer never reaches the application.
- **The identity is bound, not asserted.** `authorizeConnection` requires Node to have verified the peer
  (`authorized === true`) and then `extractJobIdentity` reads the `JobIdentity` from a **SPIFFE URI SAN**
  (`spiffe://<trust-domain>/tenant/<t>/engagement/<e>/run/<r>/job/<j>`). The certificate must carry **exactly one**
  well-formed job identity — zero ⇒ `no_job_identity`, two distinct ⇒ `ambiguous_identity` — and the SPIFFE trust
  domain can be pinned. Everything unverified / missing / malformed fails closed with a fixed `IngressAuthError` reason
  that never echoes certificate values; a malformed percent-escape is treated as an invalid identity, never an
  unmapped throw.
- **Defense in depth.** The extracted identity is exactly what `authorizeIngress` / `runStage2` require to **equal** the
  grant's `tenant/engagement/run/job` — so the three independent layers (network topology §4.1, the mTLS identity here,
  and the single-use grant) must all agree before a target is contacted.

Tests (`packages/broker/test/ingressServer.test.ts`, package at **100%** coverage): the extraction matrix (valid SAN
ignoring DNS/IP SANs, percent-decoding, non-SPIFFE / wrong-shape / wrong-key / malformed-URI / malformed-escape all
denied, distinct-vs-identical duplicate URIs, trust-domain pin); the connection authorizer (unverified ⇒
`not_authorized`, empty cert ⇒ `no_client_cert`, extraction-denial propagation, no-leak error message); and the server
hardening options. The `tls.createServer(...).listen(...)` wiring and a real client-cert-rejection handshake are Node's
behaviour enforced by the asserted options.

## Slice 5a — what it proves (this commit)

The **budget charge-before-send ledger** + durable intent (Phase 0 doc 04 §8 / §8.1, §7.1 step 10) — the first
interlock, filling the broker's now-REQUIRED `beforeEgress` hook. It makes **`sent ⇒ charged`** hold and
sent-but-uncharged traffic impossible (SI-017, SI-055, SI-062).

Migration `0004` (`db/`) persists the ledger and its guarantee **in the database**, not prose:

- **`budget_reservation` (§8.1) + `budget_reservation_transition()`.** An identifiable, fenced, owned lease per grant
  `jti`, run through a **conservative charge-before-send state machine** enforced by an explicit transition trigger:
  `claimed → charged` is the **one** irreversible `request_budget_used += 1`; `charged` is **terminal** (never
  released / expired / re-claimed / un-charged); `charged_at` is write-once; a transition needs the **current owner
  AND fence token** (a stale fence is rejected); a **live** claim can never be stolen, while an **expired** claim is
  taken over only by strictly advancing the fence (fencing the old owner); the sweeper expires **only** past-deadline
  `claimed` leases and never touches `charged`/`released`.
- **`engagement_runtime_counter` (§8).** The authoritative per-engagement monotonic `fence_seq` (+ the
  rate/concurrency/circuit fields later interlocks fill). `budget_charge_and_intent()` takes its `FOR UPDATE` lock so
  the availability check and the charge cannot race, re-checks **e-stop** under the lock (fail-closed hard gate),
  verifies `availability = total − used − live-claimed > 0`, allocates the fence token, writes the claim, charges it,
  and appends the durable **`request.intent`** — ALL in one transaction, **before any DNS/TCP/TLS**. Any denial
  (exhaustion / e-stop) or failure RAISEs and rolls the whole thing back — nothing was sent.
- **`audit_append()` — atomic hash-chained append (§9).** The intent is a tamper-evident `audit_event` on the
  engagement chain: the function locks the chain head, derives `seq = head_seq + 1`, `prev_hash = head_hash`, computes
  `payload_sha256` and the chained `event_hash`, and advances the head — the operator cannot forge the position or the
  hashes. (This primitive is reused by the broader audit wiring in a later sub-slice.)

The broker side (`packages/broker/src/budget.ts`) is the pure `beforeEgress` interlock over an **injected**
`BudgetLedger` port (no Postgres in the broker package, exactly like the socket/DNS layers): it assembles the charge
from the verified grant claims + reconstructed request, and **fails closed** — an exhaustion/e-stop outcome or ANY
ledger throw raises a fixed-reason `BudgetError`, so `runStage2` denies at the `interlock` stage and opens **no
socket**; only a committed charge hands the receipt to the informational completion step (which never alters the
charge).

Tests: `db/test/budget_ledger.test.ts` (21 DB-gated cases) — the atomic charge + used-increment + fence allocation +
hash-chained intent; the exhaustion / live-claim-reserves-capacity / expired-claim-frees-capacity / e-stop /
invalid-TTL gates; the full transition matrix (terminality, write-once `charged_at`, owner+fence gating, renew vs
fenced takeover vs live-claim theft, sweeper deadline); jti-uniqueness, DELETE-revocation, the composite spec FK, RLS
isolation, and audit identity + append-only tamper evidence. `packages/broker/test/budget.test.ts` (broker at
**100%** coverage) — the charge assembly, the deny/throw fail-closed paths, and the no-leak `BudgetError`; plus a
`runStage2` integration proving the interlock's fixed reason surfaces as `{stage:'interlock', reason:'budget_exhausted'}`
with no socket opened.

**Deliberately still to come in slice 5:** e-stop / window / expiry re-checks at grant-mint (Stage-1) and the
`claimed`-lease **sweeper** job; per-target rate / concurrency / circuit-breakers (the runtime-counter fields);
the broker wiring that emits the remaining hash-chained audit events (`scope.decision.*`, `request.completed`);
WebSocket per-connection bounds; and approval policy + dual control at request time.

## Slice 5b — what it proves (this commit)

The Stage-2 **live-state gate** (§2.3 effective-window rule / §7.1 step 9) + the **claimed-lease sweeper** (§8.1) —
the clock-derived re-checks that run BEFORE the budget charge, so a request outside its testing window / after
expiry is denied with no budget charged and no socket opened, and a crashed broker's stranded claim is reclaimed.

- **Pure live-state evaluator** (`packages/broker/src/livestate.ts`). `evaluateLiveState` decides, on the injected
  trusted-clock instant, the effective-window rule fail-closed and **deny-by-default**: revocation → expiry (the
  `expires_at` boundary is _expired_) → not-yet-effective deny first; a `blackout` covering `now` **wins** over any
  allow-window; and an allow-window is **REQUIRED** — `now` must fall inside at least one `recurring_weekly` / `one_off`
  window, so an engagement with no allow-window (or an empty window set) can test at **no** time. Windows and DST are
  resolved in the **engagement timezone** via `Intl` before comparison (incl. midnight-wrapping recurring windows).
  It is the pure Stage-2 gate; the Scope Authority reuses the same rule at Stage-1 grant-mint.
- **Composition** (`createLiveStateGate` + `composeBeforeEgress`). The gate is a `beforeEgress` hook that DENIES with a
  fixed-reason `LiveStateError` (`authorization_revoked` / `not_yet_effective` / `authorization_expired` / `blackout` /
  `window_closed`, surfaced by `runStage2` as `{stage:'interlock', reason}`). `composeBeforeEgress(gate, budget)` runs
  the gate FIRST and fail-closed, so a window/expiry denial happens **before** the budget charge — never charging for a
  request that may not run. (e-stop remains the DB hard-gate re-checked UNDER the charge lock, slice 5a.)
- **Claimed-lease sweeper** (`sweep_expired_leases()`, migration `0005`). Transitions **only** past-deadline `claimed`
  leases to `expired` (freeing the ledger state), reusing the 0004 transition trigger which independently rejects any
  expire-after-charge / expire-before-deadline — so the sweeper can never touch a `charged` (terminal) or `released`
  lease or violate charge-before-send even if its predicate were wrong.

Tests: `packages/broker/test/livestate.test.ts` (14 cases; broker package still **100%** coverage) — every deny reason,
the allow paths (recurring same-day + one_off), the midnight-wrap window, blackout-wins-over-allow, the timezone
resolution (a New-York-evening instant that is a different UTC day), and the gate/compose fail-closed ordering. A
`runStage2` integration proves the composed gate denies `window_closed` **before** the ledger is consulted (no charge,
no socket). `db/test/budget_ledger.test.ts` (sweeper cases) — the sweeper expires only past-deadline claims, leaves
live/charged/released untouched, stamps `resolved_at`, and is idempotent; `migrate:ci` covers `0005`'s exact inverse.

**Deliberately still to come in slice 5:** per-target rate / concurrency / circuit-breakers (the runtime-counter
fields); the broker wiring that emits the remaining hash-chained audit events (`scope.decision.*`, `request.completed`);
WebSocket per-connection bounds; approval policy + dual control at request time; and the Stage-1 reuse of this same
window/expiry rule at grant-mint.

## Slice 5c — what it proves (this commit)

The **egress-slot throttle** (§8) — the third pre-egress interlock: before a request leaves, the broker ACQUIRES a
slot bounded by the engagement's runtime posture, and RELEASES it (feeding the circuit breaker) on completion.

- **Pure decision core** (`packages/broker/src/throttle.ts`). `evaluateAcquire` decides in order — **CIRCUIT** (an
  `open` breaker within its cooldown denies; once the cooldown elapses exactly one `half_open` probe is let through)
  → **CONCURRENCY** (`in_flight >= max_concurrency` denies) → **SPACING** (`now - last_request_at <
min_request_interval_ms` denies); only a full allow reserves a slot. `recordResult` is the breaker transition on
  completion: a success closes it and clears the error run; a failed `half_open` probe re-opens immediately; a `closed`
  breaker opens once consecutive failures reach the threshold.
- **Broker gate** (`createThrottleGate`). A `beforeEgress` hook over an injected `ThrottleController` that DENIES with
  a fixed-reason `ThrottleError` (`circuit_open` / `concurrency_exceeded` / `min_interval`, surfaced by `runStage2` as
  `{stage:'interlock', reason}`) or on any controller throw (fail-closed). The slot is released by the caller after the
  request completes, which also drives the breaker.
- **Atomic DB layer** (`acquire_egress_slot` / `release_egress_slot`, migration `0006`). The same logic executed
  atomically over `engagement_runtime_counter` under its `FOR UPDATE` lock, so concurrent acquires cannot over-admit
  past `max_concurrency` and the breaker transitions cannot race. `in_flight` is floored at 0 on release.

Tests: `packages/broker/test/throttle.test.ts` (14 cases; broker package still **100%** coverage) — the decision
order, the half-open probe, the breaker transitions, and the gate's fixed-reason fail-closed denial; a `runStage2`
integration proving the throttle gate denies (`concurrency_exceeded`) with no socket. `db/test/throttle.test.ts`
(7 DB-gated cases) — the concurrency cap + slot-free-on-release, `in_flight` floor, min-spacing denial, the full
circuit lifecycle (threshold-open → cooldown-deny → half-open probe → close-on-success / re-open-on-probe-failure),
sub-threshold accumulation, and RLS; `migrate:ci` covers `0006`'s exact inverse.

**Deliberately still to come in slice 5:** per-HOST concurrency + the global/per-host **RPS token buckets** (need
per-host runtime state); the broker emission of the remaining hash-chained audit events; WebSocket per-connection
bounds; approval policy + dual control at request time; and the Stage-1 reuse of the window/expiry rule at grant-mint.

## Slice 5d — what it proves (this commit)

The **request-rate token buckets** (§8) — the rate-limiting pre-egress interlock. Every request must draw a token from
BOTH the engagement-GLOBAL bucket (`global_max_rps`) and the PER-HOST bucket for its target host (`per_host_max_rps`).

- **Pure token-bucket core** (`packages/broker/src/ratelimit.ts`). `refillAndTake` refills a bucket by the elapsed
  time at its rate (capped at a burst `capacity`) and draws one token if ≥ 1 is available. `evaluateRateLimit` draws
  from the global then the per-host bucket **check-both-then-consume-both**: a token is consumed from EACH only when
  BOTH can satisfy the request, so a global-allowed / host-denied request never leaks a global token (or vice-versa).
- **Broker gate** (`createRateLimitGate`). A `beforeEgress` hook over an injected `RateLimiter` that DENIES with a
  fixed-reason `RateLimitError` (`rate_limited_global` / `rate_limited_host`, surfaced by `runStage2` as
  `{stage:'interlock', reason}`) or on any limiter throw (fail-closed). The per-host bucket is keyed by the
  RECONSTRUCTED request's canonical host — the address the broker will actually dial.
- **Atomic DB layer** (`rate_bucket` + `take_rate_tokens`, migration `0007`). One row per `(engagement, scope)` —
  `scope = 'global'` for the engagement bucket or the host for a per-host bucket. `take_rate_tokens` reads the rates
  from the engagement, get-or-creates + locks both buckets in a FIXED order (global, then host — no deadlock), refills
  and requires ≥ 1 token in BOTH before consuming, and RAISEs a fixed reason otherwise. A fresh bucket is born full;
  capacity = `GREATEST(1, rate)` so a sub-1-rps rate can still ever admit a request. Persisted only on a full allow —
  a denial rolls back, so no bucket loses accrued time and no token leaks.

Tests: `packages/broker/test/ratelimit.test.ts` (11 cases; broker package still **100%** coverage) — the bucket
refill/draw incl. capacity cap and a fractional rate, the global-then-host combined draw with no token leak, and the
gate's fixed-reason fail-closed denial; a `runStage2` integration proving the rate gate denies (`rate_limited_host`)
with no socket. `db/test/ratelimit.test.ts` (6 DB-gated cases) — the global-cap exhaustion, per-host bucket
independence, the check-both-consume-both no-leak invariant, time-based refill, `invalid_host` / `unknown_engagement`,
and RLS; `migrate:ci` covers `0007`'s exact inverse.

**Deliberately still to come in slice 5:** per-HOST concurrency (a per-host version of the 5c semaphore) and reworking
the in-flight counter into a crash-safe lease; the broker emission of the remaining hash-chained audit events;
WebSocket per-connection bounds; approval policy + dual control at request time; and Stage-1 reuse of the window/expiry
rule at grant-mint.

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
