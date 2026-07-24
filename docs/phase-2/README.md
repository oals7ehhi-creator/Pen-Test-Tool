# Phase 2 — Engagement, Authorization & Scope Engine (in progress)

Phase 1 is **approved and merged** (PR #1 → `main`). Phase 2 implements the authoritative scope and authorization
engine that every outbound request must consult — deny-by-default, exclusions-always-win, SSRF-hardened, with a
single Scope Authority (decision) and a single Guarded Egress Broker (the only target-socket creator). It is
subordinate to the approved Phase 0 design (`docs/phase-0/03`, `04`, `06`, `10`).

Because Phase 2 is large, it is delivered in **tested, CI-green vertical slices**. This document tracks honestly
what is implemented versus what is still to come — nothing here claims a control that is not yet built and tested.

## Slice status

| Slice                             | Scope                                                                                                                                                                                                                                                                               | Status                                     |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| **1 — Scope Authority pure core** | Canonicalization (§5) + two-tier SSRF network guard (§6): decode any obfuscated/transition IP form to canonical bytes and classify `hard_deny` / `restricted` / `permitted`; canonicalize full candidate URLs (scheme/host/port/path, userinfo stripped). Package `@pentest/scope`. | ✅ implemented + tested (`packages/scope`) |
| **2 — Scope-entry matching**      | Allow/exclude `domain`/`ip`/`cidr`/`port`/`protocol`/`path_prefix`/`api_resource` matching; exclusions-first; Tier B elevation gating; deny-by-default over a frozen `scope_version`; breadth accounting.                                                                           | ✅ implemented + tested (`packages/scope`) |
| **3 — Schema & persistence**      | Engagement / authorization / scope_version / scope_entry / approval / audit tables + migrations (composite tenant+engagement FKs, RLS, immutability triggers).                                                                                                                      | ✅ implemented + tested (`db/`)            |
| 4 — Two-stage flow                | Immutable content-addressed `request_spec`; JIT single-use Stage-1 grants bound to `spec_sha256`; Guarded Egress Broker (resolve → validate → **pin** → connect → re-guard redirects).                                                                                              | ⏳                                         |
| 5 — Interlocks                    | Budget charge-before-send ledger; testing windows / expiry / emergency-stop; per-target rate/concurrency/circuit-breakers; hash-chained audit; WebSocket bounds; approval policy + dual control.                                                                                    | ⏳                                         |

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
