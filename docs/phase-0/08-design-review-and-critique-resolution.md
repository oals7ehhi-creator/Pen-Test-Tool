# Phase 0 — Adversarial Design Review & Critique Resolution

> **Phase 0 design artifact — no implementation code.** This document is the security-review record for the Phase 0 design package. An adversarial reviewer red-teamed the *design* (not any target) for ways an operator or attacker could push the tool out of scope, leak data, or cross tenants. Every finding below is either resolved by a change captured in the other Phase 0 documents or explicitly accepted with rationale.

## 1. Overall assessment (reviewer)

The Phase 0 design was assessed as "unusually strong and internally consistent" at the level of *"a worker makes an HTTP request through the egress choke point."* Deny-by-default, the single-egress-choke-point, scope-hash binding of authorization, immutable audit, and the safety-invariant catalog were called out as genuinely good.

The review found **one load-bearing blind spot** and a set of secondary gaps. The design originally reasoned almost entirely about the *native-check request path* and did not reconcile that model with the two components that make most requests in a real scan: **(1) sandboxed third-party tools reaching HTTPS targets through a CONNECT proxy**, and **(2) a JavaScript-executing / headless crawler**. For both, "the broker re-validates every request, every redirect, every path" is not physically enforceable as originally described, because the broker sees only an encrypted tunnel (or the browser does its own DNS and subrequests). Secondary findings covered redaction failing open, several "technically enforced" claims that are actually approval controls, no dual control on the authorization gate, and under-specified fail-closed behavior.

All findings have been folded back into the Phase 0 deliverables. The additions are: **8 new threats (T-029–T-036)** in the threat model, **12 new/strengthened safety invariants (SI-041–SI-052)**, and the canonical enforcement-model reconciliation in §3 below.

## 2. Load-bearing decision — the tool / browser egress-inspection model

This is the finding to fix first; it silently undercut SI-003/SI-005/SI-010 for the bulk of real scan traffic.

**Decision (adopted).** Two enforcement modes are defined, and **every request-making component is assigned to exactly one**:

- **Native checks and adapter-driven tools → request-by-request driving.** The adapter issues each HTTP request through the Guarded Egress Broker in a form the broker can see (cleartext-to-broker), with **automatic redirect-following disabled**; each redirect hop is a new brokered request that is re-validated for scope, path, and method. This is the default and preferred mode (ZAP API mode, Nuclei with proxy + `-dr`/no-redirect, etc.).
- **Tools that must originate their own HTTPS and cannot be driven request-by-request → broker TLS-termination with a sandbox-only internal CA.** The broker terminates TLS using a CA trusted **only inside that tool's sandbox**, inspects/scopes/redacts the request, then re-originates it to the pinned in-scope IP. This is inspection of *the tool's own egress*, not defeat of the *target's* TLS — the "never bypass TLS defenses" rule is about the target, and is preserved.
- **Headless browser → default-deny netns + broker as sole proxy for ALL request types**, with browser-side DNS disabled (proxy-side resolve + pin), and WebRTC/QUIC/direct-socket features disabled and `file:`/`data:`/`blob:` navigation restricted. **If broker-only egress cannot be guaranteed for the browser, JavaScript execution in the crawler is forbidden** and route discovery falls back to static analysis.

A tool that cannot be constrained to one of these modes is **not permitted to reach targets**. Path/redirect/body invariants are stated to apply *only where the broker can see the request*, and every adapter declares its mode.

This decision is encoded as **SI-041** (browser/tool sole-proxy) and **SI-042** (defined per-request inspection point for HTTPS), threats **T-029** (browser as autonomous request engine) and **T-030** (CONNECT blind spot), and is reflected in the Phase 4 and Phase 6 acceptance gates.

## 3. Enforcement-model reconciliation (naming)

The review flagged that the same concept appeared under three names with slightly different responsibilities. Canonical terms for all Phase 0+ documents:

| Canonical term | Role | Does I/O? | Where DNS resolution & IP pinning happen |
|---|---|---|---|
| **Scope Authority** (was "scope-validation service") | The *single source of truth* for "is (engagement, authz, method, url, ip, port, path, time, approval) permitted?" Mints short-TTL, signed, single-use **Stage-1 egress grants** (round-2 two-stage model, §7 / `10`). | No target I/O; no target DNS. | — (evaluates; does not dial) |
| **Guarded Egress Broker** (was "ScopeGuard egress client") | The *single enforcer* and the *only target-socket creator* in the data plane. Authenticates per-job ingress, re-verifies the grant, resolves DNS, validates and pins the IP **at broker time**, dials it, handles redirects, rate limits, breakers, and split audit. | Yes — the one component that dials targets. | **In the broker, co-located with socket creation** (so the validated IP is the dialed IP; no client-side resolution anywhere). |

All other layers (scheduler, worker, adapter) **call** the Scope Authority and route through the Broker; none re-implements matching or opens its own socket. This removes the "four overlapping checks that can drift permissive" risk the reviewer flagged. The glossary in `00-overview.md` records these terms.

## 4. Findings → resolution traceability

Severity is the reviewer's. "Resolution" points to the concrete change in the Phase 0 package.

| # | Area | Sev | Resolution |
|---|---|---|---|
| G1 | SSRF/scope escape — JS-executing crawler is an uncontrolled request engine | critical | **SI-041**, **T-029**; §2 decision (browser in default-deny netns, broker-only proxy, client DNS off; else no JS). Phase 4 acceptance test: out-of-scope subresource → zero out-of-scope connections. |
| G2 | SSRF/scope escape — HTTPS CONNECT-tunnel blind spot | critical | **SI-042**, **T-030**; §2 decision (request-by-request driving *or* sandbox-only-CA TLS termination; invariants apply only where broker can see the request). Phase 6 gate. |
| G3 | Scope escape — decision-token granularity (no path/method) | high | **SI-043**; token now binds canonical path-prefix and (where restricted) HTTP method. Test: GET /app token cannot be replayed for POST /admin. |
| G4 | Secret leakage / report-data exposure — denylist redaction fails open | high | **SI-045**, **T-034**; inverted to allowlist/minimization, redact-**before**-write to the immutable audit trail. Fuzz corpus with novel-format + URL-embedded secrets. |
| G5 | SSRF — forbidden-range completeness (6to4/Teredo/NAT64; metadata via covering CIDR) | high | **SI-044**, **T-031**; classifier decodes transition forms and re-classifies embedded IPv4. **Revised in round 2 (§7, blocker 1):** cloud metadata is permanent Tier A — NEVER reachable by any allow, elevated entry, or approval (the earlier "exact /32" carve-out is removed). |
| G6 | Scope escape (insider) — no dual control on authorization | high | **SI-047**, **T-035**; dual control (two approvers, never the executing tester) for attestation and any scope expansion; SoD role conflict blocked; document_sha256 pinned. |
| G7 | Inconsistency — "technically enforced" vs operator-defined business-logic checks | high | Resolved honestly (see §5.1): for app-specific/business-logic checks the enforceable controls are approval-gate + method/verb constraints + dry-run plan review + rollback declaration, **not** code-level destructiveness detection. Non-goals and Phase 5 wording corrected. |
| G8 | Fail-safe defaults specified only for the secret store | high | **SI-046**; universal fail-closed for scope verdict, authorization freshness, e-stop state, window/expiry, resolver, and clock. Fault-injection tests kill each dependency and assert zero egress. |
| G9 | SSRF — report/evidence renderer network access | medium | **SI-048**, **T-032**; renderers run with zero network egress, remote-resource loading disabled, strict CSP. |
| G10 | Cross-tenant — object storage isolation weaker than DB RLS | medium | **SI-050**; storage-layer isolation via per-engagement/tenant keys and/or per-tenant buckets/IAM; cross-tenant object-access test. |
| G11 | Tamper-evidence — audit hash-chain key custody | medium | **SI-051**; anchor to WORM / external notary at a bounded interval; separate signing capability from Admin read; document residual rewrite window. |
| G12 | Consistency — IDOR checks vs "no user data as proof" | medium | **SI-048**; access-control checks capture only a non-sensitive discriminator (id existence, status, hashed/length fingerprint); operator test-account data must be synthetic. Non-goal A4 reconciled. |
| G13 | Intake — embedded credentials handling | medium | **SI-048**, **T-036**; credentials in imported HAR/Postman are stripped and never auto-used; only operator-supplied sessions, only against designated in-scope hosts. |
| G14 | Fail-safe — trusted time source | medium | **SI-049**, **T-033**; expiry/window against monotonic + authenticated wall-clock with sanity bounds; unverifiable time fails closed. |
| G15 | Over-engineering — enforcement-point naming drift | medium | §3 reconciliation: one Scope Authority + one Guarded Egress Broker; DNS resolve + pin physically in the broker; all layers call the authority, none re-implement matching. |
| G16 | Supply-chain — offline vuln/SCA feeds under default-deny egress | low | **SI-052**; feeds ingested out-of-band via signature-verified control-plane step, pinned by version, freshness surfaced in reports. |

## 5. Accepted clarifications (honesty over over-claiming)

### 5.1 Destructiveness of app-specific requests is not technically detectable
For **operator-defined business-logic templates**, the platform cannot know that a given app-specific mutation (e.g. `POST /api/transfer`) is destructive. The design **no longer implies** arbitrary destructive operations are code-blocked for these checks. The real, enforceable controls are: **mandatory approval-gate, method/verb constraints on what a template's request primitive can express, dry-run plan review, and a required rollback declaration.** Generic destructive *payloads* (drop/delete/shell/upload-executable) remain technically blocked; app-specific *semantics* are governed by approval + minimized request expressiveness. This is stated in `07-non-goals-and-refusals.md` and Phase 5 acceptance criteria.

### 5.2 Residual risks explicitly retained
- **Collusion of two approvers** is not prevented technically (SI-047 reduces single-actor risk to a two-party act with pinned evidence and immutable audit).
- **A fully compromised host time base or a renderer/browser 0-day** is bounded, not eliminated, by network-layer default-deny and fail-closed halting.
- **Minimization misses** in redaction are permanent once in the immutable audit trail; mitigated by storing only explicitly-safe structured fields and omitting/capping bodies (SI-045).

These are logged in the Phase 0 risk register (`00-overview.md` §7) and carried forward to the Phase 12 known-risk register.

## 6. Reviewer inconsistencies list (status)

| Reviewer inconsistency | Status |
|---|---|
| SI-005/SI-010/body-caps vs CONNECT tunnel | Resolved — SI-042, §2 |
| Token binds IP/port but not path/method | Resolved — SI-043 |
| "Technically prevented" vs operator-defined mutations | Resolved — §5.1 |
| Non-goal A4 vs IDOR evidence capture | Resolved — SI-048, §5 |
| Fail-closed only for secret store | Resolved — SI-046 |
| Enforcement mechanism named three ways | Resolved — §3 |
| SI-006 "exact range" ambiguity for metadata | Resolved — round 2 (§7, blocker 1): metadata is permanent Tier A hard-deny, never reachable by any means (SI-006, SI-044) |

All seven reviewer-identified inconsistencies are resolved in this Phase 0 package.

---

## 7. Round 2 — Phase 0 revision (blockers 1–10)

A second review pass raised ten blockers that had to be resolved before Phase 1. Each is addressed below; new invariants **SI-053–SI-059** and new documents **`09`/`10`/`11`** and **ADR-12–15** carry the changes.

| # | Blocker | Resolution |
|---|---|---|
| 1 | One consistent network policy | Permanent **Tier A** hard-deny (metadata, loopback, unspecified, multicast, broadcast, reserved) — never overridable by any allow/elevated/approval. **Tier B** (RFC1918/ULA/link-local/CGNAT) internal apps supported **only** via elevated dual approval + `internal_testing_granted`; metadata stays Tier A even inside an elevated link-local range. Contradictory wording removed from SI-006, SI-044, T-031, and `07`. (`04` §6, SI-006, SI-044, SI-059) |
| 2 | Two-stage request authorization | The scheduling grant cannot bind a resolved IP before DNS resolution. Redesigned into **Stage-1** (Scope Authority mints a signed, single-use, audience-bound grant binding `iss/aud/sub/job_id/jti/iat/nbf/exp/tenant/engagement/authorization/scope_hash/method/canonical URL+host+port+scheme+path/mode/request_class/approval_ref` — **no IP**) and **Stage-2** (broker resolves DNS, validates every resolved IP, pins it, records it in the completion event). Replay protection via single-use `jti` + short TTL + `aud` binding. (`10`, `04` §7, SI-001, SI-053; ADR-12) |
| 3 | Two-approver approval model | Replaced single `decided_by` with `approval_request` + one `approval_decision` per approver: `required_approvals` threshold (floor 2 for attestation/scope/mode/business-logic), verified approver roles, per-decision plan **and** document-hash binding, and enforced SoD. (`04` §10, SI-047, SI-018, SI-020; ADR-14) |
| 4 | Definitive RBAC matrix | Published one authoritative role×action matrix + approval-authority table, with Reviewer and Administrator approval permissions made explicit (Administrator SoD-separated from engagement approval; Reviewer a valid approver, not an executor). Referenced from FR-002, SI-040, `04` §10, `06`. (`09`) |
| 5 | Schema strengthening | Composite tenant foreign keys on every child table (parent `UNIQUE(id, tenant_id)`); strict per-`entry_class` shape CHECK constraints; explicit host binding (`bound_host_ascii`) for `path_prefix`/`api_resource`; a canonical `scope_hash` over **every** security-relevant semantic field plus breadth counters. (`04` §1, §4.1, §4.2, SI-024) |
| 6 | Networking clarification | Tool/browser sandbox → **broker only**; worker → **narrow internal-service allowlist + broker**, no direct target/internet route; **authenticated per-job broker ingress** (per-job identity/capability matching the grant) — **never a generic CONNECT proxy**. (`10` §4, `03` §3.1/§3.3, SI-053, SI-054, SI-033; ADR-13) |
| 7 | Split audit + non-engagement streams | Request events split into a durable **`request.intent`** (committed before the socket opens) and **`request.completed`/`request.failed`**; three tamper-evident streams — `engagement`, `tenant`, `global` — so login, global emergency stop, tool inventory, role/retention/feed events are all chained. (`04` §9, SI-055, SI-056) |
| 8 | Raw-output retention | **No persistent raw output by default**; findings carry only minimized, allowlisted, redacted evidence. Optional per-engagement debug quarantine: encrypted under the per-engagement DEK, role-restricted, size-capped, short-TTL auto-purged, redacted before any promotion. (`11` §2, SI-057) |
| 9 | Secure deletion vs WORM | **Per-engagement cryptographic erasure** — destroy the per-engagement DEK to make all ciphertext in primary/WORM/backup stores undecryptable without mutating any immutable store; audit trail (redacted, secret-free) retained under its own policy; legal-hold override; verifiable deletion + `dek.destroyed` event; documented audit-anchor residual window. (`11` §3–§4, SI-058, SI-051; ADR-15) |
| 10 | Scope-breadth limits | Enforceable limits + elevated dual approval for broad CIDRs (min prefix, absolute floor /16 v4 & /32 v6), wildcard domains (PSL/apex hard-rejected), host/address ceilings, and **any** scope expansion (dual approval + re-attestation). (`04` §4.6, SI-059, FR-064) |

Canonical component names — **Scope Authority** and **Guarded Egress Broker** — are now used in every document; the earlier "scope-validation service" / "ScopeGuard" terminology has been removed except where a document explicitly notes the supersession for traceability.

---

## 8. Round 3 — Phase 0 revision (six semantic blockers)

A third review pass raised six deeper semantic blockers about the two-stage flow and its data model. Each is resolved with concrete pseudo-DDL **and** acceptance criteria (a blocker is only claimed resolved where the schema and exit tests actually enforce it). New invariants **SI-060–SI-063**, threats **T-037/T-038**, and **ADR-16/17/18** carry the changes; a committed **machine-checkable consistency checker** (`consistency/check_phase0_docs.py`) guards against regression.

| # | Blocker | Resolution (DDL + acceptance) |
|---|---|---|
| 1 | Immutable, fully-hashed queued object + JIT grants | New immutable `request_spec` table (`04` §7.0) with `spec_sha256` over all request-determining fields (UPDATE/DELETE revoked); the queue holds only `(spec_id, tenant_id)`. Grants are minted **just-in-time** at dispatch bound to `spec_sha256`, TTL ≤30s (`04` §7.1, `10` §1–§2). This removes the "short-TTL grant sitting in a queue" contradiction. Enforced by SI-060; exit tests: queue holds no grant, mutating a queued spec fails the mint, grant TTL bounded. |
| 2 | Broker reconstructs & normalizes requests | Stage-2 step 8 (`04` §7.1) rebuilds the wire request deterministically from the signed spec (method, canonical URL, fixed header-set, inert payload, session-by-reference) and asserts equality; the broker never sends a worker-serialized request. SI-061, ADR-17; exit test: a divergent worker-serialized request is ignored / hash-mismatch rejected. |
| 3 | Approval semantics | The unconditional `scope_must_pass` CHECK is made **conditional** — it applies only to within-scope request types; `scope_expansion`/`restricted_range_allow`/`authorization_attestation` (whose targets are not yet in scope) are exempt (`04` §10 DDL + rule 4). Intrusive approvals bind `plan_sha256` to cover each authorized `spec_sha256` (rule 5). Composite tenant FKs added on `linked_scope_version_id`, `linked_audit_event_id`, and `attestation_approval_id`. SI-047/SI-018; exit test: a scope-expansion approval *can* be created for a not-yet-in-scope target. |
| 4 | Audit + budget + window | One budget model: **reserve-at-mint / commit-on-send / release-on-denial** via `engagement_runtime_counter.reserved` (`04` §8), removing the "decremented at enqueue" contradiction. `request.intent` records `spec_sha256` + `jti` + the reserved unit and is committed **in one transaction with the reservation**, before the socket opens (`04` §9). Window/expiry/e-stop re-checked at JIT mint and Stage 2. SI-062/SI-055/SI-017; exit tests: no leak/double-spend, spec-past-window gets no grant. |
| 5 | Tenant-integrity + breadth-accounting | Composite `(id, tenant_id)` FKs everywhere, including the engagement↔authorization↔scope_version and authorization↔attestation cycles via **DEFERRABLE INITIALLY DEFERRED** FKs, and a `UNIQUE(id, tenant_id)` added to `audit_event` (`04` §2.1/§3.1/§9). Breadth redefined to be **computable and IPv6-safe**: `ipv4_equiv_addresses` (Σ `2^(32-prefix)`) + `cidr_entry_count` ceilings for IPv4, IPv6 governed by prefix floors only (no meaningless address sums), exclusions not subtracted (`04` §4.1/§4.6). SI-024/SI-059; exit tests: IPv6 /48 accepted without overflow, exclusions don't reduce counted breadth. |
| 6 | Browser/tool + WebSocket | Autonomous engines are **broker-mediated**: the broker forms a `request_spec` per intercepted request and requests a JIT grant; an out-of-scope subresource/redirect gets no grant (`04` §7.2, `10` §4.4). WebSockets: `kind='websocket'` specs authorize the handshake (scoped/resolved/pinned like HTTP); established connections are bounded by `ws_max_duration_s`/`ws_max_messages`/`ws_max_message_bytes`/`max_ws_connections` and **terminated** on e-stop/window/expiry; no per-message re-target (`04` §7.2/§8, `10` §5). SI-063; exit tests: out-of-scope handshake denied, caps close the socket, interlocks abort active WS. |

**Stale-contradiction sweep & machine-checkable tests.** Every document 00–11 was swept for the superseded phrasings ("grant binds a resolved IP at mint", "enqueue job + grant", "budget decremented at enqueue", IPv6 address-sum ceilings) and corrected. The checker `consistency/check_phase0_docs.py` encodes these as automated assertions plus SI index/body parity, cross-reference resolution, approval-policy agreement between `04` and `09`, and count parity — it is wired as a CI gate (Phase 1) and a release gate (Phase 12) and currently **passes**.

---

## 9. Round 4 — Phase 0 revision (six DDL-level blockers)

A fourth review pass raised six deeper blockers about the data model; each is resolved with concrete pseudo-DDL **and** acceptance criteria. New invariants **SI-064/SI-065**, six new tables (`catalog_template`, `operator_session`, `budget_reservation`, `audit_chain`, `approval_policy`, `approval_manifest_entry`), **ADR-19/20/21**, and **negative-fixture self-tests** in the consistency checker carry the changes.

| # | Blocker | Resolution (DDL + acceptance) |
|---|---|---|
| 1 | Durable intent before any TCP/TLS egress | `04` §7.1 reordered: `request.intent` (with `spec_sha256`, grant `jti`, reservation id, canonical target) is committed **before any egress — before the first DNS query, TCP connect, or TLS** — in one transaction with the reservation (previously it sat after DNS resolution/pin). SI-055 rewritten; `03`/`10` sequences updated; exit test asserts zero packets (incl. DNS) before the intent commit. |
| 2 | Identifiable budget reservations | Bare `reserved` counter replaced by a `budget_reservation` ledger (`04` §8.1): one row per grant `jti`, monotonic `reserved→committed/released`, availability = `total − used − live reservations`, and a crash-expiry sweeper. Commit/release are **idempotent** (no-op on a terminal state); a crashed worker's reservation auto-expires. SI-017 rewritten + SI-062; exit tests for idempotency, crash-expiry, and the concurrency boundary. |
| 3 | Content-addressed templates + repeatable specs | `request_spec` template references (`check`/`tool_template`/`header_set`/`payload`/`ws_frame_set`) are now immutable **content digests** into a new content-addressed `catalog_template`, folded into `spec_sha256` (`04` §7.0). `UNIQUE(tenant_id, spec_sha256)` was **removed** so the same content digest may recur across jobs/runs as distinct instances (a repeat, not a replay — replay is stopped by the single-use `jti` + job binding). SI-065; exit tests: no silent repoint, unknown digest rejected, repeat across jobs allowed. |
| 4 | Immutable approval policy + approved-spec manifest | `required_approvals`/`approver_roles` **removed** from `approval_request` (a requester could set their own) and moved into an immutable, Administrator-versioned `approval_policy` referenced by `approval_policy_id`. `proposed_action`/`plan_sha256` replaced by an explicit `approval_manifest_entry` set of approved `spec_sha256` digests (hashed as `manifest_sha256`); §7 Stage-1 mints a grant only if the spec's digest is in the manifest. SI-064; `09` updated (Administrator manages the policy); exit tests for policy immutability and manifest membership. |
| 5 | Audit chains with non-null identity | The old `UNIQUE(stream, tenant_id, engagement_id, seq)` was vacuous for tenant/global streams (Postgres treats the NULL keys as distinct, so `seq` uniqueness was not enforced). Added an `audit_chain` table with a **non-null `chain_key`/`id`**; `audit_event.chain_id NOT NULL` with `UNIQUE(chain_id, seq)` and `UNIQUE(chain_id, event_hash)` (`04` §9). SI-026 updated; exit test: two events with the same `seq` on a tenant/global chain are rejected. |
| 6 | WebSocket frames catalog/approval-controlled | Outbound WS frames must be drawn **only** from an approved, content-addressed inert frame set (a `ws_frame_set` `catalog_template` named by `spec.ws_frame_set_digest`); the broker's frame gate cannot emit a frame outside that set, frame count/size are bounded, and any non-catalog frame requires an approval manifest (`04` §7.2, `10` §5). SI-063 rewritten; exit test: a non-catalog frame is refused. |

**FR/RBAC/raw-retention/network contradictions.** FR-014 updated to the content-addressed spec + JIT + intent-before-egress model; new FR-068–FR-071 added for the immutable policy/manifest, content-addressed repeatable templates, identifiable reservations, and the WS frame catalog. `09` now records Administrator ownership of the immutable `approval_policy` and that approver eligibility is read from it, not from the request. Raw-retention (SI-057) and the two-tier network policy (SI-006/SI-044) were re-swept and remain consistent.

**Machine-checkable negative fixtures.** `consistency/check_phase0_docs.py` now (a) adds schema-pattern checks for the round-4 anti-patterns — `UNIQUE(tenant_id, spec_sha256)`, requester-supplied `required_approvals`/`approver_roles` on `approval_request`, a bare `reserved INT` budget authority without the ledger, audit uniqueness on nullable keys without `chain_id`, intent ordered after DNS — and (b) runs a **self-test** that injects each known-bad fixture into the corpus and asserts the detector flags it, so a vacuous (always-passing) checker fails its own build. The checker runs and passes, and every negative fixture is proven to fail.

---

## 10. Round 5 — Phase 0 revision (surgical; no new FR/SI/ADR)

A fifth review pass required **surgical** fixes to exact stale statements — no new FR/SI/ADR entries, only tightened DDL, corrected text, and updated SI *wording*. Per the directive, a negative-fixture/detector was added for **every** stale pattern first, so the corpus **failed before the fixes (28 problems) and passes after**; the checker now runs **19 negative fixtures**, all proven to fail the build.

| Stale statement (before) | Fix (after) | Where |
|---|---|---|
| Reservation created at Stage-1 mint; intent committed after DNS resolution/pin | Reservation creation + durable intent are ONE **broker** transaction **before DNS**, under an atomic `SELECT … FOR UPDATE` budget lock; each reservation is an **owned, fenced lease** (`owner` + monotonic `fence_token`) so a resumed/superseded holder can't double-commit | `04` §7.1/§8.1, `03`, `10`; SI-055/017/062 text |
| `session_ref` excluded with no bound identity; `query_canonical` "redaction-safe" but unbound | Non-secret **`session_digest`** = `sha256(account_id, session_version)` and a **protected `query_value_digest`** (over name→placeholder) are **bound into `spec_sha256`**; raw secret + values injected at the broker | `04` §7.0; SI-065 text |
| Digest FKs `REFERENCES catalog_template(digest)` (kind not enforced); `gated_needs_ref` trusts self-declared `mode` | Composite FKs `catalog_template(digest, kind)` via generated kind columns + `UNIQUE(digest, kind)`; **`approval_required` DERIVED** by trigger from templates' `safety_class`/class (mode is advisory only) | `04` §7.0; SI-064 text |
| One-directional `ws_is_get` (websocket ⇒ ws/wss only) | Bidirectional `kind_scheme` CHECK: `(kind='http') = (scheme IN ('http','https')) AND (kind='websocket') = (scheme IN ('ws','wss'))` | `04` §7.0 |
| Requester-adjacent policy trust; manifest mutable; no role quorum; dynamic requests undefined | Pin the **current, non-superseded** `approval_policy`; enforce **`role_quorum`** (per-role minimums); **freeze + trigger-verify** the manifest before any decision; define **pause/approve/resume** for broker-mediated dynamic requests | `04` §7.2/§10; SI-064 text |
| `audit_chain.chain_key` a plain NOT NULL text; `related_event_id` not constrained to a chain | `chain_key` is **GENERATED ALWAYS AS** a per-scope identity (one chain per scope); `related_event_id` has a **same-chain composite FK** `audit_event(id, chain_id)` with `UNIQUE(id, chain_id)` | `04` §9; SI-026 text |
| Draft/window/scope gaps | `draft` engagements cannot hold active pointers; one_off/blackout windows require `start_at < end_at` (and recurring `start_local <> end_local`); an `elevated` domain entry must be a wildcard | `04` §2.1/§2.3/§4.2 |

**Negative fixtures (test-first).** `consistency/check_phase0_docs.py` gained detectors + fixtures for each of the above (reservation-at-mint, mode-trusted approval, single-column catalog FK, missing `session_digest`/`fence_token`/`manifest_frozen`/`role_quorum`/`start_at < end_at`, related-event chain FK removed). Run against the pre-fix corpus these detectors reported **28 problems**; after the fixes the checker exits 0 with all **19** fixtures proven to fail — so the gate is demonstrably non-vacuous for the round-5 changes too.
