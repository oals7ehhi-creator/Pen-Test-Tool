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
| **Scope Authority** (was "scope-validation service") | The *single source of truth* for "is (engagement, authz, method, url, ip, port, path, time, approval) permitted?" Mints short-TTL, signed **decision tokens**. | No target I/O. | — (evaluates; does not dial) |
| **Guarded Egress Broker** (was "ScopeGuard egress client" / "Guarded Egress Broker") | The *single enforcer* and the *only socket-creator* in the data plane. Re-verifies the decision token, resolves DNS, pins the validated IP, dials it, handles redirects, rate limits, breakers, and audit emission. | Yes — it is the one component that dials targets. | **In the broker, co-located with socket creation** (so the validated IP is the dialed IP; no client-side resolution anywhere). |

All other layers (scheduler, worker, adapter) **call** the Scope Authority and route through the Broker; none re-implements matching or opens its own socket. This removes the "four overlapping checks that can drift permissive" risk the reviewer flagged. The glossary in `00-overview.md` records these terms.

## 4. Findings → resolution traceability

Severity is the reviewer's. "Resolution" points to the concrete change in the Phase 0 package.

| # | Area | Sev | Resolution |
|---|---|---|---|
| G1 | SSRF/scope escape — JS-executing crawler is an uncontrolled request engine | critical | **SI-041**, **T-029**; §2 decision (browser in default-deny netns, broker-only proxy, client DNS off; else no JS). Phase 4 acceptance test: out-of-scope subresource → zero out-of-scope connections. |
| G2 | SSRF/scope escape — HTTPS CONNECT-tunnel blind spot | critical | **SI-042**, **T-030**; §2 decision (request-by-request driving *or* sandbox-only-CA TLS termination; invariants apply only where broker can see the request). Phase 6 gate. |
| G3 | Scope escape — decision-token granularity (no path/method) | high | **SI-043**; token now binds canonical path-prefix and (where restricted) HTTP method. Test: GET /app token cannot be replayed for POST /admin. |
| G4 | Secret leakage / report-data exposure — denylist redaction fails open | high | **SI-045**, **T-034**; inverted to allowlist/minimization, redact-**before**-write to the immutable audit trail. Fuzz corpus with novel-format + URL-embedded secrets. |
| G5 | SSRF — forbidden-range completeness (6to4/Teredo/NAT64; metadata via covering CIDR) | high | **SI-044**, **T-031**; classifier decodes transition forms and re-classifies embedded IPv4; metadata reachable only via exact /32 or /128, never a covering CIDR. |
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
| SI-006 "exact range" ambiguity for metadata | Resolved — SI-044 (exact /32 or /128 only) |

All seven reviewer-identified inconsistencies are resolved in this Phase 0 package.
