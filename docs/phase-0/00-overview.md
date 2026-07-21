# Phase 0 — Requirements & Threat Model: Overview and Phase-Gate Report

> **Phase 0 design artifact — no implementation code.** This is the entry point and phase-gate report for Phase 0 of an **authorized, non-destructive, defensive** web-application security assessment platform. Phase 0 is analysis and design only; per the delivery process, no implementation code is written until this phase is reviewed and approved.

## What this platform is (and is not)

An operator-driven platform that automates as much of an **authorized** web-application penetration test as can be done *safely*, while keeping the essential human safety gates. It is **defensive**: it maps a permitted attack surface, runs safe rate-limited checks, correlates and validates findings non-destructively, and produces evidence-backed reports and retests.

It deliberately does **not** perform destructive exploitation, persistence, credential theft, C2, DoS, stealth/evasion, WAF/CAPTCHA/auth bypass, phishing, or any action against systems the operator has not proven authorization for. The guiding principle across every document here: **make the unsafe action structurally impossible, not merely discouraged.** Controls are enforced at the network and datastore layers so that application bugs degrade toward *refusing to act* rather than acting unsafely.

## 1. Deliverables completed (Phase 0)

| # | Deliverable | Document |
|---|---|---|
| 1 | Functional & non-functional requirements — **67 FR + 37 NFR**, traceable IDs, per-phase ownership | `01-requirements.md` |
| 2 | Threat model — **16 assets, 11 actors, 8 trust boundaries, 14 data flows, 36 threats, 12 abuse cases, 17 failure modes**; all 10 mandated named threats covered | `02-threat-model.md` |
| 3 | Architecture & technology stack — two-plane design, single egress choke point, two-stage authorization, ADR-candidates | `03-architecture.md` |
| 4 | Authorization & scope schema — the safety backbone (engagement, authorization, scope, canonicalization, two-stage decision procedure, split audit, dual-control approval, breadth limits) | `04-authorization-and-scope-schema.md` |
| 5 | Safety invariants — **59 absolute, test-enforced invariants (SI-###)** | `05-safety-invariants.md` |
| 6 | Phase-gate acceptance criteria for **Phases 1–12** (objective, criteria, exit tests, safety gates) | `06-acceptance-criteria.md` |
| 7 | Explicit non-goals & refusal/safe-alternative map | `07-non-goals-and-refusals.md` |
| 8 | Adversarial design review & critique resolution (security-review findings) | `08-design-review-and-critique-resolution.md` |
| 9 | **Definitive RBAC matrix** — one authoritative role/action table + approval-authority policy | `09-rbac-matrix.md` |
| 10 | **Request authorization flow** — two-stage egress-grant tokens & authenticated per-job broker ingress | `10-request-authorization-flow.md` |
| 11 | **Data retention & deletion** — raw-output handling, retention classes, per-engagement cryptographic erasure | `11-data-retention-and-deletion.md` |

## 2. Architectural decisions (summary; full rationale in `03-architecture.md` §8)

- **ADR-1/2 — Single Guarded Egress Broker + network-layer default-deny egress.** The data plane has *no route to the internet except the broker*. "Don't go out of scope" becomes a network-topology invariant, not a check that can be forgotten. Even a fully compromised scanner can only reach the broker.
- **ADR-3 — DNS resolve-and-pin in the broker.** The broker resolves the hostname, validates *every* resulting A/AAAA record, and dials the exact validated IP (SNI = original host). Closes DNS rebinding.
- **ADR-4 — Two-stage authorization: one Scope Authority mints signed, single-use, short-TTL Stage-1 egress grants; the Guarded Egress Broker binds the resolved IP at broker time.** The grant binds engagement, authorization, canonical URL, **method and path**, port, protocol, mode, and approval ref — but **not** a resolved IP (unknown until the broker resolves DNS). The broker validates and pins every resolved IP at Stage 2 (ADR-12). One place to reason about "permitted"; defense-in-depth via re-check. See `10-request-authorization-flow.md` (SI-001, SI-053).
- **ADR-5 — Postgres-backed transactional job queue.** A job and its scope/budget precondition commit atomically — an out-of-scope job cannot exist in the queue.
- **ADR-6 — Row-Level Security for tenant isolation**, with storage-layer isolation for evidence (SI-050).
- **ADR-7/8 — gVisor/Firecracker sandboxes; structured job specs + pinned template registry; adapters use argv arrays with allowlisted flags.** Eliminates command-injection and arbitrary-CLI classes by construction; no shell exists in the execution path.
- **ADR-9/10/11 — Hash-chained WORM-anchored audit; allowlist redaction before write; Rust safety kernel / TS control plane / Go workers; pinned, digest-verified tools.**
- **ADR-12/13/14/15 (Phase 0 revision).** Two-stage authorization with broker-time IP binding; authenticated per-job broker ingress (never a generic CONNECT proxy); dual-control (N-of-M) approval for the legal gate; per-engagement cryptographic erasure reconciling secure deletion with WORM/backups. See `03` §8.
- **Egress-inspection model (Phase 0 review decision).** Native checks and drivable tools use request-by-request brokering with redirects disabled; tools that self-originate HTTPS use broker TLS-termination with a sandbox-only CA; headless browsers run broker-only with client DNS off or JS is disabled. See `08` §2.

> **Phase 0 revision (blockers 1–10).** After the first review this package was revised to (1) state one consistent network policy — permanent Tier A hard-deny, Tier B internal apps only via elevated dual approval; (2) redesign the request flow into a two-stage egress-grant model with broker-time IP binding; (3) replace single-approver with dual-control N-of-M approvals; (4) publish one definitive RBAC matrix (`09`); (5) strengthen the schema (composite tenant FKs, strict per-entry shapes, host-bound paths/APIs, a canonical scope hash over every semantic field); (6) clarify networking (tool/browser broker-only, worker narrow internal allowlist, authenticated per-job ingress, no generic CONNECT); (7) split audit request events into intent/completion and add tenant/global streams; (8) minimize raw output with a gated quarantine; (9) reconcile secure deletion with WORM via per-engagement cryptographic erasure; (10) enforce scope-breadth limits and elevated approval. Full traceability in `08` §7.

## 3. Tests executed and results

**None — and none were claimed.** Phase 0 is design-only; there is no code to test yet. Per the delivery rules ("do not fabricate successful tests or tool results; clearly identify anything that was not executed"), this phase produces **test *specifications*, not test *runs*.** Every safety invariant (`05`) carries a concrete `Test approach`, and every phase (`06`) carries `Exit tests`. These become the executable suites in Phases 1–10; the release pipeline is required to fail if any safety-invariant test fails or is missing (SI release rule).

The Phase 0 self-check that *was* performed is the **adversarial design review** in `08`, which found one critical class of gap (tool/browser egress inspection) and 15 further findings, all resolved or explicitly accepted here.

## 4. Security review findings (Phase 0)

Full record in `08-design-review-and-critique-resolution.md`. Summary: the design was strong for the native request path but originally under-specified enforcement for **HTTPS tool traffic (CONNECT blind spot)** and **headless-browser subrequests**, and had secondary gaps in redaction (fail-open denylist), forbidden-range completeness (IPv6 transition forms), dual control on authorization, universal fail-closed behavior, renderer network access, object-storage isolation, audit key custody, IDOR evidence minimization, intake-credential handling, and trusted time. All are resolved via **T-029–T-036** (threats) and **SI-041–SI-052** (invariants), plus the honest clarification that business-logic destructiveness is governed by approval + minimized request expressiveness, not code-level detection. A second review round then resolved ten further blockers (network-policy consistency, two-stage token flow, dual-control approval, RBAC matrix, schema strengthening, networking clarification, audit-event split, raw-output retention, secure deletion vs WORM, scope-breadth limits) via **SI-053–SI-059**, the new documents `09`/`10`/`11`, and ADR-12–15 — full record in `08` §7.

## 5. Glossary (canonical terms)

| Term | Meaning |
|---|---|
| **Control plane** | Human-facing services holding authority (auth, RBAC, engagement/scope/authz, approvals, reporting). Never contacts targets. |
| **Data plane** | Network-isolated executors (workers, sandboxes). No authority of its own; no route to the internet except the broker. |
| **Scope Authority** | The single source of truth for "is this permitted?" Mints signed, short-TTL, single-use Stage-1 egress grants. Does no target I/O and no target DNS resolution. |
| **Guarded Egress Broker** | The single enforcer and only target-socket creator in the data plane. Authenticates per-job ingress, verifies the grant, resolves DNS, validates+pins the IP at broker time, dials, handles redirects, rate limits, breakers, split audit. Not a generic CONNECT proxy. |
| **Egress grant (Stage-1 token)** | Short-lived, single-use, audience-bound signed capability from the Scope Authority, binding engagement, authorization, canonical URL, method, path, port, protocol, mode, `jti`, and (where required) an approval ref. **No resolved IP** — that is validated and pinned at the broker (Stage 2). |
| **Two-stage authorization** | Stage 1 = Scope Authority mints the grant (schedule time, no IP); Stage 2 = Guarded Egress Broker resolves DNS, validates every resolved IP, pins it, and connects (execute time). See `10-request-authorization-flow.md`. |
| **Operating mode** | Passive · Safe Active · Approval-Gated Validation (see `07` and `06`). |
| **Safety invariant (SI-###)** | An absolute property automated tests must enforce; the release fails if one is violated. |
| **Elevated scope entry** | An explicit allowlist entry that grants an otherwise-restricted (Tier B) range; never grants a hard-deny (Tier A) range. |

## 6. Known limitations (Phase 0)

- **Design, not build.** These are specifications; correctness of the *implementation* is proven in later phases.
- **Tool-egress model adds constraints.** Preferring request-by-request brokering (or sandbox-only-CA termination) limits which third-party tool features are usable; some tools may be gated out entirely if they cannot be constrained.
- **Business-logic destructiveness is operator-governed**, not technically detected (see `08` §5.1).
- **Two-approver collusion, host-time compromise, renderer/browser 0-days, and redaction minimization misses** are bounded, not eliminated (see §7).
- **Concrete numeric defaults** (exact rate limits, budgets, TTLs, retention) are proposed as ranges here and fixed with data in Phases 2/9/11.

## 7. Risks & mitigations (Phase 0 risk register — carried to Phase 12)

| Risk | Likelihood | Impact | Mitigation | Residual |
|---|---|---|---|---|
| Scope escape via uncontrolled request engine (browser/tool) | medium | critical | SI-041/042, network-layer default-deny netns, broker-only egress | Browser/tool 0-day escaping proxy; bounded by netns |
| Insider self-authorization | medium | critical | SI-047 dual control, SoD, pinned document hash, immutable audit | Two-party collusion |
| Permanent secret leak into immutable audit | medium | high | SI-045 allowlist redaction **before** audit write; bodies omitted/capped | Minimization miss is permanent |
| Fail-open of perimeter under partial outage | low | critical | SI-046 universal fail-closed; fault-injection tests | — |
| Cross-tenant evidence disclosure | low | high | RLS + SI-050 storage-layer isolation | App bug bounded by storage keys/IAM |
| Supply-chain: poisoned tool/template/feed | low | high | SI-052 + ADR-11 pinning, digest verification, isolated sandboxes | Upstream compromise before pinning |
| Clock manipulation extends authorization | low | high | SI-049 monotonic + authenticated time, fail-closed | Full host-time compromise bounded |

## 8. Commands to "run" Phase 0

Phase 0 has no runnable service. To review the deliverables:

```bash
# From the repository root
ls docs/phase-0/                       # all Phase 0 documents
sed -n '1,40p' docs/phase-0/00-overview.md   # this overview

# Read in recommended order:
#   00-overview → 01-requirements → 02-threat-model → 03-architecture
#   → 04-authorization-and-scope-schema → 05-safety-invariants
#   → 06-acceptance-criteria → 07-non-goals-and-refusals
#   → 08-design-review-and-critique-resolution
#   → 09-rbac-matrix → 10-request-authorization-flow
#   → 11-data-retention-and-deletion
```

A CI docs-lint (markdown link/format check) is proposed to land with Phase 1 so these documents stay well-formed as they evolve.

## 9. Approval checkpoint — STOP

Per the phased delivery process, work **stops here and requests approval** before Phase 1.

**Phase 0 exit checklist:**

- [x] Specification converted to functional & non-functional requirements (`01`)
- [x] Users, trust boundaries, data flows, sensitive assets, abuse cases, failure modes identified (`02`)
- [x] Threat model covers all ten named threats: scope escape, SSRF, command injection, malicious scanner output, unsafe plugin execution, secret leakage, cross-tenant access, report-data exposure, queue abuse, supply-chain compromise (`02` §5)
- [x] Explicit non-goals defined (`07`)
- [x] Architecture & technology stack proposed (`03`)
- [x] Authorization & scope schema defined (`04`)
- [x] Safety invariants that automated tests must enforce defined (`05`)
- [x] Acceptance criteria created for every later phase, 1–12 (`06`)
- [x] Adversarial design review completed and findings resolved (`08`)

**To proceed to Phase 1 (Secure Project Foundation), reply with approval.** Phase 1 will scaffold the monorepo (backend API, worker, web UI, DB migrations, typed config, structured logging, authN + RBAC across the five roles, test foundations, containerized dev, dependency locking, secret-management guidance, static analysis/lint/format/CI, and a secure-by-default sample env) — implementation code begins only after this checkpoint is approved.
