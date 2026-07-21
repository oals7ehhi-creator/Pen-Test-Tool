# Phase 0 — Requirements & Threat Model: Overview and Phase-Gate Report

> **Phase 0 design artifact — no implementation code.** This is the entry point and phase-gate report for Phase 0 of an **authorized, non-destructive, defensive** web-application security assessment platform. Phase 0 is analysis and design only; per the delivery process, no implementation code is written until this phase is reviewed and approved.

## What this platform is (and is not)

An operator-driven platform that automates as much of an **authorized** web-application penetration test as can be done *safely*, while keeping the essential human safety gates. It is **defensive**: it maps a permitted attack surface, runs safe rate-limited checks, correlates and validates findings non-destructively, and produces evidence-backed reports and retests.

It deliberately does **not** perform destructive exploitation, persistence, credential theft, C2, DoS, stealth/evasion, WAF/CAPTCHA/auth bypass, phishing, or any action against systems the operator has not proven authorization for. The guiding principle across every document here: **make the unsafe action structurally impossible, not merely discouraged.** Controls are enforced at the network and datastore layers so that application bugs degrade toward *refusing to act* rather than acting unsafely.

## 1. Deliverables completed (Phase 0)

| # | Deliverable | Document |
|---|---|---|
| 1 | Functional & non-functional requirements — **60 FR + 37 NFR**, traceable IDs, per-phase ownership | `01-requirements.md` |
| 2 | Threat model — **16 assets, 11 actors, 8 trust boundaries, 14 data flows, 36 threats, 12 abuse cases, 17 failure modes**; all 10 mandated named threats covered | `02-threat-model.md` |
| 3 | Architecture & technology stack — two-plane design, single egress choke point, ADR-candidates | `03-architecture.md` |
| 4 | Authorization & scope schema — the safety backbone (engagement, authorization, scope, canonicalization, decision procedure, audit, approval) | `04-authorization-and-scope-schema.md` |
| 5 | Safety invariants — **52 absolute, test-enforced invariants (SI-###)** | `05-safety-invariants.md` |
| 6 | Phase-gate acceptance criteria for **Phases 1–12** (objective, criteria, exit tests, safety gates) | `06-acceptance-criteria.md` |
| 7 | Explicit non-goals & refusal/safe-alternative map | `07-non-goals-and-refusals.md` |
| 8 | Adversarial design review & critique resolution (security-review findings) | `08-design-review-and-critique-resolution.md` |

## 2. Architectural decisions (summary; full rationale in `03-architecture.md` §8)

- **ADR-1/2 — Single Guarded Egress Broker + network-layer default-deny egress.** The data plane has *no route to the internet except the broker*. "Don't go out of scope" becomes a network-topology invariant, not a check that can be forgotten. Even a fully compromised scanner can only reach the broker.
- **ADR-3 — DNS resolve-and-pin in the broker.** The broker resolves the hostname, validates *every* resulting A/AAAA record, and dials the exact validated IP (SNI = original host). Closes DNS rebinding.
- **ADR-4 — One Scope Authority issuing signed, short-TTL decision tokens, re-verified at the broker.** One place to reason about "permitted," defense-in-depth via re-check. Tokens bind engagement, authorization, canonical target, resolved IP, port, protocol, **path-prefix, and method** (SI-043).
- **ADR-5 — Postgres-backed transactional job queue.** A job and its scope/budget precondition commit atomically — an out-of-scope job cannot exist in the queue.
- **ADR-6 — Row-Level Security for tenant isolation**, with storage-layer isolation for evidence (SI-050).
- **ADR-7/8 — gVisor/Firecracker sandboxes; structured job specs + pinned template registry; adapters use argv arrays with allowlisted flags.** Eliminates command-injection and arbitrary-CLI classes by construction; no shell exists in the execution path.
- **ADR-9/10/11 — Hash-chained WORM-anchored audit; allowlist redaction before write; Rust safety kernel / TS control plane / Go workers; pinned, digest-verified tools.**
- **Egress-inspection model (Phase 0 review decision).** Native checks and drivable tools use request-by-request brokering with redirects disabled; tools that self-originate HTTPS use broker TLS-termination with a sandbox-only CA; headless browsers run broker-only with client DNS off or JS is disabled. See `08` §2.

## 3. Tests executed and results

**None — and none were claimed.** Phase 0 is design-only; there is no code to test yet. Per the delivery rules ("do not fabricate successful tests or tool results; clearly identify anything that was not executed"), this phase produces **test *specifications*, not test *runs*.** Every safety invariant (`05`) carries a concrete `Test approach`, and every phase (`06`) carries `Exit tests`. These become the executable suites in Phases 1–10; the release pipeline is required to fail if any safety-invariant test fails or is missing (SI release rule).

The Phase 0 self-check that *was* performed is the **adversarial design review** in `08`, which found one critical class of gap (tool/browser egress inspection) and 15 further findings, all resolved or explicitly accepted here.

## 4. Security review findings (Phase 0)

Full record in `08-design-review-and-critique-resolution.md`. Summary: the design was strong for the native request path but originally under-specified enforcement for **HTTPS tool traffic (CONNECT blind spot)** and **headless-browser subrequests**, and had secondary gaps in redaction (fail-open denylist), forbidden-range completeness (IPv6 transition forms), dual control on authorization, universal fail-closed behavior, renderer network access, object-storage isolation, audit key custody, IDOR evidence minimization, intake-credential handling, and trusted time. All are resolved via **T-029–T-036** (threats) and **SI-041–SI-052** (invariants), plus the honest clarification that business-logic destructiveness is governed by approval + minimized request expressiveness, not code-level detection.

## 5. Glossary (canonical terms)

| Term | Meaning |
|---|---|
| **Control plane** | Human-facing services holding authority (auth, RBAC, engagement/scope/authz, approvals, reporting). Never contacts targets. |
| **Data plane** | Network-isolated executors (workers, sandboxes). No authority of its own; no route to the internet except the broker. |
| **Scope Authority** | The single source of truth for "is this permitted?" Mints signed, short-TTL decision tokens. Does no target I/O. |
| **Guarded Egress Broker** | The single enforcer and only socket-creator in the data plane. Re-verifies tokens, resolves DNS, pins the IP, dials, handles redirects, rate limits, breakers, audit. |
| **Decision token** | Short-lived signed proof of an ALLOW verdict, binding engagement, authorization, canonical target, resolved IP, port, protocol, path-prefix, and (where restricted) method. |
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
