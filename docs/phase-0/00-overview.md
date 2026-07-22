# Phase 0 — Requirements & Threat Model: Overview and Phase-Gate Report

> **Phase 0 design artifact — no implementation code.** This is the entry point and phase-gate report for Phase 0 of an **authorized, non-destructive, defensive** web-application security assessment platform. Phase 0 is analysis and design only; per the delivery process, no implementation code is written until this phase is reviewed and approved.

## What this platform is (and is not)

An operator-driven platform that automates as much of an **authorized** web-application penetration test as can be done *safely*, while keeping the essential human safety gates. It is **defensive**: it maps a permitted attack surface, runs safe rate-limited checks, correlates and validates findings non-destructively, and produces evidence-backed reports and retests.

It deliberately does **not** perform destructive exploitation, persistence, credential theft, C2, DoS, stealth/evasion, WAF/CAPTCHA/auth bypass, phishing, or any action against systems the operator has not proven authorization for. The guiding principle across every document here: **make the unsafe action structurally impossible, not merely discouraged.** Controls are enforced at the network and datastore layers so that application bugs degrade toward *refusing to act* rather than acting unsafely.

## 1. Deliverables completed (Phase 0)

| # | Deliverable | Document |
|---|---|---|
| 1 | Functional & non-functional requirements — **71 FR + 37 NFR**, traceable IDs, per-phase ownership | `01-requirements.md` |
| 2 | Threat model — **16 assets, 11 actors, 8 trust boundaries, 14 data flows, 38 threats, 12 abuse cases, 17 failure modes**; all 10 mandated named threats covered | `02-threat-model.md` |
| 3 | Architecture & technology stack — two-plane design, single egress choke point, immutable-spec + JIT two-stage authorization, ADR-candidates | `03-architecture.md` |
| 4 | Authorization & scope schema — the safety backbone (engagement, authorization, scope, canonicalization, immutable `request_spec` + JIT two-stage procedure, split audit, dual-control approval, computable breadth limits) | `04-authorization-and-scope-schema.md` |
| 5 | Safety invariants — **65 absolute, test-enforced invariants (SI-###)** | `05-safety-invariants.md` |
| 6 | Phase-gate acceptance criteria for **Phases 1–12** (objective, criteria, exit tests, safety gates) | `06-acceptance-criteria.md` |
| 7 | Explicit non-goals & refusal/safe-alternative map | `07-non-goals-and-refusals.md` |
| 8 | Adversarial design review & critique resolution (security-review findings) | `08-design-review-and-critique-resolution.md` |
| 9 | **Definitive RBAC matrix** — one authoritative role/action table + approval-authority policy | `09-rbac-matrix.md` |
| 10 | **Request authorization flow** — two-stage egress-grant tokens & authenticated per-job broker ingress | `10-request-authorization-flow.md` |
| 11 | **Data retention & deletion** — raw-output handling, retention classes, per-engagement cryptographic erasure | `11-data-retention-and-deletion.md` |
| ✓ | **Machine-checkable consistency gate** — dependency-free checker over docs 00–11 (SI parity, cross-refs, approval-policy agreement, contradiction scans) | `consistency/check_phase0_docs.py` |

## 2. Architectural decisions (summary; full rationale in `03-architecture.md` §8)

- **ADR-1/2 — Single Guarded Egress Broker + network-layer default-deny egress.** The data plane has *no route to the internet except the broker*. "Don't go out of scope" becomes a network-topology invariant, not a check that can be forgotten. Even a fully compromised scanner can only reach the broker.
- **ADR-3 — DNS resolve-and-pin in the broker.** The broker resolves the hostname, validates *every* resulting A/AAAA record, and dials the exact validated IP (SNI = original host). Closes DNS rebinding.
- **ADR-4 — Immutable-spec + JIT two-stage authorization.** The queued object is an **immutable, fully-hashed `request_spec`**; the Scope Authority mints a signed, single-use, ≤30s grant **just-in-time at dispatch**, bound to `spec_sha256` (not a re-listed request line, never a resolved IP). The Guarded Egress Broker verifies `grant.spec_sha256 == sha256(spec)`, **reconstructs** the request from the spec, and validates+pins every resolved IP at Stage 2 (ADR-12/16/17). One place to reason about "permitted"; grants never sit in the queue. See `10-request-authorization-flow.md` (SI-001, SI-053, SI-060, SI-061).
- **ADR-5 — Postgres-backed transactional job queue.** A job and its scope/budget precondition commit atomically — an out-of-scope job cannot exist in the queue.
- **ADR-6 — Row-Level Security for tenant isolation**, with storage-layer isolation for evidence (SI-050).
- **ADR-7/8 — gVisor/Firecracker sandboxes; structured job specs + pinned template registry; adapters use argv arrays with allowlisted flags.** Eliminates command-injection and arbitrary-CLI classes by construction; no shell exists in the execution path.
- **ADR-9/10/11 — Hash-chained WORM-anchored audit; allowlist redaction before write; Rust safety kernel / TS control plane / Go workers; pinned, digest-verified tools.**
- **ADR-12/13/14/15 (revision round 2).** Two-stage authorization with broker-time IP binding; authenticated per-job broker ingress (never a generic CONNECT proxy); dual-control (N-of-M) approval for the legal gate; per-engagement cryptographic erasure reconciling secure deletion with WORM/backups. See `03` §8.
- **ADR-16/17/18 (revision round 3).** Immutable, fully-hashed `request_spec` as the queued object with just-in-time grant minting; broker reconstruction of the request from the signed spec; explicit WebSocket + reserve/commit/release budget semantics. See `03` §8.
- **ADR-19/20/21 (revision round 4).** Durable intent before any egress + identifiable budget reservations (idempotent commit/release, crash-expiry); content-addressed templates with repeatable specs; immutable approval policy + approved-spec manifest and non-null audit-chain identity. See `03` §8.
- **Egress-inspection model (Phase 0 review decision).** Native checks and drivable tools use request-by-request brokering with redirects disabled; tools that self-originate HTTPS use broker TLS-termination with a sandbox-only CA; headless browsers run broker-only with client DNS off or JS is disabled. See `08` §2.

> **Phase 0 revision (blockers 1–10).** After the first review this package was revised to (1) state one consistent network policy — permanent Tier A hard-deny, Tier B internal apps only via elevated dual approval; (2) redesign the request flow into a two-stage egress-grant model with broker-time IP binding; (3) replace single-approver with dual-control N-of-M approvals; (4) publish one definitive RBAC matrix (`09`); (5) strengthen the schema (composite tenant FKs, strict per-entry shapes, host-bound paths/APIs, a canonical scope hash over every semantic field); (6) clarify networking (tool/browser broker-only, worker narrow internal allowlist, authenticated per-job ingress, no generic CONNECT); (7) split audit request events into intent/completion and add tenant/global streams; (8) minimize raw output with a gated quarantine; (9) reconcile secure deletion with WORM via per-engagement cryptographic erasure; (10) enforce scope-breadth limits and elevated approval. Full traceability in `08` §7.
>
> **Phase 0 revision (round 3).** A third review round then made the queued object an **immutable, fully-hashed `request_spec`** with **just-in-time** grant minting (a short-lived grant can never sit in the queue); made the broker **reconstruct and normalize** the request from the signed spec (no worker-serialized request); and corrected approval, audit, tenant-integrity, breadth-accounting, budget, window, browser/tool, and WebSocket semantics — each backed by concrete pseudo-DDL and acceptance criteria. New invariants **SI-060–SI-063**, threats **T-037/T-038**, ADR-16/17/18, and a committed **machine-checkable consistency checker** (`consistency/check_phase0_docs.py`). Full record in `08` §8.
>
> **Phase 0 revision (round 5, surgical).** A fifth round fixed exact stale statements without adding FR/SI/ADR entries: reservation creation moved into **one broker transaction with durable intent, before DNS**, under an atomic `FOR UPDATE` budget lock with **owned/fenced reservation leases**; a non-secret **`session_digest`** (account + version) and a **protected `query_value_digest`** are now bound into `spec_sha256`; digest FKs enforce **catalog kind + safety class** and approval is **derived** from safety class (not the self-declared `mode`); **`kind`↔scheme** is enforced bidirectionally; approval **pins the current non-superseded policy**, enforces a **role quorum**, and **freezes + trigger-verifies the manifest** before decisions, with **pause/approve/resume** defined for dynamic requests; audit chain identity is **generated per scope** with events and related events **constrained to that chain**; and draft/window/scope constraints were fixed. The consistency checker gained **round-5 negative fixtures** (the corpus fails before these fixes and passes after). Full record in `08` §10.
>
> **Phase 0 revision (round 4).** A fourth round hardened the data model: durable `request.intent` now commits **before any egress** (including DNS); budget is an **identifiable `budget_reservation` ledger** with idempotent commit/release and crash-expiry; all template references are **immutable content digests** folded into `spec_sha256` and specs are **repeatable across jobs/runs** (no false uniqueness collision); approval threshold/roles moved to an **immutable, Administrator-versioned `approval_policy`** with an explicit approved-spec **manifest**; audit chains gained a **non-null `chain_id`** (fixing vacuous NULL-key uniqueness for tenant/global streams); and WebSocket outbound frames are **catalog/approval-controlled**. New invariants **SI-064/SI-065**, ADR-19/20/21, six new tables, and **negative-fixture self-tests** added to the consistency checker so the previous bad statements and schema patterns now fail the build. Full record in `08` §9.

## 3. Tests executed and results

**None — and none were claimed.** Phase 0 is design-only; there is no code to test yet. Per the delivery rules ("do not fabricate successful tests or tool results; clearly identify anything that was not executed"), this phase produces **test *specifications*, not test *runs*.** Every safety invariant (`05`) carries a concrete `Test approach`, and every phase (`06`) carries `Exit tests`. These become the executable suites in Phases 1–10; the release pipeline is required to fail if any safety-invariant test fails or is missing (SI release rule).

The Phase 0 self-check that *was* performed is the **adversarial design review** in `08`, which found one critical class of gap (tool/browser egress inspection) and 15 further findings, all resolved or explicitly accepted here. In addition, the **design-consistency checker** (`consistency/check_phase0_docs.py`) is executable and **was run — it passes**: SI index/body parity (63/63, contiguous), cross-reference resolution, approval-policy agreement between `04` §10 and `09`, count parity, and the contradiction scans (no stale "metadata via exact /32", no grant-binds-IP-at-mint, no grant-in-queue, no enqueue-time budget spend, no IPv6 address-sum breadth). It also runs **negative-fixture self-tests** proving each detector actually fails on the bad statements/schema patterns it guards against. This is the only executed result claimed; everything else is a test *specification*.

## 4. Security review findings (Phase 0)

Full record in `08-design-review-and-critique-resolution.md`. Summary: the design was strong for the native request path but originally under-specified enforcement for **HTTPS tool traffic (CONNECT blind spot)** and **headless-browser subrequests**, and had secondary gaps in redaction (fail-open denylist), forbidden-range completeness (IPv6 transition forms), dual control on authorization, universal fail-closed behavior, renderer network access, object-storage isolation, audit key custody, IDOR evidence minimization, intake-credential handling, and trusted time. All are resolved via **T-029–T-036** (threats) and **SI-041–SI-052** (invariants), plus the honest clarification that business-logic destructiveness is governed by approval + minimized request expressiveness, not code-level detection. A second review round then resolved ten further blockers (network-policy consistency, two-stage token flow, dual-control approval, RBAC matrix, schema strengthening, networking clarification, audit-event split, raw-output retention, secure deletion vs WORM, scope-breadth limits) via **SI-053–SI-059**, the new documents `09`/`10`/`11`, and ADR-12–15 — full record in `08` §7. A third round made the queued object an immutable, fully-hashed `request_spec` with just-in-time grant minting and broker reconstruction, and corrected approval/audit/tenant-integrity/breadth/budget/window/browser-tool/WebSocket semantics via **SI-060–SI-063**, T-037/T-038, ADR-16–18, and a committed consistency checker — full record in `08` §8. A fourth round moved durable intent before any egress, made budget an identifiable reservation ledger, content-addressed all templates (repeatable specs), moved approval policy into an immutable table with an approved-spec manifest, gave audit chains a non-null identity, and made WebSocket frames catalog-controlled — via **SI-064/SI-065**, ADR-19–21, and checker negative fixtures. Full record in `08` §9.

## 5. Glossary (canonical terms)

| Term | Meaning |
|---|---|
| **Control plane** | Human-facing services holding authority (auth, RBAC, engagement/scope/authz, approvals, reporting). Never contacts targets. |
| **Data plane** | Network-isolated executors (workers, sandboxes). No authority of its own; no route to the internet except the broker. |
| **Scope Authority** | The single source of truth for "is this permitted?" Mints signed, short-TTL, single-use Stage-1 egress grants. Does no target I/O and no target DNS resolution. |
| **Guarded Egress Broker** | The single enforcer and only target-socket creator in the data plane. Authenticates per-job ingress, verifies the grant, resolves DNS, validates+pins the IP at broker time, dials, handles redirects, rate limits, breakers, split audit. Not a generic CONNECT proxy. |
| **`request_spec`** | The **immutable, fully-hashed** object placed on the queue: the exact request (method, canonical URL/host/port/scheme/path, fixed `header_set_digest`, inert `payload_digest`, protected query keys + `query_value_digest`, non-secret `session_digest`, derived `approval_required`) hashed as `spec_sha256` (the advisory `mode`, `approval_ref`, and `session_ref` are excluded). Created once, never mutated; the queue stores only `(spec_id, tenant_id)`. |
| **Egress grant (Stage-1 token)** | Short-lived (≤30s), single-use, audience-bound signed capability from the Scope Authority, **minted just-in-time at dispatch** and bound to `spec_sha256` (+ ids, mode, approval ref). **No resolved IP and no re-listed request line** — the line is the hashed spec; the IP is validated and pinned at the broker (Stage 2). |
| **Two-stage authorization** | Stage 1 = Scope Authority verifies the spec hash and mints the grant just-in-time (no IP); Stage 2 = Guarded Egress Broker reconstructs the request from the spec, resolves DNS, validates every resolved IP, pins it, and connects. See `10-request-authorization-flow.md`. |
| **Budget reservation ledger** | Budget is an identifiable, owned & fenced `budget_reservation` lease per grant `jti` under a **conservative charge-before-send** state machine: the broker charges the lease (`used += 1`, irreversible) before any byte is sent, so `sent ⇒ charged` and the charged count never exceeds the total; a pre-charge claim is released, a crashed `claimed` lease is swept, and a `charged` lease is terminal (a crash around the send is a conservative over-charge, never sent-but-uncharged). |
| **`catalog_template`** | Global, content-addressed (`digest`), immutable store of checks, tool templates, header-sets, inert payloads, and WebSocket frame-sets. A request references them by digest, folded into `spec_sha256`, so nothing can be silently repointed. |
| **`approval_policy` / manifest** | Threshold + eligible approver roles live in an **immutable, Administrator-versioned** `approval_policy` (not requester fields); an intrusive approval authorizes an explicit **manifest** of approved `spec_sha256` digests, and a grant is minted only if the spec's digest is in that manifest. |
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
