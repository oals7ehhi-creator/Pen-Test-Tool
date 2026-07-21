# Web Application Security Assessment Platform

An **authorized, non-destructive** platform that automates as much of an authorized web-application penetration test as can be done *safely*, while keeping the essential human safety gates. It is a **defensive security** tool: it maps a permitted attack surface, runs safe, rate-limited checks, correlates and validates findings without breaking anything, and produces evidence-backed professional reports and retests.

> ⚠️ **Authorized use only.** This tool may be operated **only** against systems for which the operator holds explicit written authorization. It technically enforces scope, authorization, and non-destructiveness — it is not, and must not be repurposed as, an offensive tool. It does not implement destructive exploitation, persistence, credential theft, command-and-control, denial-of-service, stealth/evasion, WAF/CAPTCHA/auth-control bypass, or phishing. See [Non-Goals](docs/phase-0/07-non-goals-and-refusals.md).

## Design principle

**Make the unsafe action structurally impossible, not merely discouraged.** Scope, egress, isolation, and approval are enforced at the network and datastore layers so that application bugs degrade toward *refusing to act* rather than acting unsafely. Concretely: the data plane has **no route to the internet except a single Guarded Egress Broker** that re-validates scope, resolves DNS and pins the validated IP (anti-rebinding), re-checks every redirect, rate-limits, and audits every request.

## Operating modes

| Mode | What it does | Payloads |
|---|---|---|
| **Passive** | Analyze supplied URLs, responses, headers, cookies, certs, JS metadata, OpenAPI, imported proxy traffic | None |
| **Safe Active** | Controlled crawling, endpoint/parameter discovery, harmless reflection & config checks, low-impact validation | Non-destructive, strict request limits |
| **Approval-Gated Validation** | Prepare a validation plan (exact requests, expected impact, rollback, evidence) and execute **only after explicit operator approval** | Non-destructive; never command execution |

There is **no one-click "attack everything"** and **no automatic intrusive validation**.

## Project status — Phase 0 complete (awaiting approval)

This project follows a strict phased delivery process. Each phase stops for review before the next begins.

| Phase | Title | Status |
|---|---|---|
| **0** | **Requirements & threat model** | ✅ **Complete — awaiting approval** |
| 1 | Secure project foundation | ⏳ Pending approval |
| 2 | Engagement, authorization & scope engine | ⏳ |
| 3 | Target intake & passive analysis | ⏳ |
| 4 | Safe crawler & attack-surface inventory | ⏳ |
| 5 | Safe security check engine | ⏳ |
| 6 | Tool integration layer | ⏳ |
| 7 | Finding correlation & validation workflow | ⏳ |
| 8 | Reporting | ⏳ |
| 9 | Minimal-effort operator experience | ⏳ |
| 10 | Hardening & QA | ⏳ |
| 11 | Deployment & operations | ⏳ |
| 12 | Final review & release | ⏳ |

**Phase 0 deliverables** live in [`docs/phase-0/`](docs/phase-0/README.md): requirements, threat model, architecture, the authorization/scope schema, 63 safety invariants, phase-gate acceptance criteria for Phases 1–12, non-goals, the three-round adversarial design review, the definitive RBAC matrix, the request-authorization flow (immutable spec + just-in-time grants), the data-retention/deletion design, and a machine-checkable [consistency checker](docs/phase-0/consistency/check_phase0_docs.py). No implementation code exists yet — by design (the checker is design-doc tooling, not product code).

Start here: **[docs/phase-0/00-overview.md](docs/phase-0/00-overview.md)**.

## Repository layout (current)

```
.
├── README.md
└── docs/
    └── phase-0/          # Phase 0 design package (no code)
        ├── README.md
        ├── 00-overview.md
        ├── 01-requirements.md
        ├── 02-threat-model.md
        ├── 03-architecture.md
        ├── 04-authorization-and-scope-schema.md
        ├── 05-safety-invariants.md
        ├── 06-acceptance-criteria.md
        ├── 07-non-goals-and-refusals.md
        ├── 08-design-review-and-critique-resolution.md
        ├── 09-rbac-matrix.md
        ├── 10-request-authorization-flow.md
        ├── 11-data-retention-and-deletion.md
        └── consistency/
            ├── check_phase0_docs.py   # machine-checkable doc-consistency gate
            └── README.md
```

The monorepo (backend API, worker service, web UI, database migrations, CI) is introduced in **Phase 1**, only after Phase 0 is approved.
