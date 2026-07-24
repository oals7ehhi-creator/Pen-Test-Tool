# Web Application Security Assessment Platform

An **authorized, non-destructive** platform that automates as much of an authorized web-application penetration test as can be done _safely_, while keeping the essential human safety gates. It is a **defensive security** tool: it maps a permitted attack surface, runs safe, rate-limited checks, correlates and validates findings without breaking anything, and produces evidence-backed professional reports and retests.

> ⚠️ **Authorized use only.** This tool may be operated **only** against systems for which the operator holds explicit written authorization. It technically enforces scope, authorization, and non-destructiveness — it is not, and must not be repurposed as, an offensive tool. It does not implement destructive exploitation, persistence, credential theft, command-and-control, denial-of-service, stealth/evasion, WAF/CAPTCHA/auth-control bypass, or phishing. See [Non-Goals](docs/phase-0/07-non-goals-and-refusals.md).

## Design principle

**Make the unsafe action structurally impossible, not merely discouraged.** Scope, egress, isolation, and approval are enforced at the network and datastore layers so that application bugs degrade toward _refusing to act_ rather than acting unsafely. Concretely: the data plane has **no route to the internet except a single Guarded Egress Broker** that re-validates scope, resolves DNS and pins the validated IP (anti-rebinding), re-checks every redirect, rate-limits, and audits every request.

## Operating modes

| Mode                          | What it does                                                                                                                          | Payloads                                 |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| **Passive**                   | Analyze supplied URLs, responses, headers, cookies, certs, JS metadata, OpenAPI, imported proxy traffic                               | None                                     |
| **Safe Active**               | Controlled crawling, endpoint/parameter discovery, harmless reflection & config checks, low-impact validation                         | Non-destructive, strict request limits   |
| **Approval-Gated Validation** | Prepare a validation plan (exact requests, expected impact, rollback, evidence) and execute **only after explicit operator approval** | Non-destructive; never command execution |

There is **no one-click "attack everything"** and **no automatic intrusive validation**.

## Project status — Phase 0 approved; Phase 1 ready for review

This project follows a strict phased delivery process. Each phase stops for review before the next begins.
See [`docs/PHASE-STATUS.md`](docs/PHASE-STATUS.md).

| Phase | Title                                     | Status                      |
| ----- | ----------------------------------------- | --------------------------- |
| **0** | **Requirements & threat model**           | ✅ **Approved** (`73cfbbb`) |
| 1     | Secure project foundation                 | 🔎 **Ready for review**     |
| 2     | Engagement, authorization & scope engine  | ⏳                          |
| 3     | Target intake & passive analysis          | ⏳                          |
| 4     | Safe crawler & attack-surface inventory   | ⏳                          |
| 5     | Safe security check engine                | ⏳                          |
| 6     | Tool integration layer                    | ⏳                          |
| 7     | Finding correlation & validation workflow | ⏳                          |
| 8     | Reporting                                 | ⏳                          |
| 9     | Minimal-effort operator experience        | ⏳                          |
| 10    | Hardening & QA                            | ⏳                          |
| 11    | Deployment & operations                   | ⏳                          |
| 12    | Final review & release                    | ⏳                          |

**Phase 0 deliverables** live in [`docs/phase-0/`](docs/phase-0/README.md): requirements, threat model, architecture, the authorization/scope schema, 65 safety invariants, phase-gate acceptance criteria for Phases 1–12, non-goals, the four-round adversarial design review, the definitive RBAC matrix, the request-authorization flow (immutable spec + just-in-time grants), the data-retention/deletion design, and a machine-checkable [consistency checker](docs/phase-0/consistency/check_phase0_docs.py) (design-doc tooling, not product code). Phase 1 then adds the first product code — the secure project foundation described below — subordinate to this approved design.

Start here: **[docs/phase-0/00-overview.md](docs/phase-0/00-overview.md)**.

## Repository layout

```
.
├── package.json / pnpm-workspace.yaml     # pnpm monorepo root
├── tsconfig.base.json                     # strict shared TS config
├── .env.example                           # secure defaults, no real secrets
├── docker-compose.yml                     # local dev stack: db + api + worker + web (loopback-only, digest-pinned)
├── .github/workflows/ci.yml               # lint · format · typecheck · test · SAST · secret-scan · dep-audit · Phase-0 check · docker stack
├── packages/
│   └── shared/          # safety core: fail-closed config, minimized allowlist logger, default-deny RBAC (+ tests)
├── services/
│   ├── api/             # backend API (verified-session authN, default-deny route authorization, minimized logging)
│   └── worker/          # data-plane worker skeleton
├── apps/
│   └── web/             # operator console (placeholder)
├── db/                  # forward+rollback migration runner + migrations
└── docs/
    ├── phase-0/         # approved Phase 0 design package + consistency checker
    └── phase-1/         # Phase 1 evidence package (authN, secrets, no-shell review, acceptance matrix)
```

## Getting started (Phase 1)

```bash
# one-time
cp .env.example .env            # local dev defaults; contains no real secrets
pnpm install --frozen-lockfile  # deterministic install from the committed lockfile

# verify everything the CI gates check
pnpm run verify                 # format · lint · typecheck · test · Phase-0 consistency check

# bring up the full local stack (Postgres + API + worker + web), loopback-only, waiting for health
docker compose up --build --wait
```

The **safety foundations** every later phase plugs into live in `packages/shared`: configuration is validated at
startup and the app **refuses to boot** on missing/invalid values (fail-closed); all structured logs pass through a
**minimized allowlist** layer (SI-045) that serializes only explicit scalar fields — never whole headers, URLs,
bodies, cookies, tokens, or arbitrary objects — so callers cannot log sensitive material even by accident; and
authorization is **default-deny** across exactly the five roles (Administrator, Engagement Manager, Tester,
Reviewer, Read-only Auditor).

Protected routes accept identity **only** from a cryptographically verified session token (HS256, pinned
algorithm/issuer/audience, full signature + claim + idle ≤ 30 min / absolute ≤ 12 h lifetime checks); the role
comes exclusively from verified claims — no header, query, or body can set it — and `/healthz` is the only public
route. The signing key is referenced, never embedded: production **fails closed** if the reference cannot be
resolved to strong material, while development uses an ephemeral key so the one-command stack stays usable. The
Phase 1 evidence package (authentication trust boundary, secret management, the recorded no-shell review, and the
criterion → test → CI acceptance matrix) is in **[`docs/phase-1/`](docs/phase-1/README.md)**.
