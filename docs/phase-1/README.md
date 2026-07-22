# Phase 1 — Secure Project Foundation (evidence package)

Status: **READY FOR REVIEW** (not approved). This package documents the Phase 1 implementation and maps every
Phase 0 acceptance criterion, exit test, and safety gate to the code, tests, and CI that prove it.

Phase 1 is subordinate to the approved Phase 0 design (`docs/phase-0/`): deny-by-default, authorization-first,
non-destructive, technically enforced.

## Contents

| Doc                                                                                  | Purpose                                                                                                                                                                        |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [`01-authentication-and-key-resolution.md`](01-authentication-and-key-resolution.md) | The authentication trust boundary — what is verified before a caller is trusted — and how the signing-key **reference** is resolved to material without becoming the material. |
| [`02-secret-management.md`](02-secret-management.md)                                 | Production secret management: references vs material, fail-closed resolution, rotation, and the locations secrets must never appear (technically enforced).                    |
| [`03-no-shell-architecture-review.md`](03-no-shell-architecture-review.md)           | Recorded architectural review confirming no API/worker/UI path reaches an OS shell or dynamic-code sink, and the lint gate + adversarial proof that keeps it so.               |
| [`04-acceptance-matrix.md`](04-acceptance-matrix.md)                                 | The Phase 1 acceptance matrix: every criterion / exit test / safety gate → implementation files, tests, and CI evidence.                                                       |
| [`05-risk-and-debt-disposition.md`](05-risk-and-debt-disposition.md)                 | Consolidated risk/technical-debt register: adversarial-review fixes, accepted risks with rationale, and work explicitly deferred to later phases.                              |

## What Phase 1 delivers

- **Real authentication** — protected routes accept identity only from a cryptographically verified HS256
  session (pinned algorithm/issuer/audience; full signature, claim, and idle+absolute-lifetime checks). Role
  comes exclusively from verified claims; no header/query/body can set it. `/healthz` is the only public route.
- **Fail-closed key resolution** — `SESSION_SIGNING_KEY_REF` stays a reference; production refuses to boot on
  unresolved/weak material; non-production uses an ephemeral key so the one-command stack stays usable.
- **Default-deny RBAC** across exactly the five roles, proven through the real HTTP handler for every
  role × route.
- **Secret-safe logging** — a closed allowlist (SI-045) that structurally cannot log tokens, headers, cookies,
  or `Authorization` values.
- **Enforced CI gates** — lint (incl. no-shell), format, typecheck, tests + coverage thresholds, SAST, secret
  scanning, dependency audit, migration up/down, reproducible install, and the Phase 0 consistency check —
  each with an adversarial negative proof (runtime-seeded, self-cleaning, hard-gated) where applicable.

See `docs/phase-1/04-acceptance-matrix.md` for the full evidence map.
