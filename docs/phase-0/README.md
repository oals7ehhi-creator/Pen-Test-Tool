# Phase 0 — Requirements & Threat Model

Design and analysis package for the **authorized, non-destructive web-application security assessment platform**. No implementation code — Phase 0 defines *what* is being built and *why it is safe* before any code is written.

## Read in this order

| # | Document | Contents |
|---|---|---|
| 00 | [Overview & phase-gate report](00-overview.md) | Executive summary, decision log, glossary, risk register, run commands, **approval checkpoint** |
| 01 | [Requirements](01-requirements.md) | 67 functional + 37 non-functional requirements (traceable IDs, per-phase ownership) |
| 02 | [Threat model](02-threat-model.md) | Assets, actors, trust boundaries, data flows, 36 STRIDE threats (all 10 named threats), abuse cases, failure modes |
| 03 | [Architecture & tech stack](03-architecture.md) | Two-plane design, single egress choke point, two-stage authorization, sandboxing, ADR-candidates |
| 04 | [Authorization & scope schema](04-authorization-and-scope-schema.md) | The safety backbone: engagement, authorization, scope, canonicalization, the two-stage decision procedure, two-tier network guard, split audit, dual-control approval, breadth limits |
| 05 | [Safety invariants](05-safety-invariants.md) | 59 absolute, test-enforced safety properties (release fails if any is violated) |
| 06 | [Acceptance criteria](06-acceptance-criteria.md) | Phase-gate criteria, exit tests, and safety gates for Phases 1–12 |
| 07 | [Non-goals & refusals](07-non-goals-and-refusals.md) | What the platform will never do, and the safe defensive alternative for each refused capability |
| 08 | [Design review & critique resolution](08-design-review-and-critique-resolution.md) | Adversarial review (2 rounds); every finding/blocker → resolution with traceability |
| 09 | [RBAC matrix](09-rbac-matrix.md) | The single authoritative role/action matrix and approval-authority policy |
| 10 | [Request authorization flow](10-request-authorization-flow.md) | Two-stage egress-grant tokens and authenticated per-job broker ingress |
| 11 | [Data retention & deletion](11-data-retention-and-deletion.md) | Raw-output handling, retention classes, per-engagement cryptographic erasure |

## The one idea everything follows from

**There is exactly one path to the network, and it is a scope-enforcing choke point no component can bypass.** The data plane has no route to the internet except the Guarded Egress Broker, which re-validates scope, resolves DNS and pins the validated IP, re-checks every redirect, and records every request. Everything else — deny-by-default scope, authorization expiry, rate limits, emergency stop, redaction, approval gates — hangs off that invariant.

## Status

Phase 0 is **complete and awaiting approval**. See the [approval checkpoint](00-overview.md#9-approval-checkpoint--stop). Implementation code begins only in Phase 1, after sign-off.
