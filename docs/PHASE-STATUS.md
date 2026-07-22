# Phase status

| Phase | Title                                                               | Status                                                                                                   |
| ----- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| 0     | Requirements, threat model, architecture, safety invariants, schema | **APPROVED** (commit `73cfbbb`; `check_phase0_docs.py` green — 0 problems, 60/60 negative fixtures fire) |
| 1     | Secure Project Foundation                                           | **IN PROGRESS**                                                                                          |
| 2+    | (see `docs/phase-0/06-acceptance-criteria.md`)                      | not started                                                                                              |

## Phase 0 — approved

The Phase 0 design package (`docs/phase-0/00-*.md … 11-*.md`) is frozen and approved as the
authority for all later phases. The machine-checkable consistency gate
(`docs/phase-0/consistency/check_phase0_docs.py`) passes and is wired into CI (Phase 1). Phase 0 is
**not reopened** during implementation unless an implementation test reveals a critical blocker in the
design itself; ordinary implementation detail is resolved in the relevant phase.

Everything built from Phase 1 onward is subordinate to the Phase 0 safety model: deny-by-default,
authorization-first, non-destructive, technically-enforced. See `docs/phase-0/05-safety-invariants.md`.
