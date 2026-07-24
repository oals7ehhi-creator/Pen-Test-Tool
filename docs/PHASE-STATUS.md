# Phase status

| Phase | Title                                                               | Status                                                                                                   |
| ----- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| 0     | Requirements, threat model, architecture, safety invariants, schema | **APPROVED** (commit `73cfbbb`; `check_phase0_docs.py` green — 0 problems, 60/60 negative fixtures fire) |
| 1     | Secure Project Foundation                                           | **READY FOR REVIEW** (not approved — see `docs/phase-1/`)                                                |
| 2+    | (see `docs/phase-0/06-acceptance-criteria.md`)                      | not started                                                                                              |

## Phase 0 — approved

The Phase 0 design package (`docs/phase-0/00-*.md … 11-*.md`) is frozen and approved as the
authority for all later phases. The machine-checkable consistency gate
(`docs/phase-0/consistency/check_phase0_docs.py`) passes and is wired into CI (Phase 1). Phase 0 is
**not reopened** during implementation unless an implementation test reveals a critical blocker in the
design itself; ordinary implementation detail is resolved in the relevant phase.

Everything built from Phase 1 onward is subordinate to the Phase 0 safety model: deny-by-default,
authorization-first, non-destructive, technically-enforced. See `docs/phase-0/05-safety-invariants.md`.

## Phase 1 — ready for review (not approved)

The Phase 1 Secure Project Foundation is implemented and submitted for review. It delivers real
authentication (cryptographically verified HS256 sessions with pinned algorithm/issuer/audience and
idle ≤ 30 min / absolute ≤ 12 h lifetime limits; role exclusively from verified claims), a fail-closed
signing-key reference→material resolution boundary, default-deny RBAC across exactly the five roles proven
end-to-end through the HTTP handler, secret-safe allowlist logging (SI-045), and a CI pipeline whose gates
(lint incl. no-shell, format, typecheck, tests + coverage thresholds, SAST, secret scan, dependency audit,
migration up/down, reproducible install, Phase 0 consistency) each carry an adversarial negative proof where
applicable.

The full evidence package — authentication trust boundary, key/secret management, the recorded no-shell
architectural review, and the criterion → test → CI acceptance matrix — is in
[`docs/phase-1/`](phase-1/README.md). This status is **READY FOR REVIEW**, not approved: the phase gate is
an explicit human review/approval step per the phased-delivery process.
