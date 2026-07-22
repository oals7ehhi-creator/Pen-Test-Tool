# Phase 0 design-consistency checks

`check_phase0_docs.py` is a **machine-checkable consistency gate** for the Phase 0 design
package (`docs/phase-0/00-*.md … 11-*.md`). It has no third-party dependencies.

```bash
python3 docs/phase-0/consistency/check_phase0_docs.py   # exit 0 = consistent, 1 = drift
```

It asserts, among other things:

- **No stale contradictions** — metadata never "reachable via allowlist / exact /32"; grants never
  "bind a resolved IP at mint"; the queued object is never a grant (grants are minted just-in-time);
  budget is never "decremented at enqueue"; no IPv6-broken address-sum breadth ceiling.
- **Safety-invariant integrity** — the index table matches the invariant bodies exactly, ids are
  contiguous `SI-001..SI-NNN`, none duplicated; counts claimed in `00-overview.md` match reality.
- **Cross-reference resolution** — every `SI-`/`T-`/`FR-`/`ADR-` reference and every internal doc link
  resolves to something that exists.
- **Approval-policy agreement** — the `request_type → (threshold, approver roles)` table in
  `04` §10 matches the one in `09-rbac-matrix.md`.
- **Round-3 model present** — `request_spec` + `spec_sha256`, just-in-time grant minting, broker
  reconstruction, conservative charge-before-send budget leases, and WebSocket caps are described where required.
- **Assertion-specific semantic detectors (round 6)** — each stale statement fixed in a revision round
  (e.g. "grant binds the exact request line", "reserve-at-mint / commit-on-send", metadata lumped with
  allowlist-able third-party infra, tool sandboxes reaching "destinations the broker permits per grants")
  has a detector that flags it as a *live* claim, plus a negative fixture proving the detector fires. The
  budget/race semantics (charge-before-send state machine, owned/fenced leases, sweeper exclusions,
  audit-chain tenant/engagement binding, non-circular dynamic approval bootstrap) are asserted structurally.
- **Code-fence balance** per file.

**CI usage.** This script is wired into CI from Phase 1 (see `06-acceptance-criteria.md` Phase 1)
and is a release gate in Phase 12: a non-zero exit fails the build, so documentation drift cannot
merge or ship. It is design-doc tooling and is exempt from the "no implementation code in Phase 0"
rule — it produces no product behavior, only a pass/fail on the specification.
