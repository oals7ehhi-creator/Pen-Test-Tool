# Phase 2 — Engagement, Authorization & Scope Engine (in progress)

Phase 1 is **approved and merged** (PR #1 → `main`). Phase 2 implements the authoritative scope and authorization
engine that every outbound request must consult — deny-by-default, exclusions-always-win, SSRF-hardened, with a
single Scope Authority (decision) and a single Guarded Egress Broker (the only target-socket creator). It is
subordinate to the approved Phase 0 design (`docs/phase-0/03`, `04`, `06`, `10`).

Because Phase 2 is large, it is delivered in **tested, CI-green vertical slices**. This document tracks honestly
what is implemented versus what is still to come — nothing here claims a control that is not yet built and tested.

## Slice status

| Slice                             | Scope                                                                                                                                                                                                                                                                               | Status                                     |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| **1 — Scope Authority pure core** | Canonicalization (§5) + two-tier SSRF network guard (§6): decode any obfuscated/transition IP form to canonical bytes and classify `hard_deny` / `restricted` / `permitted`; canonicalize full candidate URLs (scheme/host/port/path, userinfo stripped). Package `@pentest/scope`. | ✅ implemented + tested (`packages/scope`) |
| 2 — Scope-entry matching          | Allow/exclude `domain`/`ip`/`cidr`/`port`/`protocol`/`path_prefix`/`api_resource` matching; exclusions-first; Tier B elevation gating; deny-by-default over a frozen `scope_version`; breadth accounting.                                                                           | ⏳ next                                    |
| 3 — Schema & persistence          | Engagement / authorization / scope_version / scope_entry / approval / audit tables + migrations (composite tenant+engagement FKs, RLS, immutability triggers).                                                                                                                      | ⏳                                         |
| 4 — Two-stage flow                | Immutable content-addressed `request_spec`; JIT single-use Stage-1 grants bound to `spec_sha256`; Guarded Egress Broker (resolve → validate → **pin** → connect → re-guard redirects).                                                                                              | ⏳                                         |
| 5 — Interlocks                    | Budget charge-before-send ledger; testing windows / expiry / emergency-stop; per-target rate/concurrency/circuit-breakers; hash-chained audit; WebSocket bounds; approval policy + dual control.                                                                                    | ⏳                                         |

## Slice 1 — what it proves (this commit)

`@pentest/scope` (`packages/scope`) is the pure, dependency-free SSRF / network-policy chokepoint:

- **Two-tier network guard (§6).** Every candidate address is decoded and classified. **Tier A** (loopback,
  unspecified, cloud/link-local metadata, multicast, broadcast, reserved/future, documentation/benchmark) is
  `hard_deny` and can never be reached. **Tier B** (RFC1918, ULA, link-local, CGNAT) is `restricted` (reachable
  only under full elevation, decided in slice 2). Metadata stays Tier A even inside link-local space.
- **Obfuscation & transition forms decoded (§5.2).** Decimal (`2130706433`), octal (`0177.0.0.1`), hex
  (`0x7f000001`), short forms, IPv4-mapped, deprecated-compat, 6to4, Teredo, and NAT64 all decode to the embedded
  IPv4 and are re-classified — so `::ffff:169.254.169.254` and `http://0x7f000001/` are hard-denied. Zone IDs are
  rejected.
- **Canonicalization (§5).** Host (IDNA/ToASCII, trailing-dot, case; IP-literal hosts are treated as IPs, not
  domains), scheme (only `https/http/wss/ws`), port (scheme defaults), and path (percent-decode unreserved only,
  reject encoded NUL/CR/LF, RFC 3986 dot-segment removal). Full-URL canonicalization strips `user:pass@` userinfo.
- **Fails closed.** Anything the guard cannot decode is `hard_deny`, never `permitted`.

Tests (`packages/scope/test`, coverage-thresholded 90/85/90/90): the SSRF-denial battery (127.0.0.1, `::1`,
10.0.0.0/8, 169.254.169.254, `[::ffff:169.254.169.254]`, `0177.0.0.1`, `0x7f000001`, `2130706433`), Tier A/B
classification, transition-form decoding, and canonicalization fuzz (mixed case, trailing dot, IDN homoglyphs,
`@`-embedded userinfo, encoded path traversal) proving alternate encodings cannot smuggle a different host/path.

**Not yet implemented (do not assume present):** scope-entry allow/exclude matching, the DB schema, the
request_spec / JIT-grant flow, the Guarded Egress Broker, budget/window/e-stop interlocks, and approval/dual-control.
Those are slices 2–5. DNS-rebinding defense is a Broker (slice 4) property — the guard classifies literals now, and
the resolve-validate-**pin** step lands with the Broker.
