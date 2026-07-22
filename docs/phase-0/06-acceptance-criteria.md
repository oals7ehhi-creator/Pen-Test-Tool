# Phase 0 — Phase-Gate Acceptance Criteria (Phases 1–12)
> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

Each downstream phase must satisfy its acceptance criteria, pass its exit tests, and demonstrably enforce its safety gates before the phase is accepted and the next begins. Every phase that touches egress, scope, external tools, or reporting carries the corresponding safety-invariant demonstrations as hard gates.

## Phase 1 — Secure Project Foundation

**Objective.** Establish a reproducible, secure-by-default monorepo (backend API, worker service, web UI, shared packages) with the technical scaffolding every later safety control plugs into: typed config, structured logging with redaction hooks, authN + default-deny RBAC across the five named roles, DB migrations, dependency locking, and a CI pipeline that enforces lint/format/typecheck/SAST/secret-scanning/dependency-audit gates.

**Acceptance criteria.**
- Monorepo bootstraps the full stack (API, worker, web UI, DB) with a single documented command; containerized dev environment (compose) brings everything up without manual patching.
- Typed configuration is loaded from environment and validated against a schema at startup; the app refuses to boot on missing/invalid required config and emits a clear, non-secret error.
- AuthN implemented plus RBAC with exactly the five roles (Administrator, Engagement Manager, Tester, Reviewer, Read-only Auditor); authorization is default-deny — no route/action is reachable without an explicit grant.
- Structured JSON logging with correlation/request IDs is in place, routed through a central redaction middleware so Authorization headers, cookies, tokens, and known secret keys are masked before any sink.
- DB migration framework supports forward + rollback; migrations run in CI against a clean database.
- Dependency lockfiles are committed for every service; a clean checkout installs deterministically.
- CI runs lint, format check, typecheck, unit tests, SAST, secret scanning, dependency vulnerability audit, and the **Phase 0 design-consistency check** (`docs/phase-0/consistency/check_phase0_docs.py`); the pipeline blocks merge on any failing gate.
- A committed .env.example ships secure defaults and contains no real secrets; secret-management guidance is documented; no secret material is present anywhere in the repo.
- Test foundation exists: unit runner, fixtures/factories, and coverage reporting wired into CI.
- No API endpoint or UI control passes user-controlled input to a shell (architectural review recorded).

**Exit tests.**
- Boot-fail test: remove/mangle a required config value and assert the service fails fast with a clear, secret-free message.
- RBAC matrix test: for each of the five roles against each protected route/action, assert allowed/denied per spec; assert an unknown role or ungranted permission is denied (default-deny proof).
- Logging-redaction unit test: emit a log call containing an Authorization header, Set-Cookie, and an API token, then assert the rendered output masks all three.
- CI-gate proof: separately seed a lint error, a planted secret, and a known-vulnerable dependency and assert each independently fails the pipeline.
- Migration up/down test on a clean DB, verifying rollback restores prior schema.
- Reproducible-install test: two clean installs resolve identical lockfile trees.

**Safety gates.**
- Default-deny authorization invariant demonstrated end-to-end (foundation for scope escape and cross-tenant-access controls).
- Secret-leakage gate: CI secret scanner blocks merges, redaction middleware is active in the logger, and .env.example is verified secret-free.
- Supply-chain gate: committed lockfiles plus a CI dependency-audit gate that fails on known-vulnerable packages.
- No-shell gate: architectural confirmation that no UI/API path reaches an OS shell (command-injection baseline).
- Dev/stack is not bound to a public interface by default.

## Phase 2 — Engagement, Authorization & Scope Engine

**Objective.** Implement the authoritative scope and authorization engine that every outbound request must consult. Deny by default; permit only allowlisted domains/IPs (v4+v6)/CIDRs/ports/protocols/path-prefixes/APIs with honored exclusions; resolve and re-verify IPs (rebinding protection); block redirects to out-of-scope hosts; enforce testing windows, auto-expiration, per-engagement rate/concurrency limits, emergency stop, and circuit breakers; record every decision in a tamper-evident audit trail. Prove out-of-scope requests can be neither scheduled nor executed.

**Acceptance criteria.**
- Engagement CRUD is tenant-owned and stores engagement owner, written-authorization reference, scope, and expiry; testing cannot begin without a confirmed authorization record (reference + owner + expiry).
- Scope model expresses allowlisted domains, IPv4 and IPv6 addresses, CIDRs, ports, protocols/schemes, URL path prefixes, and API definitions, plus explicit exclusions that override allows.
- A single **Scope Authority** is the sole decision authority and a single **Guarded Egress Broker** is the sole target-socket creator. The queued object is an **immutable, fully-hashed `request_spec`**; grants are **minted just-in-time at dispatch** bound to `spec_sha256` (no resolved IP, TTL ≤30s), so no grant sits in the queue. The Broker verifies the grant and `grant.spec_sha256 == sha256(spec)`, **reconstructs the wire request from the spec** (never a worker-serialized request), validates+pins resolved IPs at broker time, and authenticates each per-job ingress (never a generic CONNECT proxy).
- DNS resolution check resolves the host, validates every A/AAAA result against scope, pins the validated IP for the actual connection, and re-validates at request time to defeat rebinding.
- **Tier A hard-blocked by any means** (no allowlist entry, no elevated flag, no approval): loopback/localhost, unspecified (0.0.0.0/::), cloud-metadata (169.254.169.254, fd00:ec2::254, metadata.google.internal, etc.), multicast, broadcast, and reserved/future/documentation ranges. **Tier B** (RFC1918, ULA fc00::/7, link-local 169.254.0.0/16 & fe80::/10, CGNAT 100.64.0.0/10) denied **unless** an explicit elevated scope entry, a dual-approved restricted-range approval, and authorization-granted internal testing are all present; metadata stays Tier A even inside an elevated link-local range.
- Every outbound target request is authorized via the two-stage flow (JIT Scope Authority Stage-1 grant over the immutable, content-addressed spec + Guarded Egress Broker Stage-2 reconstruction/IP-validation/pinning); grants are single-use and audience-bound; **durable intent is committed and the fenced budget lease is charged (`used += 1`, irreversible) before any egress** — so `sent ⇒ charged`; the request budget uses a **conservative charge-before-send ledger** (owned/fenced leases; sweeper reclaims only pre-charge claims; a `charged` lease is terminal); window/expiry/e-stop are re-checked at JIT mint and Stage 2; template references are immutable content digests and identical specs may repeat across jobs/runs; WebSocket handshakes are scoped/pinned like HTTP with outbound frames from an approved content-addressed catalog and connections terminated on interlocks; approval thresholds/roles come from an **immutable, Administrator-managed `approval_policy`** and intrusive approvals bind an explicit **manifest** of approved `spec_sha256` digests; authorization attestation and scope expansion require dual control (≥2 role-verified approvers, SoD, per-decision hash binding); scope-breadth limits (min CIDR prefix, IPv4-equivalent-address & CIDR-entry ceilings, wildcard/host gating; IPv6 by prefix floor) and scope expansion are gated by elevated dual approval.
- URLs are canonicalized before scope checks: percent-decoding, case folding, dot-segment removal, IDN/punycode, trailing dots, embedded userinfo (@), and alternate IP encodings (decimal/octal/hex/IPv4-mapped IPv6).
- Redirects are inspected against scope; out-of-scope targets are not followed and the event is recorded.
- Per-engagement concurrency and request-rate limits are configurable with conservative safe defaults; testing windows and auto-expiration at authorization expiry are enforced; an emergency stop halts all in-flight and queued work immediately; per-target circuit breakers exist.
- Every scope decision, authorization change, and start/stop is written to an append-only, hash-chained audit log; scope config import/export validates on import.
- With no scope configuration present, all operations are denied.

**Exit tests.**
- Property-based scope tests: randomized hosts/IPs/ports/paths yield validator decisions matching the spec, with no allow lacking a matching allowlist entry.
- Canonicalization fuzz tests: decimal/octal/hex/IPv4-mapped-IPv6 encodings, mixed case, trailing dot, unicode homoglyphs, and @-embedded userinfo cannot smuggle an out-of-scope host past the checker (scope escape).
- DNS-rebinding test: a resolver returning an in-scope IP first and a metadata/RFC1918 IP on re-lookup is defeated because the connection uses the pinned validated IP (SSRF).
- SSRF denial test: requests to 127.0.0.1, ::1, 10.0.0.0/8, 169.254.169.254, [::ffff:169.254.169.254], and 0177.0.0.1 are all denied (SSRF, scope escape).
- Redirect test: a 302 to an out-of-scope host is not followed and is logged.
- Defense-in-depth scheduler test: an out-of-scope target is rejected both at enqueue time and again at execution time.
- Expiry/window tests: advancing the clock past expiry or outside the testing window refuses new tasks and stops running ones.
- Emergency-stop test: triggering the kill switch drains/pauses the queue and produces zero further egress.
- Audit-immutability test: attempts to edit/delete an audit event fail and hash-chain verification detects tampering; per-stream chains (engagement/tenant/global) each verify independently.
- Deny-by-default test: with no scope config, every candidate request is denied.
- Two-stage/token tests: a request with a forged/expired/replayed (consumed jti) or wrong-audience grant is refused before any TCP SYN; a grant bound to one spec cannot drive a different spec (a GET /app spec cannot become POST /admin); the resolved IP is validated and pinned at the broker.
- Immutable-spec/JIT tests: the queue holds only spec references, never a grant; mutating a queued spec's fields makes the JIT mint fail on spec_sha256 mismatch; a minted grant's TTL is ≤ the configured small bound (so it cannot outlive queue dwell).
- Broker-reconstruction test: a worker that presents a divergent serialized request has it ignored — the broker sends only the spec-derived request — or the spec/grant-hash mismatch is rejected; the wire request equals the spec fields.
- Budget charge-before-send tests: total *charged* never exceeds request_budget_total under concurrency (boundary total-1/total/total+1); a request is sent only when its lease is `charged`, so `sent ⇒ charged` holds; killing a worker in the `claimed` state has the sweeper reclaim the unit (no leak, no strand), while a crash around the send leaves a terminal `charged` lease (conservative over-charge, never sent-but-uncharged); a pre-charge denial releases the claim; a fenced-off owner presenting a stale `fence_token` cannot charge.
- WebSocket tests: an out-of-scope ws/wss handshake is denied; an established WS exceeding duration/message-count/message-size caps is closed; e-stop / window-close / expiry aborts active WS connections; an established socket cannot be re-pointed to another host/IP.
- Approval scope-precondition test: a `scope_expansion`/`restricted_range_allow` approval CAN be created for a not-yet-in-scope target (the scope_must_pass CHECK does not apply), while an `intrusive_validation` approval for an out-of-scope target cannot.
- Breadth-accounting tests: IPv4-equivalent address budget and CIDR-entry cap are enforced; an IPv6 /48 is accepted under prefix floor without any address-sum overflow; exclusions do not reduce the counted breadth.
- Intent-before-egress test (SI-055): a packet capture shows ZERO egress (no DNS query, no SYN) until the durable `request.intent` + reservation commit; a crash after intent leaves the intent recorded and no packet sent; an audit-sink failure blocks even the DNS query.
- Reservation-ledger tests (SI-017/SI-062): a double commit and a double release are each no-ops; killing a worker after reserve auto-expires the reservation (no strand); committed (sent) count never exceeds the total under concurrency.
- Content-addressed template tests (SI-065): changing a template's content changes its digest (no silent repoint); a spec referencing an unknown digest is rejected; the same `spec_sha256` recurs across two jobs without a uniqueness violation, each with its own single-use grant.
- Immutable-policy/manifest tests (SI-064): approval requests carry no threshold/role fields (schema); a non-Administrator cannot version `approval_policy`; an intrusive grant is refused when `spec_sha256` is not in the approval's manifest; changing the manifest voids prior decisions.
- Audit non-null-chain test (SI-026): two events with the same `seq` on a tenant or global chain are REJECTED (the NULL-key uniqueness bug is fixed by `chain_id`); each chain verifies independently; a completion event whose related intent is in a different chain is rejected (same-chain composite FK).
- Atomic reserve+intent test (SI-055/SI-062): the broker creates the reservation and commits intent in ONE `FOR UPDATE` transaction before any DNS/TCP/TLS; a concurrent race for the last budget unit admits exactly one; a packet trace shows no egress before the commit.
- Fenced-lease test (SI-017): a paused-then-resumed or superseded lease holder cannot commit (fence-token mismatch); crash-expiry reclaims a stranded lease.
- Session/query binding test (SI-065): a spec bound to account A cannot execute with account B's session (session_digest mismatch); changing a query value changes `query_value_digest` → a different spec.
- Catalog kind/safety test (SI-065/SI-064): a digest of the wrong kind is rejected by the composite FK; a template with `safety_class='requires_approval'` forces `approval_required=TRUE` (derived, not from `mode`).
- Bidirectional scheme test: `kind='http'` with a `ws/wss` scheme (and `kind='websocket'` with `http/https`) is rejected by `kind_scheme`.
- Approval-policy/manifest test (SI-064): a decision before manifest freeze is rejected; adding a manifest entry after freeze is rejected; approval requires the policy's per-role quorum; the pinned policy must be the current, non-superseded version.
- Pause/approve/resume test: a broker-mediated dynamic request needing approval pauses (no further egress, no budget) and resumes only after threshold + role quorum.
- Constraint tests: a `draft` engagement cannot hold active pointers; a one_off/blackout window with `start_at >= end_at` is rejected; an `elevated` domain entry that is not a wildcard is rejected.
- Dual-control tests: a single actor cannot attest+approve or expand+approve; below-threshold requests never reach approved; a decision pinning a different `manifest_sha256`/`document_sha256` does not count; SoD-conflicting roles cannot both be exercised by one user on one engagement.
- Breadth tests: over-broad CIDR/wildcard/host-count/address-count is rejected or gated to elevated dual approval; a CIDR below the absolute floor (/16 v4, /32 v6) is hard-rejected even with approval.
- Audit-split test: the request.intent event is durably committed before the socket opens; a crash between intent and send leaves a provable attempt and no egress.

**Safety gates.**
- Scope-escape invariant (SI-001/SI-053/SI-060/SI-061): no egress path bypasses the two-stage Scope Authority / Guarded Egress Broker chokepoint (code-level single-socket-creator proof plus a refused direct out-of-scope request); the queued object is an immutable hashed spec, grants are minted JIT bound to spec_sha256, the broker reconstructs the request from the spec, and ingress is authenticated per-job (not a generic CONNECT proxy).
- Budget/time-interlock invariant (SI-017/SI-062): budget uses a conservative charge-before-send ledger (owned/fenced leases; charge is irreversible and terminal; sweeper reclaims only pre-charge claims) so `sent ⇒ charged` and there is no leak, no send-uncharged, no strand; window/expiry/e-stop re-checked at JIT mint and Stage 2; a spec past its window gets no grant.
- Intent-before-egress invariant (SI-055): durable intent + reservation committed before any DNS/TCP/TLS action.
- Content-addressed + repeatable invariant (SI-065): all template refs are immutable digests in `spec_sha256`; identical requests repeat across jobs/runs (no spec-uniqueness constraint).
- Immutable-policy/manifest invariant (SI-064): threshold/roles come from an immutable Admin-versioned `approval_policy`; intrusive approvals bind an explicit manifest of `spec_sha256` digests.
- Non-null audit-chain invariant (SI-026): every chain has a non-null `chain_id`; per-chain `seq`/`event_hash` uniqueness is real for tenant/global streams.
- WebSocket invariant (SI-063): handshakes scoped/pinned like HTTP; connections bounded and terminated on e-stop/window/expiry; outbound frames only from the approved content-addressed frame catalog.
- SSRF / network-policy invariant (SI-006/SI-044): Tier A unreachable by any means (incl. under a broad/elevated covering entry and transition IPv6 forms); Tier B reachable only under full elevation; rebinding defeated by broker-time resolve+validate+pin.
- Authorization-first + dual-control invariant (SI-011/SI-047): no task executes without a valid, unexpired, in-window authorization; attestation and scope expansion require enforced dual control.
- Scope-breadth invariant (SI-059): breadth ceilings and scope expansion gated by elevated dual approval demonstrated.
- Emergency-stop invariant (SI-013) demonstrated to halt in-flight and queued work.
- Audit invariant (SI-026/SI-055/SI-056): append-only hash chains, split intent/completion events, and tenant/global streams demonstrated.
- Cross-tenant invariant (SI-024/SI-050): scope/authorization/evidence records are tenant-scoped (composite FK + RLS + per-engagement encryption) and unreadable/unwritable by other tenants.

## Phase 3 — Target Intake + Passive Analysis

**Objective.** Ingest targets from multiple untrusted import formats and run passive-only analysis that emits no attack payloads. All imported hosts are scope-validated on intake; any network fetch is a single benign request through the scope engine; imported artifacts (HAR/proxy history) are redacted at rest and on display.

**Acceptance criteria.**
- Importers accept seed URLs, OpenAPI/Swagger, Postman collections, HAR, sitemap.xml, manual endpoints, and optional imported proxy history.
- Every imported host/endpoint is validated against engagement scope on import; out-of-scope entries are quarantined/rejected rather than silently accepted.
- Parsers treat all imported files as untrusted and are hardened against malformed input, oversized files, XML external entities (XXE), entity/zip-bomb expansion, and deeply nested structures via strict size/time/depth limits.
- Passive checks are implemented from observable data only: TLS/certificate analysis, security headers, cookie attributes, CORS indicators, CSP analysis, information disclosure, tech fingerprinting, JS source-map references (referenced, not fetched out of scope), public API schema review, deprecated-protocol indicators, and mixed content.
- Passive mode issues zero attack payloads; any fetch is a benign in-scope request within rate/budget limits, otherwise analysis uses supplied data only.
- Findings carry provenance (originating import/source) and evidence; redaction removes cookies, tokens, Authorization headers, and PII from imported HAR/proxy content before storage and display.

**Exit tests.**
- Parser fuzz tests per format; an XXE payload in OpenAPI/HAR resolves no external entities and an entity/zip bomb is bounded by size/time limits (SSRF-via-import, resource abuse).
- Scope-on-import test: a file containing out-of-scope hosts has those entries quarantined/rejected.
- Passive no-payload test: running passive analysis against a local target yields a request log containing only benign methods within budget and zero attack payloads.
- Redaction test: importing a HAR with Authorization/Cookie/Set-Cookie/PII stores and displays only redacted values.
- Analyzer-correctness tests: TLS, header, cookie, CSP, and mixed-content analyzers produce expected findings against known-bad local fixtures.

**Safety gates.**
- Passive-mode invariant: no attack payloads emitted, proven by request-log assertion.
- Scope gate applies to all intake and any fetch (scope escape).
- Untrusted-parser gate: XXE, SSRF-via-import, and entity/zip-bomb defenses demonstrated (SSRF, malicious input handling).
- Redaction gate on imported artifacts demonstrated (secret leakage, report-data exposure).
- No out-of-scope fetching of referenced resources such as source maps.

## Phase 4 — Safe Crawler + Attack-Surface Inventory

**Objective.** Provide a scope-aware crawler that maps attack surface without leaving scope, defeating authentication, or triggering state-changing actions, under strict request budgets with crawler-trap detection, body-retention limits, and full endpoint provenance.

**Acceptance criteria.**
- The crawler consults the scope engine for every request, never leaves scope, and honors exclusions; hosts discovered out of scope are recorded but never crawled.
- Operator-provided auth sessions are used as-is; the crawler never attempts to bypass, guess, brute-force, or escalate authentication and never defeats login.
- Discovery covers forms, query/body parameters, REST APIs, GraphQL endpoints, JS-derived routes, and file-upload surfaces, with canonicalization and dedup of URLs/endpoints.
- State-changing actions (logout, delete, payment, account-change, password change, messaging/send) are recognized via method/keyword/pattern heuristics plus an operator-configurable denylist and are never triggered; state-changing forms are recorded but never auto-submitted.
- Per-engagement request budgets are enforced and the crawl halts at budget with resumable state; crawler-trap detection bounds depth and pattern explosion (infinite calendars, session-id loops, parameter explosion).
- Response-body size and retention limits truncate/stream large bodies rather than persisting them wholesale; each endpoint records its discovery provenance and feeds a produced attack-surface map.

**Exit tests.**
- Scope-confinement crawl test: on a local app mixing in-scope and out-of-scope links, out-of-scope URLs are never requested.
- No-state-change test: against local logout/delete/payment endpoints and state-changing forms, the crawler issues none of those requests and only records the forms.
- Auth-non-defeat test: a protected area reachable only with the supplied session is not accessed via guessing/bypass.
- Trap-termination test: an infinite link generator causes termination within depth/budget limits.
- Budget test: exhausting the request budget halts the crawl and saves resumable state.
- Dedup/canonicalization test: equivalent URLs collapse to one entry; oversized-body test confirms large responses are not fully persisted.

**Safety gates.**
- Scope-confinement invariant during active crawling (scope escape).
- Non-destructive invariant: no state-changing requests emitted, proven by request-log assertion (data-integrity protection).
- Auth-controls-respected invariant: authentication never bypassed or brute-forced.
- Request-budget invariant enforced (queue abuse / DoS avoidance).
- Never-scan-unrelated-infrastructure invariant: out-of-scope discoveries are quarantined, not auto-crawled.

## Phase 5 — Safe Security Check Engine

**Objective.** Deliver a modular, evidence-based, non-destructive detection engine where each check declares a full safety contract, all egress passes through the scope engine and budgets, hard restrictions are enforced in code (not warnings), and any intrusive check requires human approval before execution.

**Acceptance criteria.**
- Each check module declares id, description, preconditions, safety classification, request budget, scope requirements, harmless test method, evidence requirements, confidence calculation, cleanup routine, failure handling, and CWE/OWASP/remediation references; the registry refuses to load any check missing a required field or safety classification.
- Detection families are implemented non-destructively: authN/session, access-control indicators, input reflection/output encoding, SQLi via non-destructive differential checks (no data extraction/mutation), XSS via inert non-executing markers, SSRF via approved controlled callback infrastructure only, path traversal without retrieving sensitive OS files, open redirects, CORS, CSRF indicators, HTTP method exposure, file-upload validation with harmless files, GraphQL introspection, API-authorization consistency via operator test accounts, security-header/cookie issues, error/stack-trace disclosure, cache-control of sensitive responses, known-vulnerable components by version with confidence, and operator-defined-plus-approved business-logic templates.
- Hard restrictions are enforced in the engine: never dump databases, never retrieve secrets/keys/files/user data as proof, no reverse shells or OS commands, no executable uploads, no modify/delete/corrupt operations, no brute force/spray/MFA-bypass/ATO, no destructive race or resource-exhaustion, and no WAF/detection bypass.
- Every check runs through the scope engine, rate limits, and its declared request budget; SSRF checks only use engagement-approved, allowlisted callback infrastructure and reject arbitrary callback hosts.
- Checks default to passive/safe-active classification; any intrusive check requires a recorded operator approval before it can execute; cleanup routines run and are verified for any artifact a check creates (e.g., a harmless uploaded file).
- Raw external-tool output and raw response bodies are not persisted by default; findings carry only minimized, allowlisted, redacted evidence; access-control/IDOR checks capture only a non-sensitive discriminator (SI-048, SI-057).

**Exit tests.**
- Contract-enforcement test: a check missing any required field or safety classification is rejected by the registry and cannot run.
- Raw-output test (SI-057): a default check run persists no raw body/console text; with the debug quarantine enabled, artifacts are encrypted under the per-engagement key, role-gated, size-capped, TTL-purged, and cannot be promoted un-redacted.
- Non-destructive SQLi test: the differential check is verified to use inert, non-mutating payloads (no DROP/UPDATE/DELETE/data-extraction payloads) and cannot return row data as proof.
- Inert-marker XSS test: detection relies on reflection/encoding of a unique non-executing marker, not real script execution.
- SSRF-callback test: the check refuses to run without approved callback infrastructure and rejects arbitrary/attacker-controlled callback hosts (SSRF).
- Path-traversal safety test: attempts are bounded to a harmless canary; requests for sensitive OS files (e.g., /etc/passwd class) are refused and proof is reflection, not file contents.
- Restriction unit tests: attempts to invoke banned behaviors (OS command, executable upload, data mutation, brute force, WAF bypass) are blocked by the engine (command injection, destructive-op prevention).
- Approval-gate test: an intrusive check cannot execute without a recorded operator approval; cleanup-verification test confirms created artifacts are removed/flagged.

**Safety gates.**
- Non-destructive invariant across all checks: no mutate/delete/corrupt operations reach a target.
- No-secret-exfiltration invariant: checks cannot retrieve secrets, keys, files, or user data as evidence (secret leakage, report-data exposure).
- SSRF-callback invariant: only approved, allowlisted callback infrastructure is usable (SSRF).
- Command-injection invariant: no OS-command or reverse-shell path exists in any check (command injection).
- Approval-gating invariant for intrusive checks, plus per-check scope/budget/rate-limit enforcement (scope escape, queue abuse), plus verified cleanup.

## Phase 6 — Tool Integration Layer

**Objective.** Integrate external tools (Nuclei, OWASP ZAP baseline, TestSSL, dependency/SCA, secret scanners) through isolated adapters with version-pinned and integrity-verified binaries/templates, curated non-destructive allowlists, container isolation with restricted egress and resource limits, structured-output parsing of untrusted results, and no user-controlled arguments reaching a shell.

**Acceptance criteria.**
- Adapters exist for Nuclei (curated non-destructive template allowlist), ZAP baseline/controlled, TestSSL/TLS analysis, dependency/SCA scanners, and secret scanners for operator-supplied source only.
- Tool binaries and templates are version-pinned and integrity-verified (checksums/signatures) before execution; a mismatch aborts the run.
- Each tool runs in an isolated container: non-root, dropped capabilities, read-only filesystem where feasible, no host mounts/access, CPU/memory/time and request-count limits, and network egress restricted to in-scope targets by policy.
- Unsafe templates/options are disabled via allowlist (not denylist-only): Nuclei destructive/dos/intrusive tags excluded, ZAP active-attack beyond baseline disabled; only allowlisted templates load.
- Tool invocation builds argv arrays programmatically with no shell interpolation; no user-supplied CLI arguments reach a shell.
- Only structured (e.g., JSON) output is parsed; parsers treat output as untrusted with schema validation, size bounds, and no dynamic evaluation; raw output is stored separately from normalized findings and mapped to one normalized finding schema.
- No exploit frameworks or C2 tooling are integrated.

**Exit tests.**
- Version-pin test: an altered tool or template checksum causes the adapter to refuse to run (supply-chain compromise).
- Template-allowlist test: a destructive/intrusive Nuclei template is not loadable; only allowlisted templates run.
- Egress-restriction test: a tool container attempting to reach an out-of-scope host or 169.254.169.254 is blocked by network policy (SSRF, scope escape).
- Resource-limit test: a tool exceeding CPU/memory/time is killed and the request cap is enforced (queue abuse / DoS).
- No-shell test: an argument containing shell metacharacters is passed as literal argv with no command execution (command injection).
- Malicious-output test: crafted tool JSON with injection/oversized/malformed content is rejected or bounded by the parser with no code execution and no crash (malicious scanner output).
- Raw-vs-verified separation test: raw output is not promoted to a finding without normalization; isolation test confirms non-root, read-only, no host-mount escape.

**Safety gates.**
- Container-isolation invariant demonstrated (unsafe plugin execution).
- Egress-restriction invariant on tool containers as network-layer defense in depth (SSRF, scope escape).
- Command-injection invariant: no user-controlled argument reaches a shell (command injection).
- Malicious-scanner-output invariant: untrusted, bounded parsing with raw output separated from verified findings (malicious scanner output).
- Supply-chain invariant: pinned and integrity-verified tool/template versions (supply-chain compromise); resource/rate limits enforced (queue abuse).

## Phase 7 — Finding Correlation + Validation Workflow

**Objective.** Normalize, dedup, and score findings; grade evidence; support false-positive review, grouping, and a strict status lifecycle; and drive approval-gated validation that discloses the exact proposed request, impact, scope check, required account, expected response, retained evidence, cleanup, and stop conditions before any execution.

**Acceptance criteria.**
- Findings from all checks and tools are normalized to one schema and deduplicated; asset/endpoint grouping and root-cause grouping are supported.
- Confidence and severity scoring, evidence-quality grading, regression tracking, and retest state are implemented.
- The status lifecycle enforces allowed transitions across Unverified, Needs Review, Confirmed, False Positive, Accepted Risk, Remediated, Retest Failed, and Retest Passed, with reviewer comments and recorded risk acceptance.
- Each approval-gated validation record shows the proposed request(s), why it is needed, potential impact, the target-plus-scope check result, the required account, the expected response, the evidence to retain, the cleanup action, and the stop conditions.
- Validation cannot execute until an explicit operator approval is recorded and tied to an authorized identity/role (Reviewer or Manager); validation remains bounded by the Phase 5 non-destructive engine, scope, and budget, and scope is re-validated at execution time.
- All evidence is redacted per policy before storage or display.

**Exit tests.**
- Correlation/dedup test: the same issue reported by Nuclei and an internal check collapses into one finding with combined evidence.
- Lifecycle test: an illegal status transition is rejected and all transitions are audited.
- Approval-gate test: a validation action is blocked until approval, and approval attempted by an unauthorized role is rejected (RBAC / cross-tenant access).
- Pre-flight-completeness test: a validation record missing any required field (impact, scope check, cleanup, stop conditions) cannot be submitted for approval.
- Scope-recheck test: scope is re-validated at validation execution time and an out-of-scope target is refused (scope escape, SSRF).
- Redaction test: stored validation evidence is redacted.

**Safety gates.**
- Approval-gating invariant for all validation actions demonstrated.
- Scope re-validation at execution invariant (scope escape, SSRF).
- Non-destructive validation invariant reusing Phase 5 restrictions.
- Report-data-exposure invariant: evidence redaction demonstrated.
- RBAC/tenant-isolation invariant on approvals and finding access (cross-tenant access).

## Phase 8 — Reporting

**Objective.** Generate HTML, JSON, CSV, and PDF-ready reports containing all mandated sections with redaction enforced at generation time across every format, non-destructive reproduction steps, injection-safe rendering of untrusted finding content, and tenant/RBAC-scoped, audited export.

**Acceptance criteria.**
- Reports include executive summary, scope and exclusions, authorization details, testing dates, methodology, limitations, attack-surface summary, risk distribution, confirmed findings, evidence, non-destructive reproduction steps, business and technical impact, remediation, references, retest results, an appendix of tool versions and test configuration, and an explicit statement that automated results require professional review.
- HTML, JSON, CSV, and PDF-ready formats are produced from the same normalized data.
- Redaction is applied at generation (not merely at display) across all formats: cookies, Authorization headers, API keys, passwords, PII, sensitive response bodies, and secrets are removed or masked.
- Reproduction steps contain no destructive payloads.
- Reports are engagement/tenant scoped and access-controlled by RBAC; every export is recorded in the immutable audit log.
- Report rendering is safe against malicious finding/tool content: HTML is escaped and CSV formula-injection is neutralized.

**Exit tests.**
- Cross-format redaction test: inject a secret, cookie, Authorization header, PII, and token into a finding and its evidence, then assert all are absent from HTML, JSON, CSV, and PDF-ready output (report-data exposure, secret leakage).
- Required-sections test: a generated report contains every mandated section, including the professional-review statement and authorization/scope disclosure.
- Report-injection test: finding evidence containing <script>/HTML is escaped in HTML output and CSV cells beginning with =,+,-,@ are neutralized, with no execution (malicious scanner output propagation).
- Reproduction-non-destructive test: generated reproduction steps contain no destructive payloads.
- Access-control test: a user without rights or from another tenant cannot read or export a report (cross-tenant access); export-audit test confirms every export is logged.

**Safety gates.**
- Report-data-exposure invariant: generation-time redaction verified across all four formats (report-data exposure, secret leakage).
- Output-encoding invariant: HTML-escaping and CSV formula-injection neutralization prevent injection from untrusted finding content (malicious scanner output).
- RBAC/tenant invariant on report access with audited export (cross-tenant access).
- Mandatory professional-review statement plus authorization/scope disclosure present in every report.

## Phase 9 — Minimal-Effort Operator Experience

**Objective.** Provide a guided, safe-by-default operator workflow that gates start behind valid authorization and verified scope, previews and surfaces request budgets, keeps an always-available emergency stop, protects supplied auth material, and never offers a one-click attack-everything or automatic intrusive validation.

**Acceptance criteria.**
- A guided flow implements: create engagement, add authorization, define scope, verify scope, select mode, supply auth safely, review estimated request volume, start, review approval-gated actions, triage, export report, schedule retest.
- Safe default profiles (passive default) are provided; mode selection is explicit and intrusive actions require approval; the Start control is enabled only after authorization is present/unexpired and scope is verified.
- Estimated request volume is shown before start and live request-budget indicators are visible during a run; a clear, always-available stop/emergency-stop control is wired to the Phase 2 kill switch.
- A progress dashboard, failure explanations, resume capability, notifications, and recommended next actions are provided.
- Operator-supplied auth material is stored encrypted, redacted in the UI, and never logged.
- There is no attack-everything control and no path to automatic intrusive validation anywhere in the UX.

**Exit tests.**
- Start-gating test: Start is disabled/refused until authorization exists, is unexpired, and scope is verified.
- No-one-click test: a UI/API audit confirms no endpoint launches a full intrusive run without per-action approvals.
- Stop test: the stop control halts a run end-to-end via the emergency-stop path.
- Budget-preview test: estimated volume is shown pre-start, enforced during the run, and matches the live indicator.
- Auth-handling test: supplied session secrets are encrypted at rest, redacted in the UI, and absent from logs (secret leakage).
- Resume test: an interrupted run resumes without re-attacking targets or exceeding the request budget.

**Safety gates.**
- Authorization-first and scope-verified gating enforced before any run starts (authorization-first, scope escape).
- No-automatic-intrusive-validation invariant across the UX (approval-gating).
- Emergency-stop reachable and effective invariant.
- Secret-leakage invariant on operator auth material (encrypted, redacted, unlogged).
- Queue-abuse invariant: budget preview and enforcement surfaced to the operator.

## Phase 10 — Hardening + QA

**Objective.** Build a comprehensive test suite that maps every safety-model rule and each of the ten named threats to at least one automated test, exercise the platform only against local intentionally-vulnerable apps, and make the release pipeline auto-fail if any safety invariant fails.

**Acceptance criteria.**
- The suite includes and passes unit, integration, and e2e tests, property-based scope tests, parser and URL fuzzing, SSRF tests, authorization tests, tenant-isolation tests, race-condition tests, queue-security tests, report-redaction tests, container-isolation tests, dependency scanning, static analysis, secret scanning, performance tests, recovery tests, and backup/restore tests.
- All intentionally-vulnerable targets are local and isolated; the harness cannot be pointed at external systems.
- A machine-checkable safety-invariant suite maps each safety-model rule and each of the ten named threats (scope escape, SSRF, command injection, malicious scanner output, unsafe plugin execution, secret leakage, cross-tenant access, report-data exposure, queue abuse, supply-chain compromise) to at least one automated test.
- The release pipeline blocks release automatically if any safety-invariant test fails.
- Coverage thresholds are met for safety-critical modules (scope engine, shared egress client, redaction, tool adapters).

**Exit tests.**
- Gate-proof test: deliberately disable one invariant (e.g., the rebinding check) and confirm the release gate fails, then restore and confirm green.
- Scope/URL/parser fuzz corpora pass with no scope escape and no crash; the full SSRF suite (rebinding, metadata, private ranges, redirect, tool egress) passes.
- Tenant-isolation suite: cross-tenant read/write attempts all fail (cross-tenant access).
- Race/queue suite: concurrent enqueue plus emergency-stop and budget-under-concurrency behave correctly (queue abuse).
- Container-isolation suite: egress, resource, and privilege tests pass (unsafe plugin execution); redaction suite passes across logs and reports (secret leakage, report-data exposure).
- Recovery and backup/restore tests pass with no data loss or corruption.

**Safety gates.**
- Release-blocking safety-invariant gate demonstrated to fail the build on any violation, covering all ten named threats.
- Local-only vulnerable-target invariant: the test harness cannot target external systems.
- Traceability invariant: every safety rule and named threat maps to a passing test.
- Static-analysis, secret-scanning, and dependency-scanning gates clean or explicitly triaged (supply-chain compromise, secret leakage).

## Phase 11 — Deployment + Operations

**Objective.** Deliver secure local, single-server, and production deployment with TLS termination, hardened DB, worker isolation and network segmentation, default-deny network-layer egress filtering, centralized redacted logging with monitoring/alerting on safety events, backups, key rotation, documented upgrade/incident-response/retention procedures, and secure deletion — not publicly accessible by default.

**Acceptance criteria.**
- Local, single-server, and production topologies are documented and provisioned with TLS termination and DB security (authentication, encryption in transit and at rest, least-privilege accounts, no public DB exposure).
- Worker isolation and network segmentation are enforced; network-layer egress filtering defaults to deny. No sandbox has a direct route to any target: tool/browser sandboxes reach **only** the Guarded Egress Broker; workers reach a **narrow internal-service allowlist plus the broker**. The broker — never a sandbox — opens target sockets after grant/scope validation (SI-030, SI-054).
- The platform is not publicly accessible by default (private network / auth-gated / firewalled).
- Centralized logs apply redaction; monitoring and alerting fire on safety events (scope violations, emergency stops, circuit-breaker trips).
- Backups, a key-rotation procedure, a documented upgrade procedure, an incident-response runbook, a data-retention policy, and secure deletion of engagement data and evidence are all in place; multi-tenant and scaling considerations are documented.

**Exit tests.**
- Default-not-public test: a fresh deployment is not reachable from a public network without explicit configuration.
- Egress-filter test: from a worker, a connection to a non-approved host or 169.254.169.254 is blocked at the network layer, providing defense in depth beyond the app layer (SSRF, scope escape).
- TLS/DB test: only TLS is served with a strong configuration, the DB is not publicly exposed, and app credentials are least-privilege.
- Backup/restore drill restores to a known-good state with verified integrity; key-rotation drill rotates secrets without data loss and revokes old keys.
- Alerting test: a simulated scope violation and emergency stop each fire an alert.
- Cryptographic-erasure test (SI-058): destroying an engagement's per-engagement DEK renders sampled ciphertext undecryptable in primary, WORM/object-lock, AND backup stores without mutating any immutable store; the redacted audit trail still verifies; an active legal hold blocks erasure; a `dek.destroyed` event and a deletion-verification result are recorded (report-data exposure).
- Egress-posture test (SI-054): a tool/browser sandbox can reach ONLY the broker; a worker can reach ONLY its internal-service allowlist plus the broker; both are blocked from targets/internet/metadata.
- Prod log-redaction test confirms no secrets in centralized logs (secret leakage).

**Safety gates.**
- Network-layer egress-filtering invariant as defense in depth (SI-033/SI-054): tool/browser sandbox broker-only; worker narrow internal allowlist + broker; no direct target/internet route.
- Not-public-by-default invariant.
- Worker-isolation and segmentation invariant containing tool/plugin execution (unsafe plugin execution).
- Secret-management and key-rotation invariant (secret leakage); secure-deletion via per-engagement cryptographic erasure reconciled with WORM/audit/backups (SI-058, report-data exposure).
- Monitoring/alerting on safety events operational; backup/restore integrity invariant demonstrated.

## Phase 12 — Final Review + Release

**Objective.** Complete architecture and security review (including self-pen-test of the platform), update the threat model to cover all ten named threats, produce a full requirements-and-safety traceability matrix, verify every safety invariant on the release candidate, generate an SBOM with verified pinned dependencies, and cut a versioned, reproducible release that is blocked unless all safety invariants pass.

**Acceptance criteria.**
- Architecture review and security review (including a pen-test of the platform itself) are completed and signed off, with findings resolved or explicitly risk-accepted.
- The threat model is updated to cover all ten named threats (scope escape, SSRF, command injection, malicious scanner output, unsafe plugin execution, secret leakage, cross-tenant access, report-data exposure, queue abuse, supply-chain compromise), each mapped to mitigations, phases, and tests.
- A requirements traceability matrix links every requirement and safety-model rule from design to implementation to test with no gaps.
- A safety-invariant verification report shows all invariants demonstrably enforced with linked evidence; documentation, usability, and performance reviews are complete with acceptance thresholds met.
- A final test report, an all-green release checklist, a known-risk register with owners and residual-risk sign-off, and a versioned, reproducible release with a generated SBOM are produced; the release is blocked unless all safety invariants pass.

**Exit tests.**
- Traceability audit: no requirement, safety rule, or named threat lacks a linked passing test (any gap fails the gate).
- Release-candidate safety-invariant re-run: all invariants pass and an SBOM is generated with dependencies verified (supply-chain compromise).
- Design-consistency gate: `docs/phase-0/consistency/check_phase0_docs.py` exits 0 (SI parity, cross-reference resolution, approval-policy agreement, contradiction scans); a non-zero exit blocks the release.
- Self-security-review closure: platform pen-test findings are resolved or explicitly risk-accepted with recorded sign-off.
- Reproducible-build test: a build from the tagged source matches the released artifact.
- Threat-model coverage check: each of the ten named threats has a documented mitigation plus a referenced test.

**Safety gates.**
- Final release-blocking safety-invariant gate covering all ten named threats and every safety-model rule.
- Traceability-completeness invariant: no untested safety rule or requirement.
- Supply-chain invariant: SBOM plus verified, pinned dependencies for the release (supply-chain compromise).
- Threat-model-currency invariant: the model covers all named threats with mapped mitigations.
- Residual-risk sign-off recorded in the tamper-evident audit trail.
