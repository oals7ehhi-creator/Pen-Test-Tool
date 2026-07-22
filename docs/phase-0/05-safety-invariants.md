# Phase 0 — Safety Invariants
> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

**65 absolute, machine-checkable safety invariants (SI-###).** Each is a property that automated tests MUST enforce and that the release pipeline MUST fail on if violated (NFR + Phase 10 gate). SI-041–SI-052 were added during the first adversarial design review; SI-053–SI-059 during the second (blockers 1–10); SI-060–SI-063 during the third (immutable request-spec + JIT grants, broker reconstruction, budget/window, WebSocket); SI-064–SI-065 during the fourth (immutable approval policy + approved-spec manifest, content-addressed repeatable templates). See `08-design-review-and-critique-resolution.md`.

> **Release rule:** if any SI-### test fails or is missing, the build fails and no release is cut. Safety invariants are not advisory.

## Index

| ID | Invariant (short) | Related threats |
|---|---|---|
| SI-001 | Every outbound request to a target MUST be created only by the single Guarded Egress Broker and authorized by a two-stage flow ove… | scope escape, SSRF |
| SI-002 | If no scope configuration exists for an engagement, or the scope configuration is absent, empty, malformed, unparseable, or fails… | scope escape, SSRF |
| SI-003 | The IP the Guarded Egress Broker connects to MUST be identical to an IP it validated during Stage-2 resolution; the connection MUS… | SSRF, scope escape |
| SI-004 | When a hostname resolves to multiple addresses, EVERY resolved A and AAAA record MUST be in scope for the request to be allowed; i… | SSRF, scope escape |
| SI-005 | Every HTTP redirect (any 3xx with a Location, plus meta-refresh and equivalent) MUST be re-submitted to the Scope Authority (which… | scope escape, SSRF |
| SI-006 | Tier A ranges MUST NEVER be contacted by any means — no allowlist entry, no elevated flag, no approval: loopback (127.0.0.0/8, ::1… | SSRF, scope escape |
| SI-007 | All targets MUST be canonicalized before scope evaluation: IPv4 and IPv6 both fully validated; alternate encodings (decimal/octal/… | scope escape, SSRF |
| SI-008 | Explicit exclusions MUST always take precedence over allowlist entries: if a canonical target matches any exclusion (domain, IP, C… | scope escape |
| SI-009 | Only allowlisted ports and protocols may be contacted; a request to a non-allowlisted port or using a non-allowlisted protocol (e.… | SSRF, scope escape |
| SI-010 | When URL-prefix / path scope is defined for a target, requests to paths outside the allowed prefixes are denied; path canonicaliza… | scope escape |
| SI-011 | When an engagement's authorization is expired (past expiry timestamp) or otherwise invalid/revoked, the number of new outbound req… | scope escape |
| SI-012 | Outside the engagement's configured testing window (allowed days/hours/timezone), no outbound requests execute; work scheduled out… | scope escape, queue abuse |
| SI-013 | Activation of emergency stop (global or per-engagement) MUST, within a bounded and tested time, prevent any further dequeue, abort… | queue abuse, scope escape |
| SI-014 | Automatic circuit breakers MUST trip and halt an engagement (or a specific check/target) when tested thresholds are exceeded — tar… | queue abuse |
| SI-015 | The number of concurrent in-flight outbound requests per engagement MUST never exceed the engagement's configured concurrency ceil… | queue abuse |
| SI-016 | The outbound request rate per engagement MUST never exceed the configured requests-per-interval ceiling measured over any sliding… | queue abuse |
| SI-017 | Each engagement and run has a finite total request budget enforced by an identifiable `budget_reservation` ledger: a just-in-time… | queue abuse |
| SI-018 | No action classified as intrusive, active-injection, or destructive-class MAY execute unless a stored approval record exists that… | scope escape, command injection |
| SI-019 | The system MUST be structurally incapable of emitting destructive payloads: request bodies/parameters are constructed only from a… | command injection, scope escape |
| SI-020 | Approval records and their bound plan hashes are immutable once created; any modification to the plan (target, request, payload, s… | scope escape, cross-tenant access |
| SI-021 | Secrets, credentials, API keys, session tokens, cookies, Authorization headers, passwords, and PII MUST never be persisted in clea… | secret leakage, report-data exposure |
| SI-022 | Evidence capture MUST enforce per-item body-size limits and retention policy, and response bodies stored as evidence MUST pass thr… | report-data exposure, secret leakage |
| SI-023 | Generated reports in every format (HTML, JSON, CSV, PDF-ready) MUST contain only redacted content — no unredacted cookies, Authori… | report-data exposure, secret leakage |
| SI-024 | Every data access (API query, DB read, evidence fetch, report generation, queue consumption) MUST be constrained by the caller's t… | cross-tenant access, report-data exposure, secret leakage |
| SI-025 | A worker executing a job for engagement E can load only E's scope config, authorization, operator-supplied credentials/sessions, a… | cross-tenant access, secret leakage |
| SI-026 | The audit trail MUST be append-only and tamper-evident (hash-chained/sequence-linked so any insertion, deletion, or modification i… | scope escape, cross-tenant access, malicious scanner output |
| SI-027 | If an audit event for a safety-relevant action cannot be durably written, the action MUST NOT proceed (fail-closed on audit): a re… | scope escape, malicious scanner output |
| SI-028 | No user-, target-, or tool-supplied input EVER reaches a shell interpreter; all external processes (tool adapters, scanners) are l… | command injection, unsafe plugin execution |
| SI-029 | Output from external tools (Nuclei, ZAP, TestSSL, SCA/secret scanners) MUST be consumed only as structured, untrusted data via a s… | malicious scanner output, unsafe plugin execution, command injection, scope escape |
| SI-030 | External tools and plugins MUST run in isolated containers with default-deny network egress; their only permitted network destinat… | unsafe plugin execution, SSRF, scope escape, malicious scanner output |
| SI-031 | Every external tool binary, container image, and scan template/plugin MUST be version-pinned and integrity-verified (cryptographic… | supply-chain compromise, unsafe plugin execution, malicious scanner output |
| SI-032 | Application dependencies and container base images MUST be locked with integrity hashes and verified at build/deploy; the build fa… | supply-chain compromise |
| SI-033 | Worker network egress at the infrastructure layer MUST be default-deny, permitting only a narrow allowlist of internal control-pla… | scope escape, SSRF, unsafe plugin execution |
| SI-034 | SSRF-class and callback-based checks MAY use only pre-approved, engagement-configured controlled callback infrastructure as the in… | SSRF, scope escape |
| SI-035 | Discovery outputs (crawler-found links, redirects, tool-reported hosts, JS-extracted routes, DNS discoveries) MUST NOT automatical… | scope escape, SSRF, malicious scanner output |
| SI-036 | The safe crawler MUST NOT auto-submit or trigger state-changing actions: forms and controls matching logout, delete, payment, acco… | scope escape, queue abuse |
| SI-037 | Auth controls, WAFs, CAPTCHAs, rate limiters, and monitoring MUST NEVER be bypassed, defeated, brute-forced, or evaded: the platfo… | scope escape, queue abuse |
| SI-038 | The job queue MUST enforce that every enqueued job carries a valid engagement authorization and scope reference at both enqueue an… | queue abuse, cross-tenant access, scope escape |
| SI-039 | No path-traversal, file-read, or LFI-class check may retrieve sensitive OS or application files as proof; traversal checks target… | report-data exposure, secret leakage, scope escape |
| SI-040 | Permission-changing, configuration, scope, authorization, approval, and emergency-stop actions MUST be authorized by RBAC at the A… | scope escape, cross-tenant access, command injection |
| SI-041 | Any sandboxed tool or headless browser MUST use the Guarded Egress Broker as its sole egress proxy for ALL request types, with cli… | scope escape, SSRF |
| SI-042 | Per-request path-prefix, redirect, and body inspection MUST have a defined, non-bypassable enforcement point even for HTTPS tool t… | scope escape, SSRF |
| SI-043 | The Stage-1 egress grant MUST bind the exact HTTP method and canonical path (not merely host/IP/port), so an allow for one path or… | scope escape |
| SI-044 | The network-guard classifier MUST decode IPv4-mapped, IPv4-compatible, 6to4 (2002::/16), Teredo (2001::/32), and NAT64 (64:ff9b::/… | SSRF |
| SI-045 | Redaction MUST be allowlist/minimization-based: only explicitly-safe, structured fields are surfaced in evidence, reports, and log… | secret leakage, report-data exposure |
| SI-046 | Every safety-critical dependency — scope verdict, authorization freshness, emergency-stop state, testing-window/expiry evaluation,… | scope escape, SSRF |
| SI-047 | Authorization attestation and any scope expansion (a new host, domain, or IP range) MUST be approved under dual control: at least… | scope escape |
| SI-048 | Report/evidence renderers MUST execute with zero network egress and remote-resource loading disabled under a strict CSP; access-co… | report-data exposure, secret leakage, cross-tenant access |
| SI-049 | Authorization expiry and testing windows MUST be evaluated against a monotonic clock plus an authenticated wall-clock with sanity… | scope escape, other |
| SI-050 | Evidence/object-storage isolation MUST be enforced at the storage layer — per-engagement (or per-tenant) encryption keys from the… | cross-tenant access, report-data exposure |
| SI-051 | The audit hash-chain MUST be anchored to append-only WORM storage and/or an external notary at a bounded interval, and the chain-s… | report-data exposure, scope escape |
| SI-052 | Offline vulnerability / SCA feeds MUST be ingested out-of-band via a checksum/signature-verified control-plane step (never worker… | supply-chain compromise, malicious scanner output |
| SI-053 | The egress grant MUST be single-use (its `jti` consumed exactly once), short-lived (bounded TTL), and audience-bound to one Guarde… | scope escape, SSRF |
| SI-054 | Tool and headless-browser sandboxes MUST have the Guarded Egress Broker as their ONLY reachable network next hop (no internal-serv… | scope escape, SSRF, unsafe plugin execution |
| SI-055 | A durable `request.intent` audit event MUST be committed BEFORE any outbound network action for the request — before any DNS query… | scope escape, malicious scanner output |
| SI-056 | Events with no engagement (login/logout, user/role changes, tenant retention changes) and no tenant (global emergency stop, tool-i… | cross-tenant access, scope escape, report-data exposure |
| SI-057 | Raw external-tool output and raw target response bodies MUST NOT be persisted by default; findings carry only minimized, allowlist… | secret leakage, report-data exposure |
| SI-058 | Secure deletion of an engagement's data MUST be achieved by destroying its per-engagement Data Encryption Key (cryptographic erasu… | report-data exposure, cross-tenant access, secret leakage |
| SI-059 | Broad or expanding scope MUST be limited technically and gated by elevated dual approval: CIDR entries broader than the engagement… | scope escape |
| SI-060 | The object placed on the job queue MUST be an immutable, fully-hashed `request_spec` (`spec_sha256` over all request-determining f… | scope escape, queue abuse |
| SI-061 | The Guarded Egress Broker MUST reconstruct and normalize the outbound request deterministically from the signed immutable spec (me… | scope escape, command injection |
| SI-062 | Budget reservations MUST be identifiable (one `budget_reservation` per grant `jti`) with idempotent commit/release and crash-expir… | queue abuse, scope escape |
| SI-063 | WebSocket (`ws`/`wss`) connections MUST be authorized, scoped, resolved, and IP-pinned at the handshake exactly like an HTTP reque… | scope escape, queue abuse |
| SI-064 | Approval thresholds and eligible approver roles MUST be read from an immutable, Administrator-managed, versioned `approval_policy`… | scope escape, cross-tenant access |
| SI-065 | Every security/request-context reference in a `request_spec` (check, tool template, header-set, payload, WebSocket frame-set) MUST… | scope escape, command injection, supply-chain compromise |

## Invariants

### SI-001

**Every outbound request to a target MUST be created only by the single Guarded Egress Broker and authorized by a two-stage flow over an IMMUTABLE, fully-hashed `request_spec`: at just-in-time dispatch the Scope Authority verifies `spec_sha256`, re-checks scope/authorization/window/e-stop/budget against current state, and mints a short-TTL, single-use egress grant bound to {iss, aud=broker, run_id, job_id, jti, iat/nbf/exp, tenant, engagement, authorization_id, scope_hash, spec_sha256, mode, request_class, approval_ref?}; the Guarded Egress Broker verifies the grant and that grant.spec_sha256 == sha256(spec), reconstructs the request from the spec, resolves DNS, validates and pins every resolved IP at broker time, and connects only to a pinned validated IP. No socket opens without a valid, unconsumed grant; no resolved IP is bound before broker-time resolution; the grant binds the spec hash, not a re-listed request line.**

- **Rationale.** A single mandatory socket-creator plus a capability bound to an immutable, hashed spec closes the check-vs-use gap: the exact request that was authorized is the exact request sent. Binding `spec_sha256` transitively binds method and canonical path (they are fields of the spec), so an allow can never be replayed against another path or verb. The resolved IP is validated at the broker, where it is known — never pre-bound.
- **Enforcement point.** Guarded Egress Broker (the ONLY component permitted to create target sockets) + Scope Authority (the ONLY grant minter). An architectural/static-analysis CI gate forbids raw socket/http/DNS libraries anywhere outside the Broker module. Design: `10-request-authorization-flow.md`, `04` §7.
- **Test approach.** Static analysis fails CI if any module besides the Broker opens sockets. Integration: a request with a forged / absent / expired / replayed grant, or a grant whose `spec_sha256` ≠ `sha256(spec)`, is refused before any TCP SYN (in-process socket counter asserts zero). Replay: a consumed `jti` is rejected. Property test: no socket opens without a matching valid single-use grant.
- **Violation impact.** Total collapse of the safety model — arbitrary hosts could be contacted, defeating scope, SSRF, and egress controls simultaneously.
- **Related threats.** scope escape, SSRF

### SI-002

**If no scope configuration exists for an engagement, or the scope configuration is absent, empty, malformed, unparseable, or fails schema validation, the number of outbound requests permitted for that engagement is exactly zero.**

- **Rationale.** Deny-by-default. The system must fail closed: an error or missing config must never be interpreted as 'allow all' or 'allow anything not explicitly denied'.
- **Enforcement point.** Scope Authority verdict function default branch (returns DENY on any non-affirmative state); scheduler refuses to enqueue jobs for engagements lacking a validated scope record.
- **Test approach.** Property-based fuzzing of scope config (null, {}, truncated JSON, wrong types, huge inputs, unicode, deeply nested) asserting the verdict is always DENY and socket count is zero. Integration test: create an engagement with no scope and assert every mode (Passive/Safe Active/Approval-Gated) produces zero requests and a blocking error.
- **Violation impact.** Fail-open behavior would allow scanning of unauthorized systems the moment configuration is incomplete — the highest-consequence class of failure.
- **Related threats.** scope escape, SSRF

### SI-003

**The IP the Guarded Egress Broker connects to MUST be identical to an IP it validated during Stage-2 resolution; the connection MUST be pinned to that validated IP and MUST NOT be re-resolved by the OS resolver or HTTP stack between validation and connect. Target DNS resolution happens ONLY at the broker.**

- **Rationale.** DNS-rebinding protection. Validating a hostname then letting the socket layer re-resolve permits a TOCTOU attack where the second resolution returns an in-scope-bypassing IP (e.g. 169.254.169.254). Pinning the socket to the exact validated IP eliminates the window; keeping all target DNS at the broker means there is no other resolver to race.
- **Enforcement point.** Guarded Egress Broker custom connection factory: resolves once, validates all records, then dials the pinned in-scope IP directly and sets SNI/Host to the original hostname.
- **Test approach.** Integration test with a controllable DNS server whose response changes between resolution calls (first in-scope, second 169.254.169.254). Assert the actual TCP connection goes only to the validated IP. Test TTL=0 and rapid repeats; assert the resolver is invoked once per request and the connected peer equals the validated address.
- **Violation impact.** SSRF to cloud metadata or internal services via rebinding while appearing in-scope.
- **Related threats.** SSRF, scope escape

### SI-004

**When a hostname resolves to multiple addresses, EVERY resolved A and AAAA record MUST be in scope for the request to be allowed; if any single resolved record is out-of-scope or in a forbidden range, the entire request is denied (no fallback to an in-scope record).**

- **Rationale.** An attacker-controlled or misconfigured DNS record can return one in-scope IP alongside an internal/metadata IP; 'happy eyeballs' or resolver ordering could otherwise connect to the forbidden one. All-or-nothing prevents selective bypass.
- **Enforcement point.** Guarded Egress Broker resolution-validation step (validates the full record set, not the first usable entry).
- **Test approach.** Integration test with multi-record DNS responses mixing in-scope and out-of-scope/private IPs; assert DENY. Property-based test over random record sets asserting ALLOW iff all records are in scope.
- **Violation impact.** Partial-set bypass reaching internal or metadata endpoints.
- **Related threats.** SSRF, scope escape

### SI-005

**Every HTTP redirect (any 3xx with a Location, plus meta-refresh and equivalent) MUST be re-submitted to the Scope Authority (which mints a fresh grant) and re-validated (including fresh DNS resolution and IP-range checks); a redirect whose target is out-of-scope MUST NOT be followed, and cross-scope redirect chains terminate immediately.**

- **Rationale.** Redirects are attacker-influenceable and are a classic path from an in-scope host to an out-of-scope or internal target. Following them blindly negates scope entirely.
- **Enforcement point.** Guarded Egress Broker redirect handler (auto-follow disabled at the raw client; redirects handled explicitly with re-validation and a bounded hop count).
- **Test approach.** Integration test: in-scope host returns 301/302/307/308 to (a) out-of-scope public host, (b) private IP, (c) metadata IP, (d) localhost; assert none are followed and each is logged as a blocked redirect. Test redirect loops and long chains for hop-limit enforcement. Property-based test on Location values including relative URLs, protocol-relative URLs, and mixed encodings.
- **Violation impact.** Scope escape and SSRF via a single crafted redirect on an authorized host.
- **Related threats.** scope escape, SSRF

### SI-006

**Tier A ranges MUST NEVER be contacted by any means — no allowlist entry, no elevated flag, no approval: loopback (127.0.0.0/8, ::1), unspecified (0.0.0.0/8, ::), cloud/link-local metadata (169.254.169.254, 169.254.170.2, fd00:ec2::254 and provider metadata endpoints), multicast (224.0.0.0/4, ff00::/8), broadcast (255.255.255.255), and reserved/future/documentation ranges (240.0.0.0/4, 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15, 2001:db8::/32, 2001:20::/28, 100::/64, ::/96). Tier B ranges — RFC1918 (10/8, 172.16/12, 192.168/16), ULA (fc00::/7), link-local (169.254.0.0/16 minus metadata, fe80::/10 minus metadata), CGNAT (100.64.0.0/10) — MUST be denied UNLESS all of: an explicit elevated ip/cidr scope entry names them, a dual-approved restricted_range_allow exists, and the authorization grants internal testing. Metadata stays Tier A even inside an elevated link-local range.**

- **Rationale.** Tier A is where SSRF does its worst (metadata credential theft, loopback/internal services) and there is never a legitimate reason to reach it, so it is absolutely non-overridable. Authorized internal RFC1918/ULA/link-local engagements are real, so Tier B is supported — but only through explicit elevated dual approval, never as an incidental consequence of a broad allow. This removes the earlier contradictory wording ("unless that exact range is in the allowlist" / "metadata reachable via an exact /32").
- **Enforcement point.** The network-guard classifier — the Scope Authority ruleset applied by the Guarded Egress Broker on every resolved IP and every connect/redirect target, evaluated before the allowlist. Tier A is subtracted from any Tier B grant.
- **Test approach.** Exhaustive table-driven tests over each range including boundaries, IPv4-mapped/-compatible, and transition forms. Assert Tier A is unreachable even when an elevated covering entry (e.g. 169.254.0.0/16 or 0.0.0.0/0) is present. Assert Tier B is reachable only with the full elevation condition (elevated entry + dual-approved restricted_range_allow + internal_testing_granted). Property-based test over the full IPv4/IPv6 space asserting classification correctness.
- **Violation impact.** Credential theft from cloud metadata, access to internal-only services — the canonical SSRF impact.
- **Related threats.** SSRF, scope escape

### SI-007

**All targets MUST be canonicalized before scope evaluation: IPv4 and IPv6 both fully validated; alternate encodings (decimal/octal/hex/mixed IPv4, zero-compression and IPv4-embedded IPv6, uppercase/percent-encoded/punycode hostnames, trailing-dot, userinfo, and non-standard ports) normalized to a single canonical form, and the canonical form is what is matched against scope. Any input that cannot be unambiguously canonicalized is denied.**

- **Rationale.** Encoding tricks (http://0x7f.1/, http://2130706433/, http://[::ffff:127.0.0.1]/, http://evil.com@in-scope/) are the standard way to smuggle a forbidden target past a naive string match.
- **Enforcement point.** Scope Authority canonicalization layer, run before both allowlist matching and forbidden-range classification.
- **Test approach.** Parser/URL fuzzing corpus of known SSRF bypass encodings asserting each normalizes to the correct canonical target or is rejected. Property-based round-trip tests. Differential test against a reference URL parser to catch parser-confusion (frontend parses one host, the Scope Authority another).
- **Violation impact.** Scope match is bypassed by encoding, letting forbidden hosts through while appearing in-scope.
- **Related threats.** scope escape, SSRF

### SI-008

**Explicit exclusions MUST always take precedence over allowlist entries: if a canonical target matches any exclusion (domain, IP, CIDR, port, or path), the request is denied even when it also matches an allow rule.**

- **Rationale.** Operators exclude sub-targets (e.g., a shared host, a fragile endpoint) that would otherwise be caught by a broad allow rule. Exclusions are a safety brake and must be non-overridable.
- **Enforcement point.** Scope Authority verdict precedence order: exclusion check evaluated last with veto power over any allow.
- **Test approach.** Unit tests with overlapping allow+exclude rules (exact overlap, CIDR containing an excluded IP, allowlisted domain with excluded path) asserting DENY. Property-based test asserting exclusion always wins for any overlapping pair.
- **Violation impact.** Testing of explicitly forbidden endpoints the operator carved out for safety or legal reasons.
- **Related threats.** scope escape

### SI-009

**Only allowlisted ports and protocols may be contacted; a request to a non-allowlisted port or using a non-allowlisted protocol (e.g., gopher://, file://, ftp://, dict://, non-HTTP schemes) is denied.**

- **Rationale.** SSRF frequently pivots via non-HTTP schemes and unexpected ports (e.g., internal admin ports). Restricting to explicitly-allowed HTTP(S) ports/protocols shrinks the attack surface.
- **Enforcement point.** Scope Authority scheme/port allowlist check; the Guarded Egress Broker only implements HTTP/HTTPS transports.
- **Test approach.** Unit tests denying every non-HTTP scheme and non-allowlisted port. Integration test asserting scheme smuggling in redirects and userinfo is rejected. Property-based test over random scheme/port combinations.
- **Violation impact.** Access to internal services on non-web ports; protocol-smuggling SSRF.
- **Related threats.** SSRF, scope escape

### SI-010

**When URL-prefix / path scope is defined for a target, requests to paths outside the allowed prefixes are denied; path canonicalization (dot-segment, encoded-slash, and traversal normalization) occurs before matching so that ../ and %2e%2e cannot escape an allowed prefix.**

- **Rationale.** Path scoping lets operators restrict testing to a specific application area on a shared host; traversal encodings must not defeat it.
- **Enforcement point.** Scope Authority path-matching step operating on canonicalized paths.
- **Test approach.** Table-driven tests of traversal/encoding variants against allowed prefixes asserting correct allow/deny. Fuzz path inputs for normalization consistency.
- **Violation impact.** Testing outside the authorized application area on a shared host.
- **Related threats.** scope escape

### SI-011

**When an engagement's authorization is expired (past expiry timestamp) or otherwise invalid/revoked, the number of new outbound requests is zero and all in-flight and queued jobs for that engagement are halted within a bounded, tested time (e.g., <= 5s for dequeue stop, in-flight requests aborted).**

- **Rationale.** Legal authority to test ends precisely at expiry. The system must enforce the calendar boundary technically, not rely on operators to stop.
- **Enforcement point.** the Scope Authority (Stage 1) and Guarded Egress Broker (Stage 2) validate authorization freshness on every request (defense in depth); scheduler/worker supervisor runs an expiry sweep that cancels queued jobs and signals in-flight abort; auth expiry re-checked at dequeue and at connect time.
- **Test approach.** Integration test with a clock shim: start a running scan, advance the clock past expiry mid-scan, assert in-flight requests abort and no new requests fire. Property-based test asserting request timestamps never exceed authorization expiry. Test the boundary at expiry - epsilon and expiry + epsilon.
- **Violation impact.** Testing continues without legal authorization — a compliance and legal breach.
- **Related threats.** scope escape

### SI-012

**Outside the engagement's configured testing window (allowed days/hours/timezone), no outbound requests execute; work scheduled outside the window is held, and work that runs into a window boundary halts at the boundary.**

- **Rationale.** Operators contractually limit testing to change windows / low-traffic periods. The window is a hard interlock, not a suggestion.
- **Enforcement point.** Scheduler window-gate at enqueue/dequeue plus Guarded Egress Broker per-request window check using the engagement timezone.
- **Test approach.** Integration test with clock shim crossing window open/close boundaries (including DST transitions and timezone edge cases) asserting requests only occur inside the window. Property-based test over random window definitions and request times.
- **Violation impact.** Testing during prohibited hours, risking production impact and contract violation.
- **Related threats.** scope escape, queue abuse

### SI-013

**Activation of emergency stop (global or per-engagement) MUST, within a bounded and tested time, prevent any further dequeue, abort all in-flight requests, and block all new outbound requests until explicitly cleared by an authorized role; a stopped engagement can issue zero requests.**

- **Rationale.** The operator must have an absolute, immediate kill switch that overrides everything else regardless of scope or approval state.
- **Enforcement point.** Emergency-stop flag checked by the Scope Authority (Stage 1) and Guarded Egress Broker (Stage 2) on every request AND by the worker supervisor which sends abort signals; flag stored in a fast, consistent store read on the hot path.
- **Test approach.** Integration/chaos test: trip e-stop during a high-concurrency scan and assert in-flight sockets close and request count freezes within the bound. Test that a stopped engagement cannot be restarted without an authorized clear. Race test hammering e-stop concurrently with the scheduler.
- **Violation impact.** Inability to stop an in-progress scan causing harm — loss of operator control.
- **Related threats.** queue abuse, scope escape

### SI-014

**Automatic circuit breakers MUST trip and halt an engagement (or a specific check/target) when tested thresholds are exceeded — target error rate, 5xx spike, response-time degradation signaling target stress, or anomaly counts — and a tripped breaker blocks further requests until reset.**

- **Rationale.** Non-destructive by design means the platform must back off the instant it might be harming a target, without waiting for a human.
- **Enforcement point.** Guarded Egress Broker / worker instrumentation feeding a per-engagement and per-target breaker evaluated before each request.
- **Test approach.** Integration test injecting rising 5xx/latency from a mock target and asserting the breaker trips at the configured threshold and requests stop. Property-based test on threshold arithmetic. Assert a tripped breaker refuses subsequent requests until reset.
- **Violation impact.** Continued load on a struggling target — an availability/DoS risk contradicting the non-destructive mandate.
- **Related threats.** queue abuse

### SI-015

**The number of concurrent in-flight outbound requests per engagement MUST never exceed the engagement's configured concurrency ceiling at any instant, including across worker restarts and multiple worker processes.**

- **Rationale.** Concurrency is the primary lever for target load; exceeding it risks DoS and violates the conservative-load promise.
- **Enforcement point.** Distributed concurrency limiter (per-engagement leased slots in a shared store) consulted by the Guarded Egress Broker before every request; slots released on completion/abort with leak-safe timeouts.
- **Test approach.** Concurrency/race integration test spawning many workers and asserting an instantaneous-in-flight counter never exceeds the ceiling (sampled continuously). Property-based/stress test with randomized ceilings and worker counts. Fault-injection: kill a worker mid-request and assert slots are reclaimed, not lost or double-counted.
- **Violation impact.** Unintended load amplification approaching DoS; violates conservative-concurrency safety promise.
- **Related threats.** queue abuse

### SI-016

**The outbound request rate per engagement MUST never exceed the configured requests-per-interval ceiling measured over any sliding window; bursts that would exceed the ceiling are delayed or dropped, never sent.**

- **Rationale.** Rate ceilings bound the aggregate pressure on a target independent of concurrency and protect against accidental flooding.
- **Enforcement point.** Distributed token-bucket/rate limiter per engagement enforced in the Guarded Egress Broker on the send path.
- **Test approach.** Integration test measuring actual request timestamps under sustained and bursty demand asserting no sliding window exceeds the ceiling. Property-based test over random rate configs and arrival patterns. Multi-worker test asserting the global (not per-worker) rate holds.
- **Violation impact.** Request flooding of a target — DoS risk and violation of agreed rate limits.
- **Related threats.** queue abuse

### SI-017

**Each engagement and run has a finite total request budget enforced by an identifiable `budget_reservation` ledger: a just-in-time grant-mint inserts exactly one reservation row keyed by the grant `jti` only if availability (`total − used − live reservations`) > 0; a sent request idempotently commits it (`used += 1`); a pre-send denial idempotently releases it; a crashed worker's reservation auto-expires. The number of committed (sent) requests MUST never exceed `request_budget_total`, and no reservation may strand.**

- **Rationale.** A bare counter cannot be committed/released idempotently and strands budget when a worker crashes between reserve and send. An identifiable ledger with monotonic state gives idempotent commit/release and crash-expiry, so the cap holds exactly under concurrency, retries, and crashes.
- **Enforcement point.** `budget_reservation` (one row per grant `jti`) with monotonic `reserved→committed`/`reserved→released` transitions and a crash-expiry sweeper (`04` §8.1); the Scope Authority reserves at mint, the Guarded Egress Broker commits on send / releases on denial.
- **Test approach.** Total *committed* never exceeds the budget under concurrency (boundary total-1/total/total+1); a double commit and a double release are each no-ops (idempotent); killing a worker after reserve but before send leaves the unit reclaimed by expiry, not stranded; a race for the last unit admits exactly one.
- **Violation impact.** Unbounded or under-counted scan volume; runaway crawls; stranded budget starving an engagement.
- **Related threats.** queue abuse

### SI-018

**No action classified as intrusive, active-injection, or destructive-class MAY execute unless a stored approval record exists that (a) references the exact plan hash of the concrete request(s) to be sent, (b) identifies an approver holding an authorized role, (c) is unexpired, and (d) has not been consumed beyond its permitted use; absent a matching valid approval, the action does not run.**

- **Rationale.** Approval-Gated Validation is a core safety mode. Binding approval to the exact plan hash prevents approving a benign plan and then executing a different, harmful one.
- **Enforcement point.** Validation executor gate that recomputes the plan hash at execution time and matches it to an immutable approval record before the Guarded Egress Broker sends; the Scope Authority refuses to mint a grant for an intrusive-class request lacking a valid approval reference, and the grant carries that reference.
- **Test approach.** Integration test: attempt intrusive validation with (no approval / expired approval / approval for a different plan hash / approval by an unauthorized role) and assert refusal in every case; only an exact-hash, authorized, unexpired approval permits execution. Tamper test: mutate the plan after approval and assert the hash mismatch blocks it.
- **Violation impact.** Intrusive/destructive actions executing without human authorization — the exact outcome the approval gate exists to prevent.
- **Related threats.** scope escape, command injection

### SI-019

**The system MUST be structurally incapable of emitting destructive payloads: request bodies/parameters are constructed only from a curated allowlist of inert, non-destructive test payloads (e.g., unique benign reflection markers, boolean-differential SQL probes that cannot modify data, path-traversal probes targeting only known-harmless canary paths); destructive tokens (DROP/DELETE/UPDATE/INSERT/TRUNCATE, shell metacharacters, OS commands, reverse-shell strings, executable uploads) can never be generated or sent.**

- **Rationale.** Non-destructive-by-design must be enforced in the payload layer, not by operator discipline. Differential SQLi and inert XSS markers give evidence without impact.
- **Enforcement point.** Check-engine payload factory restricted to an allowlisted, versioned payload catalog; an egress payload scanner in the Guarded Egress Broker rejects any outbound body/param matching destructive-signature deny rules as a backstop.
- **Test approach.** Unit test asserting every payload in every check's catalog is inert per a destructive-signature classifier. Property-based test attempting to coerce checks into emitting destructive strings via crafted target metadata, asserting none escape. Backstop test: inject a synthetic destructive payload into the send path and assert Guarded Egress Broker blocks it.
- **Violation impact.** Data destruction/modification, command execution on the target — catastrophic and irreversible.
- **Related threats.** command injection, scope escape

### SI-020

**Approval records and their bound plan hashes are immutable once created; any modification to the plan (target, request, payload, scope, or count) invalidates the approval and requires a new approval, and an approval is single-run unless explicitly marked reusable with a bounded use count.**

- **Rationale.** Prevents approval reuse/replay and post-approval tampering, which would let a benign approval authorize a changed, harmful action.
- **Enforcement point.** Append-only approval store; execution gate binds one approval to one plan hash and records consumption.
- **Test approach.** Integration test: approve plan A, mutate to plan B, assert execution blocked; replay a consumed single-use approval and assert refusal. Tamper test on stored approval bytes detected via hash. Concurrency test: two workers racing to consume the same single-use approval, assert only one succeeds.
- **Violation impact.** Replay/substitution of approvals to run unapproved intrusive actions.
- **Related threats.** scope escape, cross-tenant access

### SI-021

**Secrets, credentials, API keys, session tokens, cookies, Authorization headers, passwords, and PII MUST never be persisted in cleartext to any log, audit event, evidence store, database record, or report; such values are redacted or tokenized at the sink before write, so that no persisted artifact contains a recoverable secret.**

- **Rationale.** The platform handles operator-supplied auth sessions and captures target responses; a leak of those to logs/reports is itself a serious security incident (secret leakage / report-data exposure).
- **Enforcement point.** Central redaction filter wrapping all persistence sinks (logger, evidence writer, report renderer, DB serializers) plus structured-field classification that marks sensitive fields for redaction at capture time.
- **Test approach.** Report-redaction and log-redaction tests: seed requests/responses/evidence with known secret canaries (fake API keys, cookies, JWTs, SSNs, emails) and assert no canary appears in any persisted artifact (grep the emitted logs, DB rows, evidence blobs, and all report formats). Property-based fuzzing of secret formats. Golden-file tests for each report format (HTML/JSON/CSV/PDF-ready).
- **Violation impact.** Leakage of operator or target secrets/PII via logs or shared reports — a breach caused by the security tool itself.
- **Related threats.** secret leakage, report-data exposure

### SI-022

**Evidence capture MUST enforce per-item body-size limits and retention policy, and response bodies stored as evidence MUST pass through redaction; no unbounded response body is retained and sensitive-classified bodies are stored only in redacted form.**

- **Rationale.** Bulk retention of target response data risks storing PII/secrets and enables report-data exposure; size/retention limits bound the blast radius.
- **Enforcement point.** Evidence writer applies size truncation, sensitivity classification, redaction, and retention TTL before persistence.
- **Test approach.** Integration test feeding oversized and secret-laden bodies and asserting truncation, redaction, and TTL expiry. Assert retention job deletes expired evidence. Redaction canary test on stored evidence.
- **Violation impact.** Accumulation of sensitive target data increasing exposure surface and breach impact.
- **Related threats.** report-data exposure, secret leakage

### SI-023

**Generated reports in every format (HTML, JSON, CSV, PDF-ready) MUST contain only redacted content — no unredacted cookies, Authorization headers, API keys, passwords, PII, or sensitive response bodies — and reproduction steps MUST be non-destructive; a report failing the redaction assertion cannot be produced.**

- **Rationale.** Reports are the artifact most likely to be shared beyond the operator; a leak here has the widest distribution.
- **Enforcement point.** Report renderer runs the redaction filter as a mandatory final pass and a post-render verifier that fails the build/export if any canary/secret pattern is present.
- **Test approach.** Golden-file + canary tests per format asserting zero secret/PII patterns. Snapshot diffing to catch regressions. Verifier gate that blocks export on any detected secret. Assert reproduction steps contain only inert payloads.
- **Violation impact.** Wide-distribution leak of secrets/PII through a shared report.
- **Related threats.** report-data exposure, secret leakage

### SI-024

**Every data access (API query, DB read, evidence fetch, report generation, queue consumption) MUST be constrained by the caller's tenant and engagement authorization; no query, job, or endpoint can read or write data belonging to another tenant or another engagement the caller is not authorized for.**

- **Rationale.** Multi-tenant isolation prevents one client's data, scope, credentials, or findings from being exposed to another — a confidentiality and legal boundary.
- **Enforcement point.** Row-level security / mandatory tenant+engagement predicate enforced at the data-access layer and re-checked in the API authorization middleware; worker jobs execute under an engagement-scoped identity.
- **Test approach.** Tenant-isolation test suite: for every read/write endpoint and every worker job, attempt cross-tenant and cross-engagement access with a valid-but-unauthorized identity and assert denial (no rows, 403). Property-based test generating random (tenantA asset, tenantB caller) pairs. IDOR fuzzing over object IDs. Assert RLS is active on every table containing tenant data.
- **Violation impact.** One client viewing/altering another client's scope, credentials, or findings — a severe multi-tenant breach.
- **Related threats.** cross-tenant access, report-data exposure, secret leakage

### SI-025

**A worker executing a job for engagement E can load only E's scope config, authorization, operator-supplied credentials/sessions, and budgets; it MUST NOT be able to read another engagement's configuration or secrets, even when running on shared worker infrastructure.**

- **Rationale.** Workers hold the most sensitive material (auth sessions, scope). Cross-engagement access at the worker layer would let a compromised or buggy job pivot across clients.
- **Enforcement point.** Per-job scoped credential provisioning (short-lived, engagement-bound secret leases); worker process receives only the target engagement's context; secret store enforces engagement-scoped access policies.
- **Test approach.** Integration test attempting, from within a job for E, to fetch F's scope/secrets and asserting denial. Container/isolation test asserting no shared secret volume across engagements. Verify secret leases are engagement-scoped and expire.
- **Violation impact.** Cross-engagement credential/scope leakage; a pivot path for cross-tenant compromise.
- **Related threats.** cross-tenant access, secret leakage

### SI-026

**The audit trail MUST be append-only and tamper-evident (hash-chained/sequence-linked so any insertion, deletion, or modification is detectable), and every safety-relevant action — scope decision, request intent/completion, approval, e-stop, expiry halt, config change, login, data export — MUST produce exactly one corresponding immutable audit event. Every chain MUST have a NON-NULL identity (`audit_chain.chain_id`), and per-chain `seq`/`event_hash` uniqueness MUST be enforced on that non-null key.**

- **Rationale.** Tamper-evidence and completeness are prerequisites for trusting that the other invariants held. A per-chain uniqueness constraint over columns that are NULL for tenant/global streams is vacuous in SQL (NULLs compare distinct), so a non-null `chain_id` is required for the constraint to actually enforce one event per (chain, seq).
- **Enforcement point.** `audit_chain` (non-null `chain_key`/`id`) + `audit_event.chain_id NOT NULL` with `UNIQUE(chain_id, seq)` and `UNIQUE(chain_id, event_hash)`; hash-chained per chain; write-once storage; instrumentation at every safety-relevant action site (`04` §9).
- **Test approach.** Each safety-relevant action emits exactly one event with correct linkage; tamper/reorder/delete on any chain (including tenant and global) fails verification; a coverage test enumerates action types; a negative test proves two events with the same `seq` on a tenant/global chain are REJECTED (the bug the non-null `chain_id` fixes).
- **Violation impact.** Undetectable tampering or duplicate/forked chains — destroys accountability, especially for platform/tenant governance events.
- **Related threats.** scope escape, cross-tenant access, malicious scanner output

### SI-027

**If an audit event for a safety-relevant action cannot be durably written, the action MUST NOT proceed (fail-closed on audit): a request that cannot be logged is not sent, an approval that cannot be recorded does not authorize execution.**

- **Rationale.** An action that escapes the audit trail is indistinguishable from a covert bypass; correctness of the tamper-evident log requires that no auditable action outruns its record.
- **Enforcement point.** Guarded Egress Broker and the validation executor treat a durable audit write as a precondition (write-then-act ordering) rather than fire-and-forget.
- **Test approach.** Fault-injection test making the audit sink fail/latency-spike and asserting the guarded action is blocked, not silently executed. Assert ordering: no request timestamp precedes its audit event's durable commit.
- **Violation impact.** Silent, unlogged requests or approvals — a blind spot that voids the audit guarantee.
- **Related threats.** scope escape, malicious scanner output

### SI-028

**No user-, target-, or tool-supplied input EVER reaches a shell interpreter; all external processes (tool adapters, scanners) are launched with explicit argument vectors (no shell, no string interpolation, no shell=true), and there is no code path from any API/UI field to a command line.**

- **Rationale.** Command injection is one of the ten named threats and the highest-impact failure of a tool that orchestrates external binaries. Argv-only exec with a static allowlist of binaries eliminates the injection surface.
- **Enforcement point.** Process-launch wrapper that accepts only (allowlisted-binary, validated-argv[]) and forbids shell invocation; static-analysis CI rule forbidding shell=true, os.system, backticks, eval, and string-built commands anywhere.
- **Test approach.** Static-analysis gate failing CI on any shell-exec construct. Integration/fuzz test injecting shell metacharacters and command-substitution into every field that flows toward a tool adapter, asserting they are passed as inert literal args (or rejected) and never interpreted. Argument-injection tests (leading-dash args) asserting arg boundaries hold.
- **Violation impact.** Remote command execution on the platform host — full compromise of the assessment infrastructure.
- **Related threats.** command injection, unsafe plugin execution

### SI-029

**Output from external tools (Nuclei, ZAP, TestSSL, SCA/secret scanners) MUST be consumed only as structured, untrusted data via a strict parser into the normalized finding schema; tool output is NEVER executed, eval'd, deserialized into code, used to construct commands, or auto-followed as new targets, and it cannot influence scope or egress destinations.**

- **Rationale.** Malicious or malformed scanner output is a named threat; treating it as trusted (e.g., following URLs it reports, or code-deserializing it) turns a scanning tool into an injection vector.
- **Enforcement point.** Tool-adapter parsing layer using safe structured parsers (no code-eval, no unsafe deserialization), schema validation, and a hard boundary that raw tool output cannot expand scope or spawn requests without going through the two-stage Scope Authority / Guarded Egress Broker flow and (for intrusive follow-ups) approval.
- **Test approach.** Parser fuzzing with malformed/huge/adversarial tool output asserting no crash, no code execution, and safe rejection. Test that URLs/targets present in tool output do NOT become new outbound requests without a scope check. Test that a scanner claiming an out-of-scope host as a finding cannot trigger a request to it. Verify no unsafe deserializer (pickle/yaml.load/etc.) is used on tool output.
- **Violation impact.** Scanner output driving code execution, scope expansion, or SSRF — weaponizing a defensive tool.
- **Related threats.** malicious scanner output, unsafe plugin execution, command injection, scope escape

### SI-030

**External tools and plugins MUST run in isolated containers with default-deny network egress; their only permitted network destinations are those the Guarded Egress Broker permits per the current engagement's grants, enforced at the network/sandbox layer (not merely inside the tool), and they run under CPU/memory/time/request limits.**

- **Rationale.** Unsafe plugin execution and tool egress are named threats; a tool that can reach arbitrary hosts bypasses every scope control the application layer enforces.
- **Enforcement point.** Container runtime + network policy (egress firewall / sandbox) that whitelists only Guarded Egress Broker-approved destinations for the tool's engagement; resource cgroup limits; read-only/ephemeral filesystem.
- **Test approach.** Container-isolation test: from inside a tool container, attempt connections to out-of-scope hosts, metadata IP, other engagements' hosts, and the internet at large, asserting all are blocked at the network layer. Resource-limit tests asserting CPU/mem/time caps enforced (tool killed on breach). Assert the egress allowlist is derived from and stays in sync with the live scope verdict set.
- **Violation impact.** A tool reaching unauthorized or internal hosts — SSRF/scope escape and lateral movement from the scanning layer.
- **Related threats.** unsafe plugin execution, SSRF, scope escape, malicious scanner output

### SI-031

**Every external tool binary, container image, and scan template/plugin MUST be version-pinned and integrity-verified (cryptographic digest / signature) before execution; an unpinned, unverified, or digest-mismatched tool, image, or template MUST NOT run, and only templates on the curated non-destructive allowlist are permitted.**

- **Rationale.** Supply-chain compromise is a named threat; unverified templates could contain destructive or exfiltrating logic. Pinning + verification + a destructive-template denylist keeps the tool layer non-destructive and trusted.
- **Enforcement point.** Tool loader verifies digests/signatures against a pinned manifest before launch; template allowlist enforced by the adapter; CI blocks introduction of unpinned tools/templates.
- **Test approach.** Integration test: tamper a template/image digest and assert execution is refused. Assert a destructive/unsafe template (denylisted or not on the allowlist) cannot be selected or run. Supply-chain test verifying the pinned manifest matches deployed artifacts. CI check failing on unpinned dependencies.
- **Violation impact.** Execution of tampered or destructive scan logic — supply-chain-driven harm to targets or the platform.
- **Related threats.** supply-chain compromise, unsafe plugin execution, malicious scanner output

### SI-032

**Application dependencies and container base images MUST be locked with integrity hashes and verified at build/deploy; the build fails on any unpinned, hash-mismatched, or unverifiable dependency, and known-vulnerable/unapproved dependencies block release per policy.**

- **Rationale.** Supply-chain compromise via the platform's own dependencies would undermine every other invariant; reproducible, verified builds are the baseline defense.
- **Enforcement point.** Locked dependency manifests with hashes; CI verification step; SCA gate in the release pipeline.
- **Test approach.** CI test asserting lockfile integrity and that installation uses hash verification (fails on tampered lock). Reproducible-build check. SCA scan gating release on policy-violating advisories. Assert no floating version ranges in production manifests.
- **Violation impact.** Compromised dependency injecting malicious behavior into the platform — broad, stealthy compromise.
- **Related threats.** supply-chain compromise

### SI-033

**Worker network egress at the infrastructure layer MUST be default-deny, permitting only a narrow allowlist of internal control-plane services (job queue, database, object storage, Scope Authority, secret manager) plus the Guarded Egress Broker; a worker has NO direct route to any target or to the internet and can reach a target only by presenting a valid grant to the broker.**

- **Rationale.** Defense in depth: even if an application-layer bypass existed, a network-layer egress lock confines the worker so it cannot itself dial a target. The worker still needs specific internal services to do its job, so those — and only those — plus the broker are reachable.
- **Enforcement point.** Network namespace / NetworkPolicy allowlist per worker (design in `10-request-authorization-flow.md` §4.2); complemented by SI-054 for the stricter broker-only tool/browser sandbox posture. Egress collapses to deny-all on scope loss / expiry / e-stop.
- **Test approach.** Container/network isolation test: from a worker, attempt raw connections to a target IP, an out-of-scope host, a private address, the metadata IP, and the internet at large, asserting the network layer blocks all of them and only the internal-service allowlist + broker are reachable. Chaos test removing scope and asserting egress collapses to deny-all.
- **Violation impact.** A worker reaching unauthorized hosts directly — loss of the defense-in-depth network lock behind SSRF/scope escape.
- **Related threats.** scope escape, SSRF, unsafe plugin execution

### SI-034

**SSRF-class and callback-based checks MAY use only pre-approved, engagement-configured controlled callback infrastructure as the interaction destination; a check can never induce the target to contact an arbitrary or attacker-chosen callback host, and no callback endpoint outside the approved infra is ever used.**

- **Rationale.** SSRF validation requires an out-of-band interaction endpoint; allowing arbitrary callback hosts would let the platform be used to prove SSRF against unrelated third parties or to pivot. Restricting to approved infra keeps it controlled and non-abusive.
- **Enforcement point.** Check engine draws callback targets only from the engagement's approved callback-infra registry; the Guarded Egress Broker / egress policy blocks any other callback destination.
- **Test approach.** Integration test asserting SSRF checks only ever reference approved callback hosts; attempt to configure/inject an arbitrary callback host and assert rejection. Assert callbacks to third-party or internal hosts are impossible. Property-based test over callback-host inputs.
- **Violation impact.** Using the platform to trigger interactions with arbitrary third parties — abuse and potential attack-relay via a defensive tool.
- **Related threats.** SSRF, scope escape

### SI-035

**Discovery outputs (crawler-found links, redirects, tool-reported hosts, JS-extracted routes, DNS discoveries) MUST NOT automatically expand scope or generate requests to newly-discovered hosts; any newly-discovered target outside the existing validated scope is recorded as inventory only and requires an explicit operator scope change (with its own authorization check) before any request is made to it.**

- **Rationale.** The 'never scan unrelated infrastructure discovered during testing' rule must be technical: automated scope growth from crawl/tool output is exactly how a bounded assessment becomes an unauthorized one.
- **Enforcement point.** Crawler and correlation layers write discoveries to an inventory store flagged in/out of current scope; the Scope Authority evaluates every request against the operator-defined scope only, never against auto-discovered additions.
- **Test approach.** Integration test: seed a crawl where an in-scope page links to out-of-scope and internal hosts; assert those hosts are inventoried but never requested. Assert tool-reported external hosts do not become targets. Property-based test asserting the set of requested hosts is always a subset of the operator-approved scope regardless of discovery input.
- **Violation impact.** Automatic scanning of unrelated/third-party infrastructure discovered mid-test — unauthorized testing and scope escape.
- **Related threats.** scope escape, SSRF, malicious scanner output

### SI-036

**The safe crawler MUST NOT auto-submit or trigger state-changing actions: forms and controls matching logout, delete, payment, account-change, password-change, messaging/send, or other destructive/state-changing semantics are recorded but never submitted, and no request the crawler issues is a non-idempotent state-changing action without an approval record.**

- **Rationale.** Non-destructive crawling requires that the crawler observe attack surface without mutating target state; auto-submitting destructive forms would cause real damage (deleted data, sent messages, charges).
- **Enforcement point.** Crawler action classifier that marks state-changing/destructive controls as record-only; request issuance restricted to safe idempotent methods by default; state-changing submissions require the approval gate (SI-018).
- **Test approach.** Integration test against a local vulnerable app with destructive forms (delete/logout/pay/send) asserting the crawler records but never submits them and issues no non-idempotent request. Property-based test over form/control classification. Assert only GET/HEAD/OPTIONS-class safe methods are auto-issued absent approval.
- **Violation impact.** Data deletion, spurious payments, sent messages, or forced logouts on the target caused by the crawler.
- **Related threats.** scope escape, queue abuse

### SI-037

**Auth controls, WAFs, CAPTCHAs, rate limiters, and monitoring MUST NEVER be bypassed, defeated, brute-forced, or evaded: the platform issues no credential brute-force/spray, no MFA-bypass, no WAF/detection-evasion transformations, and no CAPTCHA-solving; operator-supplied auth sessions are used as-is without attempting to escalate or bypass.**

- **Rationale.** The safety model explicitly forbids defeating protective controls; enforcing it technically prevents the platform from behaving like an attacker even under aggressive configuration.
- **Enforcement point.** Check engine excludes any bypass/brute-force/evasion technique from its catalog; a policy gate rejects check configurations that imply credential spraying, MFA bypass, or evasion encodings.
- **Test approach.** Catalog audit test asserting no check performs brute-force/spray/MFA-bypass/CAPTCHA-solving/WAF-evasion. Behavioral test asserting repeated-auth checks do not exceed benign single-attempt semantics and no evasion encoding is applied to payloads. Assert configuration attempting to enable such behavior is rejected.
- **Violation impact.** The platform behaving as an attacker (account takeover, control evasion) — legal and ethical breach of the authorized-testing mandate.
- **Related threats.** scope escape, queue abuse

### SI-038

**The job queue MUST enforce that every enqueued job carries a valid engagement authorization and scope reference at both enqueue and dequeue time; jobs cannot be injected, duplicated, reordered, or replayed to exceed budgets or cross engagements, and a job whose engagement authorization has since become invalid is discarded at dequeue rather than executed.**

- **Rationale.** Queue abuse is a named threat; the queue is a second place (besides direct requests) where authorization must be re-verified so that stale or forged jobs cannot bypass expiry, scope, or budget.
- **Enforcement point.** Queue producer signs/authorizes jobs with an engagement-scoped token; consumer re-validates authorization, scope, budget, and e-stop/expiry state before processing; idempotency keys prevent replay/duplication.
- **Test approach.** Queue-security test: attempt to enqueue a job for an unauthorized engagement, replay a completed job, forge a job payload, and enqueue for an expired engagement; assert each is rejected or discarded at dequeue. Race test on idempotency. Assert dequeue re-checks expiry/e-stop so a job queued while valid but dequeued after expiry does not run.
- **Violation impact.** Bypassing scope/expiry/budget via queue manipulation; cross-engagement job execution.
- **Related threats.** queue abuse, cross-tenant access, scope escape

### SI-039

**No path-traversal, file-read, or LFI-class check may retrieve sensitive OS or application files as proof; traversal checks target only known-harmless canary paths and evidence of the vulnerability is demonstrated without exfiltrating secret file contents (no /etc/passwd, no key/credential files, no user data captured as evidence).**

- **Rationale.** The safety model forbids retrieving secret files/tokens/keys/user data as proof; demonstrating traversal must not itself cause a data breach of the target.
- **Enforcement point.** Traversal check restricted to a canary-path allowlist; evidence capture rejects/redacts any content matching sensitive-file signatures.
- **Test approach.** Integration test against a local app with a traversal flaw asserting the check proves it via harmless canaries and never stores sensitive-file contents. Redaction test on captured evidence for sensitive-file signatures. Assert the check's target-path set excludes OS/secret paths.
- **Violation impact.** The assessment causing a real data breach of the target by extracting secret files as evidence.
- **Related threats.** report-data exposure, secret leakage, scope escape

### SI-040

**Permission-changing, configuration, scope, authorization, approval, and emergency-stop actions MUST be authorized by RBAC at the API/service layer with least privilege; no unauthenticated or under-privileged principal can alter scope, extend authorization, approve intrusive validation, or clear an emergency stop, and no arbitrary shell/command capability is exposed via UI or API.**

- **Rationale.** The safety controls themselves must be protected: if a low-privilege user can widen scope or approve intrusive actions, the interlocks are meaningless. RBAC integrity is a meta-invariant guarding all others.
- **Enforcement point.** API authorization middleware with role checks on every sensitive mutation; no endpoint maps user input to shell execution; approval/e-stop/scope endpoints gated to named authorized roles.
- **Test approach.** Authorization test matrix: for each sensitive action and each role, assert allow/deny matches the RBAC policy; assert unauthenticated and lower-privilege principals are denied scope/auth/approval/e-stop mutations. Fuzz for privilege-escalation and missing-authz endpoints. Assert no endpoint accepts commands for shell execution.
- **Violation impact.** Unauthorized widening of scope, self-approval of intrusive actions, or disabling safety controls — subversion of the entire interlock system.
- **Related threats.** scope escape, cross-tenant access, command injection

### SI-041

**Any sandboxed tool or headless browser MUST use the Guarded Egress Broker as its sole egress proxy for ALL request types, with client-side DNS disabled (proxy-side resolve + IP pinning) and direct-socket / WebRTC / QUIC features disabled. A tool or browser that cannot be so constrained is not permitted to reach targets.**

- **Rationale.** A headless browser and many tools are autonomous request engines that otherwise resolve DNS and open sockets themselves, bypassing every request-path invariant. Forcing all request types through the single broker, with no client-side resolution, is the only way IP-pinning and scope re-validation hold for them.
- **Enforcement point.** Data-plane network namespace (default-deny egress, only next hop = broker) + browser/tool launch flags that disable client DNS and direct sockets; CI gate on adapter launch configuration.
- **Test approach.** Integration test: render/scan a page referencing an out-of-scope subresource and assert zero out-of-scope connections observed at the broker and zero sockets from the sandbox netns to any non-broker address. Config test: assert browser/tool launch disables client DNS, WebRTC, QUIC, and direct sockets.
- **Violation impact.** Scope escape and SSRF via an uncontrolled request engine, silently defeating SI-001/SI-003.
- **Related threats.** scope escape, SSRF

### SI-042

**Per-request path-prefix, redirect, and body inspection MUST have a defined, non-bypassable enforcement point even for HTTPS tool traffic — either broker TLS-termination using a sandbox-only internal CA, or request-by-request adapter driving with auto-redirect disabled. The design MUST pick one explicitly per adapter; invariants that require request visibility apply only where the broker can see the request.**

- **Rationale.** Inside a CONNECT tunnel the broker sees only host:port, so path/redirect/body invariants are unenforceable for HTTPS tools unless a specific model is chosen. Leaving it implicit silently voids SI-005/SI-010 and body caps for the bulk of real scanning.
- **Enforcement point.** Guarded Egress Broker (TLS-termination mode with sandbox-only CA) and/or tool adapter (request-by-request driving with redirects disabled).
- **Test approach.** Integration test per HTTPS-capable adapter: a redirect to an out-of-scope path/host inside TLS is detected and stopped (termination mode) or the adapter issues each hop through the broker in broker-visible form (driven mode). Assert no adapter both terminates-blind and follows redirects.
- **Violation impact.** Path-scope and redirect scope escape for tool-originated HTTPS traffic.
- **Related threats.** scope escape, SSRF

### SI-043

**The Stage-1 egress grant MUST bind the exact HTTP method and canonical path (not merely host/IP/port), so an allow for one path or verb can never be replayed against another; the Guarded Egress Broker rejects any request whose method or canonical path differs from the grant.**

- **Rationale.** A capability bound only to (engagement, authz, host, IP, port, protocol) would authorize any path and any method on that host. Binding method + canonical path makes path-prefix and method scope enforceable at the broker even for tool-driven HTTPS traffic. (This property is also stated inside SI-001; SI-043 is retained as the explicit path/method-replay guarantee.)
- **Enforcement point.** Scope Authority (grant minting binds method + canonical path) + Guarded Egress Broker / adapter (verifies the grant against the actual request line before sending).
- **Test approach.** Property test: a grant minted for `GET /app` cannot be replayed for `POST /admin` on the same host/IP; the broker rejects the mismatch. Fuzz path/method variants asserting the bound values are enforced after canonicalization.
- **Violation impact.** Path- and method-level scope escape via grant replay.
- **Related threats.** scope escape

### SI-044

**The network-guard classifier MUST decode IPv4-mapped, IPv4-compatible, 6to4 (2002::/16), Teredo (2001::/32), and NAT64 (64:ff9b::/96) forms and re-classify the embedded IPv4 against all ranges; any form decoding to a Tier A range is hard-denied and cloud-metadata addresses are NEVER reachable by any allow, elevated entry, or approval. A Tier B covering entry (e.g. an elevated 169.254.0.0/16) does NOT permit any Tier A address inside it.**

- **Rationale.** Transition IPv6 forms can encode 169.254.169.254 or RFC1918 and slip past a naive deny list; and a broad allow must never incidentally grant a metadata address. Consistent with SI-006's absolute Tier A, metadata is unreachable by construction — the earlier "reachable only via an exact /32 elevated allow" clause is removed.
- **Enforcement point.** Scope Authority address classifier + Guarded Egress Broker resolved-IP check; Tier A is subtracted from any Tier B grant.
- **Test approach.** Table-driven test over 6to4/Teredo/NAT64/IPv4-mapped forms (including 2002:a9fe:a9fe:: which decodes to 169.254.169.254) asserting the decoded IPv4 is classified Tier A and hard-denied. Assert an elevated 169.254.0.0/16 entry does NOT permit 169.254.169.254. Assert a 0.0.0.0/0 allow never reaches any Tier A address.
- **Violation impact.** SSRF to cloud metadata / internal ranges via encoded addresses or broad covering entries.
- **Related threats.** SSRF

### SI-045

**Redaction MUST be allowlist/minimization-based: only explicitly-safe, structured fields are surfaced in evidence, reports, and logs; every response body, URL, and header is treated as secret-bearing by default and stored size-capped/minimized. Redaction MUST happen BEFORE any write to the immutable audit trail — raw target auth material and bodies are never written there.**

- **Rationale.** Denylist redaction fails open on novel/opaque tokens, URL-embedded secrets, and PII in arbitrary bodies; because the audit trail is immutable, any unredacted write is a permanent, unfixable leak.
- **Enforcement point.** Worker redaction pipeline stage (pre-egress-of-data-plane) + API re-assertion before storage; audit-write path routes only through redacted, allowlisted fields.
- **Test approach.** Fuzz corpus with novel-format secrets, URL-embedded tokens, and PII in bodies asserting none appear in evidence, reports, or audit; test that the audit-write path cannot receive a raw body or auth header.
- **Violation impact.** Permanent secret/PII leakage into evidence, reports, or the immutable audit trail.
- **Related threats.** secret leakage, report-data exposure

### SI-046

**Every safety-critical dependency — scope verdict, authorization freshness, emergency-stop state, testing-window/expiry evaluation, DNS resolver, and trusted clock — MUST fail closed on unavailability or uncertainty: the request is denied and, where applicable, the engagement halts. There is no permissive default anywhere on the safety-critical path.**

- **Rationale.** Fail-closed was originally stated only for the secret store; any of these dependencies being unreachable while the broker defaults permissive is a fail-open of the core perimeter.
- **Enforcement point.** Guarded Egress Broker and Scope Authority (deny on any unresolved dependency); scheduler (block on uncertainty).
- **Test approach.** Fault-injection tests killing each dependency mid-scan (scope service, e-stop store, breaker store, resolver, clock source) and asserting zero egress and, where applicable, engagement halt.
- **Violation impact.** Fail-open of the scope/authorization perimeter under partial outage.
- **Related threats.** scope escape, SSRF

### SI-047

**Authorization attestation and any scope expansion (a new host, domain, or IP range) MUST be approved under dual control: at least `required_approvals` (floor 2) distinct `approval_decision` rows, each by a distinct user holding an eligible approver role per the RBAC matrix (`09-rbac-matrix.md`), none of whom is the requester or the executing tester, each pinning the same plan hash and — for attestation — the same authorization `document_sha256`; the threshold is enforced by the system, not advisory. A single user MUST NOT hold two separation-of-duties-conflicting roles on the same engagement.**

- **Rationale.** The primary abuse actor is a privileged insider; scope-hash binding stops silent drift but not a deliberate broaden-and-re-attest by one person. The legal gate the whole product rests on needs an enforced two-person rule with per-approver hash binding so approvals cannot be moved onto a changed plan.
- **Enforcement point.** The `approval_request` / `approval_decision` threshold logic (`04` §10) with a DB trigger + application check; RBAC verification of each `approver_role` (doc 09); audit records each `approval.decided` and the `approval.threshold_met` event.
- **Test approach.** Authorization tests: a single actor cannot attest+expand+approve; the requester and the executing tester cannot be approvers; two decisions by the same user count once; a decision whose `approved_plan_sha256` ≠ the request's plan hash does not count; below-threshold requests never reach `approved`. SoD test that conflicting roles cannot both be exercised by one user on one engagement.
- **Violation impact.** Insider self-authorization enabling scope escape with a veneer of legitimacy.
- **Related threats.** scope escape

### SI-048

**Report/evidence renderers MUST execute with zero network egress and remote-resource loading disabled under a strict CSP; access-control/IDOR checks MUST capture only a non-sensitive discriminator (object-id existence, HTTP status, hashed/length fingerprint) as evidence and NEVER record another account's contents; credentials embedded in imported intake artifacts (HAR/Postman) MUST be stripped and never auto-used.**

- **Rationale.** Bundles three data-exposure gaps: renderer SSRF/exfil, IDOR evidence over-capture conflicting with the no-user-data-as-proof rule, and auto-replay of intake-embedded credentials.
- **Enforcement point.** Renderer sandbox (no network) + check contract for access-control checks (evidence-minimization) + intake pipeline (credential stripping).
- **Test approach.** Renderer test: evidence with external URL + script payload → no outbound request, no execution. IDOR check test: evidence contains only a discriminator, not contents; operator test-account data is synthetic. Intake test: a token in an imported HAR is never replayed.
- **Violation impact.** Report-data exposure, PII capture, and credential misuse.
- **Related threats.** report-data exposure, secret leakage, cross-tenant access

### SI-049

**Authorization expiry and testing windows MUST be evaluated against a monotonic clock plus an authenticated wall-clock with sanity bounds; large or backward time jumps are rejected and unverifiable time is fail-closed (testing halts).**

- **Rationale.** Expiry and windows are only as trustworthy as the clock; NTP manipulation or host drift can extend unauthorized testing.
- **Enforcement point.** Scheduler and Guarded Egress Broker time evaluation; time-source integrity monitor.
- **Test approach.** Clock-skew tests advancing/reversing time across expiry and window edges asserting correct halt; test that an implausible jump triggers fail-closed halt.
- **Violation impact.** Testing continues past the authorized time boundary.
- **Related threats.** scope escape, other

### SI-050

**Evidence/object-storage isolation MUST be enforced at the storage layer — per-engagement (or per-tenant) encryption keys from the secret manager and/or per-tenant buckets/prefixes with IAM boundaries — not by application-level filtering alone, so a mis-scoped fetch returns undecryptable ciphertext or is denied by storage policy.**

- **Rationale.** Postgres uses RLS, but object storage was only 'tagged and filtered by engagement'; a single app bug passing the wrong id would leak cross-engagement evidence with no storage backstop.
- **Enforcement point.** Object storage (per-tenant keys/buckets/IAM) + secret manager key custody.
- **Test approach.** Cross-tenant object-access test: a request with another engagement's id returns ciphertext the caller cannot decrypt or is denied at the storage layer.
- **Violation impact.** Cross-tenant/cross-engagement evidence disclosure.
- **Related threats.** cross-tenant access, report-data exposure

### SI-051

**The audit hash-chain MUST be anchored to append-only WORM storage and/or an external notary at a bounded interval, and the chain-signing capability MUST be separated from Administrator read access (e.g. a write-only signing service whose key Admins cannot read). The residual rewrite window between anchors MUST be documented.**

- **Rationale.** If the signing key lives where Admins can read it and the audit table shares the platform database, an Admin (or attacker with Admin) can rewrite and re-sign history since the last anchor; tamper-evidence must be independent of the operators it holds accountable.
- **Enforcement point.** Audit subsystem (WORM anchoring + external notary) + secret manager (write-only signing capability).
- **Test approach.** Tamper test: mutate an audit event and assert the chain/anchor detects it; access test that Admin cannot read the signing key; verify anchoring cadence bounds the rewrite window.
- **Violation impact.** Undetectable audit-trail tampering by a privileged insider.
- **Related threats.** report-data exposure, scope escape

### SI-052

**Offline vulnerability / SCA feeds MUST be ingested out-of-band via a checksum/signature-verified control-plane step (never worker egress), pinned by version like tool templates, with feed freshness surfaced in reports so stale-data confidence is visible.**

- **Rationale.** The data plane is default-deny egress, so vuln DBs cannot be fetched at runtime; an unpinned, unverified, or stale feed produces wrong findings and has no stated update path.
- **Enforcement point.** Control-plane feed-ingestion build step (signature verification) + reporting layer (freshness surfacing).
- **Test approach.** Ingestion test rejecting an unsigned/tampered feed; test that a stale feed's age is reflected in report confidence; assert workers never fetch feeds over egress.
- **Violation impact.** Incorrect known-vulnerable-component findings from poisoned/stale data.
- **Related threats.** supply-chain compromise, malicious scanner output

### SI-053

**The egress grant MUST be single-use (its `jti` consumed exactly once), short-lived (bounded TTL), and audience-bound to one Guarded Egress Broker; the broker MUST authenticate each request via a per-job identity/capability matching the grant's tenant/engagement/run/job, and MUST NOT expose a generic CONNECT proxy or serve any destination not carried by a Scope-Authority grant.**

- **Rationale.** A grant is a capability; a leaked or replayed grant, or a generic `CONNECT host:port` proxy, would void the network-topology guarantee. Single-use + short TTL + audience binding + per-job ingress identity make a stolen grant useless and keep the broker a narrow, request-line-bound egress point rather than an arbitrary tunnel.
- **Enforcement point.** Guarded Egress Broker authenticated per-job ingress + a strongly-consistent `jti` consumption store; Scope Authority mint (`10-request-authorization-flow.md` §2, §4.3).
- **Test approach.** Replay a consumed `jti` → deny. Present a grant for broker A at broker B (wrong `aud`) → deny. Connect without a valid per-job identity → deny. Attempt an arbitrary `host:port` CONNECT with no matching grant → refused. Assert every served destination traces to a Scope-Authority grant.
- **Violation impact.** Bypass of the two-stage flow; SSRF/scope escape via a leaked grant or an open proxy.
- **Related threats.** scope escape, SSRF

### SI-054

**Tool and headless-browser sandboxes MUST have the Guarded Egress Broker as their ONLY reachable network next hop (no internal-service or internet route); workers MUST reach only a narrow internal-service allowlist plus the broker. Neither may open a socket directly to a target; the network namespace enforces this independent of any application-layer check.**

- **Rationale.** Separates the two data-plane postures explicitly: a tool/browser is a fully untrusted request engine and gets broker-only egress; a worker needs specific internal services but still must never dial a target. Enforcing at the netns layer makes the guarantee a topology fact.
- **Enforcement point.** Per-posture network namespace / NetworkPolicy (`10-request-authorization-flow.md` §4); complements SI-041 (browser/tool proxy config) and SI-033 (worker allowlist).
- **Test approach.** From a tool/browser sandbox, assert the ONLY reachable endpoint is the broker (targets, internal services, metadata, internet all blocked). From a worker, assert only the internal-service allowlist + broker are reachable and every target/internet/metadata destination is blocked.
- **Violation impact.** Scope escape / SSRF from an uncontrolled sandbox reaching targets or internal services directly.
- **Related threats.** scope escape, SSRF, unsafe plugin execution

### SI-055

**A durable `request.intent` audit event MUST be committed BEFORE any outbound network action for the request — before any DNS query, TCP connect, or TLS handshake — in the same transaction as the budget reservation; a request that cannot durably record its intent performs NO egress. It records `spec_sha256`, the grant `jti`, the reservation id, and the canonical target; the completion event references it (same chain) and idempotently commits or releases the reservation.**

- **Rationale.** DNS resolution is itself egress that can leak the target or fail silently; committing intent before ANY packet leaves the box means nothing is ever contacted without a prior durable record, and the shared transaction means a crash can neither egress-without-record nor leak a reserved unit.
- **Enforcement point.** Guarded Egress Broker ordering (`04` §7.1 step 10 before step 11): intent + reservation commit precedes the first resolver call; a failed audit write blocks all egress including DNS.
- **Test approach.** Fault-inject a crash after intent and before DNS → the intent event is durably present and a packet-capture shows ZERO egress (no DNS, no SYN). Make the audit sink fail → no DNS query is issued. Assert no resolver call precedes the intent commit.
- **Violation impact.** A target contacted (even via DNS) with no durable record — a blind spot in the tamper-evident trail.
- **Related threats.** scope escape, malicious scanner output

### SI-056

**Events with no engagement (login/logout, user/role changes, tenant retention changes) and no tenant (global emergency stop, tool-inventory/version-pin changes, feed ingestion, key rotation) MUST be recorded in tamper-evident `tenant` and `global` audit streams respectively, each an independent hash chain; no safety- or governance-relevant action is left unlogged merely because it is not tied to an engagement.**

- **Rationale.** The original audit design chained only per engagement, leaving platform- and tenant-level actions (including the global kill switch and tool-inventory changes) without tamper-evident logging. Separate streams close that gap while keeping each chain independent.
- **Enforcement point.** `audit_event.stream ∈ {engagement, tenant, global}` with per-stream-key hash chaining and genesis (`04` §9); instrumentation at every non-engagement action site.
- **Test approach.** Each listed action emits exactly one event in the correct stream; per-stream tamper detection (edit/reorder/delete breaks that chain); a coverage test enumerates non-engagement actions and asserts none is unlogged.
- **Violation impact.** Untracked privileged/governance actions — an accountability blind spot for exactly the insider the threat model names.
- **Related threats.** cross-tenant access, scope escape, report-data exposure

### SI-057

**Raw external-tool output and raw target response bodies MUST NOT be persisted by default; findings carry only minimized, allowlisted, redacted evidence. If a debug quarantine is explicitly enabled per engagement, raw artifacts MUST be encrypted under the per-engagement DEK, access-restricted by role, size-capped, short-TTL auto-purged, and redacted before any promotion to long-term evidence/report storage.**

- **Rationale.** Retaining raw output is the easiest way to accumulate secrets/PII; minimization by default bounds the blast radius, and any deliberately-retained raw quarantine is tightly controlled and ephemeral (`11-data-retention-and-deletion.md`).
- **Enforcement point.** Evidence pipeline default-minimizes; quarantine gated by `engagement.raw_quarantine_enabled` with encryption/TTL/role controls; promotion path forces redaction.
- **Test approach.** A default run persists no raw body or console text (grep evidence store). With quarantine enabled, artifacts are encrypted, role-gated, size-capped, auto-purged at TTL, and cannot be promoted to reports/evidence un-redacted.
- **Violation impact.** Accumulation and leakage of sensitive raw target/tool data.
- **Related threats.** secret leakage, report-data exposure

### SI-058

**Secure deletion of an engagement's data MUST be achieved by destroying its per-engagement Data Encryption Key (cryptographic erasure), rendering all ciphertext in primary, WORM/object-lock, and backup stores permanently undecryptable WITHOUT mutating any immutable store; the audit trail (redacted and secret-free by SI-045) is retained under its own policy and is NOT crypto-erased with engagement data; a `dek.destroyed` event and a deletion-verification result are recorded, and an active legal hold blocks erasure.**

- **Rationale.** Reconciles verifiable deletion with WORM immutability, audit retention, and backups: WORM protects integrity during retention, key destruction provides deletion at end-of-life, and neither mutates an immutable store (`11-data-retention-and-deletion.md`).
- **Enforcement point.** Per-engagement DEK custody in the secret manager (`engagement.dek_key_ref`); envelope encryption of findings/evidence/reports/quarantine/backups; a deletion-verification job.
- **Test approach.** Destroy the DEK → sampled ciphertext no longer decrypts in primary + WORM + backup stores; the audit chain still verifies; an active legal hold blocks destruction; `dek.destroyed` is recorded before the key is gone.
- **Violation impact.** Either undeletable client data (WORM/backups) or broken immutability — both unacceptable; crypto-erasure avoids the dilemma.
- **Related threats.** report-data exposure, cross-tenant access, secret leakage

### SI-059

**Broad or expanding scope MUST be limited technically and gated by elevated dual approval: CIDR entries broader than the engagement's minimum prefix require elevated approval and are hard-rejected below an absolute floor (/16 IPv4, /32 IPv6); wildcard-domain entries require elevated approval (PSL/apex wildcards hard-rejected); host and total-address counts are capped; and ANY scope expansion (new host/domain/range) requires a dual-approved `scope_expansion` plus re-attestation. The Scope Authority refuses to mint grants for a `scope_version` exceeding ceilings without the approved elevation.**

- **Rationale.** Over-broad or silently-growing scope is the quiet path from an authorized assessment to an unauthorized one; breadth is bounded in schema and any broadening is a deliberate, dual-approved, re-attested act (`04` §4.6, §10).
- **Enforcement point.** Scope validation (`04` §4.6) + Scope Authority grant minting refusal; approval thresholds (`04` §10, doc 09).
- **Test approach.** An over-broad CIDR/wildcard or an over-count scope is rejected or gated to elevated dual approval; a CIDR below the absolute floor is hard-rejected even with approval; a scope expansion cannot take effect without dual approval + re-attestation.
- **Violation impact.** Scanning far beyond the intended target set — unauthorized testing at scale.
- **Related threats.** scope escape

### SI-060

**The object placed on the job queue MUST be an immutable, fully-hashed `request_spec` (`spec_sha256` over all request-determining fields); egress grants MUST be minted just-in-time at dispatch with a TTL covering only dispatch→send, never enqueued. The Scope Authority MUST recompute and verify `spec_sha256` before minting; a spec whose recomputed hash differs is rejected.**

- **Rationale.** Grants are short-lived and single-use, so a grant cannot be placed on a queue and wait — the immutable spec waits instead, and the grant is minted only when a dispatcher is ready. Immutability + hashing make the authorized request tamper-evident end to end.
- **Enforcement point.** `request_spec` is immutable (UPDATE/DELETE revoked) and carries `spec_sha256`; the queue stores only `(spec_id, tenant_id)`; the Scope Authority mints JIT after re-verifying the hash (`04` §7.0/§7.1).
- **Test approach.** Mutate a queued spec's fields and assert the mint is rejected on hash mismatch. Assert the queue never contains a grant (only spec references). Assert minted grant `exp - iat` ≤ the configured small bound.
- **Violation impact.** A stale grant sitting in the queue, or a mutated request being sent under an old authorization — scope escape via time or tamper.
- **Related threats.** scope escape, queue abuse

### SI-061

**The Guarded Egress Broker MUST reconstruct and normalize the outbound request deterministically from the signed immutable spec (method, canonical URL, fixed header-set, inert payload, operator session injected by reference) and MUST NOT send a worker-serialized or otherwise externally-supplied raw request; the reconstructed request MUST equal the spec's fields or it is not sent.**

- **Rationale.** If the broker sent a request a worker serialized, the worker could inject a deviation between authorization and the wire. Reconstructing from the spec guarantees the wire request is exactly what the grant authorized.
- **Enforcement point.** Guarded Egress Broker reconstruction stage (`04` §7.1 step 8 / `10` §3): rebuild from spec, re-canonicalize, assert equality to spec fields before sending.
- **Test approach.** A worker supplies a divergent serialized request → the broker ignores it and sends only the spec-derived request (or rejects on spec/grant-hash mismatch). Tamper the reconstructed request in-broker → equality assertion fails and nothing is sent.
- **Violation impact.** A sent request that differs from the authorized one — path/verb/body scope escape or injection.
- **Related threats.** scope escape, command injection

### SI-062

**Budget reservations MUST be identifiable (one `budget_reservation` per grant `jti`) with idempotent commit/release and crash-expiry, so a crashed or retried worker can neither double-spend nor strand budget; and testing-window, authorization-expiry, and emergency-stop MUST be re-evaluated at just-in-time grant-mint AND again at Stage 2, with a fired interlock releasing reservations and aborting in-flight work (HTTP and WebSocket).**

- **Rationale.** Because the queued spec can wait arbitrarily long, the time interlocks must be checked at the last possible moment (JIT mint) and again at the broker; and reservations must survive crashes without leaking or double-counting.
- **Enforcement point.** `budget_reservation` idempotent transitions + sweeper (`04` §8.1); Scope Authority JIT re-check; Guarded Egress Broker Stage-2 re-check; interlock handlers release reservations and abort in-flight HTTP + WebSocket.
- **Test approach.** A spec dwelling past window-close or expiry gets no grant; e-stop/expiry mid-scan releases reservations and aborts in-flight requests and WebSocket connections within the bound; a crash leaves no stranded reservation (expiry reclaims it); idempotent commit/release verified under retry.
- **Violation impact.** Testing past the authorized time boundary, or budget corruption (leak/double-spend).
- **Related threats.** queue abuse, scope escape

### SI-063

**WebSocket (`ws`/`wss`) connections MUST be authorized, scoped, resolved, and IP-pinned at the handshake exactly like an HTTP request; the established connection MUST be bounded by per-connection duration, message-count, and message-size caps and a per-engagement connection cap, MUST NOT change target after the pinned handshake, and MUST be terminated on emergency stop, window close, or expiry. Outbound frames MUST be drawn ONLY from an approved, content-addressed inert frame set (a `ws_frame_set` `catalog_template` named by `spec.ws_frame_set_digest`); the broker CANNOT emit a frame outside that set, and any non-catalog frame requires an approval manifest.**

- **Rationale.** A WebSocket is long-lived and bidirectional; without an approved, content-addressed frame catalog the platform could send arbitrary (possibly destructive or high-volume) frames, and without connection bounds it could escape the per-request scope/budget/time model.
- **Enforcement point.** `kind='websocket'` `request_spec` with `ws_frame_set_digest` into `catalog_template`; Guarded Egress Broker handshake scoping + IP pin + per-connection caps + a frame gate that admits only catalog frames (`04` §7.2, §8); interlock handlers terminate active connections.
- **Test approach.** An out-of-scope handshake is denied; an established WS exceeding a duration/message-count/message-size cap is closed; e-stop/window/expiry aborts active connections; a frame NOT in the approved set is refused by the broker; a non-catalog frame is only sendable under an approval manifest; an established socket cannot be re-pointed.
- **Violation impact.** A long-lived channel escaping scope/budget/time, or the platform emitting arbitrary/destructive frames.
- **Related threats.** scope escape, queue abuse

### SI-064

**Approval thresholds and eligible approver roles MUST be read from an immutable, Administrator-managed, versioned `approval_policy` (referenced by `approval_policy_id`, pinned by `policy_digest`) — never from requester-supplied fields — and an approval MUST authorize only the explicit, content-addressed set of `request_spec` digests recorded in its `approval_manifest_entry` rows (hashed as `manifest_sha256`); Stage-1 mints a grant only if the spec's digest is in that manifest and the policy threshold is met.**

- **Rationale.** If a requester could set the threshold or eligible roles, or approve a free-form plan, dual control is defeatable by the very insider it targets. Threshold/roles live in an immutable Admin-managed table, and the approval binds an explicit, content-addressed manifest of exact spec digests.
- **Enforcement point.** `approval_policy` immutable (UPDATE/DELETE revoked; Administrator-only writes); `approval_request` has NO `required_approvals`/`approver_roles` columns and references the policy by id; `approval_manifest_entry` + `manifest_sha256`; §7 Stage-1 step (h) checks manifest membership (`04` §10).
- **Test approach.** There is no request field to set threshold/roles (schema check); an intrusive grant is refused when `spec_sha256` is not a manifest entry; changing the manifest or the policy version voids prior decisions; a non-Administrator cannot create/version `approval_policy`.
- **Violation impact.** Self-set approval policy or approval of an unpinned request — insider scope escape with a veneer of legitimacy.
- **Related threats.** scope escape, cross-tenant access

### SI-065

**Every security/request-context reference in a `request_spec` (check, tool template, header-set, payload, WebSocket frame-set) MUST be an immutable content digest into `catalog_template`, and ALL such digests MUST be folded into `spec_sha256`; catalog templates are immutable and content-addressed. A `request_spec` MUST be repeatable across jobs/runs — `spec_sha256` is a reusable content digest that excludes `run_id`/`job_id`/`session_ref` and carries no uniqueness constraint — and a repeat is a distinct instance with its own single-use grant, not a replay.**

- **Rationale.** Referencing templates by mutable ids would let a benign-looking id be silently repointed to a different payload/header/frame after authorization. Content digests make the whole request tamper-evident; excluding instance identity from the digest lets the same logical request legitimately recur without a false uniqueness collision.
- **Enforcement point.** `catalog_template` (content-addressed, immutable); `request_spec` digest columns are FKs into it and are part of `spec_sha256`; NO `UNIQUE(tenant_id, spec_sha256)` (`04` §7.0).
- **Test approach.** Changing a template's content changes its digest (so a changed template is a new spec, never a silent swap); a spec referencing an unknown digest is rejected; the same content digest recurs across two jobs/runs without a uniqueness violation and each gets its own single-use grant.
- **Violation impact.** A silently repointed template sends a different request than was authorized; or a false uniqueness collision blocks a legitimate retest/repeat.
- **Related threats.** scope escape, command injection, supply-chain compromise
