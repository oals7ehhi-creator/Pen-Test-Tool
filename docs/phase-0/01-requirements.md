# Phase 0 — Functional & Non-Functional Requirements
> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

**71 functional requirements (FR-###)** and **37 non-functional requirements (NFR-###)**, each atomic, traceable, and verifiable. Functional requirements are grouped by their primary owning phase; non-functional requirements by category. Priority uses MoSCoW (must / should / could).

## Functional Requirements

### Coverage by phase

| Phase | Requirement IDs |
|---|---|
| Phase 1 | FR-001, FR-002, FR-003, FR-004 |
| Phase 2 | FR-005, FR-006, FR-007, FR-008, FR-009, FR-010, FR-011, FR-012, FR-013, FR-014, FR-015, FR-016, FR-017, FR-018, FR-019, FR-020, FR-021, FR-022, FR-023, FR-024, FR-025, FR-061, FR-062, FR-063, FR-064, FR-065, FR-068, FR-069, FR-070 |
| Phase 3 | FR-026, FR-027, FR-028, FR-029, FR-030, FR-031, FR-032 |
| Phase 4 | FR-033, FR-034, FR-035, FR-036, FR-037, FR-038 |
| Phase 5 | FR-039, FR-040, FR-041, FR-042, FR-043, FR-044, FR-045, FR-046, FR-066, FR-071 |
| Phase 6 | FR-047, FR-048, FR-049, FR-050 |
| Phase 7 | FR-051, FR-052, FR-053, FR-054 |
| Phase 8 | FR-055, FR-056 |
| Phase 9 | FR-057, FR-058, FR-059, FR-060 |
| Phase 11 | FR-067 |

### Phase 1

**FR-001 — Authentication and session management**  ·  _priority: must_

The platform shall require every human and API client to authenticate before any engagement, scope, scan, finding, or report resource is accessible, and shall manage sessions with expiry and revocation.

> **Verification:** Integration tests confirming all API routes and UI views reject unauthenticated requests; session-expiry and revocation tests.

**FR-002 — Role-based access control with five named roles**  ·  _priority: must_

The platform shall implement RBAC with the roles Administrator, Engagement Manager, Tester, Reviewer, and Read-only Auditor, enforcing least-privilege such that each role can perform only its authorized actions (e.g. only Engagement Manager/Administrator can approve authorization; only approvers can release approval-gated validation; Read-only Auditor cannot mutate state). The authoritative role-to-action matrix (including who may approve authorization attestation, scope expansion, and intrusive validation) is defined once in 09-rbac-matrix.md and referenced everywhere.

> **Verification:** Authorization test matrix per role x action asserting allow/deny; negative tests for privilege escalation. The authorization test matrix is generated from 09-rbac-matrix.md so doc/code drift fails CI.

**FR-003 — No arbitrary shell or OS command execution from UI or API**  ·  _priority: must_

The platform shall provide no interface (UI, API, job parameter, or plugin input) that permits an operator to execute arbitrary shell or OS commands; all tool invocation is limited to predefined, parameterized adapters.

> **Verification:** Code review and injection tests confirming no endpoint routes external input into a shell; static analysis rule forbidding shell=true / string-built commands.

**FR-004 — Typed configuration, secure-by-default sample environment, structured logging foundation**  ·  _priority: should_

The platform shall load configuration through a typed, validated schema, ship a secure-by-default sample environment containing no real secrets, and emit structured logs from a shared logging foundation.

> **Verification:** Config-schema validation tests rejecting malformed/unsafe values; inspection that sample env contains placeholders only; log-format schema test.

### Phase 2

**FR-005 — Deny-all operation without explicit scope configuration**  ·  _priority: must_

The platform shall deny all target-directed operations for an engagement unless a valid, explicit scope configuration exists; absence, emptiness, or invalidity of scope results in fail-closed denial.

> **Verification:** Tests attempting any scan/crawl/check on an engagement with no/empty/invalid scope and asserting denial.

**FR-006 — Engagement lifecycle management**  ·  _priority: must_

The platform shall support create, read, update, archive, and state transitions (e.g. Draft, Authorized, Active, Suspended, Expired, Closed) for engagements, with each engagement owning its authorization, scope, runs, findings, and reports.

> **Verification:** CRUD and state-machine tests including illegal-transition rejection.

**FR-007 — Authorization record capture**  ·  _priority: must_

The platform shall capture an authorization record per engagement containing written-authorization reference, engagement owner, expiry date/time, and the authorized scope, and shall bind testing eligibility to this record.

> **Verification:** Schema tests requiring all mandatory fields; test that runs are blocked until a complete authorization record exists.

**FR-008 — Written-authorization attestation gate**  ·  _priority: must_

The platform shall require an operator with sufficient privilege to explicitly confirm that written authorization exists before any active (Safe Active or Approval-Gated) testing can be enabled for an engagement.

> **Verification:** Test that active modes cannot be started without a recorded attestation; audit event asserted for the attestation.

**FR-009 — Automatic halt on authorization expiry**  ·  _priority: must_

The platform shall automatically stop scheduling and executing all testing for an engagement the moment its authorization expiry is reached, terminating in-flight work and blocking new work.

> **Verification:** Time-controlled test advancing the clock past expiry and asserting queued and in-flight tasks are halted and new tasks rejected.

**FR-010 — Testing-window enforcement**  ·  _priority: must_

The platform shall permit execution only within operator-defined allowed testing windows and shall suspend activity automatically outside those windows.

> **Verification:** Tests with configured windows asserting execution allowed inside and blocked/suspended outside, including timezone handling.

**FR-011 — Scope allowlist definition**  ·  _priority: must_

The platform shall let operators define an allowlist of authorized targets by domain, IP address, CIDR range, port, protocol/scheme, URL path prefix, and API definition, and treat everything not allowlisted as out of scope.

> **Verification:** Unit tests for each scope-primitive type; property-based tests that non-listed targets are denied.

**FR-012 — Explicit exclusions with precedence**  ·  _priority: must_

The platform shall support explicit exclusions (hosts, ranges, ports, paths) that take precedence over the allowlist, so an excluded target is always out of scope even if otherwise covered.

> **Verification:** Tests where an allowlisted-but-excluded target is rejected; precedence property tests.

**FR-013 — Scope import and export**  ·  _priority: should_

The platform shall support importing and exporting scope configurations in a structured, validated format to enable review, versioning, and reuse.

> **Verification:** Round-trip import/export tests; import validation rejecting malformed or unsafe scope files.

**FR-014 — Pre-flight scope validation on every request**  ·  _priority: must_

The platform shall authorize every outbound target request through a two-stage flow over an immutable, content-addressed request_spec: the central Scope Authority, JUST-IN-TIME at dispatch, verifies the spec's content digest (spec_sha256), evaluates scope/authorization/mode/window/budget against current state, and mints a signed, single-use, audience-bound egress grant bound to spec_sha256 with no resolved IP; the Guarded Egress Broker then verifies the grant and spec hash, reconstructs the request from the spec, durably records intent before any egress, resolves DNS, validates and pins every resolved IP, and connects only to a pinned in-scope IP.

> **Verification:** Instrumentation test asserting no outbound socket without a valid grant; spec-hash, JIT-mint, and intent-before-egress tests; broker-time resolved-IP validation and pinning tests.

**FR-015 — DNS resolution with in-scope IP verification**  ·  _priority: must_

The platform shall resolve target domains and verify that every resulting IP address (IPv4 and IPv6) is within scope, denying the request if any resolved address is out of scope.

> **Verification:** Tests with mocked resolvers returning in-scope and out-of-scope addresses asserting correct allow/deny.

**FR-016 — DNS-rebinding protection**  ·  _priority: must_

The platform shall prevent DNS rebinding by re-resolving and pinning the validated IP address for the actual connection, ensuring the host contacted is the one that passed scope validation.

> **Verification:** Rebinding test where resolution changes between validation and connection, asserting the connection uses the pinned validated IP or is aborted.

**FR-017 — Out-of-scope redirect detection and stop**  ·  _priority: must_

The platform shall detect HTTP redirects to out-of-scope hosts and stop following them, recording the event rather than continuing the request chain.

> **Verification:** Tests issuing redirects to out-of-scope and in-scope hosts asserting follow only for in-scope and a recorded stop for out-of-scope.

**FR-018 — Canonical URL normalization before scope evaluation**  ·  _priority: must_

The platform shall canonicalize URLs (case, encoding, dot-segments, default ports, IDN/punycode, trailing constructs) before scope evaluation to prevent scope bypass via URL obfuscation.

> **Verification:** URL-fuzzing/parser tests confirming equivalent obfuscated URLs canonicalize identically and cannot bypass scope.

**FR-019 — IPv4/IPv6 validation and reserved-range blocking**  ·  _priority: must_

The platform shall reject localhost/loopback, RFC1918 private ranges, link-local, unique-local (IPv6 ULA), and cloud-metadata addresses (e.g. 169.254.169.254) for both IPv4 and IPv6 unless the operator has explicitly allowlisted them.

> **Verification:** Property-based tests over reserved ranges (v4 and v6) asserting denial by default and allow only when explicitly listed.

**FR-020 — Per-engagement concurrency and rate limits**  ·  _priority: must_

The platform shall enforce conservative, configurable per-engagement concurrency and request-rate limits, bounded by safe maximum caps that operators cannot exceed.

> **Verification:** Load tests asserting observed concurrency/rate never exceeds configured or capped values.

**FR-021 — Emergency stop**  ·  _priority: must_

The platform shall provide an emergency stop, at both per-engagement and global scope, that immediately halts dispatch and terminates in-flight testing.

> **Verification:** Tests triggering emergency stop and asserting cessation of new dispatch and termination of active tasks within the bounded time.

**FR-022 — Automatic circuit breakers**  ·  _priority: must_

The platform shall implement automatic circuit breakers that suspend an engagement's activity when anomaly thresholds (e.g. target error/5xx rate, latency spikes, budget burn) are exceeded.

> **Verification:** Tests injecting threshold-breaching conditions and asserting automatic suspension and audit recording.

**FR-023 — Approval-gating mechanism for intrusive validation**  ·  _priority: must_

The platform shall require explicit, recorded operator approval before any intrusive validation action executes, and shall block execution of such actions absent a valid approval.

> **Verification:** Tests that approval-gated actions cannot execute without an approval record; role checks on who may approve.

**FR-024 — Immutable, tamper-evident audit events**  ·  _priority: must_

The platform shall record every security-relevant action (scope decisions, authorization changes, mode changes, approvals, tool runs, emergency stops) as immutable, tamper-evident audit events.

> **Verification:** Tamper-detection tests altering stored events and asserting integrity verification fails; coverage test that key actions emit events.

**FR-025 — Dual-layer scheduling and execution enforcement**  ·  _priority: must_

The platform shall enforce scope, authorization, window, and mode constraints at both the scheduling layer and the execution layer, so that an out-of-scope or unauthorized request can be neither queued nor executed even if one layer is bypassed.

> **Verification:** Property-based and fault-injection tests proving out-of-scope/unauthorized requests are rejected at scheduler and again at executor.

**FR-061 — Authenticated per-job broker ingress (no generic proxy)**  ·  _priority: must_

The Guarded Egress Broker shall accept egress requests only over an authenticated, per-job identity/capability matching the grant's tenant/engagement/run/job, and shall never expose a generic CONNECT proxy or serve any destination not carried by a Scope-Authority grant.

> **Verification:** Ingress-auth tests: unauthenticated or mismatched-identity callers rejected; attempts to open an arbitrary host:port tunnel refused; every served destination traces to a grant.

**FR-062 — Dual-control approval for the legal gate**  ·  _priority: must_

The platform shall require dual control (a configurable threshold with a floor of two distinct, role-verified approvers, none being the requester or executing tester, each pinning the plan and authorization-document hash) for authorization attestation and any scope expansion, via an approval_request plus one approval_decision per approver.

> **Verification:** Approval-threshold and separation-of-duties tests: single-actor attest+approve rejected; below-threshold never approved; a decision whose pinned plan hash differs does not count.

**FR-063 — Two-tier network guard with elevated internal testing**  ·  _priority: must_

The platform shall permanently hard-deny Tier A ranges (metadata, loopback, unspecified, multicast, broadcast, reserved) by any means, and shall permit Tier B ranges (RFC1918, ULA, link-local, CGNAT) only when an explicit elevated scope entry names them, a dual-approved restricted-range approval exists, and the authorization grants internal testing.

> **Verification:** Table-driven range tests incl. transition forms; assert Tier A unreachable even under a broad/elevated covering entry; assert Tier B reachable only under the full elevation condition.

**FR-064 — Scope-breadth limits and elevated approval**  ·  _priority: must_

The platform shall bound scope breadth (minimum CIDR prefix with an absolute floor, wildcard-domain gating, host and total-address ceilings) and shall require elevated dual approval plus re-attestation for any scope expansion; scopes exceeding ceilings cannot mint grants without the approved elevation.

> **Verification:** Breadth tests: over-broad CIDR/wildcard/count rejected or gated; below the absolute floor hard-rejected even with approval; scope expansion requires dual approval + re-attestation.

**FR-065 — Split audit request events and non-engagement streams**  ·  _priority: must_

The platform shall record each outbound request as a durable pre-send intent event and a post-send completion/failure event, and shall maintain separate tamper-evident tenant and global audit streams for events without an engagement (login, global emergency stop, tool-inventory changes, role changes, retention/feed changes).

> **Verification:** Intent-before-send ordering test (crash between intent and send leaves a provable attempt); per-stream chain tamper tests; coverage test that non-engagement actions are logged in the correct stream.

**FR-068 — Immutable approval policy and approved-spec manifest**  ·  _priority: must_

The platform shall read approval thresholds and eligible approver roles from an immutable, Administrator-managed, versioned approval policy (never from requester-supplied fields), and shall authorize intrusive/business-logic actions only against an explicit manifest of approved request_spec content digests; a grant is minted only if the spec's digest is in that manifest and the policy threshold is met.

> **Verification:** Schema check that approval requests carry no threshold/role fields; manifest-membership test (a spec not in the manifest is refused); Administrator-only policy versioning; changing manifest/policy voids prior decisions.

**FR-069 — Content-addressed templates and repeatable specs**  ·  _priority: must_

The platform shall reference every request template (check, tool, header-set, payload, WebSocket frame-set) by an immutable content digest folded into spec_sha256, and shall permit the same content digest to recur across jobs and runs as distinct instances (no spec-uniqueness constraint), each with its own single-use grant.

> **Verification:** Test that changing template content changes the digest (no silent repoint); that an unknown digest is rejected; and that the same content digest recurs across two jobs without a uniqueness violation.

**FR-070 — Identifiable budget reservations**  ·  _priority: must_

The platform shall account request budget with an identifiable reservation ledger keyed by grant jti, with idempotent commit/release and crash-expiry, so that committed (sent) requests never exceed the total and no reservation strands.

> **Verification:** Idempotent double-commit/double-release no-op tests; crash-after-reserve auto-expiry; concurrency boundary at total-1/total/total+1.

### Phase 3

**FR-026 — Multi-format target intake**  ·  _priority: must_

The platform shall accept targets and endpoints from seed URLs, OpenAPI/Swagger, Postman collections, HAR files, sitemaps, manual endpoint entry, and optionally imported proxy history.

> **Verification:** Parser tests per format producing a normalized endpoint set; fuzz tests on each importer.

**FR-027 — Ingest validation and scope filtering**  ·  _priority: must_

The platform shall validate imported artifacts and filter all ingested endpoints against engagement scope, discarding or flagging out-of-scope items before they can be used.

> **Verification:** Tests importing mixed in/out-of-scope artifacts asserting only in-scope endpoints are retained and out-of-scope are excluded/flagged.

**FR-028 — Passive TLS and certificate analysis**  ·  _priority: must_

The platform shall analyze TLS configuration and certificates (validity, expiry, chain, protocol/cipher indicators) from observed connections without active exploitation.

> **Verification:** Tests against fixtures with known TLS/cert issues asserting correct passive findings.

**FR-029 — Passive security-header analysis**  ·  _priority: must_

The platform shall analyze security-relevant response headers (e.g. HSTS, X-Content-Type-Options, frame controls, referrer policy) and report missing or weak configurations.

> **Verification:** Header-fixture tests asserting expected findings for present/missing/weak headers.

**FR-030 — Cookie attribute analysis**  ·  _priority: must_

The platform shall analyze cookie attributes (Secure, HttpOnly, SameSite, domain/path scope, expiry) and flag insecure configurations.

> **Verification:** Cookie-fixture tests asserting correct attribute findings.

**FR-031 — CORS indicator and CSP analysis**  ·  _priority: should_

The platform shall analyze CORS response indicators and Content-Security-Policy configuration for weaknesses (e.g. wildcard origins with credentials, unsafe CSP directives).

> **Verification:** CORS/CSP fixture tests asserting detection of weak configurations.

**FR-032 — Passive information-exposure and environment detection**  ·  _priority: should_

The platform shall detect information disclosure, technology fingerprints from observable responses, JS source-map references, deprecated-protocol indicators, and mixed content, using only observed data and no attack payloads.

> **Verification:** Fixture tests for each detection type; assertion that no probing payloads are emitted during passive analysis.

### Phase 4

**FR-033 — Scope-aware safe crawler with request budget**  ·  _priority: must_

The platform shall provide a crawler that stays within scope and a per-run request budget, stopping when the budget is exhausted.

> **Verification:** Crawl tests asserting no out-of-scope fetch and hard stop at budget limit.

**FR-034 — Operator-supplied authenticated sessions without defeating auth**  ·  _priority: must_

The platform shall use operator-provided authenticated sessions/credentials for crawling while never attempting to bypass, brute force, or otherwise defeat authentication controls.

> **Verification:** Tests confirming supplied sessions are used as-is and no auth-bypass behavior is attempted; review of crawler auth handling.

**FR-035 — Attack-surface discovery with canonicalization and dedup**  ·  _priority: must_

The platform shall discover forms, parameters, REST APIs, GraphQL endpoints, JS-defined routes, and file-upload surfaces, then canonicalize and deduplicate them into a unified inventory.

> **Verification:** Tests against a fixture app asserting expected surfaces discovered and duplicates collapsed.

**FR-036 — State-changing action avoidance**  ·  _priority: must_

The platform shall avoid triggering state-changing actions during crawling, including logout, delete, payment, account-change, and messaging operations.

> **Verification:** Tests against fixtures with dangerous links/actions asserting they are not invoked; heuristic-detection unit tests.

**FR-037 — State-changing forms recorded but not auto-submitted**  ·  _priority: must_

The platform shall record discovered state-changing forms as attack surface but shall never automatically submit them.

> **Verification:** Tests asserting state-changing forms appear in the inventory with zero submission requests emitted.

**FR-038 — Crawler safety controls and attack-surface map**  ·  _priority: should_

The platform shall detect crawler traps, enforce response body-size and retention limits, track endpoint provenance, and produce an attack-surface map.

> **Verification:** Trap-detection tests; body-size/retention limit tests; provenance assertions linking each endpoint to its discovery source.

### Phase 5

**FR-039 — Operating-mode selection and enforcement defaulting to Passive**  ·  _priority: must_

The platform shall let operators select one of three modes (Passive, Safe Active, Approval-Gated Validation) per engagement/run, default to Passive, and technically enforce each mode's constraints.

> **Verification:** Tests asserting default is Passive and that each mode gates the permissible check classes.

**FR-040 — Passive mode emits no attack payloads**  ·  _priority: must_

The platform shall ensure Passive mode performs analysis only and emits no attack payloads or intrusive probes.

> **Verification:** Traffic-capture test in Passive mode asserting zero payload-bearing requests are sent.

**FR-041 — Safe Active mode limited to budgeted non-destructive checks**  ·  _priority: must_

The platform shall restrict Safe Active mode to controlled crawling, endpoint/parameter discovery, harmless reflection/config checks, and low-impact validation using non-destructive payloads under strict request budgets.

> **Verification:** Tests asserting only non-destructive checks run in Safe Active mode and budgets are enforced.

**FR-042 — Modular check registry with mandatory metadata schema**  ·  _priority: must_

The platform shall implement checks as modular units, each declaring id, description, preconditions, safety classification, request budget, scope requirements, harmless test method, evidence requirements, confidence calculation, cleanup, failure handling, and CWE/OWASP/remediation references.

> **Verification:** Registry validation test rejecting any check missing required metadata fields.

**FR-043 — Non-destructive detection catalog**  ·  _priority: must_

The platform shall provide non-destructive detection for authN/session, access-control indicators, input reflection/output encoding, SQLi via differential checks, XSS via inert markers, path traversal without retrieving sensitive OS files, open redirects, CORS, CSRF indicators, HTTP method exposure, harmless file-upload validation, GraphQL introspection, API authorization consistency via operator test accounts, header/cookie issues, error/stack-trace disclosure, cache-control of sensitive responses, known-vulnerable components by version with confidence, and operator-defined business-logic templates.

> **Verification:** Per-check tests against intentionally vulnerable local apps asserting detection with non-destructive methods only.

**FR-044 — Hard in-check restrictions enforced**  ·  _priority: must_

The platform shall technically prevent checks from dumping databases, retrieving secrets/files/tokens/keys/user data as proof, executing OS commands or reverse shells, uploading executables, modifying/deleting/corrupting data, brute forcing/spraying/bypassing MFA or performing account takeover, running destructive race/resource-exhaustion attacks, or bypassing WAF/detection controls.

> **Verification:** Guardrail tests asserting each prohibited behavior is blocked at the check-execution layer; code review of check primitives.

**FR-045 — SSRF checks via approved controlled callback infrastructure only**  ·  _priority: must_

The platform shall perform SSRF detection only through pre-approved, controlled callback infrastructure and shall not direct callbacks to arbitrary or third-party endpoints.

> **Verification:** Tests asserting SSRF checks only use configured callback infra and reject unconfigured callback targets.

**FR-046 — Per-check evidence, confidence, cleanup, and failure handling**  ·  _priority: should_

The platform shall capture evidence, compute a confidence value, perform any declared cleanup, and handle failures gracefully for each executed check.

> **Verification:** Tests asserting each check run yields evidence and confidence, invokes cleanup, and degrades safely on error.

**FR-066 — Raw-output minimization with gated quarantine**  ·  _priority: should_

The platform shall not persist raw external-tool output or raw target response bodies by default, storing only minimized, allowlisted, redacted evidence; an optional per-engagement debug quarantine shall be encrypted under the per-engagement key, role-restricted, size-capped, short-TTL auto-purged, and redacted before any promotion to long-term storage.

> **Verification:** Default-run test asserts no raw body/console text persisted; quarantine-enabled test asserts encryption, TTL purge, role gating, and redaction-before-promotion.

**FR-071 — WebSocket frame catalog control**  ·  _priority: must_

The platform shall send WebSocket outbound frames only from an approved, content-addressed inert frame catalog, bounded by count and size, with any non-catalog frame requiring an approval manifest; established connections are bounded by duration/message/size/count caps and terminated on emergency stop, window close, or expiry.

> **Verification:** A frame outside the approved set is refused; caps close the connection; e-stop/window/expiry aborts active connections; non-catalog frame requires an approval manifest.

### Phase 6

**FR-047 — Isolated tool adapters with pinned, verified versions and curated allowlists**  ·  _priority: must_

The platform shall integrate external tools (Nuclei, OWASP ZAP baseline, TestSSL/TLS analysis, dependency/SCA scanners, secret scanners) through isolated adapters using pinned, checksum-verified tool and template versions and curated non-destructive template/option allowlists.

> **Verification:** Version/checksum verification tests; allowlist tests asserting unsafe templates/options are excluded.

**FR-048 — Sandboxed tool execution with resource and egress limits**  ·  _priority: must_

The platform shall run each tool in an isolated container with CPU, memory, time, and request limits and restricted egress, and shall disable unsafe templates and options.

> **Verification:** Container-isolation and egress tests; resource-limit enforcement tests; assertion that unsafe options are disabled.

**FR-049 — Structured, untrusted tool-output handling with normalized schema**  ·  _priority: must_

The platform shall parse structured tool output (not console text), treat it as untrusted input, normalize it to a single finding schema, and retain raw output separately from verified findings.

> **Verification:** Parser tests with malicious/malformed tool output asserting safe handling; schema-mapping tests; separation of raw vs normalized stores.

**FR-050 — No shell-reaching CLI args and no exploit frameworks**  ·  _priority: must_

The platform shall ensure no user-supplied CLI arguments reach a shell and shall not integrate exploit frameworks or command-and-control tooling.

> **Verification:** Injection tests on adapter argument construction; inventory review confirming no exploit/C2 tools are present.

### Phase 7

**FR-051 — Finding normalization, dedup, scoring, grading, and grouping**  ·  _priority: must_

The platform shall normalize findings, deduplicate them, compute severity and confidence, grade evidence quality, and group them by asset/endpoint and root cause with reviewer commentary.

> **Verification:** Tests over synthetic finding sets asserting correct dedup, scoring, grading, and grouping.

**FR-052 — Finding status lifecycle and risk acceptance**  ·  _priority: must_

The platform shall support the finding status lifecycle (Unverified, Needs Review, Confirmed, False Positive, Accepted Risk, Remediated, Retest Failed, Retest Passed) with false-positive review and risk acceptance.

> **Verification:** State-machine tests asserting valid transitions and role-gated status changes.

**FR-053 — Approval-gated validation plan content and execution**  ·  _priority: must_

The platform shall, for approval-gated validation, present the proposed request, rationale, potential impact, target and scope check, required account, expected response, evidence to be retained, cleanup action, and stop conditions, and execute only after explicit operator approval without destructive exploitation or command execution.

> **Verification:** Tests asserting the plan includes all required fields and that execution is blocked until approval and never runs destructive/exec actions.

**FR-054 — Retest execution and regression tracking**  ·  _priority: should_

The platform shall support retesting of findings and track regression across engagement runs, updating retest status accordingly.

> **Verification:** Tests scheduling retests and asserting correct retest/regression state transitions.

### Phase 8

**FR-055 — Multi-format reporting with required sections**  ·  _priority: must_

The platform shall generate HTML, JSON, CSV, and PDF-ready reports containing executive summary, scope and exclusions, authorization details, testing dates, methodology, limitations, attack-surface summary, risk distribution, confirmed findings with evidence, non-destructive reproduction steps, business and technical impact, remediation, references, retest results, an appendix of tool versions and test configuration, and a statement that automated results require professional review.

> **Verification:** Report-generation tests asserting all required sections and formats are produced.

**FR-056 — Report and log redaction of sensitive data**  ·  _priority: must_

The platform shall redact cookies, authorization headers, API keys, passwords, PII, secrets, and sensitive response bodies from all reports and logs.

> **Verification:** Redaction test corpus asserting zero leakage of known secret/PII patterns across every report format and log stream.

### Phase 9

**FR-057 — Guided end-to-end operator workflow**  ·  _priority: must_

The platform shall provide a guided workflow: create engagement, add authorization, define scope, verify scope, select mode, supply auth safely, review estimated request volume, start, review approval-gated actions, triage, export report, and schedule retest.

> **Verification:** End-to-end UX test walking the full workflow; step-gating tests preventing skipping mandatory safety steps.

**FR-058 — Safe default profiles and pre-start request-volume preview**  ·  _priority: must_

The platform shall offer safe default profiles and display an estimated request volume for operator review before a run can be started.

> **Verification:** Tests asserting default profiles are non-intrusive and that a volume estimate is shown and acknowledged before start.

**FR-059 — Operational dashboard and controls**  ·  _priority: should_

The platform shall provide a progress dashboard with request-budget indicators, a prominent stop control, failure explanations, resume capability, notifications, and recommended next actions.

> **Verification:** UI tests asserting presence and function of dashboard elements, stop, resume, and notifications.

**FR-060 — Prohibition of one-click attack and automatic intrusive validation**  ·  _priority: must_

The platform shall not provide any one-click "attack everything" capability and shall never perform intrusive validation automatically without explicit per-action operator approval.

> **Verification:** UX and workflow review confirming no bulk-attack control exists and that intrusive actions always require explicit approval.

### Phase 11

**FR-067 — Retention classes and cryptographic erasure**  ·  _priority: must_

The platform shall implement per-engagement cryptographic erasure (destroying the per-engagement data key) as the secure-deletion mechanism reconciled with WORM storage, audit retention, and backups, retaining the redacted audit trail under its own policy, honoring legal holds, and recording a verifiable deletion result.

> **Verification:** Crypto-erase test: after key destruction sampled ciphertext no longer decrypts in primary/WORM/backup; audit remains verifiable; legal hold blocks erasure; dek.destroyed recorded.

## Non-Functional Requirements

| Category | Requirement IDs |
|---|---|
| compliance | NFR-032, NFR-033, NFR-034 |
| maintainability | NFR-030, NFR-031 |
| observability | NFR-035, NFR-036, NFR-037 |
| performance | NFR-019, NFR-020, NFR-021, NFR-022 |
| privacy | NFR-015, NFR-016, NFR-017, NFR-018 |
| reliability | NFR-023, NFR-024, NFR-025, NFR-026 |
| safety | NFR-008, NFR-009, NFR-010, NFR-011, NFR-012, NFR-013, NFR-014 |
| security | NFR-001, NFR-002, NFR-003, NFR-004, NFR-005, NFR-006, NFR-007 |
| usability | NFR-027, NFR-028, NFR-029 |

### Compliance

**NFR-032 — Tamper-evident audit trail**  ·  _target: Hash-chained/append-only audit; integrity verification detects any modification; complete action coverage._

The audit trail shall be append-only and tamper-evident (e.g. hash-chained), covering every security-relevant action and retained per policy.

> **Verification:** Tamper-detection tests altering records and asserting integrity failure; audit-coverage tests.

**NFR-033 — Standards mapping and requirements traceability**  ·  _target: 100% of finding types carry CWE/OWASP mapping; traceability matrix maintained and current._

Findings shall map to CWE/OWASP references and a requirements traceability matrix shall link requirements to design, implementation, and tests.

> **Verification:** Report inspection for CWE/OWASP mapping; traceability-matrix completeness review.

**NFR-034 — Auditable authorization and auto-expiration**  ·  _target: Every authorization change, approval, and expiry event recorded and independently verifiable._

Authorization state, approvals, and automatic expiration shall be fully auditable and demonstrably enforced.

> **Verification:** Audit-trail review correlating authorization/approval/expiry events with enforced behavior.

### Maintainability

**NFR-030 — Modular extensibility and safety-critical coverage**  ·  _target: New check/adapter requires no core changes; 100% branch coverage on the scope validator and >= 90% on authorization/redaction modules._

Checks and tool adapters shall be addable without modifying core, and safety-critical modules shall carry high automated test coverage.

> **Verification:** Coverage reports for safety-critical modules; a sample check/adapter added without core edits.

**NFR-031 — Static analysis, lint, and format gates**  ·  _target: CI blocks on lint/format/static-analysis failures; 0 suppressed critical findings._

The codebase shall enforce static analysis, linting, and formatting in CI, blocking merges on violations.

> **Verification:** CI configuration review and a forced-violation test confirming merge is blocked.

### Observability

**NFR-035 — Structured, correlated, redacted logging**  ·  _target: All logs structured with correlation+engagement IDs; redaction applied pre-write._

Logs shall be structured, carry correlation and engagement identifiers, and apply redaction before persistence.

> **Verification:** Log-schema tests and redaction tests asserting IDs present and sensitive data absent.

**NFR-036 — Metrics, health, and alerting**  ·  _target: Metrics for budget burn, breaker state, queue depth, and egress denials; alerts on breaker trips and scope-denial spikes._

The platform shall expose metrics and health signals (budget usage, circuit-breaker state, queue depth, egress denials) and alert on safety-relevant conditions.

> **Verification:** Monitoring tests asserting metrics emission and alert firing on simulated conditions.

**NFR-037 — Logged safety decisions with reasons**  ·  _target: 100% of safety decisions logged with a machine-readable reason._

Every safety-relevant decision (scope allow/deny, redirect stop, rebinding block, authorization/window block, approval grant) shall be logged with an explicit reason code.

> **Verification:** Tests asserting each safety-decision path emits a log entry with a reason code.

### Performance

**NFR-019 — Conservative default concurrency and rate**  ·  _target: Default concurrency <= 2 requests/engagement; default rate <= 5 req/s; enforced hard caps above which configuration is rejected._

The platform shall default to conservative per-engagement concurrency and request rate, configurable only within safe hard caps.

> **Verification:** Load tests measuring observed concurrency/rate against defaults and caps.

**NFR-020 — Request-budget and crawl caps**  ·  _target: Configurable request budgets and default crawl page cap; hard stop at limit._

Per-run and per-engagement request budgets and crawl page caps shall be enforced and halt activity when reached.

> **Verification:** Tests asserting activity halts exactly at budget/crawl caps.

**NFR-021 — Report generation time**  ·  _target: < 60 s for a typical engagement dataset._

Report generation for a typical engagement shall complete within a bounded time.

> **Verification:** Performance test measuring generation time across formats on representative data.

**NFR-022 — Dashboard responsiveness**  ·  _target: Dashboard status/budget updates within <= 5 s of underlying change._

The progress dashboard shall reflect run status and budget usage with low latency.

> **Verification:** Latency test measuring update propagation to the dashboard.

### Privacy

**NFR-015 — Redaction coverage**  ·  _target: 100% redaction of the known-sensitive test corpus with 0 leaks._

Redaction of secrets, tokens, cookies, authorization headers, API keys, passwords, PII, and sensitive bodies shall be complete across all logs and every report format.

> **Verification:** Redaction corpus tests run against all report formats and log outputs asserting zero leakage.

**NFR-016 — Response-body retention and size limits**  ·  _target: Configurable per-response body cap (e.g. default <= 512 KB) and bounded retention window._

The platform shall cap stored response body sizes, truncate beyond the cap, and retain bodies only within a configurable window.

> **Verification:** Tests asserting oversized bodies are truncated and bodies are purged after the retention window.

**NFR-017 — Data retention and secure deletion**  ·  _target: Configurable retention; verifiable secure deletion with no recoverable residue._

The platform shall enforce a data-retention policy and perform secure deletion (including cryptographic erasure) of engagement data on expiry or request.

> **Verification:** Retention-policy tests and secure-deletion tests asserting data is unrecoverable after deletion.

**NFR-018 — Multi-tenant and cross-engagement isolation**  ·  _target: 0 cross-tenant/cross-engagement data access in isolation tests._

No user, engagement, or tenant shall access another's engagements, scope, findings, evidence, or reports.

> **Verification:** Tenant-isolation tests attempting cross-boundary access and asserting denial; data-scoping review.

### Reliability

**NFR-023 — Safe resume without loss or duplication**  ·  _target: 0 duplicated state-changing/intrusive actions on resume; no lost completed work._

After interruption, the platform shall resume runs without losing progress and without re-issuing any non-idempotent or state-changing action.

> **Verification:** Recovery tests interrupting runs and asserting correct, non-duplicating resume.

**NFR-024 — Queue durability and idempotency**  ·  _target: Durable persistence across restart; exactly-once effective execution for intrusive actions._

The task queue shall be durable and enforce idempotency so intrusive/approval-gated actions are never duplicated and cannot be abused for amplification.

> **Verification:** Queue-security and crash-recovery tests asserting durability, idempotency, and no duplicate intrusive execution.

**NFR-025 — Backup, restore, and recovery objectives**  ·  _target: Defined RPO and RTO (e.g. RPO <= 24 h, RTO <= 4 h) with verified restore._

The platform shall support backup and restore of engagement, audit, and finding data meeting defined recovery objectives.

> **Verification:** Backup/restore tests validating data integrity and meeting RPO/RTO targets.

**NFR-026 — Isolated tool-failure degradation**  ·  _target: Single adapter failure contained; run continues or safely pauses with recorded reason._

Failure of a single tool adapter shall be isolated and shall not crash the run or the platform; the engagement shall continue or pause safely.

> **Verification:** Fault-injection tests failing an adapter and asserting isolated, safe degradation.

### Safety

**NFR-008 — Fail-closed deny-by-default**  ·  _target: 100% of guard-evaluation error paths result in denial._

Any error, timeout, or ambiguity in scope, authorization, window, or mode evaluation shall result in denial of the request (fail-closed), never in permitting it.

> **Verification:** Fault-injection tests forcing guard errors and asserting denial; property-based tests over guard inputs.

**NFR-009 — Universal scope validation coverage**  ·  _target: 100% of outbound requests validated; 0 un-gated egress paths._

Every outbound target request across all modes and tools shall pass through the scope-validation gate with no bypass path.

> **Verification:** Instrumented egress interception asserting no request leaves without a scope decision; architecture review.

**NFR-010 — SSRF protection**  ·  _target: All named reserved/metadata ranges blocked (IPv4+IPv6); callbacks limited to approved infra._

The platform shall block requests and callbacks to reserved, private, link-local, and metadata addresses and restrict callbacks to approved infrastructure, resistant to redirect and rebinding-based SSRF.

> **Verification:** Dedicated SSRF test suite covering direct, redirect, rebinding, and IPv6 vectors.

**NFR-011 — Passive-by-default posture**  ·  _target: Default mode = Passive; intrusive actions require recorded approval 100% of the time._

The default operating mode shall be Passive, and any active or intrusive activity shall require explicit operator selection and, for intrusive validation, explicit per-action approval.

> **Verification:** Configuration default test; workflow tests asserting active/intrusive activity requires explicit selection/approval.

**NFR-012 — Bounded emergency-stop latency**  ·  _target: New-dispatch halt <= 5 s; in-flight drain/termination <= 30 s._

Activating emergency stop shall cease new dispatch and terminate in-flight testing within bounded time.

> **Verification:** Timed emergency-stop tests measuring dispatch halt and in-flight termination latency.

**NFR-013 — Circuit-breaker auto-halt**  ·  _target: Configurable thresholds for target error/5xx rate, latency, and budget burn; auto-suspend on breach._

Circuit breakers shall automatically suspend engagement activity when configured anomaly thresholds are exceeded.

> **Verification:** Tests injecting threshold breaches and asserting automatic suspension and audit recording.

**NFR-014 — Safety-invariant release gate**  ·  _target: Release blocked on any safety-invariant test failure; no manual override in CI._

A release shall automatically fail if any safety-invariant test (scope, SSRF, authorization, redaction, isolation, non-destructiveness) fails.

> **Verification:** CI pipeline configuration review and a forced-failure test confirming the release is blocked.

### Security

**NFR-001 — Strong authentication**  ·  _target: MFA supported for all interactive roles; idle session timeout <= 30 min; absolute session lifetime <= 12 h._

Authentication shall enforce strong credential policy, support MFA, and expire idle and absolute sessions.

> **Verification:** Auth policy tests for password strength, MFA enrollment, and session timeout enforcement.

**NFR-002 — Encryption in transit and at rest**  ·  _target: TLS 1.2+ only (no deprecated protocols/ciphers); AES-256 (or equivalent) at rest._

All network communication shall use TLS 1.2+ and all engagement data, credentials, evidence, and audit records shall be encrypted at rest.

> **Verification:** TLS configuration scan; storage-encryption verification; test rejecting downgraded protocols.

**NFR-003 — Secret management with no plaintext secrets**  ·  _target: 0 plaintext secrets detected by secret scanning across repo, images, and logs._

The platform shall store no plaintext secrets in source, configuration, container images, or logs, sourcing secrets from a managed secret store or injected environment.

> **Verification:** Secret-scanning in CI over repo and build artifacts; log inspection tests.

**NFR-004 — RBAC enforced on every endpoint**  ·  _target: 100% of state-changing and data-read endpoints covered by authorization checks._

Every API endpoint and UI action shall enforce role-based authorization server-side, independent of client-side controls.

> **Verification:** Automated per-endpoint authorization coverage test; negative role tests.

**NFR-005 — Worker and tool isolation with default-deny egress**  ·  _target: Egress default-deny; only scope-allowlisted destinations reachable from tool containers._

Workers and integrated tools shall run in isolated containers with a default-deny egress policy allowing only in-scope targets and approved callback/infra hosts.

> **Verification:** Container-isolation and egress tests attempting connections to non-allowlisted hosts and asserting denial.

**NFR-006 — Command-injection resistance**  ·  _target: 0 shell-string-built command paths; 100% of adapters use argument-array execution._

External input shall never be interpolated into a shell; all subprocess/tool execution shall use parameterized argument arrays with no shell interpretation.

> **Verification:** Static analysis forbidding shell execution of built strings; injection fuzz tests on adapter inputs.

**NFR-007 — Supply-chain integrity**  ·  _target: All dependencies pinned with lockfiles + integrity hashes; all tools/templates pinned by version+checksum; SCA gate in CI; signed release artifacts._

Dependencies shall be locked and checksum-verified, external tool and template versions pinned and verified, SCA run in CI, and releases signed.

> **Verification:** CI checks for lockfile integrity, tool/template checksum verification, SCA results, and signature validation.

### Usability

**NFR-027 — Single-operator workflow with non-destructive default**  ·  _target: Time-to-first-passive-scan target (e.g. <= 15 min) with zero destructive default steps._

A single operator shall be able to complete the guided workflow to a first passive scan with minimal effort and no destructive default action.

> **Verification:** Usability test measuring completion time and confirming no destructive default is invoked.

**NFR-028 — Accessibility**  ·  _target: WCAG 2.1 AA conformance._

The web UI shall meet accessibility standards for operators using assistive technology.

> **Verification:** Automated and manual accessibility audit against WCAG 2.1 AA.

**NFR-029 — Actionable failure explanations**  ·  _target: Every safety block/halt surfaces a human-readable reason and remediation hint._

When the platform blocks or halts an action, it shall present a clear, actionable explanation of the cause (e.g. out of scope, expired authorization, budget exhausted).

> **Verification:** Tests asserting each block/halt condition renders a specific, actionable message.
