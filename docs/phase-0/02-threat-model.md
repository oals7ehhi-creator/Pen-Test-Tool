# Phase 0 — Threat Model
> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

Methodology: STRIDE + abuse-case analysis over the platform's assets, actors, trust boundaries, and data flows. The ten mandated named threats are each covered and cross-referenced. Threats T-029–T-036 and their mitigations were added during the Phase 0 adversarial design review (see `08-design-review-and-critique-resolution.md`).

## 1. Assets

| Asset | Sensitivity | Description |
|---|---|---|
| Scope configuration / allowlist | critical | Per-engagement allowlist of domains, IPs, CIDRs, ports, protocols, URL prefixes, APIs plus explicit exclusions. The single source of truth the Scope Authority evaluates and the Guarded Egress Broker enforces on every outbound request. Tampering with it is the direct path to scope escape and third-party attack. |
| Authorization records | critical | Written-authorization reference, engagement owner, signatory, expiry timestamp, testing window, and bound scope. Legal proof-of-consent gating all activity; forged or altered records enable attacking systems the operator has no right to test. |
| Operator-supplied target auth sessions & test-account credentials | critical | Session cookies, bearer tokens, and low-priv test accounts the operator provides so the scanner can reach authenticated surface of the in-scope target. High-value secrets that must only ever be transmitted to in-scope hosts. |
| Audit trail / audit events | critical | Tamper-evident, hash-chained record of every action (scope edits, approvals, requests dispatched, tool runs, exports). Forensic and legal record; its integrity is what proves the engagement stayed non-destructive and in-scope. |
| Platform secrets & signing keys | critical | DB credentials, queue-message HMAC/signing keys, audit hash-chain key, session keys, callback-infra credentials, tool feed API keys. Compromise breaks tenant isolation, audit integrity, and queue trust simultaneously. |
| Platform user accounts, sessions & RBAC assignments | critical | Operator identities and role bindings (Administrator, Engagement Manager, Tester, Reviewer, Read-only Auditor) and engagement membership that enforce separation of duties and the approval gate. |
| Findings & evidence | high | Vulnerability findings with captured request/response evidence. Evidence may contain sensitive data reflected from the target; must be minimized, size-capped, and redacted. |
| Reports & exports | high | HTML/JSON/CSV/PDF-ready deliverables. If redaction fails they expose target cookies, authorization headers, API keys, PII, and sensitive bodies to anyone with the export. |
| Raw scanner / tool output | high | Untrusted structured output from Nuclei, ZAP, TestSSL, SCA and secret scanners. Attacker-influenceable (via target responses) and must be treated as hostile input before parsing, storing, or rendering. |
| Job queue messages | high | Scan/task descriptors moving from API to workers. If forgeable they can schedule out-of-scope or high-volume work, or carry injected command fields. |
| Callback / OOB validation infrastructure config | high | Approved controlled callback domains and per-check correlation tokens used for SSRF/OOB detection. Misuse turns it into an open redirector or a channel to assert false findings. |
| Target intake data (OpenAPI, Postman, HAR, sitemap, imported proxy history) | high | Seed material describing attack surface. Often contains third-party domains and embedded tokens; intake is not authorization and every entry must be scope-validated before use. |
| Tool & template inventory with pinned versions | high | Curated non-destructive template allowlist and pinned/verified tool binaries. Integrity determines whether only safe, non-destructive checks can run. |
| DNS resolution results | medium | Resolved IPs used for scope verification and connection pinning. Central to DNS-rebinding protection; stale or unpinned results enable TOCTOU scope escape. |
| Tenant / engagement isolation metadata | critical | The tenant and engagement identifiers and boundaries that every query, queue message, and object-access check must be scoped by to prevent cross-engagement leakage. |
| Approval records & validation plans | high | Approval-gated validation plans (exact requests, expected impact, rollback, evidence, stop conditions) and their sign-offs. Bypass allows intrusive actions without authorization. |

## 2. Actors

| Actor | Trust | Description |
|---|---|---|
| Administrator | internal-trusted | Configures the platform, manages users/roles, tool inventory and pinned versions, callback infra, and global safety defaults. Highest privilege; cannot silently disable safety invariants (enforced server-side and audited). |
| Engagement Manager | internal-trusted | Creates engagements, records authorization (owner, reference, expiry, window), defines scope, and approves approval-gated validation. Separation of duties: cannot also be the executing Tester on the same gated action. |
| Tester | internal-limited | Runs passive and safe-active scans within assigned engagements and supplies target auth sessions. Cannot approve intrusive validation, cannot edit authorization, cannot access other engagements. |
| Reviewer | internal-limited | Triages and grades findings, marks false positives, comments, manages status lifecycle. Cannot launch scans or approve intrusive validation. |
| Read-only Auditor | internal-limited | Views reports, findings, and the audit trail for oversight. No mutating actions. |
| Malicious or careless insider operator | internal-limited | An authenticated operator who tries (deliberately or through negligence) to point the platform at systems they are not authorized to test, broaden scope, or run intrusive checks. Primary abuse-case actor. |
| Target system under test | system | The in-scope application/host. Responds to requests and may be attacker-controlled or compromised; its responses, redirects, DNS, and any content are untrusted input to the scanner. |
| External attacker (unauthenticated) | external-malicious | Attacker with no platform account attempting to compromise the platform itself (auth bypass, queue injection, exploiting the scanner via a malicious target they control) to weaponize it or steal engagement data. |
| External security tools | system | Nuclei, ZAP, TestSSL, SCA and secret scanners executed as untrusted third-party code inside isolated containers. Assumed potentially buggy or hostile. |
| Third-party / supply-chain sources | external-malicious | Package registries, tool binaries, and template feeds. A compromised dependency, binary, or template is code the platform would otherwise execute with worker privilege. |
| Callback / OOB infrastructure | system | Platform-controlled infrastructure that records out-of-band interactions for SSRF/OOB checks and correlates them by token. |

## 3. Trust boundaries

| Boundary | Description | Controls at the boundary |
|---|---|---|
| Browser <-> Backend API | Operator UI/API surface where all human intent enters the system. | TLS; strong authN (MFA-capable) + short-lived sessions; RBAC on every endpoint; object-level authorization (engagement/tenant scoping); anti-CSRF; strict server-side input validation and canonicalization; no client-side safety toggles — safety invariants enforced server-side; per-role rate limiting. |
| Backend API <-> Worker (via job queue) | Control-plane to execution-plane boundary; the only way scan work reaches workers. | HMAC/signed queue messages with per-message nonce and TTL; strict typed message schema with no free-form command/argument fields; tenant+engagement id bound and re-verified on dequeue; workers cannot self-authorize scope — they re-run scope validation before any request. |
| Worker <-> Tool sandbox | Execution of untrusted external tools separated from worker/host. | One-shot isolated container per run; read-only root FS + ephemeral scratch; non-root user; seccomp/AppArmor; dropped capabilities; no host mounts; CPU/mem/time/PID/request caps; args passed via argv arrays (never a shell); structured output over a file/pipe, never console scraping. |
| Platform <-> Target (egress boundary) | Every outbound request to a target crosses here; the core safety perimeter. | Two-stage authorization (Scope Authority Stage-1 grant + Guarded Egress Broker Stage-2) on each request; authenticated per-job broker ingress (no generic CONNECT proxy); DNS resolve + IP re-check + connection pinning (rebinding protection); Tier A hard-deny (metadata/loopback/unspecified/multicast/broadcast/reserved) and Tier B (RFC1918/ULA/link-local/CGNAT) only via elevated dual approval; redirect re-authorized per hop; per-engagement concurrency/rate caps and circuit breakers; testing-window + authorization-expiry gate; forced egress allowlist (no direct sockets). |
| Platform <-> Supply-chain sources | Fetching dependencies, tool binaries, and templates. | Pinned versions + checksum/signature verification at fetch and at load; isolated fetch with restricted egress; curated non-destructive template allowlist; SBOM + dependency/secret scanning in CI; no runtime auto-update of tools/templates. |
| Tenant / engagement isolation boundary | Logical boundary between engagements and tenants inside DB, queue, and storage. | Row-level tenant/engagement scoping on every query; authorization checks keyed to engagement membership; separate secret namespaces per engagement; queue messages and evidence blobs tagged and filtered by engagement; no cross-engagement joins in reporting. |
| Untrusted-data boundary | Boundary where target responses and tool output enter storage/rendering. | Treat all target/tool data as hostile; schema-validate and size-cap before parse; parse in memory-limited sandboxed parsers (no entity expansion, no eval); contextual output-encoding on all UI/report rendering; store raw output separately from verified findings. |
| Secret-store boundary | Access to platform and engagement secrets. | Central secret manager; short-lived scoped credentials; no plaintext secrets in code, env dumps, logs, or queue; encryption at rest; access audited; fail-closed when unreachable. |

## 4. Data flows

| Flow | Source → Destination | Data | Crosses boundary |
|---|---|---|---|
| Define scope & authorization | Operator browser → Backend API -> Database | Allowlist entries, exclusions, authorization reference, owner, expiry, testing window | yes |
| Enqueue scan job | Backend API → Job queue -> Worker | Signed job descriptor (engagement id, mode, target set, budgets) | yes |
| Scope + DNS validation | Worker → Scope Authority (Stage-1) → Guarded Egress Broker (Stage-2 DNS resolve) | Candidate target URL/host, resolved IPs, in/out-of-scope verdict | yes |
| Outbound test request to target | Worker / tool sandbox → Target system (via egress proxy) | HTTP request with non-destructive payloads; operator target session only if host in scope | yes |
| Target response ingest | Target system → Worker (untrusted-data boundary) | Untrusted response headers/body, redirects, TLS/cert data | yes |
| Tool invocation | Worker → Tool sandbox container | argv array, curated template id, resource limits (no shell, no user CLI args) | yes |
| Tool structured output | Tool sandbox → Worker output parser | Untrusted JSON/XML scan results | yes |
| OOB/SSRF callback correlation | Callback infrastructure → Worker correlation service | Interaction record + per-check correlation token | yes |
| Persist findings & evidence | Worker → Database / evidence store | Redacted, size-capped findings and evidence tagged by engagement | no |
| Generate & export report | Reporting service → Operator browser / file export | Redacted findings, scope, authorization, methodology | yes |
| Fetch tools/templates/dependencies | Build/worker fetcher → Supply-chain source | Pinned versions + checksums/signatures | yes |
| Emit audit event | All services → Append-only hash-chained audit log | Actor, action, target, timestamp, prev-hash | no |
| Resolve secret | API / Worker → Secret store | Short-lived scoped credential request | yes |
| Import intake artifacts | Operator browser → Backend API -> intake store | OpenAPI/Postman/HAR/sitemap/proxy history (untrusted, scope-unvalidated) | yes |

## 5. Named-threat coverage

The specification mandates coverage of ten named threats. Mapping to threat entries:

| Named threat | Threat entries |
|---|---|
| scope escape | T-001, T-002, T-003, T-004, T-027, T-029, T-030, T-035, T-037 |
| SSRF | T-005, T-006, T-031 |
| command injection | T-007, T-008 |
| malicious scanner output | T-009, T-010 |
| unsafe plugin execution | T-011, T-012 |
| secret leakage | T-013, T-014, T-034, T-036 |
| cross-tenant access | T-015 |
| report-data exposure | T-016, T-017, T-032 |
| queue abuse | T-018, T-019, T-038 |
| supply-chain compromise | T-020 |

## 6. Threats (STRIDE)

### T-001 — Scope-config tampering / scope-logic bypass

- **STRIDE:** Tampering, Elevation of Privilege
- **Named threat:** scope escape
- **Likelihood / Impact:** medium / critical
- **Assets at risk:** Scope configuration / allowlist, Audit trail / audit events

A target outside the engagement allowlist is scheduled or executed because the scope allowlist is altered after approval, or a defect in the Scope Authority (missing check on a code path, exclusion not honored) lets an off-scope request through.

**Vector.** Direct API edit of scope during an active engagement; a scan code path that reaches the egress proxy without calling the scope service; exclusion list evaluated after the allow decision.

**Mitigations.**
- Single mandatory choke-point: every outbound request passes the two-stage Scope Authority / Guarded Egress Broker flow — no code path may open a target socket without a valid grant
- Fail-closed default deny; empty/absent scope denies all
- Exclusions evaluated before allows; deny wins ties
- Scope changes on an active engagement require re-approval and are hash-chained into the audit log
- Property-based and fuzz tests proving out-of-scope requests cannot be scheduled or executed (Phase 2/10 acceptance criteria)

**Residual risk.** A logic bug on an unusual protocol/port path could still slip; mitigated by centralized enforcement, fuzzing, and default-deny but not eliminated.

### T-003 — DNS rebinding (TOCTOU) scope escape

- **STRIDE:** Spoofing, Tampering
- **Named threat:** scope escape
- **Likelihood / Impact:** medium / critical

An in-scope domain resolves to an in-scope IP at validation time, then to a private/metadata/off-scope IP at connection time, so scope is verified against one address but the request lands on another.

**Vector.** Attacker-controlled authoritative DNS with very low TTL returning benign IP for the check and 169.254.169.254 or an RFC1918 address for the actual connection.

**Mitigations.**
- Resolve once, validate the resolved IP set, then pin and connect to that exact validated IP (no second resolution)
- Re-check every resolved A/AAAA record against scope and private/metadata deny-list, not just the hostname
- Reject responses whose connected peer IP differs from the validated IP
- IPv4 and IPv6 both validated; multi-record answers all must pass

**Residual risk.** Low once IP-pinning is enforced end-to-end including inside tool sandboxes; tools that resolve independently are the gap, mitigated by sandbox egress proxy doing the pinning.

### T-005 — SSRF to cloud metadata & internal services

- **STRIDE:** Information Disclosure, Elevation of Privilege
- **Named threat:** SSRF
- **Likelihood / Impact:** medium / critical

The worker or a tool is coerced into requesting cloud metadata (169.254.169.254), link-local, loopback, or RFC1918 internal services, exposing credentials or reaching infrastructure never in scope.

**Vector.** Malicious target redirect/rebinding, an intake artifact containing internal URLs, or a tool template that follows a target-supplied URL to an internal address.

**Mitigations.**
- Hard default-deny of loopback, RFC1918, link-local (169.254/16, fe80::/10), ULA, metadata IPs and 0.0.0.0 — applied even if textually allowlisted, requiring explicit elevated override that is flagged and audited
- Egress forced through a filtering proxy that enforces the same deny-list independent of the tool
- No credentials/headers auto-attached to internal destinations
- SSRF-specific tests (Phase 10) asserting metadata/private ranges are unreachable

**Residual risk.** An operator deliberately allowlisting a private range for an internal engagement reintroduces exposure; mitigated by elevated approval + prominent flagging, not removable.

### T-007 — Command injection via target-derived data into tool arguments

- **STRIDE:** Elevation of Privilege
- **Named threat:** command injection
- **Likelihood / Impact:** low / critical

Data influenced by the target (hostname, URL, parameter names, response-derived values) flows into a command line used to invoke an external tool and is interpreted as shell metacharacters, yielding code execution in the worker/sandbox.

**Vector.** A crafted host or URL containing ; | $() ` newlines passed to a tool wrapper that builds a shell string.

**Mitigations.**
- Never construct shell strings; invoke tools via argv arrays with no shell interpreter
- Strict allowlist validation/canonicalization of any value placed in argv
- No user- or target-supplied CLI flags ever reach a tool invocation
- Tools run in a sandbox with dropped privileges so even successful injection is contained
- Static analysis rule banning shell=true / string-concatenated exec

**Residual risk.** Very low with argv-only execution; residual limited to bugs in a specific adapter, contained by the sandbox.

### T-008 — Command injection via operator/API config reaching a shell

- **STRIDE:** Elevation of Privilege
- **Named threat:** command injection
- **Likelihood / Impact:** low / critical

An operator-supplied field (custom header value, tool option, engagement name used in a filename, report template) is passed to a shell or command execution path on the server.

**Vector.** Malicious value in an API field that a component later interpolates into an OS command, cron, or filename.

**Mitigations.**
- No arbitrary shell commands from UI or API by design (explicit requirement)
- All operator inputs validated/escaped; filenames derived from server-generated ids, not user strings
- Report/PDF rendering done in-process or in a sandbox with no shell
- Least-privilege service accounts; no command-exec primitives exposed to request handlers

**Residual risk.** Low; concentrated in report rendering and file handling, addressed by sandboxed renderers.

### T-011 — Unsafe plugin execution — tool sandbox escape

- **STRIDE:** Elevation of Privilege
- **Named threat:** unsafe plugin execution
- **Likelihood / Impact:** low / critical

An untrusted external tool (or a compromised version of one) escapes its container to the worker host, gaining access to other engagements, secrets, or the network.

**Vector.** Kernel/container vulnerability, a mounted socket, an over-privileged container, or a tool exploiting a shared resource.

**Mitigations.**
- One ephemeral container per run, non-root, read-only root FS, dropped capabilities, seccomp/AppArmor, no docker socket, no host mounts
- Per-run network namespace with egress only through the filtering proxy
- Resource limits (CPU/mem/PID/time) and automatic teardown
- Pinned, checksum-verified tool images; run on a hardened, patched host; consider gVisor/microVM isolation

**Residual risk.** Low but non-zero (kernel 0-day); reduced by microVM isolation and minimal host attack surface.

### T-014 — Operator target-credential/session theft or misdelivery

- **STRIDE:** Information Disclosure, Spoofing
- **Named threat:** secret leakage
- **Likelihood / Impact:** low / critical

Operator-supplied target session tokens/test-account credentials are exfiltrated from storage, or transmitted to a host other than the intended in-scope target (e.g., via redirect or rebinding), handing them to a third party.

**Vector.** Credentials sent on an off-scope redirect; stored in plaintext; visible to another engagement; logged.

**Mitigations.**
- Target sessions bound to specific in-scope host(s); scope check on every request prevents attaching them to any other host, including redirects
- Encrypted at rest, engagement-scoped, never logged or exported
- Short-lived storage tied to the active engagement; purged on completion
- No credential-harvesting/ATO checks in the engine to consume or replay them

**Residual risk.** Low; principal risk is a redirect/rebinding bug leaking to an off-scope host, covered by T-002/T-003 controls.

### T-015 — Cross-tenant / cross-engagement access

- **STRIDE:** Elevation of Privilege, Information Disclosure
- **Named threat:** cross-tenant access
- **Likelihood / Impact:** medium / critical

A Tester or Reviewer in engagement A reads or acts on another engagement's scope, authorization, credentials, findings, or launches scans under it — breaking isolation and possibly attacking a target under someone else's authorization.

**Vector.** Missing engagement filter on a query/endpoint (IDOR), queue message not re-scoped on dequeue, shared cache/blob store without tenant tags.

**Mitigations.**
- Row-level tenant/engagement scoping enforced in the data layer on every read/write; object-level authorization on every endpoint
- Queue messages carry and re-verify engagement id on dequeue; workers cannot act cross-engagement
- Per-engagement secret and evidence namespaces; no cross-engagement joins in reporting
- Tenant-isolation tests (Phase 10) as a release-blocking safety invariant

**Residual risk.** Medium; classic IDOR risk on new endpoints, reduced by centralized authorization middleware and isolation tests.

### T-018 — Queue abuse — job forgery / injection

- **STRIDE:** Spoofing, Tampering, Elevation of Privilege
- **Named threat:** queue abuse
- **Likelihood / Impact:** low / critical

An attacker or lower-privilege actor injects or modifies job-queue messages to run scans against out-of-scope targets, escalate mode, or smuggle command fields to workers.

**Vector.** Direct broker access, a compromised service, or an API path that enqueues without full authorization, producing messages a worker trusts.

**Mitigations.**
- HMAC/signed messages with per-message nonce + TTL; workers reject unsigned/invalid/replayed messages
- Typed message schema with no free-form command/argument fields — nothing in a message can select a shell command or arbitrary target
- Workers re-run scope + authorization + window validation on dequeue rather than trusting the message
- Broker access restricted, authenticated, and network-segmented

**Residual risk.** Low; a forged message still fails worker-side re-validation of scope and authorization.

### T-020 — Supply-chain compromise of dependencies, tools, or templates

- **STRIDE:** Tampering, Elevation of Privilege
- **Named threat:** supply-chain compromise
- **Likelihood / Impact:** medium / critical

A compromised package, tool binary, container image, or template feed introduces malicious code that executes in CI or in the worker/sandbox with its privileges.

**Vector.** Typosquat/dependency-confusion, a backdoored tool release, or a poisoned template repository pulled at build or runtime.

**Mitigations.**
- Pin all dependencies, tool images, and templates by version + checksum/signature; verify at fetch and at load
- Dependency locking, SBOM generation, dependency/SCA and secret scanning in CI
- No runtime auto-update of tools/templates; curated allowlist reviewed before promotion
- Isolated fetch with restricted egress; sandboxed execution so a compromised tool is contained

**Residual risk.** Medium; signature verification narrows but cannot eliminate a compromised-but-signed upstream; contained by sandboxing and least privilege.

### T-021 — Platform authentication bypass / session hijack

- **STRIDE:** Spoofing
- **Named threat:** other
- **Likelihood / Impact:** medium / critical

An attacker gains an authenticated platform session (auth bypass, session fixation, stolen/predictable token, missing MFA) and can then operate the scanner or read engagement data.

**Vector.** Weak session management, credential stuffing, XSS-driven token theft (see T-010), or missing brute-force protection on login.

**Mitigations.**
- Strong authN with MFA support, secure/HttpOnly/SameSite cookies, short-lived rotated sessions, server-side session invalidation
- Brute-force/lockout protection and anomaly alerting on auth
- CSP + output encoding to prevent token-stealing XSS
- All privileged actions still gated by RBAC and approval, limiting a single hijacked account

**Residual risk.** Medium; account compromise remains a top risk, contained by MFA, RBAC, separation of duties, and audit.

### T-024 — Authorization-expiry / testing-window / emergency-stop bypass

- **STRIDE:** Tampering, Denial of Service
- **Named threat:** other
- **Likelihood / Impact:** medium / critical

Testing continues after the written authorization expires, outside the permitted testing window, or after an emergency stop — producing unauthorized activity against an otherwise in-scope target.

**Vector.** Clock skew, a long-running job not re-checking expiry, an emergency-stop signal that does not reach a busy worker, or cached authorization.

**Mitigations.**
- Authorization expiry and testing window re-checked on every request dispatch, not just at scan start; expired/out-of-window => deny
- Emergency stop propagated via worker heartbeats + short job leases; workers self-terminate on missed heartbeat or lease expiry
- Auto-expiration halts scheduling and drains running jobs; trusted time source with skew tolerance that fails closed
- Every stop/expiry event audited

**Residual risk.** Low; in-flight requests at the instant of expiry may complete, bounded by short leases and per-request checks.

### T-027 — Fabricated authorization to attack unauthorized systems

- **STRIDE:** Spoofing, Elevation of Privilege
- **Named threat:** scope escape
- **Likelihood / Impact:** medium / critical

A malicious operator fabricates an authorization record and scope for a system they have no real-world permission to test (e.g., a competitor or third party), using the platform to conduct an unauthorized assessment.

**Vector.** Entering a plausible but false authorization reference/owner and adding the third-party domain to scope, then running active checks.

**Mitigations.**
- Authorization is a first-class, mandatory record (reference, owner, signatory, expiry, window) with no activity permitted without it
- Separation of duties: Engagement Manager records/authorizes; a distinct Tester executes; intrusive validation needs independent approval
- Ownership attestation, tamper-evident audit of who created scope/authorization, and default-to-passive posture
- Wildcard/large-CIDR scope requires elevated approval and is flagged; discovered hosts never auto-added

**Residual risk.** High by nature — software cannot verify real-world legal authorization; the platform enforces accountability, non-repudiation, and least intrusiveness rather than preventing a determined insider outright.

### T-029 — Headless/JS-executing crawler as an autonomous request engine

- **STRIDE:** Tampering, Information Disclosure, Elevation of Privilege
- **Named threat:** scope escape
- **Likelihood / Impact:** high / critical
- **Assets at risk:** Scope configuration / allowlist, In-scope target systems, Third-party / out-of-scope systems

A headless browser used for JavaScript-route discovery does its own DNS resolution and autonomously fetches subresources (img/script/iframe/fetch/XHR/WebSocket, WebRTC/QUIC) to whatever a page references — third-party CDNs, analytics, or attacker-chosen hosts — bypassing the single egress choke point entirely.

**Vector.** Rendering an in-scope page whose DOM references out-of-scope or attacker-controlled URLs; browser-side DNS and direct sockets that never traverse the broker.

**Mitigations.**
- SI-041: any headless browser runs inside the default-deny egress netns with the Guarded Egress Broker as its ONLY proxy for ALL request types
- Browser-side DNS disabled (proxy-side resolve + IP pinning); WebRTC/QUIC/direct-socket features disabled; file:/data:/blob: navigation restricted
- Acceptance test: a page referencing an out-of-scope subresource produces zero out-of-scope connections
- If broker-only egress cannot be guaranteed for the browser, JS execution in the crawler is forbidden

**Residual risk.** A browser 0-day that escapes proxy enforcement could still egress; contained by the network-layer default-deny netns (no route except the broker) as a second, non-application layer.

### T-031 — IPv6 transition-address SSRF (6to4 / Teredo / NAT64)

- **STRIDE:** Spoofing, Information Disclosure
- **Named threat:** SSRF
- **Likelihood / Impact:** low / critical
- **Assets at risk:** Cloud metadata endpoints, Internal / private network

IPv4-embedding IPv6 transition forms — 6to4 (2002::/16, e.g. 2002:a9fe:a9fe:: encodes 169.254.169.254), Teredo (2001::/32), NAT64 (64:ff9b::/96) — can encode cloud-metadata or RFC1918 addresses and are absent from a naive forbidden-range list; on hosts with relays these reach internal endpoints.

**Vector.** A target hostname or redirect resolving to a transition-form IPv6 address that decodes to a forbidden IPv4 range.

**Mitigations.**
- SI-044: the network-guard classifier decodes IPv4-mapped, IPv4-compatible, 6to4, Teredo, and NAT64 forms and re-classifies the embedded IPv4 against all ranges
- SI-006: cloud-metadata (and all Tier A) addresses are NEVER reachable by any allow, elevated entry, or approval; a Tier B covering entry (e.g. an elevated 169.254.0.0/16, or a 0.0.0.0/0 allow) does not permit any Tier A address within it
- Table-driven test corpus including 2002:a9fe:a9fe:: (decodes to 169.254.169.254 → hard-denied)

**Residual risk.** Novel transition/encoding schemes may emerge; mitigated by deny-by-default on any address that cannot be positively classified as in-scope.

### T-035 — Insider self-authorization (single-actor scope expansion + self-attestation)

- **STRIDE:** Elevation of Privilege, Repudiation
- **Named threat:** scope escape
- **Likelihood / Impact:** medium / critical
- **Assets at risk:** Authorization record, Scope configuration / allowlist, Audit trail / audit events

The threat model names a malicious/careless insider operator as the primary abuse actor, yet a single Engagement Manager could define scope, self-attest (unverifiable free-text) that written authorization exists, bind it, and approve gated validation — defeating the authorization-first premise with no two-person control.

**Vector.** One privileged insider broadening scope to a new host and re-attesting written authorization.

**Mitigations.**
- SI-047: authorization attestation and any scope expansion introducing a new host/domain/range require two distinct approvers (dual control), neither being the executing tester, with document_sha256 pinned at both approvals
- A user cannot hold two separation-of-duties-conflicting roles on the same engagement even if globally granted
- All attestations and scope changes are hash-chained into the audit trail

**Residual risk.** Collusion between two approvers is not prevented technically; reduced to a two-party act with pinned evidence and immutable audit.

### T-002 — Redirect-based scope escape

- **STRIDE:** Tampering
- **Named threat:** scope escape
- **Likelihood / Impact:** medium / high

An in-scope target responds with a 3xx redirect (or meta/JS redirect) to an out-of-scope or internal host and the scanner follows it, issuing requests to a system that was never authorized.

**Vector.** Location header or refresh pointing to attacker-controlled or internal host; chained redirects that drift off-scope.

**Mitigations.**
- Redirects are never auto-followed; the redirect target is re-run through the scope + private-range checks before any follow
- Off-scope redirect stops the flow and is recorded, not followed
- Redirect chain depth capped; each hop re-validated independently
- Operator target sessions/cookies never attached to a redirected off-scope host

**Residual risk.** Low; requires the redirect target to also pass scope, which by definition keeps it in-scope.

### T-004 — URL canonicalization / IPv6 / encoding scope bypass

- **STRIDE:** Tampering
- **Named threat:** scope escape
- **Likelihood / Impact:** medium / high

An off-scope destination is expressed in a form the allowlist matcher fails to normalize, so it is treated as in-scope or as a different host than it connects to.

**Vector.** Percent-encoding, mixed case, trailing dot, userinfo (user@host), decimal/octal/hex IP literals, IPv6 zone ids or bracket tricks, unicode/IDN homoglyphs, embedded credentials or fragments.

**Mitigations.**
- Canonicalize URLs/hosts to a single normalized form before matching (lowercase, IDN->punycode, strip userinfo, normalize IP literals to canonical IPv4/IPv6)
- Match on the canonical form only; reject unparseable or ambiguous inputs (fail closed)
- Validate against the post-resolution IP, not just the textual host
- URL-parser fuzzing in QA (Phase 10) covering these encodings

**Residual risk.** Parser differentials between the scope engine and the HTTP client remain a subtle risk; mitigated by using one shared canonicalizer for both.

### T-006 — SSRF callback / OOB infrastructure abuse

- **STRIDE:** Tampering, Spoofing
- **Named threat:** SSRF
- **Likelihood / Impact:** low / high

The controlled callback infrastructure is abused as an open redirector or reflector, or forged callbacks are used to assert false SSRF findings or to interact with non-engagement systems.

**Vector.** Guessable correlation tokens; callback endpoint that echoes/redirects arbitrary URLs; a third party sending crafted interactions to the callback host.

**Mitigations.**
- High-entropy per-check correlation tokens bound to engagement, target, and time window
- Callback infra only records interactions — it never redirects, proxies, or fetches attacker-supplied URLs
- Callbacks accepted only during the check's active window and matched to an expected token before asserting a finding
- Callback infra network-isolated with no access to internal platform services

**Residual risk.** Low; forged callbacks without a valid token are ignored and cannot create findings.

### T-009 — Malicious scanner output — parser exploitation & false-finding injection

- **STRIDE:** Tampering, Elevation of Privilege
- **Named threat:** malicious scanner output
- **Likelihood / Impact:** medium / high

A tool (influenced by a hostile target) emits crafted structured output that exploits the parser (XXE, billion-laughs, deserialization), injects fabricated findings, or overflows storage.

**Vector.** Malicious XML/JSON in Nuclei/ZAP output; oversized output; entity-expansion; polyglot payloads designed to break normalization.

**Mitigations.**
- Treat all tool output as untrusted; parse with hardened parsers (external entities disabled, no DTD, expansion limits, safe deserialization only)
- Schema-validate against the normalized finding schema; reject non-conforming output
- Size/time caps on output; raw output stored separately and never executed
- All findings from tools enter as Unverified pending review, so injected findings cannot auto-escalate

**Residual risk.** Low-medium; a novel parser bug remains possible, bounded by sandboxed parsing and unverified default status.

### T-010 — Malicious scanner output — stored XSS via unescaped rendering

- **STRIDE:** Elevation of Privilege, Tampering
- **Named threat:** malicious scanner output
- **Likelihood / Impact:** medium / high

Target responses or tool output containing HTML/JS are rendered unescaped in the operator UI or HTML report, executing script in a reviewer's authenticated browser (potential platform account takeover).

**Vector.** A target that reflects a script payload captured as evidence, later shown verbatim in the UI/report.

**Mitigations.**
- Contextual output-encoding on every rendering of target/tool-derived data in UI and reports
- Strict Content-Security-Policy on the UI and generated HTML reports; evidence shown as inert text, not live HTML
- Sanitize/escape evidence at storage and at render (defense in depth)
- Reports opened in a sandboxed context; no inline event handlers

**Residual risk.** Low with CSP + encoding; residual from a missed sink, caught by report-redaction/rendering tests.

### T-012 — Unsafe plugin execution — destructive or intrusive template/option enabled

- **STRIDE:** Tampering, Elevation of Privilege
- **Named threat:** unsafe plugin execution
- **Likelihood / Impact:** medium / high

A tool runs a template or option that performs an intrusive or destructive action (active exploit, fuzzing, brute force, DoS, data modification) that violates the non-destructive model, even against an in-scope target.

**Vector.** A Nuclei template outside the curated allowlist, a ZAP active-scan policy, or a dangerous CLI flag enabled by misconfiguration.

**Mitigations.**
- Curated allowlist of non-destructive templates/policies only; everything else disabled by default
- Safety classification per check; destructive/intrusive categories are not present in the engine and cannot be selected
- No user-supplied templates or CLI args; template set pinned and version-verified
- Intrusive validation only via the separate approval-gated workflow with an explicit plan, never through a tool's own active mode

**Residual risk.** Low; requires bypassing the allowlist, which is version-pinned and reviewed.

### T-013 — Secret leakage into logs, findings, and reports

- **STRIDE:** Information Disclosure
- **Named threat:** secret leakage
- **Likelihood / Impact:** medium / high

Platform secrets (DB creds, signing keys, callback creds, tool API keys) or captured target secrets appear in structured logs, error traces, evidence, or exported reports.

**Vector.** Verbose logging of request/response, stack traces including config, evidence capture of Set-Cookie/Authorization, error messages echoing secrets.

**Mitigations.**
- Secrets only from the secret store, never in env dumps/logs/queue; log redaction filters for tokens/cookies/keys/PII
- Structured logging with explicit field allowlists, not raw request/response dumps
- Pre-storage and pre-export redaction of cookies, Authorization headers, API keys, passwords, PII, sensitive bodies
- Secret-scanning canary tokens to detect leakage in outputs (Phase 10)

**Residual risk.** Medium; redaction is pattern-based and can miss novel formats, mitigated by canaries and field allowlisting.

### T-016 — Report-data exposure via redaction failure

- **STRIDE:** Information Disclosure
- **Named threat:** report-data exposure
- **Likelihood / Impact:** medium / high

A generated report or export contains sensitive data that should have been redacted — target cookies, authorization headers, API keys, PII, or sensitive response bodies — exposing them to report recipients.

**Vector.** A finding evidence field or embedded raw response that the redaction rules did not cover; a new report format bypassing the redaction pass.

**Mitigations.**
- Centralized redaction applied to all export formats (HTML/JSON/CSV/PDF) as a single gate before any file is produced
- Deny-by-default: unredactable/unknown sensitive fields are dropped, not passed through
- Post-generation secret/PII scan of the export; block delivery on any hit (fail closed)
- Report-redaction tests with canary secrets as a release-blocking invariant (Phase 10)

**Residual risk.** Medium; redaction completeness is the recurring weak point, mitigated by canary-based blocking scans and drop-by-default.

### T-017 — Report-data exposure via broken object-level authorization (IDOR)

- **STRIDE:** Information Disclosure
- **Named threat:** report-data exposure
- **Likelihood / Impact:** medium / high

A report/evidence/export endpoint returns another engagement's or tenant's report because it authorizes by authentication but not by object ownership.

**Vector.** Guessable/sequential report or evidence ids fetched by a user without membership in that engagement.

**Mitigations.**
- Object-level authorization on every report/evidence/export retrieval keyed to engagement membership and role
- Unguessable ids for reports and evidence blobs
- Read-only Auditor and Reviewer scoping enforced server-side
- Access to reports and evidence written to the audit trail

**Residual risk.** Low-medium; standard IDOR class, reduced by mandatory object-level checks and audit visibility.

### T-019 — Queue abuse — flooding, worker exhaustion & target amplification

- **STRIDE:** Denial of Service
- **Named threat:** queue abuse
- **Likelihood / Impact:** medium / high

Excessive jobs are enqueued to exhaust workers (self-DoS) or to amplify request volume against a target, turning the platform into a DoS tool despite the non-destructive mandate.

**Vector.** Automated bulk enqueue, a runaway crawl, or an operator raising volume beyond safe bounds.

**Mitigations.**
- Hard per-engagement concurrency and request-rate caps that operators cannot exceed beyond safe ceilings
- Request budgets per scan with pre-run volume estimate shown to the operator (Phase 9)
- Queue depth/backpressure limits and per-user enqueue quotas
- Circuit breakers that trip on target error-rate/latency and emergency-stop that drains and halts work

**Residual risk.** Low-medium; conservative defaults reduce impact, but aggregate load across engagements needs global ceilings too.

### T-022 — RBAC escalation & approval-gate bypass

- **STRIDE:** Elevation of Privilege
- **Named threat:** other
- **Likelihood / Impact:** medium / high

A user performs actions above their role — a Tester approves their own intrusive validation, or a gated action executes without an independent approval — defeating separation of duties and the non-destructive gate.

**Vector.** Missing server-side role check, client-side-only gating, or self-approval allowed on the same action the actor initiated.

**Mitigations.**
- Server-side RBAC on every action; approval-gated validation requires a different qualified user (separation of duties) than the initiator
- Approval workflow records plan, approver identity, and timestamp in the immutable audit log before execution
- Gated actions cannot execute without a valid, unexpired, matching approval token
- Least privilege by default; role changes audited and require Administrator

**Residual risk.** Low-medium; collusion between roles remains possible, deterred by audit and required distinct approvers.

### T-023 — Audit-trail tampering / repudiation

- **STRIDE:** Repudiation, Tampering
- **Named threat:** other
- **Likelihood / Impact:** low / high

An actor deletes or alters audit events to hide out-of-scope activity, unapproved validation, or scope edits, undermining the legal/forensic record.

**Vector.** Direct DB write to audit rows, disabling logging before an action, or replaying/backdating events.

**Mitigations.**
- Append-only, hash-chained audit events (each entry commits to the previous hash) so gaps/edits are detectable
- Signed events; write to storage the application role cannot update or delete; periodic export to WORM/external sink
- Actions that cannot be audited are refused (fail closed — see failure modes)
- Continuity verification job that alarms on chain breaks

**Residual risk.** Low; full compromise of the signing key + storage could still forge a consistent chain, mitigated by external replication and key isolation.

### T-025 — Unrestricted worker/tool egress (data exfiltration / C2)

- **STRIDE:** Information Disclosure, Elevation of Privilege
- **Named threat:** other
- **Likelihood / Impact:** low / high

A compromised tool or worker reaches arbitrary internet destinations to exfiltrate engagement data (credentials, findings) or receive command-and-control instructions, beyond the approved targets.

**Vector.** A backdoored dependency/tool (T-020) or sandbox escape (T-011) opening outbound connections to attacker infrastructure.

**Mitigations.**
- Default-deny egress; all outbound traffic forced through a filtering proxy that only permits current in-scope targets and approved callback infra
- Per-run network namespace; no DNS or raw sockets outside the proxy
- Egress volume/destination monitoring with alerts on anomalies
- Secrets not present in the sandbox; nothing valuable to exfiltrate co-located with tool execution

**Residual risk.** Low; the egress allowlist itself is derived from validated scope, so exfiltration to non-target hosts is blocked.

### T-028 — Scope-engine ReDoS / parser crash causing fail-open

- **STRIDE:** Denial of Service
- **Named threat:** other
- **Likelihood / Impact:** low / high

A crafted host/URL triggers catastrophic backtracking or a crash in the scope/URL parser, and a poorly designed error path lets the request proceed without a scope verdict (fail-open) or halts the whole engagement.

**Vector.** Pathological input in a scope rule or target URL hitting a vulnerable regex or recursive parser.

**Mitigations.**
- No catastrophic-backtracking regexes in scope matching; linear-time matchers with input length caps
- Any parser error or timeout in the scope path yields deny, never allow (fail closed)
- Parser/URL fuzzing and property-based tests in QA (Phase 10)
- Resource/time limits around scope evaluation with a safe-deny fallback

**Residual risk.** Low; the failure is designed to deny, so the worst realistic outcome is over-blocking, not scope escape.

### T-030 — HTTPS CONNECT-tunnel scope blind spot (tool-originated traffic)

- **STRIDE:** Tampering, Information Disclosure
- **Named threat:** scope escape
- **Likelihood / Impact:** medium / high
- **Assets at risk:** Scope configuration / allowlist, In-scope target systems

If a naive HTTP `CONNECT` tunnel were used, the Guarded Egress Broker would see only host:port for the initial CONNECT — it could not see the request path, re-validate redirects, or inspect/size-cap/redact bodies. Per-hop redirect re-validation, path-prefix scoping, and body caps would be unenforceable for tool HTTPS traffic. **The design therefore forbids a generic CONNECT proxy** and requires the broker's authenticated, per-job, request-line-bound ingress (SI-053).

**Vector.** An in-scope host redirecting or path-traversing to an off-scope path/host inside an opaque TLS tunnel driven by a tool.

**Mitigations.**
- SI-053: the broker never exposes a generic `CONNECT host:port` proxy; each request carries a per-job identity and a single-use grant bound to the exact request line, and the broker serves only that line.
- SI-042: one visibility model chosen and documented per adapter — (a) broker TLS-termination using an internal CA installed ONLY inside the sandbox to inspect the tool's own egress, or (b) request-by-request adapter driving (ZAP API mode, Nuclei with proxy + redirects disabled) so each request/redirect crosses the broker in broker-visible form.
- Path/redirect/body invariants apply wherever the broker can see the request (both models above); tools that cannot be so constrained are gated out.
- Host:port + resolved-IP scope + IP pinning always enforced (rebinding-safe), even before body visibility.

**Residual risk.** Model (a) requires disciplined sandbox-only CA custody; model (b) constrains which tool features are usable. Documented explicitly rather than left implicit; a generic tunnel is disallowed outright.

### T-032 — Report / PDF renderer SSRF and exfiltration

- **STRIDE:** Information Disclosure, Elevation of Privilege
- **Named threat:** report-data exposure
- **Likelihood / Impact:** medium / high
- **Assets at risk:** Findings & evidence, Generated reports

Reports are HTML/PDF-ready and embed target-derived evidence. If rendering loads remote resources (<img src>, external CSS/fonts) it becomes an SSRF/exfiltration vector; if it executes reflected content it is stored XSS in the renderer.

**Vector.** A finding whose evidence contains an attacker-reflected external URL or script payload processed by a network-enabled renderer.

**Mitigations.**
- SI-048: report/evidence renderers run with zero network egress and remote-resource loading disabled, under a strict CSP on generated HTML
- Evidence is treated as untrusted data and encoded, never executed
- Test: evidence containing an external URL and a script payload produces no outbound request and no script execution during render

**Residual risk.** Renderer engine bugs; contained by running the renderer itself in a no-network sandbox.

### T-033 — Clock / NTP manipulation to extend authorization or testing window

- **STRIDE:** Tampering
- **Named threat:** other
- **Likelihood / Impact:** low / high
- **Assets at risk:** Authorization record, Audit trail / audit events

Authorization expiry and testing windows depend on system time. Clock skew (NTP manipulation, VM host drift) can make an expired engagement appear valid or shift windows, extending unauthorized testing beyond its legal boundary.

**Vector.** Manipulating or drifting the host clock backward/forward while an engagement is active.

**Mitigations.**
- SI-049: expiry/window evaluated against a monotonic clock plus an authenticated wall-clock with sanity bounds; large backward/forward jumps rejected
- Unverifiable time is fail-closed — testing halts
- Time source integrity monitored and audited

**Residual risk.** A fully compromised host time base is hard to fully defeat; monotonic-clock cross-checks and fail-closed halting bound the exposure.

### T-034 — Permanent secret leakage into the immutable audit trail

- **STRIDE:** Information Disclosure, Repudiation
- **Named threat:** secret leakage
- **Likelihood / Impact:** medium / high
- **Assets at risk:** Audit trail / audit events, Target credentials & session material, Personal data (PII)

Every request is recorded as a tamper-evident, un-editable audit event. If request auth headers, session cookies, or response bodies reach the audit store unredacted, the leak is permanent and cannot be scrubbed without breaking the chain.

**Vector.** Redaction applied after (or not before) the write to the immutable audit trail; denylist redaction missing a novel-format secret.

**Mitigations.**
- SI-045: redaction is allowlist/minimization-based and happens BEFORE any write to the audit trail; raw target auth material and bodies are never stored there
- All response bodies/URLs/headers treated as secret-bearing by default
- Tests with novel-format secrets and URL-embedded tokens assert they never appear in evidence, reports, or audit

**Residual risk.** A minimization miss is permanent; mitigated by storing only explicitly-safe structured fields in the audit trail and capping/omitting bodies.

### T-026 — Platform weaponized to DoS an in-scope target

- **STRIDE:** Denial of Service
- **Named threat:** other
- **Likelihood / Impact:** medium / medium

Even against an authorized target, aggressive concurrency/rate or a resource-exhaustion check degrades or takes down the target, violating the non-destructive guarantee.

**Vector.** Misconfigured high rate limits, a crawler trap causing runaway requests, or a heavy check pattern.

**Mitigations.**
- Conservative default concurrency/rate caps with hard safe ceilings the operator cannot exceed
- Circuit breakers tripping on rising target latency/error rates; automatic backoff
- Crawler-trap detection, request budgets, and body-size limits
- No DoS/resource-exhaustion checks in the engine; destructive categories excluded by classification

**Residual risk.** Low-medium; a fragile target can still be affected by legitimate load, reduced by breakers and conservative defaults.

### T-036 — Auto-replay of credentials embedded in imported HAR / Postman artifacts

- **STRIDE:** Spoofing, Information Disclosure
- **Named threat:** secret leakage
- **Likelihood / Impact:** medium / medium
- **Assets at risk:** Target credentials & session material, Third-party / out-of-scope systems

HAR files and Postman collections routinely embed Authorization headers, cookies, and API keys — often for third-party hosts. Auto-replaying an intake-embedded token, especially against a host it was not issued for, is credential misuse and a scope risk.

**Vector.** Importing a HAR/Postman artifact whose embedded credentials are then used as auth material by the crawler/checks.

**Mitigations.**
- SI-048: credentials embedded in intake artifacts are stripped and never auto-used as auth material
- Only explicitly operator-supplied sessions are used, and only against the in-scope hosts they were designated for
- Test: a token in an imported HAR is never replayed

**Residual risk.** Operator may still manually paste a credential; bounded by scope enforcement on the destination host.

### T-037 — Stale/mismatched grant or tampered queued request spec

- **STRIDE:** Tampering, Elevation of Privilege
- **Named threat:** scope escape
- **Likelihood / Impact:** low / high
- **Assets at risk:** Scope configuration / allowlist, In-scope target systems

If the queued object were a short-lived grant, it could expire in the queue (forcing long TTLs that widen the replay window) or be replayed; and if a queued request could be mutated after authorization, a benign-authorized request could be silently changed before it is sent.

**Vector.** Mutating a queued request's fields after authorization; enqueuing or replaying a grant.

**Mitigations.**
- SI-060: the queued object is an **immutable, fully-hashed `request_spec`**; grants are minted **just-in-time** at dispatch, bound to `spec_sha256`, with a TTL that only covers dispatch→send — no grant sits in the queue.
- SI-061: the broker **reconstructs** the request from the signed spec and rejects any spec/grant-hash mismatch; a worker cannot inject a deviation.
- `spec_sha256` is recomputed and verified both at JIT mint and at the broker; grants are single-use (`jti`).

**Residual risk.** Compromise of the Scope Authority signing key; bounded by key custody, single-use grants, and the immutable audit trail.

### T-038 — WebSocket connection escaping scope, budget, or time interlocks

- **STRIDE:** Tampering, Elevation of Privilege, Denial of Service (of the target)
- **Named threat:** queue abuse
- **Likelihood / Impact:** low / medium
- **Assets at risk:** In-scope target systems, Scope configuration / allowlist

A long-lived `ws`/`wss` connection could, if unhandled, run past the testing window / authorization expiry / emergency stop, attempt to change target mid-connection, or amplify load beyond the request budget.

**Vector.** Opening a WebSocket and holding it across interlock events, or trying to re-target an established socket.

**Mitigations.**
- SI-063: the handshake is scoped, resolved, and IP-**pinned** exactly like HTTP; scope is fixed at the pinned handshake (no per-message re-target); per-connection duration/message-count/message-size caps + a per-engagement connection cap bound each socket.
- SI-062: emergency stop, window close, and expiry **terminate active WebSocket connections**, not merely block new ones.
- Only inert/observation frames per the check contract are sent — never destructive or high-volume fuzzing.

**Residual risk.** Protocol-level abuse within the configured caps; bounded by the caps and the non-destructive frame contract.

## 7. Abuse cases

**AB-001 — actor: Malicious insider operator**

_Scenario._ Operator adds a domain they do not own (e.g., a competitor) to an engagement's scope and launches a safe-active scan against it.

_Prevention._ No activity is permitted without a mandatory authorization record (reference, owner, signatory, expiry, window). Separation of duties requires the Engagement Manager to record/approve authorization distinct from the executing Tester; scope and authorization creation are tamper-evidently audited with actor identity; default posture is passive. The platform cannot verify real-world consent but forces accountable, non-repudiable, least-intrusive operation and flags anomalous scope.

**AB-002 — actor: Malicious insider operator**

_Scenario._ Operator enters an overly broad CIDR or wildcard domain to sweep across adjacent third-party infrastructure under one engagement.

_Prevention._ Wildcard and large-CIDR scope entries are capped and require elevated approval, are prominently flagged, and are audited. Scope is normalized and each resolved IP re-validated; exclusions honored; per-target authorization expected. Broad sweeps cannot be launched silently.

**AB-003 — actor: Malicious insider operator**

_Scenario._ During an authorized crawl the platform discovers an out-of-scope host; the operator tries to manually target it.

_Prevention._ Explicit requirement that unrelated infrastructure discovered during testing is never scanned. The crawler records discovered hosts but never auto-adds them to scope, and the scope-validation choke-point denies any request to a host not in the approved allowlist, regardless of how it was discovered.

**AB-004 — actor: Malicious insider operator**

_Scenario._ A careless operator leaves a scan running past the authorization expiry or outside the agreed testing window.

_Prevention._ Authorization expiry and testing window are re-checked on every request dispatch; auto-expiration halts scheduling and drains running jobs; the scheduler refuses to dispatch out-of-window work. All stop/expiry events are audited.

**AB-005 — actor: Tester**

_Scenario._ Operator attempts to run intrusive or destructive validation without independent sign-off.

_Prevention._ Intrusive validation is only available through the approval-gated workflow requiring a distinct approver, an explicit validation plan (exact requests, expected impact, rollback, evidence, stop conditions), and a valid unexpired approval token. Destructive exploitation and command execution are not implemented in the engine at all.

**AB-006 — actor: Malicious insider operator**

_Scenario._ Operator supplies a custom Nuclei/ZAP template or CLI option to weaponize the scanner into an exploit tool.

_Prevention._ Only a curated, version-pinned, non-destructive template/policy allowlist is runnable; user-supplied templates and CLI arguments are not accepted and no user input reaches a shell. Unsafe templates/options are disabled by default and cannot be selected.

**AB-007 — actor: Malicious insider operator**

_Scenario._ Operator raises rate/concurrency to overwhelm an in-scope target, using the platform as a DoS tool.

_Prevention._ Hard per-engagement concurrency and request-rate ceilings the operator cannot exceed, conservative defaults, request budgets with pre-run volume estimates, circuit breakers that trip on target distress, and exclusion of all DoS/resource-exhaustion checks by safety classification.

**AB-008 — actor: Malicious insider operator**

_Scenario._ Operator tries to bulk-extract data from a target and store it as 'evidence' (e.g., dumping a database or downloading user records).

_Prevention._ Evidence is minimized and size/retention-capped; checks are forbidden from dumping databases, retrieving secret files/tokens/keys, or bulk-extracting user data as proof. Non-destructive detection captures only the minimal evidence needed and redacts sensitive content.

**AB-009 — actor: Malicious insider operator**

_Scenario._ Operator points a supplied target auth session at other hosts to harvest or replay credentials.

_Prevention._ Operator-supplied sessions are bound to specific in-scope hosts; the scope check on every request (including redirects) prevents attaching them to any other host. No credential-harvesting, brute-force, spraying, or account-takeover checks exist to consume or replay them.

**AB-010 — actor: Malicious insider operator**

_Scenario._ Operator defines a 'target' that resolves to cloud metadata or an internal service to reach infrastructure via the scanner.

_Prevention._ Loopback, RFC1918, link-local, ULA, and metadata IPs are default-denied even if textually allowlisted; overriding requires flagged, audited elevated approval. Egress is forced through a filtering proxy enforcing the same deny-list, and DNS results are re-validated and IP-pinned to defeat rebinding.

**AB-011 — actor: Malicious insider operator**

_Scenario._ Operator imports a HAR/proxy history containing third-party domains and expects the platform to scan them all.

_Prevention._ Intake is explicitly not authorization: every imported endpoint is scope-validated before any request is made, out-of-scope entries are flagged and blocked, and nothing from intake is auto-added to scope.

**AB-012 — actor: Malicious insider operator**

_Scenario._ Operator attempts to disable scope enforcement, rate limits, or redaction via the API to broaden or intensify testing.

_Prevention._ Safety invariants are enforced server-side, not as client toggles; there is no API to bypass the scope choke-point, exceed hard ceilings, or turn off redaction. Certain controls are immutable during an active engagement, and all configuration changes are audited. Release fails automatically if any safety invariant test fails.

## 8. Failure modes

| Component | Failure | Detection | Response | Fails safe |
|---|---|---|---|---|
| Scope Authority | Service unavailable, throws, or times out while evaluating a candidate request. | Health checks; per-request error/timeout on the scope call; missing verdict. | Deny the request, halt the job, alert the operator; never dispatch without an explicit allow verdict (fail-closed, SI-046). | yes |
| DNS resolver / rebinding guard | Resolution fails, returns records outside scope, or the connected peer IP differs from the validated IP. | Compare resolved A/AAAA records to scope + deny-list; verify connected socket peer equals the pinned validated IP. | Refuse the request and pin only validated IPs; on mismatch abort the connection. | yes |
| Authorization / expiry / testing-window checker | Checker down, clock skew, or cached authorization goes stale. | Heartbeat on checker; trusted time source with skew detection; per-request re-check. | Treat as expired/out-of-window and stop testing; drain running jobs. | yes |
| Egress filtering proxy | Proxy down or misconfigured, or a component attempts a direct socket. | Connection errors; egress-policy audit; alerts on direct-socket attempts. | Block all outbound traffic; no direct-connection fallback is permitted. | yes |
| Redirect handler | Cannot parse or scope-evaluate a redirect target. | Location/refresh parse errors; scope-check failure on the target. | Do not follow the redirect; stop and record. | yes |
| Tool sandbox container | Container crash, resource-limit breach, seccomp violation, or escape attempt. | Runtime monitor, seccomp/AppArmor denials, resource metrics, unexpected syscalls/egress. | Kill and tear down the container, quarantine its output, mark the job failed; alert. | yes |
| Scanner output parser | Malformed, oversized, or malicious tool output; parse error or timeout. | Schema validation, size/time caps, hardened-parser exceptions. | Discard the output, quarantine raw separately, create no findings, mark job unverified. | yes |
| Job queue / broker | Unsigned/forged/replayed message, or broker unreachable/backlogged. | HMAC/signature + nonce/TTL verification on dequeue; queue-depth monitoring. | Reject invalid messages; pause dispatch and apply backpressure when unverifiable. | yes |
| Rate limiter / circuit breaker | Limiter state lost or breaker stuck. | Counter monitoring; per-target error-rate/latency watch; state-store health. | Default to the most conservative limit and open the breaker (stop sending). | yes |
| Redaction engine | Redaction rule misses a secret/PII or the engine errors during export. | Post-generation secret/PII/canary scan of the export; engine exceptions. | Block report/export generation and delivery; flag for manual review; drop unknown sensitive fields. | yes |
| Audit log writer | Audit store unavailable, write fails, or hash-chain continuity breaks. | Write-ack failures; periodic hash-chain continuity verification. | Refuse to perform any auditable action that cannot be logged; alert on chain breaks. | yes |
| Emergency stop / kill switch | Stop signal does not reach a busy worker. | Worker heartbeats and short job leases; watchdog on ack. | Workers self-terminate on missed heartbeat or lease expiry; no new work leased. | yes |
| Secret store | Secret manager unreachable or returns error. | Fetch errors; TTL expiry on cached scoped credentials. | Deny any operation needing the secret; do not use expired cached plaintext. | yes |
| AuthN / RBAC service | Auth provider down or token validation fails. | Token-validation errors; provider health checks. | Deny access to the requested action. | yes |
| Callback / OOB correlation service | Service down, or a callback arrives without/with a mismatched token. | Token match against expected per-check value and active window; source anomaly checks. | Ignore the callback; do not assert any finding or take action. | yes |
| Supply-chain verifier | Checksum/signature mismatch on a dependency, tool image, or template at fetch or load. | Hash/signature verification at fetch and at load time. | Refuse to load/run the artifact; block the build/deploy; alert. | yes |
| Worker service | Worker crashes mid-scan leaving a job in an ambiguous state. | Lease/heartbeat timeout; orphaned-job sweep. | Re-queue only after full re-validation of scope, authorization, and window; clean partial state before any resume. | yes |
