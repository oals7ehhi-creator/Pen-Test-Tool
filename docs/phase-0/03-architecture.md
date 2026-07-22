> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

# Phase 0 — Architecture & Technology Stack
## Authorized Defensive Web Application Security Assessment Platform

This document proposes the system architecture and stack. It is design/analysis only. Every decision is subordinate to the **authorization-first, non-destructive, technically-enforced safety model**: the architecture must make out-of-scope or destructive action *structurally impossible*, not merely discouraged.

The single most important architectural idea in this document: **there is exactly one path to the network, and that path is a scope-enforcing choke point that no component can bypass.** Everything else follows from that.

---

## 1. High-Level Component Architecture

Two planes, separated by trust and by network policy:

- **Control plane** — human-facing, holds authority (who, what scope, what approvals). Never touches target systems directly.
- **Data plane** — executes checks against targets, network-isolated, has *no* authority of its own and *no* unmediated route to the internet.

```
                        ┌────────────────────────────────────────────────────────┐
                        │                     OPERATORS                            │
                        │      Admin · Eng.Manager · Tester · Reviewer · Auditor   │
                        └───────────────────────────┬────────────────────────────┘
                                                    │ HTTPS (mTLS at edge, OIDC)
              ══════════════════════════════════════▼══════════════════════════════ CONTROL PLANE
              │                                                                     │
              │   ┌───────────────┐        ┌───────────────────────────────────┐   │
              │   │  Web UI (SPA) │◄──────►│  Backend API / BFF                 │   │
              │   │  React/TS     │  REST  │  authN, RBAC, engagement CRUD,     │   │
              │   └───────────────┘  +WS   │  approval gates, job intake,       │   │
              │                             │  finding review, reporting        │   │
              │                             └──┬────────────┬──────────┬────────┘   │
              │                                │            │          │            │
              │         ┌──────────────────────▼──┐   ┌─────▼─────┐  ┌─▼──────────┐ │
              │         │  Scope-Validation Svc     │  │ Job Queue │  │  Audit Log │ │
              │         │  (authority for "is this  │  │ (durable, │  │  Store     │ │
              │         │  in scope, now, approved")│  │  txn'l)   │  │ (hash-     │ │
              │         └──────────┬────────────────┘  └─────┬─────┘  │  chained)  │ │
              │                    │  signed scope decisions │        └────────────┘ │
              │         ┌──────────▼─────────────────────────▼──────┐               │
              │         │  PostgreSQL  (tenants, engagements, scope, │               │
              │         │   authz records, findings; RLS-isolated)  │               │
              │         └───────────────────────────────────────────┘               │
              │              │                                                       │
              │   ┌──────────▼─────────┐   ┌──────────────────┐   ┌──────────────┐  │
              │   │  Secrets Manager   │   │  Object Storage  │   │ Report Store │  │
              │   │  (Vault/KMS)       │   │  (evidence, WORM)│   │ (rendered)   │  │
              │   └────────────────────┘   └──────────────────┘   └──────────────┘  │
              ═══════════════════════════════════╪═════════════════════════════════
                                                 │  jobs pulled (no inbound to workers)
              ═══════════════════════════════════▼═════════════════════════════════ DATA PLANE
              │   default-deny egress netns · no NAT to internet · only route = broker │
              │                                                                        │
              │   ┌─────────────────────────────────────────────────────────────┐    │
              │   │                  WORKER POOL (stateless executors)           │    │
              │   │   pull job → NEVER opens a socket to a target directly       │    │
              │   └───────────┬─────────────────────────────┬───────────────────┘    │
              │               │ structured check request     │ structured tool spec   │
              │   ┌───────────▼──────────────┐   ┌───────────▼───────────────────┐    │
              │   │  Scanner Sandbox / Tool   │   │  (native safe checks also go  │    │
              │   │  Adapters (gVisor/microVM)│   │   through the broker)         │    │
              │   │  Nuclei · ZAP · testssl   │   └───────────┬───────────────────┘    │
              │   │  SCA · secret-scan        │               │                        │
              │   └───────────┬──────────────┘                │                        │
              │               └────────────────┬──────────────┘                        │
              │                                 ▼                                       │
              │            ╔══════════════════════════════════════════╗                │
              │            ║   GUARDED EGRESS BROKER  (THE choke point) ║                │
              │            ║   • re-validates scope on EVERY request    ║                │
              │            ║   • own DNS resolve + IP pinning (anti-    ║                │
              │            ║     rebinding) • redirect scope checks     ║                │
              │            ║   • per-engagement rate/concurrency limits ║                │
              │            ║   • circuit breakers + emergency stop      ║                │
              │            ║   • records every request as audit event  ║                │
              │            ╚═════════════════════╪══════════════════════╝                │
              ══════════════════════════════════╪═══════════════════════════════════════
                                                 │  ONLY sanctioned internet path
                                                 ▼
                                    ┌──────────────────────────┐
                                    │  IN-SCOPE TARGET SYSTEMS │
                                    └──────────────────────────┘
```

**Component responsibilities (concise):**

| Component | Responsibility | Explicitly *not* allowed |
|---|---|---|
| Web UI (SPA) | Guided workflow, triage, approvals, dashboards | Never constructs raw requests or commands |
| Backend API / BFF | AuthN, RBAC, engagement/scope/authz CRUD, job intake, approval-gate state machine, report orchestration | Never contacts targets; never spawns processes |
| Scope Authority | *Sole decision authority* on "is (method,url,ip,port,path,time,approval) permitted for engagement E." Mints short-lived, signed **Stage-1 egress grants** bound to the immutable request spec by `spec_sha256` — no resolved IP (see `10-request-authorization-flow.md`) | Does not perform target I/O; does not resolve target DNS |
| Job Queue | Durable, transactional, per-engagement fair scheduling, budgets | Cannot enqueue a job lacking a valid scope token |
| Worker Pool | Pull jobs, orchestrate checks/adapters, capture evidence | No direct socket to targets; no shell |
| Scanner Sandbox / Adapters | Run pinned third-party tools in isolation, parse structured output | No arbitrary flags; no network except via broker |
| Guarded Egress Broker | The only egress path and only target-socket creator; authenticates per-job ingress, verifies the grant, resolves DNS, validates+pins every resolved IP at broker time, enforces redirects/rate/breakers, emits split audit | Cannot be bypassed by network policy; is **not** a generic CONNECT proxy |
| PostgreSQL | System of record; tenant isolation via RLS | — |
| Object Storage (evidence) | Redacted evidence blobs, WORM/object-lock | — |
| Secrets Manager | Target auth sessions, tool creds, signing keys | Secrets never land in DB rows or logs |
| Audit Log Store | Append-only, hash-chained, tamper-evident event log | No update/delete API |

---

## 2. Recommended Technology Stack

Bias: typed, memory-safe, well-audited, boring-where-it-counts. The security-critical hot path (egress broker, scope guard) gets the strongest language guarantees; the control plane optimizes for developer velocity and typed correctness.

### 2.1 Languages

| Concern | Primary recommendation | Why | Safe alternative & trade-off |
|---|---|---|---|
| **Guarded Egress Broker + Scope guard core** | **Rust** (tokio + hyper/reqwest with custom connector) | This is the safety kernel. Memory-safe with no GC pauses, precise control over socket creation, DNS resolution, TLS, and connection reuse — exactly what IP-pinning and redirect interception need. Small, auditable, fuzz-friendly surface. | **Go**: simpler, faster to staff, excellent net stack and `net/http` hooks. Trade-off: GC, and slightly weaker guarantees around low-level connection control; still an excellent choice and acceptable. |
| **Backend API / BFF** | **TypeScript on Node with NestJS** | Strong typing end-to-end shared with the SPA, mature RBAC/guard/interceptor primitives that map cleanly to the approval-gate state machine, huge audited ecosystem, first-class OpenAPI generation. | **Python + FastAPI + Pydantic**: superb typed validation, great for the analysis/parsing domain, and lets API + workers share models. Trade-off: two language runtimes if workers are Go/Rust. |
| **Worker runtime / tool adapters** | **Go** | Great concurrency for orchestrating containers and I/O, static binaries, easy sandbox packaging, strong stdlib, `os/exec` with argv arrays (no shell). | **Rust** (max safety, steeper velocity) or **Python** (fast adapter glue, but keep it strictly no-shell). |
| **Passive analysis engine** | **Python** modules (or TS) | Best library coverage for TLS/cert parsing, HAR/OpenAPI/Postman parsing, header/CSP analysis. | TypeScript equivalents exist; keep parser inputs treated as untrusted regardless. |

Opinion: a three-language footprint (**Rust broker / TS control plane / Go workers**) is justified precisely because the components have different risk profiles. If the team wants to minimize languages, collapse to **Go everywhere except the SPA** — Go for broker, workers, and API — accepting slightly weaker memory guarantees on the broker in exchange for one runtime.

### 2.2 Data, queue, storage

| Concern | Primary | Why | Alternative / trade-off |
|---|---|---|---|
| **Database** | **PostgreSQL 16+** | ACID, Row-Level Security for tenancy, rich constraints (CHECK/exclusion) to encode scope invariants at the storage layer, `SKIP LOCKED` for queueing. | CockroachDB if multi-region HA is a hard requirement (Phase 11); more ops overhead. |
| **Job queue** | **Postgres-backed durable queue** (River for Go / graphile-worker or pg-boss for TS) | Transactional enqueue: a job and its scope precondition commit together, so an out-of-scope job *cannot* be enqueued. Full audit lives in the same DB. | **NATS JetStream** or **Redis Streams** for higher throughput. Trade-off: enqueue no longer shares a transaction with scope state — mitigated by requiring a signed scope token at dequeue (see §4). Prefer Postgres queue for this platform; request volumes are deliberately low. |
| **Migrations** | Stack-native, versioned, forward-only in prod: **Drizzle/Prisma** (TS), **Alembic** (Py), **sqlx/refinery** (Rust) | Typed schema, reviewable diffs, CI-gated. | — |
| **Object storage (evidence)** | **S3-compatible with Object Lock / WORM** — MinIO (single-server), AWS S3/equivalent (prod) | Immutable, retention-locked, versioned evidence; separates large untrusted blobs from the relational core; SSE encryption. | Filesystem + application-enforced immutability for the smallest deployments; weaker tamper-evidence. |
| **Secrets manager** | **HashiCorp Vault** (dynamic secrets, transit engine for signing, short TTL leases) | Central custody of target auth sessions, tool creds, and the broker/audit signing keys; audited access; rotation. | Cloud KMS + Secrets Manager (managed, less portable) for cloud-only deployments. |
| **Audit log store** | **Append-only Postgres table, hash-chained**, keys in Vault transit, periodically anchored to WORM object storage | Tamper-evident without a new datastore; cryptographic chain detects mutation/gaps. | Dedicated immutable ledger (e.g., QLDB-style) if regulatory needs demand; added complexity. |

### 2.3 Frontend, containers, isolation, egress control

| Concern | Primary | Why | Alternative / trade-off |
|---|---|---|---|
| **Frontend** | **React + TypeScript + Vite**, TanStack Query, a headless component lib (Radix) + design system | Typed API client generated from the API's OpenAPI; strong forms for scope/approval; WebSocket for live progress. | SvelteKit/Vue if team prefers; equivalent. |
| **Containerization** | **OCI/Docker images**, orchestrated by **Kubernetes** (prod) / **Docker Compose** (dev/single-server) | Declarative network policy, resource limits, and pod-level isolation are exactly the primitives the safety model needs. | HashiCorp Nomad if K8s is too heavy for target deployments. |
| **Scanner/tool sandbox** | **gVisor (runsc)** runtime, or **Firecracker microVMs** for the highest-risk adapters | Kernel-level syscall interception (gVisor) or true VM boundary (Firecracker) contains untrusted tool binaries far better than vanilla containers. Combined with read-only rootfs, seccomp, dropped caps, `no-new-privileges`, non-root UID. | Plain containers + seccomp + AppArmor as a floor; weaker isolation, acceptable only for the most trusted, pinned tools. |
| **Egress control** | **Network namespaces with default-deny egress**; enforce with **Cilium/K8s NetworkPolicy** (prod) or **nftables** (single-server). Worker & sandbox namespaces have **no NAT/route to the internet** — the *only* reachable next hop is the egress broker's address. | Makes bypass a network-layer impossibility, not an application check. Even a fully compromised scanner can only talk to the broker. | Sidecar egress proxy per pod (Envoy) enforcing the same; more moving parts. The broker approach is simpler to audit. |

---

## 3. Where Each Safety Control Lives

The safety model maps to specific, single-owner components. No control is duplicated in a way that lets one copy drift permissive.

### 3.1 The single egress choke point — Guarded Egress Broker
**All outbound requests from the data plane traverse the broker. There is no second path.** Enforced at two layers:
1. **Network layer (primary, non-bypassable):** worker and sandbox network namespaces are default-deny egress with no route to `0.0.0.0/0`; the sole allowed destination is the broker service. A compromised worker/tool physically cannot reach a target except through the broker.
2. **Application layer (defense in depth):** the broker authenticates the calling job's per-job identity and independently verifies the Scope Authority's signed grant before opening any socket. The broker exposes an **authenticated, per-job ingress** — never a generic `CONNECT host:port` proxy — and serves only the request it reconstructs from the immutable spec whose digest equals the grant's `spec_sha256` (`10-request-authorization-flow.md` §4).

The broker owns, per request:
- **Grant verification** (signature, `aud`=self, `nbf`/`exp`, single-use `jti`) — never trusts the caller's assertion; the resolved IP is validated here at broker time, not pre-bound in the grant.
- **DNS resolution with IP pinning:** the broker resolves the hostname itself, checks *every* resulting A/AAAA record against scope, then **connects to the exact pinned IP it validated** and sets the TLS SNI/Host to the original name. This closes DNS rebinding: the resolved-and-validated IP is the one dialed; a later re-resolution to a private IP cannot occur.
- **RFC1918 / loopback / link-local / cloud-metadata (169.254.169.254, fd00:ec2::254, etc.) / ULA / documentation-range rejection**, for both IPv4 and IPv6, applied to the *resolved IP*, not just the hostname.
- **Redirect handling:** the broker does not blindly follow redirects; each hop's target is re-validated for scope, and out-of-scope redirects stop the chain and are recorded.
- **Per-engagement rate limit, concurrency cap, and request budget** (token buckets keyed by engagement).
- **Circuit breakers** (error-rate, latency, target-5xx spikes) and the **emergency-stop** signal (a kill switch that flips the engagement to `halted`, draining in-flight and refusing new egress).
- **Testing-window & authorization-expiry enforcement:** the broker refuses egress outside the window or after expiry, even if a job slipped through scheduling.
- **Audit emission:** every attempted request (allowed or denied, with reason) becomes an audit event.

### 3.2 The scope authority — Scope Authority
Authority for *"is this permitted?"* lives in exactly one service. It evaluates (Stage 1): allowlisted domains/IPs/CIDRs/ports/URL-prefixes/APIs, explicit exclusions (exclusions win), canonicalized URL, IP-literal network guard, active testing window, non-expired authorization, mode, budget, and — for intrusive/elevated actions — an existing dual-approved approval. It mints a **short-lived, single-use, signed Stage-1 egress grant** bound to the immutable request spec by `spec_sha256` (which fixes method + canonical URL/path + header-set + payload digests), consumed at the broker. It performs **no target DNS resolution and no target I/O** — resolved-IP validation and pinning happen at the broker (Stage 2). Because the broker re-checks live state and validates every resolved IP, and the network layer is default-deny, a stale or forged grant cannot produce out-of-scope traffic. Full two-stage design: `10-request-authorization-flow.md`.

### 3.3 Per-worker / per-sandbox network policy
Two distinct data-plane postures, both default-deny with no internet route (`10-request-authorization-flow.md` §4):
- **Tool / headless-browser sandbox — broker only.** The *only* reachable next hop is the Guarded Egress Broker: no route to targets, the internet, or internal services. Client-side DNS disabled (proxy-side resolve+pin), WebRTC/QUIC/direct sockets disabled (SI-041, SI-054).
- **Worker — narrow internal allowlist + broker.** Reaches only the internal services it needs (queue, DB, object storage, Scope Authority, secret manager) **plus** the broker; **no direct route to any target or the internet**. A worker reaches a target only by presenting a grant to the broker (SI-033, SI-054).

Both add: read-only rootfs; dropped capabilities; seccomp/AppArmor; non-root; CPU/mem/PID/time quotas; no host mounts. This localizes blast radius per job.

### 3.4 Approval gates
The **approval-gate state machine lives in the Backend API** and is persisted in Postgres. Intrusive/validation checks cannot transition to `schedulable` without a recorded operator approval (who, when, `manifest_sha256`). The signed scope decision for an intrusive check embeds the approval reference; the broker refuses intrusive-class egress whose decision lacks a valid approval. Human approval is thus enforced at both the scheduling boundary and the egress boundary.

### 3.5 Redaction
Redaction is a **mandatory pipeline stage owned by the worker before any evidence leaves the data plane** and re-asserted by the API before storage/reporting. Secrets/tokens/cookies/authz headers/PII/sensitive bodies are stripped/tokenized at capture time; the raw-vs-redacted separation is enforced so unredacted data never reaches the audit log, findings, or reports.

---

## 4. Data Flow — One Check Request, End to End

```
Operator selects check  ──►  API validates RBAC + engagement state
        │
        ▼
Check engine builds an IMMUTABLE, fully-hashed request_spec (spec_sha256 over the exact request)
   and ENQUEUES only (spec_id, tenant_id)  — the queue holds the spec, never a grant
        │
        ▼  dispatcher pulls a queued spec (SKIP LOCKED) when ready to execute
STAGE 1 — Scope Authority (JUST-IN-TIME): load spec; recompute+verify spec_sha256
        │                        │
        │      DENY ◄────────────┘  (reason recorded; spec stays queued or is dropped)
        ▼ ALLOW  → re-check scope/auth/window/e-stop over CURRENT state; mint SIGNED, ≤30s, single-use
        │          GRANT bound to spec_sha256 (NO IP). Reservation is created by the broker (below), not here.
        ▼
Worker presents (per-job identity + grant + spec) to the broker's authenticated ingress
   (the worker does NOT serialize the HTTP request itself)
        │
        ▼  (only path out of the netns; NOT a generic CONNECT proxy)
STAGE 2 — Guarded Egress Broker:
   auth per-job ingress ─► verify grant (sig/aud/exp/jti single-use) AND grant.spec_sha256==sha256(spec)
   ─► RECONSTRUCT+normalize the request FROM THE SPEC (assert == spec) ─► re-check live state
   (auth/window/e-stop/rate, fail-closed) ─► ATOMIC (budget FOR UPDATE; fenced lease TRANSITIONED to
   'charged' [used += 1, IRREVERSIBLE]; commit request.intent spec_sha256/jti/reservation-id) BEFORE ANY
   EGRESS — budget charged before the first byte ─► resolve DNS (first egress)
   ─► check ALL resolved IPs (Tier A/B) ─► PIN validated IP
   ─► connect to PINNED IP (TCP+TLS, SNI=orig host) ─► send ─► redirect? new spec + FRESH grant, stop if off-scope
   ─► request.completed/failed (resolved+pinned IP, redacted) — INFORMATIONAL only; does NOT change the charge
        │
        ▼
Target responds (in-scope only) ──► response returns to worker/sandbox
        │
        ▼
Evidence capture (size-capped, body-retention-limited)
        │
        ▼
REDACTION stage (mandatory): strip cookies/authz/tokens/PII/sensitive bodies → redacted evidence
        │
        ▼
Redacted evidence → Object Storage (WORM, encrypted); pointer + hash → DB
        │
        ▼
Check logic computes result → Finding (id, CWE/OWASP refs, confidence, non-destructive repro,
        evidence pointer, provenance)  → written to DB (tenant-scoped via RLS)
        │
        ▼
API surfaces finding to Reviewer → triage/lifecycle; audit event closes the loop
```

Key invariant: **at every stage the request is data, validated independently, and the only way onto the wire re-checks scope.** A bug in one layer cannot alone cause an out-of-scope or destructive request.

---

## 5. Multi-Tenancy Model & Isolation

**Model: shared control-plane infrastructure, per-tenant logical isolation, per-engagement execution isolation.** Tenancy hierarchy: **Tenant (org) → Engagement → Authorization/Scope → Jobs/Findings/Evidence.**

- **Database isolation — PostgreSQL Row-Level Security.** Every tenant-owned table carries `tenant_id`; RLS policies bind reads/writes to the authenticated tenant context set per request (`SET LOCAL app.tenant_id`). This is defense that survives ORM/application bugs. Cross-tenant access requires no application check to be *added*; it requires an RLS policy to be *removed*, which is CI-guarded.
- **Object storage isolation.** Evidence objects keyed by `tenant_id/engagement_id/...`; bucket policies + per-tenant prefixes; **encrypted under a per-engagement Data Encryption Key** (envelope encryption via the secret manager) so a mis-scoped fetch returns undecryptable ciphertext (SI-050). The same per-engagement DEK is the unit of **cryptographic erasure** for secure deletion (`11-data-retention-and-deletion.md`, SI-058).
- **Secrets isolation.** Vault namespaces/policies per tenant; target auth sessions are never shared across engagements.
- **Queue & worker isolation.** Jobs carry tenant + engagement identity; per-engagement rate/concurrency budgets prevent one tenant's engagement from starving another (queue-abuse threat). Workers are stateless and scrubbed between jobs; a worker never holds two tenants' target sessions simultaneously.
- **Egress isolation.** Broker token buckets and scope decisions are per-engagement; audit events are tenant-tagged. Circuit breakers and emergency-stop are scoped to an engagement so one halt does not disrupt others.
- **Audit isolation.** Hash-chained audit stream is partitioned/tagged per tenant; auditors get read-only, tenant-scoped access.

For customers requiring hard isolation, the architecture supports a **dedicated-worker-pool / dedicated-broker per tenant** deployment variant without code change (Phase 11), since the data plane is already namespace-isolated.

---

## 6. Deployment Topology (high level; details → Phase 11)

- **Dev:** Docker Compose. Postgres, MinIO, Vault-dev, API, worker, broker, SPA. Egress default-deny enforced via nftables in the compose network so developers exercise the real safety path. **Intentionally vulnerable target apps run only on a separate, explicitly-allowlisted local network** — never reachable except by adding them to scope.
- **Single-server:** One host, containers, nftables egress policy forcing worker/sandbox traffic through the broker; MinIO for evidence; local Vault; TLS terminated at a reverse proxy. Not publicly accessible by default. Suitable for a solo tester or small team.
- **Production:** Kubernetes with **network segmentation into control-plane and data-plane namespaces**; NetworkPolicy (Cilium) default-deny egress on data-plane pods with the broker as the only permitted destination; gVisor/Firecracker runtime class for scanner sandboxes; managed Postgres with encryption + PITR; S3 with Object Lock; Vault HA; centralized logging/monitoring/alerting; the platform itself sits behind mTLS and is not internet-exposed. Horizontal scaling of stateless workers behind per-engagement budgets.

Common to all tiers: **the egress choke point and default-deny data-plane network are non-negotiable and present even in dev**, so the safety model is exercised continuously rather than only in prod.

---

## 7. Guaranteeing No Arbitrary Shell & No User CLI Args Reach a Shell

This is a structural guarantee, achieved by never having a shell in the execution path and never letting user input become a command line.

1. **The API/UI accepts structured job specs only.** A job references a **registered check ID or a pinned tool-template ID** plus **typed, schema-validated parameters**. There is no field anywhere in the UI or API that accepts a command, a command fragment, a flag string, or a script. Requests that don't validate against the check/tool schema are rejected before enqueue.
2. **Adapters spawn processes with `execve`-style argv arrays, never a shell.** Go `exec.Command(binary, args...)` / Rust `Command` with an argv vector — **no `sh -c`, no shell interpolation, no string concatenation into a command line.** There is no shell interpreter in the sandbox image at all.
3. **Binary paths are fixed and pinned.** Each adapter hard-codes the absolute path of its tool binary and the pinned version/digest. Users cannot select the binary.
4. **Flags come from an allowlist mapped from typed parameters, not from user strings.** The adapter owns a fixed table: typed parameter → specific, safe flag. Unsafe/destructive tool options are never in the table and thus never reachable. Values that must be passed (e.g., a target URL) go through **strict typed validation and are delivered as discrete argv elements or via files/stdin**, never spliced into a shell string. Template selection is from the **curated, pinned allowlist registry**, not free text.
5. **Tool output is parsed as structured data, treated as untrusted.** Adapters read JSON/structured output, never scrape console text, and never `eval` results. Raw output is retained separately from verified findings.
6. **The sandbox has no route to a shell or the host.** No shell binary, read-only rootfs, dropped caps, seccomp allowlist, non-root, no host mounts, network egress only to the broker. Even if a tool tried to spawn a shell, there is nothing to spawn and nowhere to go.
7. **CI enforcement.** Static checks fail the build on any `sh -c`, string-built command line, or reachable-from-request path to `exec`. Adapter parameter tables are reviewed as security-critical code.

Result: there is **no path from UI/API input to a shell**, and **no user-controlled string ever becomes part of a command line.**

---

## 8. ADR-Candidates (key decisions & rationale)

- **ADR-1: Single Guarded Egress Broker as the sole data-plane egress path.** Rationale: converts "don't go out of scope" from a check that can be forgotten into a network-topology invariant. Trade-off: broker is a critical dependency and a throughput bottleneck — acceptable given deliberately low request volumes; scale horizontally with per-engagement affinity.
- **ADR-2: Network-layer default-deny egress on workers/sandboxes, broker as only next hop.** Rationale: even a fully compromised scanner cannot reach targets except through scope enforcement. Trade-off: more network plumbing per environment; justified by the threat model (scope escape, SSRF, malicious scanner output).
- **ADR-3: DNS resolve-and-pin inside the broker.** Rationale: eliminates DNS rebinding by dialing the exact validated IP. Trade-off: broker must own DNS and TLS SNI handling rather than delegating to a stock HTTP client — a reason to write it in Rust/Go with low-level connection control.
- **ADR-4: Scope authority centralized in one service issuing signed, short-TTL decisions, re-verified at the broker.** Rationale: one place to reason about "permitted," defense-in-depth via re-check. Trade-off: extra hop; mitigated by caching decisions for a job's lifetime only.
- **ADR-5: PostgreSQL-backed transactional job queue.** Rationale: a job and its scope precondition/budget commit atomically — an out-of-scope job cannot exist in the queue. Trade-off: lower throughput than a dedicated broker; a non-issue at this platform's intentionally conservative volumes.
- **ADR-6: Row-Level Security for tenant isolation.** Rationale: isolation enforced at the datastore, surviving application bugs; cross-tenant leakage requires actively removing a policy (CI-guarded). Trade-off: RLS discipline in every query path; enforced by tests (Phase 10 tenant-isolation tests).
- **ADR-7: gVisor/Firecracker sandbox for third-party tools; no shell in images.** Rationale: untrusted tool binaries and untrusted tool output are named threats; kernel/VM isolation contains them. Trade-off: performance overhead and runtime-class complexity — worth it for the highest-risk components.
- **ADR-8: Structured job specs + pinned template registry; adapters use argv arrays with allowlisted flags.** Rationale: eliminates command injection and arbitrary-CLI classes by construction. Trade-off: adding a new tool option requires a code change and review — intentionally, since that is a security boundary.
- **ADR-9: Hash-chained append-only audit log with WORM anchoring; mandatory redaction before evidence egress.** Rationale: tamper-evident audit trail and no secret/PII leakage into logs, findings, or reports (secret-leakage and report-data-exposure threats). Trade-off: redaction must be conservative and may occasionally over-redact — the correct failure direction.
- **ADR-10: Rust for the safety kernel, TypeScript for the control plane, Go for workers.** Rationale: strongest memory-safety guarantees where a bug is most dangerous; developer velocity and shared types where iteration matters. Trade-off: three runtimes to operate; collapse to Go-everywhere-plus-SPA if the team needs fewer languages, accepting marginally weaker broker guarantees.
- **ADR-11: Pinned tool/template versions verified by digest; egress-restricted, resource-capped sandboxes.** Rationale: supply-chain-compromise threat — a swapped tool image or malicious template cannot run un-pinned or reach the network freely. Trade-off: version bumps become deliberate, reviewed events.
- **ADR-12: Two-stage request authorization with broker-time IP binding.** The Scope Authority mints a Stage-1 grant bound to the immutable request spec by `spec_sha256` (which fixes method + canonical URL/path + header-set + payload digests) but no resolved IP; the Guarded Egress Broker resolves DNS, validates every resolved IP, and pins it at Stage 2. Rationale: the resolved IP is unknown until DNS is resolved, and only the broker resolves target DNS — pre-binding an IP at scheduling was impossible and internally contradictory. Trade-off: a second in-band grant per redirect hop; acceptable at this platform's low volumes. Design: `10-request-authorization-flow.md`.
- **ADR-13: Authenticated per-job broker ingress, never a generic CONNECT proxy.** Each broker request carries a per-job identity/capability matching a single-use, audience-bound grant; the broker serves only the request it reconstructs from the immutable spec whose digest equals the grant's `spec_sha256`. Rationale: a generic `CONNECT` proxy would void the network-topology guarantee. Trade-off: per-job identity issuance and a `jti` consumption store.
- **ADR-14: Dual-control approval (N-of-M) for the legal gate.** Authorization attestation and scope expansion require ≥2 distinct, role-verified approvers (never the requester/tester), each pinning the manifest/document hash (`manifest_sha256`/`document_sha256`) and the policy digest. Rationale: the primary abuse actor is a privileged insider; a single-approver model let one person broaden-and-re-attest. Trade-off: two humans in the loop for legal/scope changes — intentional friction on the highest-consequence action.
- **ADR-15: Per-engagement cryptographic erasure reconciles secure deletion with WORM/backups.** Engagement data is envelope-encrypted under a per-engagement DEK; deletion destroys the DEK, making ciphertext in primary/WORM/backup stores undecryptable without mutating any immutable store. Rationale: WORM protects integrity during retention but blocks physical deletion. Trade-off: DEK custody and a deletion-verification step. Design: `11-data-retention-and-deletion.md`.
- **ADR-16: The queued object is an immutable, fully-hashed `request_spec`; grants are minted just-in-time.** Short-lived single-use grants cannot be enqueued (they would expire in the queue or force wide TTLs), so the queue holds an immutable `spec_sha256`-hashed spec and the Scope Authority mints a ≤30s grant only at dispatch, after re-verifying the hash and re-checking scope/auth/window/e-stop/budget against current state. Rationale: keeps the grant out of the queue and makes the authorized request tamper-evident. Trade-off: a JIT mint call on the dispatch hot path — acceptable at this platform's low volumes. Design: `04` §7, `10`.
- **ADR-17: The broker reconstructs and normalizes the request from the signed spec.** The Guarded Egress Broker never sends a worker-serialized request; it rebuilds the wire request deterministically from the immutable spec (method, canonical URL, fixed header-set, inert payload, session-by-reference) and asserts equality. Rationale: a worker cannot inject a deviation between authorization and the wire. Trade-off: the broker owns request construction and the safe header/payload catalogs.
- **ADR-18: Explicit WebSocket and budget semantics.** ws/wss handshakes are scoped/pinned like HTTP; established connections are bounded by duration/message/size/count caps and terminated on e-stop/window/expiry. Request budget uses a conservative **charge-before-send** state machine: the broker irreversibly charges the fenced lease (`used += 1`) in the same transaction as the durable intent, before the first byte, so `sent ⇒ charged` and the charged count never exceeds the total; a pre-charge denial releases the claim, a crashed `claimed` lease is swept, and a `charged` lease is terminal (the only crash residue is a conservative over-charge). Rationale: long-lived sockets and queue-dwell would otherwise escape the per-request scope/time/budget model, and no request may be sent uncharged. Trade-off: per-connection accounting and interlock-driven connection teardown.
- **ADR-19: Durable intent before any egress + charge-before-send budget leases.** `request.intent` is committed before any DNS/TCP/TLS action, in one transaction that transitions a `budget_reservation` row (keyed by the grant `jti`, owned + fenced) to `charged` (`used += 1`, IRREVERSIBLE); the charge is terminal, a crashed `claimed` lease is swept, and completion is informational. Rationale: DNS is itself egress that can leak/fail silently, and no request may be sent without its budget already charged. Trade-off: a ledger write on the hot path and a claim-expiry sweeper. Design: `04` §7.1/§8.1.
- **ADR-20: Content-addressed templates; repeatable specs.** Every template reference (check, tool, header-set, payload, WS frame-set) is an immutable content digest into `catalog_template`, folded into `spec_sha256`; there is no `UNIQUE(spec_sha256)`, so identical requests recur across jobs/runs as distinct instances. Rationale: mutable ids could be silently repointed after authorization, and legitimate repeats must not collide. Trade-off: a content-addressed catalog and digest bookkeeping. Design: `04` §7.0.
- **ADR-21: Immutable approval policy + approved-spec manifest; non-null audit-chain identity.** Approval threshold/roles live in an immutable, Administrator-versioned `approval_policy` (not requester fields), and intrusive approvals authorize an explicit manifest of `spec_sha256` digests. Audit chains carry a non-null `chain_id` so per-chain uniqueness is actually enforced for tenant/global streams. Rationale: a requester must not set their own policy, an approval must bind exact requests, and NULL chain keys made the old uniqueness constraint vacuous. Trade-off: policy versioning and an `audit_chain` table. Design: `04` §9/§10.

---

### Phase 0 acceptance-criteria hooks this architecture must satisfy downstream
- **Provable single egress path:** an integration test shows a worker with a target IP in hand cannot open a connection except through the broker (network-policy test, Phase 10).
- **Scope cannot be bypassed:** property-based tests prove no `(job, scope decision)` pair reaches the wire without passing broker re-validation, and out-of-scope jobs cannot be enqueued (Phase 2/10).
- **No shell reachable:** CI static analysis proves no request-reachable path to a shell and no string-built command lines (Phase 1/6).
- **Tenant isolation:** RLS tests prove no cross-tenant read/write (Phase 10).
- **Redaction:** report/audit outputs contain no secrets/PII across a fuzzed corpus (Phase 8/10).

This architecture is deliberately opinionated around one principle: **make the unsafe action structurally impossible.** Scope, egress, isolation, and approval are enforced at network and datastore layers — not by warnings — so that application bugs degrade toward *refusing to act* rather than acting unsafely.
