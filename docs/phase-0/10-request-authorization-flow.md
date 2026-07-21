> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

# Request Authorization Flow, Egress-Grant Tokens & Broker Ingress

This document specifies **how a single outbound request is authorized end-to-end** and **how the data-plane network is arranged** so that authorization cannot be bypassed. It resolves two Phase 0-review blockers:

- **Blocker 2** — the scheduling token cannot bind a resolved IP before the Guarded Egress Broker resolves DNS. We define a **two-stage flow** with **broker-time IP binding** and a fully-specified grant token.
- **Blocker 6** — the sandbox/worker network arrangement and an **authenticated, per-job broker ingress that is never a generic CONNECT proxy**.

Canonical components (see `04` and `00`): **Scope Authority** (sole decision authority, mints grants, no target I/O) and **Guarded Egress Broker** (sole socket-creator to targets, resolves/pins/connects).

---

## 1. Why two stages

The resolved IP of a target is unknown until DNS is resolved, and **only the Guarded Egress Broker resolves target DNS** (co-located with socket creation, so the validated IP is the dialed IP — the anti-rebinding guarantee). A grant minted at scheduling time therefore **cannot** contain a resolved IP. Binding a resolved IP at mint time was the internal contradiction the review flagged. The fix:

- **Stage 1 — Scheduling / grant issuance (Scope Authority).** Authorizes the exact *request line* (method + canonical URL/host/port/scheme/path), binds it to the frozen scope and authorization, and mints a short-TTL, single-use signed **egress grant**. No IP is bound.
- **Stage 2 — Broker-time authorization (Guarded Egress Broker).** Authenticates the job, verifies the grant, re-checks live state (fail-closed), resolves DNS, validates **every** resolved IP against the network guard and the frozen scope, **pins** the validated IP, connects, and records the resolved+pinned IP in the completion audit event.

This preserves "one decision authority, one enforcer" while making IP validation happen where — and only where — the IP is known.

---

## 2. The egress grant token (Stage-1 output)

A compact, signed token (e.g. a PASETO/JWS-style structure with an Ed25519 signature from the Scope Authority; algorithm pinned, `none` forbidden). It is a **capability**: possession + validity authorizes exactly one request line, once.

| Claim | Purpose |
|---|---|
| `iss` | Issuer = the Scope Authority instance/cluster id. Broker rejects unknown issuers. |
| `aud` | Audience = the specific Guarded Egress Broker instance/cluster id. A grant for broker A is invalid at broker B. |
| `sub` | Subject = `run_id` (the scan run). |
| `job_id` | The specific job/check invocation this grant serves. |
| `jti` | Unique nonce. **Single-use**: the broker consumes it exactly once (replay protection). |
| `iat`, `nbf`, `exp` | Issued-at, not-before, expiry. **Short TTL** (seconds to low minutes) bounds the replay window. |
| `tenant_id`, `engagement_id` | Tenancy binding; must match the job's identity and the broker's per-job context. |
| `authorization_id`, `authorization_exp` | The legal authority in force; broker re-checks freshness at Stage 2. |
| `scope_hash` | The exact frozen `scope_version` the decision was made against (`04` §4.1). Broker loads that immutable version to re-validate resolved IPs. |
| `method` | Exact HTTP method authorized. A grant for `GET` cannot drive a `POST`. |
| `canonical_url` | Full canonical URL (scheme, host, port, path) — the exact request line. |
| `canonical_host`, `port`, `scheme`, `canonical_path` | Decomposed, redundant with `canonical_url`, for cheap broker checks and path-prefix enforcement. |
| `mode` | `passive` / `safe_active` / `approval_gated`. |
| `request_class` | `native` / `tool_driven` / `browser`. Controls which egress-inspection mode applies (`08` §2). |
| `approval_ref` | Required for intrusive/elevated class; the approval must be `approved`, unexpired, and plan-hash-matched. Null otherwise. |
| `budget_ref` | Reference used to atomically decrement the engagement request budget on send. |
| `sig` | Signature over all claims (Ed25519). Broker verifies before anything else. |

**Explicitly NOT in the grant:** any resolved IP (unknown at Stage 1). Path and method **are** bound (closing the earlier "IP-level token authorizes any path/verb" gap — the former SI-043, now folded into SI-001/SI-053).

**Replay & forgery protection:** signature + pinned algorithm; `aud` binding to one broker; `nbf`/`exp` short window; `jti` single-use consumed in a strongly-consistent store; per-job ingress identity (§4) so a leaked grant is useless without the job's mTLS identity.

---

## 3. End-to-end sequence

```
Scheduler ── job ──▶ Scope Authority  (STAGE 1)
                     run §7 steps 0–5 over the frozen scope_version
                     PASS ─▶ mint egress grant (claims in §2), emit scope.decision.allow
                     FAIL ─▶ DENY (audited); job not dispatched
        │
        ▼ grant + job dispatched to a Worker (control plane → data plane; jobs pulled, no inbound to workers)
Worker (data plane) constructs a STRUCTURED request (typed struct; never a command string)
        │  presents (job identity + grant) to the broker's authenticated per-job ingress (§4)
        ▼
Guarded Egress Broker  (STAGE 2)
   1. INGRESS AUTH   — verify per-job mTLS/capability; bind connection to (tenant, engagement, run, job)
   2. VERIFY GRANT   — signature, iss, aud==self, nbf/exp, jti unused → consume; tenant/engagement match
   3. RE-CHECK STATE — authorization fresh, window open, e-stop clear, budget>0, rate/concurrency slot
                       (fail-closed per SI-046: any unknown ⇒ DENY)
   4. RESOLVE DNS    — canonical_host → all A/AAAA
   5. GUARD + SCOPE  — every resolved IP: network guard (§6) + must satisfy scope_hash's ip/cidr/domain rules
   6. PIN + CONNECT  — dial ONLY a pinned validated IP; TLS cert host must match canonical_host
   7. INTENT AUDIT   — durably commit request.intent BEFORE the socket write (SI-055)
   8. SEND           — issue exactly the grant's method + path; body from inert payload catalog only
   9. REDIRECT?      — do NOT auto-follow; request a FRESH grant for the Location; else STOP
  10. COMPLETE AUDIT — request.completed/failed with resolved+pinned IP, status, byte counts (redacted)
        │
        ▼ response (in-scope only) ─▶ redaction ─▶ minimized evidence ─▶ finding
```

If any Stage-2 step fails, **no socket is opened** (or an open socket is closed) and a deny/failure event is recorded.

---

## 4. Data-plane network arrangement & authenticated broker ingress (blocker 6)

The network is arranged so that authorization is a **topology invariant**, not just an application check. Two distinct sandbox postures:

### 4.1 Tool / headless-browser sandbox — broker only
- Runs in a default-deny egress network namespace whose **only** reachable next hop is the Guarded Egress Broker's ingress address. No route to targets, to the internet, or to control-plane services.
- Client-side DNS disabled; the broker resolves (proxy-side resolve + pin). WebRTC/QUIC/direct-socket features disabled; `file:`/`data:`/`blob:` navigation restricted (SI-041).
- Even a fully compromised tool/browser can reach nothing but the broker.

### 4.2 Worker — narrow internal allowlist + broker, no direct target/internet
- The worker orchestrates checks/adapters and needs specific **internal** services: the job queue, the database (RLS-scoped), object storage (evidence), the Scope Authority, and the secret manager (per-job leases). Its egress netns allowlists **exactly those internal service endpoints plus the broker** — and **nothing else**: no direct route to targets and no route to the internet.
- Targets are reachable **only** by handing a grant to the broker. A worker never opens a socket to a target (SI-054, tightening the old "worker egress to scope destinations" wording).

### 4.3 Authenticated, per-job broker ingress — never a generic CONNECT proxy
- The broker does **not** expose a generic `CONNECT host:port` proxy that any sandbox process could use for arbitrary destinations. That would make the network-topology guarantee meaningless.
- Instead the broker exposes an **authenticated ingress** where each connection carries a **per-job identity/capability** (short-lived per-job mTLS client certificate or capability token, issued when the job is dispatched and bound to `tenant/engagement/run/job`). The broker:
  - accepts a request **only** with a valid per-job identity **and** a matching, unconsumed egress grant whose `tenant_id/engagement_id/run_id/job_id` equal the identity's;
  - serves **only** the exact request line the grant authorizes — not an arbitrary host:port tunnel;
  - never proxies a destination that did not come from a Scope-Authority grant.
- HTTPS inspection mode is chosen per `request_class` (`08` §2, SI-042): request-by-request adapter driving with redirects disabled (preferred), or broker TLS-termination with a **sandbox-only** internal CA. The broker is not a passthrough tunnel in either mode — every request line is grant-authorized and visible to the broker for scope/path/redirect/body enforcement.

**Result:** three independent layers must all agree before a target is contacted — (1) the network namespace lets the sandbox reach only the broker, (2) the broker authenticates the per-job identity, and (3) a valid, single-use, request-line-bound grant exists. A defect in any one degrades toward *refusing to connect*.

---

## 5. Invariant mapping

| Concern | Invariant |
|---|---|
| Single choke point; grant binds request line (method/path), broker-time IP validation & pinning | **SI-001** (rewritten), **SI-003**, **SI-004** |
| Two-stage flow, grant claim set, single-use/replay protection, broker-time binding | **SI-053** |
| Authenticated per-job ingress; no generic CONNECT proxy | **SI-053** |
| Tool/browser broker-only; client DNS off | **SI-041** |
| HTTPS inspection point (driven vs sandbox-CA termination) | **SI-042** |
| Worker narrow internal allowlist + broker only; no direct target/internet | **SI-054** (refines **SI-033**) |
| Redirect re-authorization per hop | **SI-005** |
| Fail-closed on any unresolved dependency at Stage 2 | **SI-046** |
| Request intent durably committed before egress | **SI-055** |
