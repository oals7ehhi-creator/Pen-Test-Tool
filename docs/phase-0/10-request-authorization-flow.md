> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

# Request Authorization Flow, Egress-Grant Tokens & Broker Ingress

This document specifies **how a single outbound request is authorized end-to-end** and **how the data-plane network is arranged** so that authorization cannot be bypassed. It resolves several review blockers:

- **The scheduling token cannot bind a resolved IP** before the Guarded Egress Broker resolves DNS → a **two-stage flow** with **broker-time IP binding**.
- **Grants are short-lived but jobs sit in a queue** → the **queued object is an immutable, fully-hashed `request_spec`**, and grants are **minted just-in-time (JIT) at dispatch**, bound to the spec's hash, so no grant ever waits in the queue.
- **The broker must not trust a worker-built request** → the broker **reconstructs and normalizes** the wire request deterministically from the signed immutable spec.
- **Autonomous request engines** (headless browser, self-driving tools) and **WebSockets** need explicit semantics (§4.4, §5).
- The sandbox/worker network arrangement and an **authenticated, per-job broker ingress that is never a generic CONNECT proxy** (§4).

Canonical components (see `04` and `00`): **Scope Authority** (sole decision authority, mints grants, no target I/O, no target DNS) and **Guarded Egress Broker** (sole target-socket creator, resolves/pins/connects, reconstructs the request).

---

## 1. Why two stages

The resolved IP of a target is unknown until DNS is resolved, and **only the Guarded Egress Broker resolves target DNS** (co-located with socket creation, so the validated IP is the dialed IP — the anti-rebinding guarantee). A grant minted at scheduling time therefore **cannot** contain a resolved IP. Furthermore, grants are short-lived and single-use, so a grant cannot be enqueued and wait — the **immutable `request_spec`** is what waits in the queue, and the grant is minted **just-in-time** when a dispatcher is ready to execute. The fix:

- **Queued object — immutable `request_spec` (`04` §7.0).** A fully-hashed (`spec_sha256`) specification of the exact request: method, canonical URL/host/port/scheme/path, a fixed `header_set_digest`, an inert `payload_digest`, protected query keys + `query_value_digest`, a non-secret `session_digest` (the secret operator-session value resolved later at the broker via `session_ref`), the derived `approval_required`, and (if approval is required) an approval reference. Created once, never mutated; the queue stores only `(spec_id, tenant_id)`.
- **Stage 1 — JIT grant issuance (Scope Authority).** At dispatch, the Authority loads the spec, **recomputes and verifies `spec_sha256`**, re-runs the scope/authorization/window/e-stop checks and **checks budget availability** against *current* state (it does **not** charge budget — the broker charges the fenced lease before send at Stage 2, §8.1), and mints a short-TTL (≤30s), single-use signed **egress grant bound to `spec_sha256`** — not to a re-listed request line, and never to a resolved IP.
- **Stage 2 — Broker-time authorization (Guarded Egress Broker).** Authenticates the job, verifies the grant and that `grant.spec_sha256 == sha256(spec)`, **reconstructs and normalizes** the wire request from the spec (never a worker-serialized request), re-checks live state (fail-closed), resolves DNS, validates **every** resolved IP against the network guard and the frozen scope, **pins** the validated IP, connects, and records the resolved+pinned IP in the completion event.

This preserves "one decision authority, one enforcer," makes IP validation happen where — and only where — the IP is known, and keeps the short-lived grant out of the queue entirely.

---

## 2. The egress grant token (Stage-1 output)

A compact, signed token (e.g. a PASETO/JWS-style structure with an Ed25519 signature from the Scope Authority; algorithm pinned, `none` forbidden). It is a **capability**: possession + validity authorizes exactly one immutable spec, once. Because it binds `spec_sha256`, it transitively binds the exact method and canonical path (they are fields of the spec) without re-listing them.

| Claim | Purpose |
|---|---|
| `iss` | Issuer = the Scope Authority instance/cluster id. Broker rejects unknown issuers. |
| `aud` | Audience = the specific Guarded Egress Broker instance/cluster id. A grant for broker A is invalid at broker B. |
| `sub` | Subject = `run_id` (the scan run). |
| `job_id` | The specific job/check invocation this grant serves. |
| `jti` | Unique nonce. **Single-use**: the broker consumes it exactly once (replay protection). |
| `iat`, `nbf`, `exp` | Issued-at, not-before, expiry. **Short TTL (≤30s)** — the grant is minted JIT and only has to cover dispatch→send. |
| `tenant_id`, `engagement_id` | Tenancy binding; must match the job's identity and the broker's per-job context. |
| `authorization_id`, `authorization_exp` | The legal authority in force; broker re-checks freshness at Stage 2. |
| `scope_hash` | The exact frozen `scope_version` the decision was made against (`04` §4.1). Broker loads that immutable version to re-validate resolved IPs. |
| **`spec_sha256`** | **Hash of the immutable `request_spec` this grant authorizes.** The broker requires `grant.spec_sha256 == sha256(presented spec)`; the method, canonical URL/host/port/scheme/path, header-set, and payload all live in the spec, so a grant cannot be replayed against any other request line or verb. |
| `mode` | `passive` / `safe_active` / `approval_gated`. |
| `request_class` | `native` / `tool_driven` / `browser`. Controls which egress-inspection mode applies (`08` §2). |
| `approval_ref` | Required for intrusive/elevated class; the approval must be `approved`, unexpired, and its immutable **manifest must contain this `spec_sha256`** (its threshold/roles come from the immutable `approval_policy`, `04` §10). Null otherwise. |
| `sig` | Signature over all claims (Ed25519). Broker verifies before anything else. |

**Explicitly NOT in the grant:** any resolved IP (unknown at Stage 1); and no re-listed request line — the line is the hashed spec. Budget is not referenced by a claim in the grant: availability is only pre-checked at grant-mint, and the fenced lease is **charged by the broker before any byte is sent** (`04` §8.1). Method and path are bound via `spec_sha256` (closing the earlier "IP-level token authorizes any path/verb" gap).

**Replay & forgery protection:** signature + pinned algorithm; `aud` binding to one broker; `nbf`/`exp` short window; `jti` single-use consumed in a strongly-consistent store; per-job ingress identity (§4) so a leaked grant is useless without the job's mTLS identity.

---

## 3. End-to-end sequence

```
Check engine ── builds ──▶ immutable request_spec (hashed: spec_sha256); ENQUEUE (spec_id, tenant_id)
        │                    (the queue holds the spec reference, NOT a grant)
        ▼ dispatcher pulls a queued spec when ready to execute
Dispatcher ── spec_id ──▶ Scope Authority  (STAGE 1, JUST-IN-TIME)
                     load spec; recompute + verify spec_sha256 (else DENY spec_tampered)
                     re-run §7 checks 0–5 over the frozen scope_version, against CURRENT state
                     PASS ─▶ mint short-TTL grant bound to spec_sha256 (§2); emit scope.decision.allow
                              (the reservation is created by the BROKER, atomically with intent, before DNS — §8.1)
                     FAIL ─▶ DENY (audited); spec stays queued for later, or dropped on hard failure
        │
        ▼ grant + spec dispatched to a Worker (control plane → data plane; jobs pulled, no inbound to workers)
Worker (data plane) presents (per-job identity + grant + spec) to the broker's authenticated ingress (§4)
        │  the worker does NOT serialize the HTTP request itself
        ▼
Guarded Egress Broker  (STAGE 2)
   1. INGRESS AUTH   — verify per-job mTLS/capability; bind connection to (tenant, engagement, run, job)
   2. VERIFY GRANT   — signature, iss, aud==self, nbf/exp, jti unused → consume; AND grant.spec_sha256 == sha256(spec)
   3. RECONSTRUCT    — deterministically rebuild the wire request FROM THE SPEC (method, url, header-set,
                       inert payload, operator session from the secret lease); re-normalize; assert == spec  else DENY
   4. RE-CHECK STATE — authorization fresh, window open, e-stop clear, rate/concurrency slot
                       (fail-closed per SI-046: any unknown ⇒ DENY and RELEASE any pre-charge 'claimed' lease)
   5. ATOMIC CHARGE + INTENT — one txn, BEFORE ANY EGRESS: SELECT budget FOR UPDATE; verify availability;
                       write the fenced budget_reservation lease (owner + monotonic fence_token, grant jti) and
                       TRANSITION it to 'charged' (request_budget_used += 1, IRREVERSIBLE); durably commit
                       request.intent (spec_sha256, jti, reservation id, canonical target) — budget charged
                       before the first byte, so sent ⇒ charged (SI-055)
   6. RESOLVE DNS    — the FIRST egress: canonical_host → all A/AAAA
   7. GUARD + SCOPE  — every resolved IP: network guard (§6) + must satisfy scope_hash's ip/cidr/domain rules
   8. PIN + CONNECT  — dial ONLY a pinned validated IP; TCP + TLS; cert host must match canonical_host
   9. SEND           — issue exactly the reconstructed request
  10. REDIRECT?      — do NOT auto-follow; form a NEW spec for the Location and request a FRESH JIT grant; else STOP
  11. COMPLETE AUDIT — request.completed/failed with resolved+pinned IP, status, byte counts (redacted);
                       INFORMATIONAL only — does NOT change the charge (a pre-charge denial already released
                       the claim; a post-charge crash leaves a terminal 'charged' lease) (§8.1)
        │
        ▼ response (in-scope only) ─▶ redaction ─▶ minimized evidence ─▶ finding
```

Intent (step 5) precedes DNS (step 6): **no packet — not even a DNS query — leaves the box before the durable intent commit that also charges the budget.** If any Stage-2 step fails *before* the charge, no socket is opened, the `claimed` lease is released (or crash-swept); once the lease is `charged` the budget is spent irreversibly and a crash around the send is a conservative over-charge — never sent-but-uncharged traffic. A deny/failure event is recorded either way.

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
  - serves **only** the request it reconstructs from the immutable spec whose digest equals the grant's `spec_sha256` — not an arbitrary host:port tunnel;
  - never proxies a destination that did not come from a Scope-Authority grant.
- HTTPS inspection mode is chosen per `request_class` (`08` §2, SI-042): request-by-request adapter driving with redirects disabled (preferred), or broker TLS-termination with a **sandbox-only** internal CA. The broker is not a passthrough tunnel in either mode — every request is grant-authorized (bound via `spec_sha256`) and visible to the broker for scope/path/redirect/body enforcement.

**Result:** three independent layers must all agree before a target is contacted — (1) the network namespace lets the sandbox reach only the broker, (2) the broker authenticates the per-job identity, and (3) a valid, single-use, `spec_sha256`-bound grant exists. A defect in any one degrades toward *refusing to connect*.

### 4.4 Broker-mediated JIT for autonomous request engines
A headless browser or a self-driving tool emits many requests the check engine did not pre-enumerate, so they cannot be pre-enqueued as specs. Instead the broker mediates: for **each** intercepted request line it **forms a `request_spec` on the fly**, computes `spec_sha256`, and asks the Scope Authority for a **JIT grant** (Stage 1 over the frozen scope). Only if a grant is minted does the request proceed (Stage 2 reconstruction/resolve/pin/connect). An out-of-scope subresource or an off-scope redirect gets **no grant → blocked**. The Scope Authority stays the sole minter and the broker the sole socket creator; budget/rate/window/e-stop apply per intercepted request exactly as for native checks.

---

## 5. WebSocket semantics

WebSockets do not fit the one-request/one-response model, so their handling is stated explicitly:

- **Handshake is authorized like HTTP.** A `kind='websocket'` spec (method `GET`, scheme `ws`/`wss`) authorizes the **Upgrade handshake** to a canonical path. Stage 1 scopes it; Stage 2 reconstructs, resolves DNS, validates every IP, **pins**, and connects — identical to an HTTP request. There is no separate un-scoped path.
- **Scope is fixed at the pinned handshake.** An established socket cannot change target host/IP; there is no per-message re-targeting, so post-upgrade frames need no per-message scope check — the connection is already pinned in-scope.
- **Bounded connection.** Each connection counts against `engagement.max_ws_connections` (`ws_in_flight`) and is capped by `ws_max_duration_s`, `ws_max_messages`, and `ws_max_message_bytes` (`04` §8). Exceeding a cap closes the connection.
- **Interlocks terminate connections.** Emergency stop, testing-window close, and authorization expiry **abort active WebSocket connections**, not just block new ones (SI-013 extended to long-lived sockets).
- **Catalog/approval-controlled outbound frames.** Outbound frames are drawn **only** from an approved, content-addressed inert frame set — a `ws_frame_set` `catalog_template` named by `spec.ws_frame_set_digest` (`04` §7.0). The broker's frame gate **cannot emit a frame outside that set**; frame count and size are bounded by the caps above; and any non-catalog frame requires an approval manifest (`04` §10). This makes "non-destructive frames only" a technical control, not a convention (SI-063).
- **Handshake redirects** are re-authorized like any HTTP redirect (new spec + JIT grant); an established WS is never auto-followed anywhere.

---

## 6. Invariant mapping

| Concern | Invariant |
|---|---|
| Single choke point; grant binds `spec_sha256`; broker-time IP validation & pinning | **SI-001** (rewritten), **SI-003**, **SI-004** |
| Immutable hashed `request_spec` as queued object; JIT grant minting | **SI-060** |
| Broker reconstructs/normalizes the request from the spec; no worker-serialized request | **SI-061** |
| Two-stage flow, grant claim set, single-use/replay protection, broker-time binding, per-job ingress, no generic CONNECT | **SI-053** |
| Identifiable, owned & fenced budget lease (per grant jti), charge-before-send, sweeper reclaims only pre-charge claims | **SI-017**, **SI-062** |
| Content-addressed template digests folded into spec_sha256; specs repeatable across jobs/runs | **SI-065** |
| Immutable approval policy + approved-spec manifest membership | **SI-064** |
| Tool/browser broker-only; client DNS off; broker-mediated JIT per request | **SI-041**, **SI-054** |
| HTTPS inspection point (driven vs sandbox-CA termination) | **SI-042** |
| Worker narrow internal allowlist + broker only; no direct target/internet | **SI-054** (refines **SI-033**) |
| Redirect re-authorization per hop (new spec + grant) | **SI-005** |
| WebSocket handshake scoped/pinned; connection bounded and terminated on interlocks | **SI-063** |
| Window/expiry/e-stop re-checked at JIT mint and Stage 2 | **SI-011**, **SI-012**, **SI-049** |
| Fail-closed on any unresolved dependency at Stage 2 | **SI-046** |
| Request intent (spec_sha256 + jti + reservation) durably committed before egress | **SI-055** |
