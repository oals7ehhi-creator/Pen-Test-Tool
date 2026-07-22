# Phase 1 — Authentication trust boundary & key-reference resolution

This document records the Phase 1 authentication design: where the trust boundary sits, exactly what is
verified before a caller is trusted, and how the signing-key **reference** is resolved to key **material**
without the reference ever being treated as the material itself.

It is subordinate to the approved Phase 0 design — in particular NFR-001 (session-lifetime limits,
`docs/phase-0/01-requirements.md`), the default-deny RBAC of `docs/phase-0/09-rbac-matrix.md`, and the
logging/secret invariants of `docs/phase-0/05-safety-invariants.md` (SI-045).

## 1. Trust boundary

```
                        ┌──────────────────────── trusted ────────────────────────┐
  untrusted input       │                                                          │
  ───────────────►  extractToken ──► verifySession ──► VerifiedIdentity ──► authorizeRequest ──► handler
  (Authorization:       │  (jose, HS256)   (pinned iss/aud/alg,           (default-deny RBAC,
   Bearer / Cookie)     │                   full claim + timing checks)    role from claims only)
                        └──────────────────────────────────────────────────────────┘
   headers · query · body  ✗ never contribute a role or identity
```

- **The only thing that crosses the boundary is a cryptographically verified session token.** Identity
  (subject + role + session id) is derived **exclusively** from verified JWT claims. No header, query
  parameter, cookie name, or request body can set or override a role. The former `x-dev-role` header — a
  role-injection path, not authentication — has been removed as an authorization input entirely.
- **`/healthz` is the sole public route.** Every other route requires a verified session; there is no
  implicit public access (`services/api/src/router.ts`, `permission: null` is explicit and only on health).
- Token transport is `Authorization: Bearer <jwt>` or the `pentest_session` cookie
  (`services/api/src/auth.ts`, `extractToken`). Both carry the _same_ verified-token requirement; the cookie
  is not a trusted side channel.

## 2. What `verifySession` verifies (`packages/shared/src/session.ts`)

A token is accepted only if **all** of the following hold; any failure throws a typed, secret-free
`SessionError` whose message is `session rejected: <reason>` and never contains the token, claims, or key.

| Check                                                                                                  | Enforcement                                                                                    | Reject reason           |
| ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------- | ----------------------- |
| Algorithm is exactly HS256                                                                             | `jwtVerify(..., { algorithms: ['HS256'] })` (defeats `alg:none` / `HS384` / `RS256` confusion) | `wrong_algorithm`       |
| Signature valid under the resolved key                                                                 | jose HMAC verification                                                                         | `bad_signature`         |
| Issuer is the pinned `iss`                                                                             | `jwtVerify(..., { issuer })`                                                                   | `wrong_issuer`          |
| Audience is the pinned `aud`                                                                           | `jwtVerify(..., { audience })`                                                                 | `wrong_audience`        |
| Not expired (`exp`)                                                                                    | jose, with a 5 s clock tolerance                                                               | `expired`               |
| Not before (`nbf`)                                                                                     | jose                                                                                           | `not_yet_valid`         |
| `iat` not in the future                                                                                | explicit check vs `now`                                                                        | `future_issued`         |
| **Claim chronology** `sat ≤ iat` (session cannot start after its token was issued)                     | explicit check                                                                                 | `bad_chronology`        |
| **Idle lifetime** `exp - iat ≤ 30 min`                                                                 | `IDLE_MAX_SECONDS`                                                                             | `idle_exceeded`         |
| **Absolute lifetime** `now - sat ≤ 12 h` AND `exp ≤ sat + 12 h` (`sat` = session absolute-start claim) | `ABSOLUTE_MAX_SECONDS`                                                                         | `absolute_exceeded`     |
| Subject present                                                                                        | explicit                                                                                       | `no_subject`            |
| Role is exactly one of the five                                                                        | `isRole(...)` against the Phase 0 role set                                                     | `unknown_role`          |
| Session id present                                                                                     | explicit                                                                                       | `malformed`             |
| Token missing / not a JWT                                                                              | —                                                                                              | `missing` / `malformed` |

The two lifetime bounds implement NFR-001 **statelessly**: `signSession` clamps the minted TTL to
`IDLE_MAX_SECONDS` and stamps `sat` (absolute session start); the verifier independently re-derives the idle
window (`exp - iat`) and the absolute window and rejects anything beyond the Phase 0 limits (idle ≤ 30 min,
absolute ≤ 12 h). The absolute cap is enforced by verification, not merely trusted from the signer: `sat` may not
be after `iat` (`bad_chronology` — so a signer cannot advance `sat` toward "now" to shrink the measured age), and
`exp` may not exceed `sat + 12 h` (so a fresh idle-valid token near the absolute deadline cannot run past it).
None of these bounds can be widened by a crafted token — they are checked against constants, not attacker-supplied
durations. The one thing statelessness cannot prevent — a signing-key holder minting a wholly new session with a
fresh `sat` — requires server-side session state and is deferred (see `05-risk-and-debt-disposition.md`, D-1).

Role is read **only** from the verified `role` claim and validated against the exactly-five-role set; an
otherwise-valid token carrying `superuser` is rejected (`unknown_role`), never silently downgraded or trusted.

## 3. Key-reference resolution boundary (`packages/shared/src/keyprovider.ts`)

`SESSION_SIGNING_KEY_REF` is a **reference** — a name that identifies a key (e.g. an entry in a secret
manager) — and is **never** used as key bytes. Resolution is a narrow, explicit boundary:

```
config.sessionSigningKeyRef  ──(name)──►  loadSigningKey(ref, nodeEnv, env)
                                             │
                                             ├─ material = env[SESSION_SIGNING_KEY_MATERIAL]   (the resolved secret)
                                             │
      production:  material missing OR weak ─┴─► throw KeyResolutionError (fail closed, secret-free)
      production:  strong material          ────► ResolvedSigningKey { kid = keyIdFor(ref), key, ephemeral:false }
      non-prod:    material absent           ────► ResolvedSigningKey { kid:'ephemeral', key = random(32), ephemeral:true }
```

- **The reference is only ever used to derive a non-secret key id** (`keyIdFor(ref)` = a SHA-256-derived
  `k_…` label for logs/rotation bookkeeping). It is never hashed into, or used as, the signing key.
- **Material** comes from a _separate_ input (`SESSION_SIGNING_KEY_MATERIAL`), modelling "the secret manager
  resolved the reference to this value." Strength is enforced (`weaknessOf`): `≥ 32` bytes, sufficient
  distinct characters, and rejection of obvious placeholders (`change-me`, `example`, `dev-key`, …).
- **Production fails closed.** If the reference resolves to no material, or to weak material, the API refuses
  to boot with a `KeyResolutionError` that names the _reference_ and the _reason_ only — never any material.
- **Non-production stays usable.** With no material present, a process-random 32-byte ephemeral key is used
  (`ephemeral: true`), so the one-command Compose stack runs with no secret on disk. Ephemeral keys simply do
  not survive a restart (tokens minted before a restart stop verifying), which is the correct dev trade-off.

`buildAuthContext` (`services/api/src/auth.ts`) performs this resolution once at boot; `start()` therefore
**fails fast in production** on an unresolved/weak key before it ever binds a socket.

## 4. Dev token minter (non-production only)

The optional dev helper (`POST /dev/token`, gated by `DEV_TOKEN_MINTER` and `nodeEnv !== 'production'`) does
**not** re-introduce role injection. It only **mints a properly signed, short-lived session** for a requested
role (via `signSession`, TTL = `IDLE_MAX_SECONDS`). It is:

- **default off** (config default `false`), and
- **structurally unavailable in production**, enforced in depth at three layers so a hand-built config cannot
  re-enable it: (1) `loadConfig` forces `devTokenMinterEnabled` off when `NODE_ENV=production`; (2)
  `buildAuthContext` computes `devMinterEnabled = devTokenMinterEnabled && !isProduction`, so even a manually
  constructed `AppConfig` passed to `start()` yields a disabled minter; and (3) the handler independently returns
  `404` whenever `ctx.isProduction`. A real-socket test boots the server with `nodeEnv: 'production'` +
  `devTokenMinterEnabled: true` and asserts `POST /dev/token` is `404` with no token minted.

The `x-dev-mint-role` header is consulted **only** inside the minter to choose which signed token to issue; it
is never an authorization input on a protected route.

## 5. Secret hygiene (SI-045)

Tokens, signing material, claims, cookies, and `Authorization` values never reach logs or error messages:

- `SessionError` / `KeyResolutionError` messages are constructed from a fixed reason (and, for key errors, the
  _reference name_) — never from material, claims, or the token.
- The request logger is a **closed allowlist** (`packages/shared/src/logsafe.ts`, SI-045): the `request`
  event can carry only `{ method, route, status, reason }`, where `route` is a known template string and
  `reason` is a fixed enum. There is no field through which a header, cookie, token, or URL could be logged —
  secrecy is achieved by construction, not by after-the-fact masking. This is proven end-to-end by the
  log-secrecy test in `services/api/test/auth.e2e.test.ts`.

## 6. Verifying this design

See `docs/phase-1/04-acceptance-matrix.md` for the full criterion → test → CI-evidence mapping. The
load-bearing suites are `packages/shared/test/session.test.ts`, `packages/shared/test/keyprovider.test.ts`,
`services/api/test/auth.e2e.test.ts`, and `services/api/test/boot.test.ts`.
