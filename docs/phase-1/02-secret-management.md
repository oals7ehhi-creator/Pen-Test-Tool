# Phase 1 — Secret management, rotation & prohibited locations

Scope: how secrets are referenced, resolved, rotated, and kept out of the repository in Phase 1. This governs
the session signing key today and is the pattern every later phase's secret (DB credentials, broker keys,
engagement encryption keys) must follow.

## 1. References, not material

Configuration holds **references**, never secret material:

- `SESSION_SIGNING_KEY_REF` names the signing key. It is validated as a non-empty, sufficiently-long label and
  is **never** used as key bytes (`packages/shared/src/config.ts`, `packages/shared/src/keyprovider.ts`).
- The **resolved material** is supplied out-of-band as `SESSION_SIGNING_KEY_MATERIAL`, modelling the value a
  secret manager returns for that reference. In a real deployment this is injected at runtime by the
  orchestrator/secret store, not written to any file in the repo or image.

This separation is what lets the reference live safely in `.env.example`, `docker-compose.yml`, and CI while
the material never does.

## 2. Resolution & fail-closed behaviour

`loadSigningKey(ref, nodeEnv, env)` (`packages/shared/src/keyprovider.ts`) is the single resolution point:

| Environment        | Material present & strong   | Material missing                                | Material weak                         |
| ------------------ | --------------------------- | ----------------------------------------------- | ------------------------------------- |
| **production**     | resolve → `ephemeral:false` | **boot fails** (`KeyResolutionError`)           | **boot fails** (`KeyResolutionError`) |
| development / test | resolve → `ephemeral:false` | process-random ephemeral key (`ephemeral:true`) | rejected as if missing → ephemeral    |

"Strong" = at least **32 bytes**, enough distinct characters, and not an obvious placeholder
(`change-me`, `example`, `placeholder`, `dev-key`, `test-key`, `dummy`, `sample`, `insecure`). Enforced by
`weaknessOf`.

Fail-closed messages are **secret-free**: they name the _reference_ and the _reason_
(e.g. `signing key for reference "…" could not be resolved: no key material is available for this reference`)
and never echo material. Proven by `services/api/test/boot.test.ts` and the production boot smoke path.

## 3. Rotation

The design supports rotation without code changes:

- **Key id derives from the reference**, not the material (`keyIdFor(ref)` → a non-secret `k_…` label). The
  resolved key id is surfaced in the `api_listening` log (`keyEphemeral` flag) for operational visibility, so
  a rollout can be observed without exposing any secret.
- **To rotate**: publish new material for the same reference in the secret manager and restart/redeploy the
  API; the new material is resolved at boot. Because absolute session lifetime is capped at **12 h** and idle
  at **30 min** (NFR-001, enforced in `session.ts`), any session minted under the previous material naturally
  ages out within the absolute window — there is no unbounded-lifetime token to invalidate manually.
- **To retire a key**: change `SESSION_SIGNING_KEY_REF` to the new reference; the old material can then be
  destroyed in the secret store. Multi-key/`kid`-indexed verification (accepting the previous key during an
  overlap window) is a straightforward extension the `kid` field already anticipates; it is intentionally out
  of Phase 1 scope (no rotation _orchestration_ is claimed here — only that the boundary makes it safe).

## 4. Prohibited locations — secrets must never appear in

- Source code, tests, fixtures, or committed configuration (`.env`, `.env.example`, `docker-compose.yml`,
  Dockerfiles, CI workflows).
- Container images or build layers.
- Logs, error messages, stack traces, or exception payloads (SI-045; see
  `docs/phase-1/01-authentication-and-key-resolution.md` §5).
- Version-control history.

### How this is enforced technically (not by convention)

- **Secret scanning** — `gitleaks` runs in CI (`security-gates` job) and blocks any committed secret. The
  allowlist in `.gitleaks.toml` is rule-scoped and value-anchored (`condition = 'AND'`), and an **adversarial
  test** (`ci/gitleaks-allowlist-test.sh`) proves the allowlist is tight: a real secret is still caught even
  on the same line as, or in a different path than, a permitted low-entropy placeholder.
- **`.env.example` is verified secret-free** — it ships references and non-secret defaults only;
  `SESSION_SIGNING_KEY_MATERIAL` is deliberately left unset/commented.
- **Log allowlist** — the closed-allowlist logger (SI-045) has no field capable of carrying a secret.
- **Test material is derived, not committed** — where tests need signing material they compute it at runtime
  from a fixed seed (`createHash('sha256')…`), so no high-entropy literal is committed
  (`services/api/test/factories.ts`, `packages/shared/test/session.test.ts`).

## 5. Local development

`cp .env.example .env` yields a runnable stack with **no real secret**: `SESSION_SIGNING_KEY_MATERIAL` stays
unset, so the API (and Compose) boot on an ephemeral key. This keeps the one-command developer experience while
guaranteeing that a production deployment cannot accidentally inherit a weak or placeholder key — production
resolves real material or refuses to start.
