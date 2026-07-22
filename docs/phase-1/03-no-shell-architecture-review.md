# Phase 1 — Recorded no-shell architectural review (command-injection baseline)

**Reviewer:** Phase 1 implementation review.
**Question:** Does any API endpoint, worker path, or UI control pass user-controlled input to an OS shell (or
to a dynamic-code sink such as `eval`)?
**Finding:** **No.** There is no shell, subprocess, or dynamic-code-execution path anywhere in the product
code, and the absence is enforced technically at the lint layer (with an adversarial CI proof that the gate
has teeth), not merely asserted here.

## 1. Method

1. **Whole-tree search** of tracked TypeScript sources for every subprocess / shell / dynamic-code sink:
   `child_process`, `node:child_process`, `exec`, `execSync`, `execFile`, `spawn`, `spawnSync`, `/bin/sh`,
   `shelljs`, `eval(`, and `new Function(`.
   Result: **zero** occurrences in product code (the only textual hit is a prose comment in
   `services/api/src/server.ts`, not a call).
2. **Architectural walk** of every request-handling and process path (below).
3. **Confirmation of the technical gate** that keeps it that way.

## 2. Architectural walk

| Surface          | Entry point                                                                    | External-input handling                                                                                                                              | Shell reachable?                                            |
| ---------------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| API HTTP handler | `services/api/src/server.ts` (`handle`)                                        | Reads method/path/headers/cookie; routes via a fixed table; identity from verified JWT claims only. Responses are `JSON.stringify` of fixed objects. | **No** — no exec/spawn/template-shell anywhere in the path. |
| Auth / sessions  | `services/api/src/auth.ts`, `packages/shared/src/session.ts`, `keyprovider.ts` | JWT verify/sign via `jose`; key resolution via env lookup + hashing.                                                                                 | **No.**                                                     |
| Routing / authz  | `services/api/src/router.ts`, `packages/shared/src/rbac.ts`                    | Pure functions over a frozen route/permission table.                                                                                                 | **No.**                                                     |
| Logging          | `packages/shared/src/logger.ts`, `logsafe.ts`                                  | Closed-allowlist field serialization; `JSON.stringify` only.                                                                                         | **No.**                                                     |
| Worker           | `services/worker/src/index.ts`                                                 | A `setInterval` heartbeat that writes a liveness file with `fs.writeFileSync`. No command execution, no queue consumption yet.                       | **No.**                                                     |
| Web              | `apps/web` (static shell)                                                      | Serves a static placeholder; no server-side command execution.                                                                                       | **No.**                                                     |
| DB migrations    | `db/src`                                                                       | Parameterized SQL via the `pg` driver; no shelling out to `psql`.                                                                                    | **No.**                                                     |

There is deliberately **no** feature in Phase 1 that maps user input to a command line (no "run tool X",
no report renderer that shells to a binary, no archive extractor that spawns a subprocess). Those integrations
arrive in later phases and must preserve this baseline (Phase 0 non-goals; `docs/phase-0/07`).

## 3. The technical gate (why it stays true)

The no-shell property is enforced by ESLint, so a regression fails CI rather than merging silently:

- **Rule** — `no-restricted-imports` forbids importing `child_process` / `node:child_process` anywhere in the
  workspace, plus `no-eval` and `no-implied-eval` (`eslint.config.js`). `pnpm run lint` runs in the
  `build-test` CI job and blocks merge on any violation.
- **Adversarial proof the gate has teeth** — `ci/lint-noshell-negative-test.sh` (CI step _No-shell lint gate —
  negative proof_) plants, at runtime, a TypeScript file that imports `node:child_process`, runs ESLint, and
  asserts ESLint **fails specifically via `no-restricted-imports`**. The planted file is always removed and
  the check is a hard gate (never `continue-on-error`), so it cannot weaken the normal lint.

## 4. Residual risk & scope

- The lint rule covers `child_process` imports; it does not, by itself, forbid a future indirect subprocess
  (e.g. a dependency that shells out). That risk is mitigated by the dependency-audit and SAST gates
  (`security-gates` job) and must be re-reviewed whenever a phase introduces a tool-integration dependency.
- `eval`/`new Function` are covered by lint (`no-eval`, `no-implied-eval`) and confirmed absent by search.

**Conclusion:** the Phase 1 command-injection baseline holds — no product path reaches an OS shell or a
dynamic-code sink, and the property is technically enforced with an adversarial CI proof.
