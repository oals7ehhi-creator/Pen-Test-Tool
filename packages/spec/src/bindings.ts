/**
 * Operator-secret BINDINGS (Phase 0 §7.0 / §7.1 step 8). The immutable `request_spec` never stores the operator's
 * session secret or the protected query VALUES — those live only in the secret manager and are injected at the broker.
 * What the spec DOES fold into `spec_sha256` are non-secret *bindings* that pin WHICH secret version is in force and a
 * KEYED digest of the values, so a rotation invalidates the spec and the broker can re-verify at reconstruction time
 * without the secret ever entering the hash or any global store.
 *
 * These helpers are the single source of truth for the two sides that must agree on those bindings:
 *   - `operatorSessionDigest` / `operatorQueryValueBinding` recompute, byte-for-byte, the `session_digest` /
 *     `value_binding` that the database stores as GENERATED columns (migration `0003`) — a colon-delimited SHA-256 of
 *     the identity + version. The broker recomputes them from a resolved lease and requires equality with the spec.
 *   - `computeQueryValueDigest` is the KEYED (HMAC-SHA256) digest of the actual protected query values. The spec
 *     builder computes it once (folding it into `spec_sha256`); the broker recomputes it from the secret-manager
 *     values and CONSTANT-TIME compares — a value tamper or wrong version fails closed before any egress.
 *
 * The colon-delimited pre-images below mirror the DB exactly (`tenant:engagement:account:version` etc.); they are NOT
 * canonical-JSON — they must track the schema's GENERATED expression, not the spec-digest canonicalization.
 */

import { createHmac } from 'node:crypto';
import { canonicalJson, sha256Hex } from './canonical.js';

/** Identity of an operator session lease (mirrors `operator_session` (§7.0)); its non-secret content address. */
export interface OperatorSessionIdentity {
  readonly tenantId: string;
  readonly engagementId: string;
  readonly accountId: string;
  readonly sessionVersion: number;
}

/**
 * The non-secret `session_digest` = SHA-256 of `tenant:engagement:account:version`. Mirrors the `operator_session`
 * GENERATED column byte-for-byte so the broker's recompute equals what the spec bound.
 */
export function operatorSessionDigest(id: OperatorSessionIdentity): string {
  return sha256Hex(`${id.tenantId}:${id.engagementId}:${id.accountId}:${id.sessionVersion}`);
}

/** Identity of an operator query-value set version (mirrors `operator_query_value` (§7.0)). */
export interface OperatorQueryValueIdentity {
  readonly tenantId: string;
  readonly engagementId: string;
  readonly valueSetName: string;
  readonly valueVersion: number;
}

/**
 * The non-secret `value_binding` = SHA-256 of `tenant:engagement:value_set_name:value_version`. Mirrors the
 * `operator_query_value` GENERATED column, so a withdrawn/rotated version no longer matches the spec's binding.
 */
export function operatorQueryValueBinding(id: OperatorQueryValueIdentity): string {
  return sha256Hex(`${id.tenantId}:${id.engagementId}:${id.valueSetName}:${id.valueVersion}`);
}

/** One protected query parameter: its non-secret key and its secret value (resolved from the secret manager). */
export interface QueryValueEntry {
  readonly key: string;
  readonly value: string;
}

/**
 * The KEYED digest of the protected query values: HMAC-SHA256(key, canonicalJson(ordered [{key,value}])). Order is
 * significant (it is the wire order of the parameters). Because it is keyed, an attacker who can influence the values
 * cannot forge a matching `query_value_digest` without the broker/authority key; because it binds the keys too, a
 * key-substitution is caught. The same function is used by the spec builder (to fold the digest into `spec_sha256`)
 * and by the broker (to re-verify against the secret-manager values), so the two never diverge.
 */
export function computeQueryValueDigest(
  key: Uint8Array,
  entries: readonly QueryValueEntry[],
): string {
  const canonical = canonicalJson(entries.map((e) => ({ key: e.key, value: e.value })));
  return createHmac('sha256', key).update(canonical, 'utf8').digest('hex');
}
