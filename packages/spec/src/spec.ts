/**
 * The immutable, content-addressed `request_spec` (Phase 0 §7.0). A spec fully determines the wire request; its
 * `spec_sha256` is the SHA-256 over the canonical JSON of ONLY the request-determining fields. INSTANCE identity
 * (`run_id`/`job_id`), broker-resolved secret POINTERS (`approval_ref`/`session_ref`/`query_value_ref`), and the
 * advisory `mode` are deliberately EXCLUDED, so:
 *   - the same logical request may legitimately recur across jobs/runs with the SAME digest (a repeat, not a replay);
 *   - a dynamic request that later needs approval keeps a STABLE digest while `approval_ref` is attached (§10);
 *   - the non-secret bindings (`query_value_binding`, `session_digest`) ARE bound in, so rotation invalidates the
 *     digest, but the secret values/pointers themselves never enter the hash or any global store.
 *
 * `computeSpecSha256` here computes byte-for-byte what the database trigger computes for the same fields, so the
 * app and the DB agree on a spec's identity.
 */

import { canonicalJson, sha256Hex, type JsonValue } from './canonical.js';

export const REQUEST_CLASSES = ['native', 'tool_driven', 'browser'] as const;
export type RequestClass = (typeof REQUEST_CLASSES)[number];

export const KINDS = ['http', 'websocket'] as const;
export type Kind = (typeof KINDS)[number];

export const METHODS = ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type Method = (typeof METHODS)[number];

export const SPEC_SCHEMES = ['https', 'http', 'wss', 'ws'] as const;
export type SpecScheme = (typeof SPEC_SCHEMES)[number];

/**
 * The request-determining fields that are folded into `spec_sha256` (§7.0). Optional catalog/query/session digests
 * are `string | null` — the null must be EXPLICIT so an absent field is a deliberate, hashed value, never a silently
 * dropped one. `tenant_id`, `run_id`, `job_id`, `approval_ref`, `session_ref`, `query_value_ref`, and `mode` are NOT
 * here by design (see the module doc).
 */
export interface RequestSpecContent {
  readonly engagementId: string;
  readonly scopeHash: string;
  readonly authorizationId: string;
  readonly requestClass: RequestClass;
  readonly kind: Kind;

  readonly checkDigest: string | null;
  readonly toolTemplateDigest: string | null;
  readonly headerSetDigest: string; // the fixed safe header-set is always present
  readonly payloadDigest: string | null;
  readonly wsFrameSetDigest: string | null;

  readonly method: Method;
  readonly canonicalUrl: string;
  readonly canonicalHost: string;
  readonly port: number;
  readonly scheme: SpecScheme;
  readonly canonicalPath: string;

  readonly queryKeysCanonical: string | null;
  readonly queryTemplateDigest: string | null;
  readonly queryValueBinding: string | null;
  readonly queryValueDigest: string | null;

  readonly sessionDigest: string | null;
  readonly approvalRequired: boolean;
}

/**
 * The exact, ordered set of keys the digest covers. Building the digest object from THIS list (rather than spreading
 * the input) is what guarantees no extra field can sneak into — and no required field can fall out of — the hash.
 * Canonicalization sorts keys anyway, so this array documents membership, not order.
 */
const DIGEST_KEYS = [
  'engagement_id',
  'scope_hash',
  'authorization_id',
  'request_class',
  'kind',
  'check_digest',
  'tool_template_digest',
  'header_set_digest',
  'payload_digest',
  'ws_frame_set_digest',
  'method',
  'canonical_url',
  'canonical_host',
  'port',
  'scheme',
  'canonical_path',
  'query_keys_canonical',
  'query_template_digest',
  'query_value_binding',
  'query_value_digest',
  'session_digest',
  'approval_required',
] as const;

/** Map the typed content to the exact snake_case digest object (the DB column names), all keys present. */
export function specDigestObject(
  c: RequestSpecContent,
): Record<(typeof DIGEST_KEYS)[number], JsonValue> {
  return {
    engagement_id: c.engagementId,
    scope_hash: c.scopeHash,
    authorization_id: c.authorizationId,
    request_class: c.requestClass,
    kind: c.kind,
    check_digest: c.checkDigest,
    tool_template_digest: c.toolTemplateDigest,
    header_set_digest: c.headerSetDigest,
    payload_digest: c.payloadDigest,
    ws_frame_set_digest: c.wsFrameSetDigest,
    method: c.method,
    canonical_url: c.canonicalUrl,
    canonical_host: c.canonicalHost,
    port: c.port,
    scheme: c.scheme,
    canonical_path: c.canonicalPath,
    query_keys_canonical: c.queryKeysCanonical,
    query_template_digest: c.queryTemplateDigest,
    query_value_binding: c.queryValueBinding,
    query_value_digest: c.queryValueDigest,
    session_digest: c.sessionDigest,
    approval_required: c.approvalRequired,
  };
}

/** The canonical JSON string that `spec_sha256` is taken over (exposed for cross-checking against the DB trigger). */
export function canonicalSpecJson(c: RequestSpecContent): string {
  return canonicalJson(specDigestObject(c));
}

/** The content address of a request spec: lowercase-hex SHA-256 over its canonical request-determining fields. */
export function computeSpecSha256(c: RequestSpecContent): string {
  return sha256Hex(canonicalSpecJson(c));
}

/** The digest field names covered by `spec_sha256`, for documentation / test assertions. */
export const SPEC_DIGEST_FIELDS: readonly string[] = DIGEST_KEYS;
