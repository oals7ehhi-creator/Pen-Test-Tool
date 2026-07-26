/**
 * @pentest/spec — the two-stage flow's content-addressing + Stage-1 grant core (Phase 2, slice 4a).
 *
 * This is the pure, dependency-light foundation of Phase 0 §7: the immutable, content-addressed `request_spec`
 * digest (`spec_sha256`) that identifies a wire request while excluding instance/secret-pointer fields, and the
 * short-TTL, single-use, spec-bound egress grant the Scope Authority mints and the Guarded Egress Broker verifies.
 * The DB persistence of `request_spec` / catalog templates / operator sessions and the Broker's
 * resolve→validate→pin→connect→re-guard data path land in later slice-4 sub-slices.
 */

export { type JsonValue, canonicalJson, sha256Hex, canonicalDigest } from './canonical.js';

export {
  type OperatorSessionIdentity,
  type OperatorQueryValueIdentity,
  type QueryValueEntry,
  operatorSessionDigest,
  operatorQueryValueBinding,
  computeQueryValueDigest,
} from './bindings.js';

export {
  REQUEST_CLASSES,
  type RequestClass,
  KINDS,
  type Kind,
  METHODS,
  type Method,
  SPEC_SCHEMES,
  type SpecScheme,
  type RequestSpecContent,
  specDigestObject,
  canonicalSpecJson,
  computeSpecSha256,
  SPEC_DIGEST_FIELDS,
} from './spec.js';

export {
  GRANT_ALG,
  MAX_GRANT_TTL_SECONDS,
  GRANT_CLOCK_TOLERANCE_SECONDS,
  type GrantErrorReason,
  GRANT_ERROR_REASONS,
  GrantError,
  type GrantClaims,
  type MintGrantParams,
  mintGrant,
  type VerifyGrantParams,
  verifyGrant,
} from './grant.js';
