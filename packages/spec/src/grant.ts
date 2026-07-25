/**
 * The Stage-1 egress grant (Phase 0 §7.1). The Scope Authority mints a grant JUST-IN-TIME at dispatch; the Guarded
 * Egress Broker (aud=broker) verifies it before any egress. A grant is:
 *   - short-TTL (≤ 30 s) — its life only spans dispatch → send, never the queue dwell;
 *   - single-use — bound to a `jti` the broker consumes exactly once (defeats replay);
 *   - bound to `spec_sha256` — the broker also recomputes the presented spec's digest and requires equality, so the
 *     grant authorizes THAT exact request and no other;
 *   - carrying NO resolved IP and NO request line — the request line lives in the immutable spec, and the resolved
 *     IP is chosen + pinned by the broker at connect time.
 *
 * Alg (HS256), issuer, and audience are PINNED (defeats alg-confusion / cross-audience reuse). Every rejection is a
 * typed `GrantError` whose message is a fixed reason code — never the token, claims, or key material.
 */

import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';
import { REQUEST_CLASSES, type RequestClass } from './spec.js';

/** The one accepted grant-signing algorithm. */
export const GRANT_ALG = 'HS256' as const;
/** §7.1: a grant's TTL is at most 30 seconds. */
export const MAX_GRANT_TTL_SECONDS = 30;
/** Small allowance for clock skew between the Scope Authority (signer) and the Broker (verifier). */
export const GRANT_CLOCK_TOLERANCE_SECONDS = 5;

export type GrantErrorReason =
  | 'malformed'
  | 'bad_signature'
  | 'wrong_algorithm'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'expired'
  | 'not_yet_valid'
  | 'invalid_claims'
  | 'spec_mismatch'
  | 'replayed';

export const GRANT_ERROR_REASONS: readonly GrantErrorReason[] = [
  'malformed',
  'bad_signature',
  'wrong_algorithm',
  'wrong_issuer',
  'wrong_audience',
  'expired',
  'not_yet_valid',
  'invalid_claims',
  'spec_mismatch',
  'replayed',
];

export class GrantError extends Error {
  readonly reason: GrantErrorReason;
  constructor(reason: GrantErrorReason) {
    super(reason); // the message IS the fixed reason code — no token/claim/key content
    this.name = 'GrantError';
    this.reason = reason;
  }
}

/** The security-authority claims a grant binds (§7.1). No resolved IP, no request line. */
export interface GrantClaims {
  readonly runId: string;
  readonly jobId: string;
  readonly tenantId: string;
  readonly engagementId: string;
  readonly authorizationId: string;
  readonly scopeHash: string;
  readonly specSha256: string;
  readonly requestClass: RequestClass;
  /** Present iff the spec required approval (§7.1 precondition h). */
  readonly approvalRef?: string;
}

export interface MintGrantParams {
  readonly claims: GrantClaims;
  /** Raw HS256 key material (resolved from the secret manager by the caller). */
  readonly key: Uint8Array;
  /** Non-secret key id for the token header (audit / rotation). */
  readonly kid: string;
  readonly issuer: string;
  /** The broker audience — a grant is usable only by the broker it is minted for. */
  readonly audience: string;
  /** Seconds; must be in (0, MAX_GRANT_TTL_SECONDS]. */
  readonly ttlSeconds: number;
  /** Current time in epoch seconds (injectable for deterministic tests). */
  readonly nowSeconds: number;
  /** The single-use token id. Callers pass a unique jti per dispatch. */
  readonly jti: string;
}

const CLAIM = {
  runId: 'run_id',
  jobId: 'job_id',
  tenantId: 'tenant_id',
  engagementId: 'engagement_id',
  authorizationId: 'authorization_id',
  scopeHash: 'scope_hash',
  specSha256: 'spec_sha256',
  requestClass: 'request_class',
  approvalRef: 'approval_ref',
} as const;

/** Mint a signed, short-TTL, single-use Stage-1 grant. Throws on an out-of-policy TTL (fail closed on misconfig). */
export async function mintGrant(params: MintGrantParams): Promise<string> {
  const { ttlSeconds, nowSeconds } = params;
  if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_GRANT_TTL_SECONDS) {
    throw new GrantError('invalid_claims');
  }
  const c = params.claims;
  const payload: Record<string, string> = {
    [CLAIM.runId]: c.runId,
    [CLAIM.jobId]: c.jobId,
    [CLAIM.tenantId]: c.tenantId,
    [CLAIM.engagementId]: c.engagementId,
    [CLAIM.authorizationId]: c.authorizationId,
    [CLAIM.scopeHash]: c.scopeHash,
    [CLAIM.specSha256]: c.specSha256,
    [CLAIM.requestClass]: c.requestClass,
  };
  if (c.approvalRef !== undefined) payload[CLAIM.approvalRef] = c.approvalRef;

  return new SignJWT(payload)
    .setProtectedHeader({ alg: GRANT_ALG, kid: params.kid })
    .setIssuer(params.issuer)
    .setAudience(params.audience)
    .setIssuedAt(nowSeconds)
    .setNotBefore(nowSeconds)
    .setExpirationTime(nowSeconds + ttlSeconds)
    .setJti(params.jti)
    .sign(params.key);
}

export interface VerifyGrantParams {
  readonly key: Uint8Array;
  readonly issuer: string;
  /** This broker's audience; a grant minted for another audience is rejected. */
  readonly audience: string;
  /** The digest of the spec the broker is about to reconstruct; must equal the grant's `spec_sha256`. */
  readonly presentedSpecSha256: string;
  readonly nowSeconds: number;
  /**
   * Single-use consumer: returns true iff THIS `jti` was previously unused (and marks it used). A false return
   * means the grant was already consumed ⇒ replay. Called ONLY after every other check passes, so an invalid token
   * never burns a jti.
   */
  readonly consumeJti: (jti: string) => boolean | Promise<boolean>;
}

function reasonFromJose(err: unknown): GrantErrorReason {
  if (err instanceof joseErrors.JWTExpired) return 'expired';
  if (err instanceof joseErrors.JOSEAlgNotAllowed) return 'wrong_algorithm';
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) return 'bad_signature';
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    const claim = (err as { claim?: string }).claim;
    if (claim === 'iss') return 'wrong_issuer';
    if (claim === 'aud') return 'wrong_audience';
    if (claim === 'nbf') return 'not_yet_valid';
    return 'invalid_claims';
  }
  return 'malformed';
}

function asNonEmptyString(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

/**
 * Verify a Stage-1 grant against this broker's audience and the presented spec's digest, then consume its jti.
 * Returns the parsed claims on success; throws a typed `GrantError` otherwise (§7.1 step 7).
 */
export async function verifyGrant(token: string, params: VerifyGrantParams): Promise<GrantClaims> {
  let payload: Record<string, unknown>;
  let header: { alg?: string; jti?: string };
  try {
    const result = await jwtVerify(token, params.key, {
      algorithms: [GRANT_ALG],
      issuer: params.issuer,
      audience: params.audience,
      clockTolerance: GRANT_CLOCK_TOLERANCE_SECONDS,
      currentDate: new Date(params.nowSeconds * 1000),
      requiredClaims: ['jti', 'iat', 'nbf', 'exp'],
    });
    payload = result.payload as Record<string, unknown>;
    header = result.protectedHeader;
  } catch (err) {
    throw new GrantError(reasonFromJose(err));
  }
  // jwtVerify already pinned the alg via `algorithms`, but assert defensively.
  /* v8 ignore next -- unreachable: jwtVerify rejects a non-HS256 alg before this point */
  if (header.alg !== GRANT_ALG) throw new GrantError('wrong_algorithm');

  const jti = asNonEmptyString(payload['jti']);
  const runId = asNonEmptyString(payload[CLAIM.runId]);
  const jobId = asNonEmptyString(payload[CLAIM.jobId]);
  const tenantId = asNonEmptyString(payload[CLAIM.tenantId]);
  const engagementId = asNonEmptyString(payload[CLAIM.engagementId]);
  const authorizationId = asNonEmptyString(payload[CLAIM.authorizationId]);
  const scopeHash = asNonEmptyString(payload[CLAIM.scopeHash]);
  const specSha256 = asNonEmptyString(payload[CLAIM.specSha256]);
  const requestClassRaw = asNonEmptyString(payload[CLAIM.requestClass]);
  const approvalRefRaw = payload[CLAIM.approvalRef];

  if (
    jti === null ||
    runId === null ||
    jobId === null ||
    tenantId === null ||
    engagementId === null ||
    authorizationId === null ||
    scopeHash === null ||
    specSha256 === null ||
    requestClassRaw === null ||
    !(REQUEST_CLASSES as readonly string[]).includes(requestClassRaw)
  ) {
    throw new GrantError('invalid_claims');
  }
  // approval_ref, if present, must be a non-empty string (never a non-string smuggled value).
  let approvalRef: string | undefined;
  if (approvalRefRaw !== undefined) {
    const ar = asNonEmptyString(approvalRefRaw);
    if (ar === null) throw new GrantError('invalid_claims');
    approvalRef = ar;
  }

  // The grant must authorize exactly the request the broker is about to send (§7.1 step 7).
  if (specSha256 !== params.presentedSpecSha256) throw new GrantError('spec_mismatch');

  // Single-use: consume LAST, so a token that failed any earlier check never burns its jti.
  const fresh = await params.consumeJti(jti);
  if (!fresh) throw new GrantError('replayed');

  return {
    runId,
    jobId,
    tenantId,
    engagementId,
    authorizationId,
    scopeHash,
    specSha256,
    requestClass: requestClassRaw as RequestClass,
    ...(approvalRef !== undefined ? { approvalRef } : {}),
  };
}
