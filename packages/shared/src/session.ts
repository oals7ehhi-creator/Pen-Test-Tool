import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';
import { isRole, type Role } from './roles.js';

/**
 * Signed-session foundation (JOSE / JWT via the pinned `jose` library). A protected route accepts identity ONLY
 * from a token verified here. The accepted algorithm (HS256), issuer, and audience are PINNED; signature, subject,
 * exact role, issued-at, not-before, and expiry are all validated; idle validity is capped at 30 minutes and
 * absolute session lifetime at 12 hours (Phase 0 NFR-001). Any failure raises a typed `SessionError` whose message
 * is a fixed reason code — never the token, claims, or key material.
 */

/** The one and only accepted signing algorithm. Pinning this defeats algorithm-confusion / `alg:none` attacks. */
export const SESSION_ALG = 'HS256' as const;

/** NFR-001: idle session validity ≤ 30 min (a single token's lifetime). */
export const IDLE_MAX_SECONDS = 30 * 60;
/** NFR-001: absolute session lifetime ≤ 12 h (measured from the session start claim `sat`). */
export const ABSOLUTE_MAX_SECONDS = 12 * 60 * 60;
/** Small allowance for clock skew between signer and verifier. */
export const CLOCK_TOLERANCE_SECONDS = 5;

export type SessionErrorReason =
  | 'missing'
  | 'malformed'
  | 'bad_signature'
  | 'wrong_algorithm'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'expired'
  | 'not_yet_valid'
  | 'future_issued'
  | 'idle_exceeded'
  | 'absolute_exceeded'
  | 'no_subject'
  | 'unknown_role';

/** Every rejection reason is a fixed, safe enum member — usable as a log field and never carrying secret content. */
export const SESSION_ERROR_REASONS: readonly SessionErrorReason[] = [
  'missing',
  'malformed',
  'bad_signature',
  'wrong_algorithm',
  'wrong_issuer',
  'wrong_audience',
  'expired',
  'not_yet_valid',
  'future_issued',
  'idle_exceeded',
  'absolute_exceeded',
  'no_subject',
  'unknown_role',
];

export class SessionError extends Error {
  readonly reason: SessionErrorReason;
  constructor(reason: SessionErrorReason) {
    super(`session rejected: ${reason}`); // SECRET-FREE: only a reason code, never the token/claims/key.
    this.name = 'SessionError';
    this.reason = reason;
  }
}

/** The verified, trusted identity extracted from a valid session. Role comes EXCLUSIVELY from verified claims. */
export interface VerifiedIdentity {
  readonly sub: string;
  readonly role: Role;
  readonly sid: string;
}

export interface SignSessionParams {
  readonly key: Uint8Array;
  readonly issuer: string;
  readonly audience: string;
  readonly subject: string;
  readonly role: Role;
  readonly sid: string;
  /** Session absolute start (epoch seconds); the 12 h cap is measured from here. */
  readonly sessionStart: number;
  /** Token (idle) lifetime in seconds; clamped to `IDLE_MAX_SECONDS`. */
  readonly ttlSeconds: number;
  /** Current time (epoch seconds). Injectable for deterministic tests. */
  readonly now: number;
  readonly kid?: string;
}

/** Mint a signed session token. The idle lifetime is clamped so no token can exceed the 30-minute cap. */
export async function signSession(p: SignSessionParams): Promise<string> {
  const ttl = Math.min(Math.max(1, Math.floor(p.ttlSeconds)), IDLE_MAX_SECONDS);
  const header: { alg: typeof SESSION_ALG; kid?: string } = { alg: SESSION_ALG };
  if (p.kid !== undefined) header.kid = p.kid;
  return await new SignJWT({ role: p.role, sid: p.sid, sat: p.sessionStart })
    .setProtectedHeader(header)
    .setSubject(p.subject)
    .setIssuer(p.issuer)
    .setAudience(p.audience)
    .setIssuedAt(p.now)
    .setNotBefore(p.now)
    .setExpirationTime(p.now + ttl)
    .sign(p.key);
}

export interface VerifyParams {
  readonly token: string | undefined;
  readonly key: Uint8Array;
  readonly issuer: string;
  readonly audience: string;
  /** Current time (epoch seconds). Injectable for deterministic tests. */
  readonly now: number;
}

/**
 * Verify a session token and return the trusted identity, or throw `SessionError`. In order: signature + pinned
 * algorithm + issuer + audience + exp + nbf (via jose), then issued-at not in the future, idle window ≤ 30 min,
 * absolute session ≤ 12 h, a non-empty subject, and an EXACT known role. No claim other than these is trusted.
 */
export async function verifySession(p: VerifyParams): Promise<VerifiedIdentity> {
  if (p.token === undefined || p.token === '') throw new SessionError('missing');

  let payload: Record<string, unknown>;
  try {
    const res = await jwtVerify(p.token, p.key, {
      algorithms: [SESSION_ALG], // pin alg → reject none/RS256/confusion
      issuer: p.issuer, // pin issuer
      audience: p.audience, // pin audience
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
      currentDate: new Date(p.now * 1000),
    });
    payload = res.payload as Record<string, unknown>;
  } catch (e) {
    throw mapJoseError(e);
  }

  const iat = payload['iat'];
  if (typeof iat !== 'number') throw new SessionError('malformed');
  if (iat > p.now + CLOCK_TOLERANCE_SECONDS) throw new SessionError('future_issued');

  const exp = payload['exp'];
  if (typeof exp !== 'number') throw new SessionError('malformed');
  if (exp - iat > IDLE_MAX_SECONDS + CLOCK_TOLERANCE_SECONDS)
    throw new SessionError('idle_exceeded');

  const sat = payload['sat'];
  if (typeof sat !== 'number') throw new SessionError('malformed');
  if (sat > p.now + CLOCK_TOLERANCE_SECONDS) throw new SessionError('future_issued');
  if (p.now - sat > ABSOLUTE_MAX_SECONDS + CLOCK_TOLERANCE_SECONDS) {
    throw new SessionError('absolute_exceeded');
  }

  const sub = payload['sub'];
  if (typeof sub !== 'string' || sub === '') throw new SessionError('no_subject');

  const role = payload['role'];
  if (!isRole(role)) throw new SessionError('unknown_role');

  const sid = payload['sid'];
  if (typeof sid !== 'string' || sid === '') throw new SessionError('malformed');

  return { sub, role, sid };
}

function mapJoseError(e: unknown): SessionError {
  if (e instanceof joseErrors.JWTExpired) return new SessionError('expired');
  if (e instanceof joseErrors.JOSEAlgNotAllowed) return new SessionError('wrong_algorithm');
  if (e instanceof joseErrors.JWSSignatureVerificationFailed)
    return new SessionError('bad_signature');
  if (e instanceof joseErrors.JWTClaimValidationFailed) {
    switch (e.claim) {
      case 'iss':
        return new SessionError('wrong_issuer');
      case 'aud':
        return new SessionError('wrong_audience');
      case 'nbf':
        return new SessionError('not_yet_valid');
      default:
        return new SessionError('malformed');
    }
  }
  return new SessionError('malformed');
}
