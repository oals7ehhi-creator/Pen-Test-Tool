import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import {
  verifySession,
  signSession,
  loadSigningKey,
  isRole,
  IDLE_MAX_SECONDS,
  type AppConfig,
  type ResolvedSigningKey,
  type VerifiedIdentity,
} from '@pentest/shared';

/**
 * API authentication wiring. Identity for a protected route comes EXCLUSIVELY from a cryptographically verified
 * session token carried in `Authorization: Bearer` or the session cookie. No header, query parameter, or body can
 * set a role. The optional dev token minter (non-production, opt-in) only issues a properly signed short-lived
 * token — it is not an authorization path.
 */

export const SESSION_COOKIE = 'pentest_session';
/** Dev-only helper endpoint that mints a signed session; unavailable (404) unless the minter is enabled. */
export const DEV_TOKEN_PATH = '/dev/token';

export interface AuthContext {
  readonly signingKey: ResolvedSigningKey;
  readonly issuer: string;
  readonly audience: string;
  /** True in a production environment. The dev token minter is structurally unavailable whenever this is true. */
  readonly isProduction: boolean;
  /** True only when the dev token minter is enabled AND the environment is non-production (never in production). */
  readonly devMinterEnabled: boolean;
  /** Current time in epoch seconds; injectable for deterministic tests. */
  readonly now: () => number;
}

/**
 * Resolve the signing key and assemble the auth context. In production this FAILS CLOSED (throws) when the key
 * reference cannot be resolved to strong material; non-production falls back to a process-random ephemeral key.
 *
 * The dev token minter is force-disabled in production HERE (defense in depth): `loadConfig` already forces it off,
 * but `start()`/`buildAuthContext` also accept a hand-constructed `AppConfig`, so a config that (incorrectly) sets
 * `devTokenMinterEnabled: true` alongside `nodeEnv: 'production'` still yields a disabled minter.
 */
export function buildAuthContext(
  config: AppConfig,
  env: Record<string, string | undefined> = process.env,
  now: () => number = () => Math.floor(Date.now() / 1000),
): AuthContext {
  const signingKey = loadSigningKey(config.sessionSigningKeyRef, config.nodeEnv, env);
  const isProduction = config.nodeEnv === 'production';
  return {
    signingKey,
    issuer: config.authIssuer,
    audience: config.authAudience,
    isProduction,
    devMinterEnabled: config.devTokenMinterEnabled && !isProduction,
    now,
  };
}

/** Extract the session token from `Authorization: Bearer` or the session cookie; undefined if absent. */
export function extractToken(req: IncomingMessage): string | undefined {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string') {
    const m = /^Bearer (.+)$/.exec(auth);
    if (m && m[1]) return m[1];
  }
  const cookie = req.headers['cookie'];
  if (typeof cookie === 'string') {
    for (const part of cookie.split(';')) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      const name = part.slice(0, eq).trim();
      if (name === SESSION_COOKIE) {
        const value = part.slice(eq + 1).trim();
        if (value !== '') return value;
      }
    }
  }
  return undefined;
}

/** Authenticate a request to a protected route. Throws `SessionError` on any failure. */
export async function authenticate(
  req: IncomingMessage,
  ctx: AuthContext,
): Promise<VerifiedIdentity> {
  return await verifySession({
    token: extractToken(req),
    key: ctx.signingKey.key,
    issuer: ctx.issuer,
    audience: ctx.audience,
    now: ctx.now(),
  });
}

/**
 * Dev-only token minter. Mints a properly signed, short-lived session for a role named in `x-dev-mint-role`
 * (consulted ONLY here, never for authorization). Returns undefined for an unknown role. Callers must have already
 * confirmed the minter is enabled and the environment is non-production.
 */
export async function mintDevToken(
  req: IncomingMessage,
  ctx: AuthContext,
): Promise<{ token: string; role: string } | undefined> {
  const raw = req.headers['x-dev-mint-role'];
  const role = typeof raw === 'string' ? raw : undefined;
  if (!isRole(role)) return undefined;
  const now = ctx.now();
  const token = await signSession({
    key: ctx.signingKey.key,
    kid: ctx.signingKey.kid,
    issuer: ctx.issuer,
    audience: ctx.audience,
    subject: `dev:${role}`,
    role,
    sid: randomUUID(),
    sessionStart: now,
    ttlSeconds: IDLE_MAX_SECONDS,
    now,
  });
  return { token, role };
}
