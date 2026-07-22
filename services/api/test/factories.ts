import { EventEmitter } from 'node:events';
import { createHash } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  signSession,
  resolveSigningKey,
  createLogger,
  type Role,
  type ResolvedSigningKey,
  type SignSessionParams,
} from '@pentest/shared';
import { handle, type HandlerDeps } from '../src/server.js';
import { API_EVENTS } from '../src/logevents.js';
import type { AuthContext } from '../src/auth.js';

/**
 * Reusable test factories for signed identities, claims, and HTTP requests. All fixtures are deterministic. The
 * test signing-key material is DERIVED from a fixed seed at runtime (not a committed high-entropy literal), so no
 * secret is committed to the repository.
 */

export const TEST_ISSUER = 'pentest-tool';
export const TEST_AUDIENCE = 'pentest-api';
/** A fixed "now" (epoch seconds) so token timing is fully deterministic. */
export const FIXED_NOW = 1_700_000_000;

/** Strong signing-key material derived from a fixed seed (deterministic, high-entropy, not a committed literal). */
export const TEST_KEY_MATERIAL = createHash('sha256')
  .update('pentest-phase1-test-signing-key-material-seed')
  .digest('base64url');

export function testSigningKey(): ResolvedSigningKey {
  return resolveSigningKey({
    ref: 'test-signing-key-ref',
    material: TEST_KEY_MATERIAL,
    nodeEnv: 'test',
  });
}

export function testAuthContext(
  over: Partial<Pick<AuthContext, 'devMinterEnabled' | 'isProduction' | 'now'>> & {
    signingKey?: ResolvedSigningKey;
  } = {},
): AuthContext {
  return {
    signingKey: over.signingKey ?? testSigningKey(),
    issuer: TEST_ISSUER,
    audience: TEST_AUDIENCE,
    isProduction: over.isProduction ?? false,
    devMinterEnabled: over.devMinterEnabled ?? false,
    now: over.now ?? ((): number => FIXED_NOW),
  };
}

/** Mint a VALID signed session for a role, with optional claim/timing overrides (for adversarial variants). */
export async function signIdentity(
  role: Role,
  over: Partial<SignSessionParams> = {},
  key: ResolvedSigningKey = testSigningKey(),
): Promise<string> {
  return signSession({
    key: key.key,
    kid: key.kid,
    issuer: TEST_ISSUER,
    audience: TEST_AUDIENCE,
    subject: `user:${role}`,
    role,
    sid: `sid-${role}`,
    sessionStart: FIXED_NOW,
    ttlSeconds: 15 * 60,
    now: FIXED_NOW,
    ...over,
  });
}

export interface InvokeResult {
  status: number;
  body: string;
  lines: string[];
  headers: Record<string, string>;
}

export interface InvokeOptions {
  method: string;
  path: string;
  /** Bearer token to present (added as `Authorization: Bearer <token>`). */
  token?: string;
  /** Extra raw request headers (e.g. spoof attempts, cookies). */
  headers?: Record<string, string>;
  ctx?: AuthContext;
}

/** Drive a request through the real `handle()` and capture status, body, response headers, and log lines. */
export async function invoke(opts: InvokeOptions): Promise<InvokeResult> {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.token !== undefined) headers['authorization'] = `Bearer ${opts.token}`;

  const req = Object.assign(new EventEmitter(), {
    method: opts.method,
    url: opts.path,
    headers,
  }) as unknown as IncomingMessage;

  const captured = { status: 0, body: '', headers: {} as Record<string, string> };
  const res = {
    statusCode: 0,
    headersSent: false,
    setHeader(k: string, v: string): void {
      captured.headers[k.toLowerCase()] = String(v);
    },
    end(chunk?: string): void {
      captured.status = res.statusCode;
      captured.body = chunk ?? '';
    },
  } as unknown as ServerResponse;

  const lines: string[] = [];
  const deps: HandlerDeps = {
    log: createLogger({
      level: 'info',
      events: API_EVENTS,
      sink: (l) => lines.push(l),
      now: () => new Date(0),
    }),
    auth: opts.ctx ?? testAuthContext(),
  };
  await handle(req, res, deps);
  return { status: captured.status, body: captured.body, lines, headers: captured.headers };
}

/** Parse the emitted `request` log record (or throw if none). */
export function requestLog(r: InvokeResult): {
  correlationId: string;
  event: string;
  fields: Record<string, unknown>;
} {
  const raw = r.lines.find((l) => l.includes('"event":"request"'));
  if (raw === undefined) throw new Error('no request log line emitted');
  return JSON.parse(raw) as {
    correlationId: string;
    event: string;
    fields: Record<string, unknown>;
  };
}
