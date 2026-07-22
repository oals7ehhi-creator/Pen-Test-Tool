import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import {
  loadConfig,
  createLogger,
  SessionError,
  type AppConfig,
  type Logger,
} from '@pentest/shared';
import { authorizeRequest, matchRoute, UNMATCHED_ROUTE, DEV_TOKEN_PATH } from './router.js';
import { API_EVENTS } from './logevents.js';
import {
  authenticate,
  mintDevToken,
  buildAuthContext,
  SESSION_COOKIE,
  type AuthContext,
} from './auth.js';

/**
 * Phase 1 API on the Node standard library (no framework dependency yet). Load-bearing foundations: fail-closed
 * config + key resolution at boot, per-request correlation id + SI-045 allowlist logging, and DEFAULT-DENY route
 * authorization where identity comes ONLY from a cryptographically verified session (Authorization: Bearer or the
 * session cookie). No header, query, or body can set a role. `/healthz` is the sole public route. Business
 * endpoints are authorized then stubbed (501) — they arrive in later phases.
 */

export interface HandlerDeps {
  readonly log: Logger;
  readonly auth: AuthContext;
}

function send(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  res.end(JSON.stringify(body));
}

export async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  deps: HandlerDeps,
): Promise<void> {
  // Authoritative per-request correlation id (set via childWithCorrelationId, never from caller context).
  const rlog = deps.log.childWithCorrelationId(randomUUID());
  const method = req.method ?? 'GET';
  const path = (req.url ?? '/').split('?')[0] ?? '/';
  const ctx = deps.auth;

  const logReq = (route: string, status: number, reason?: string): void => {
    rlog.info(
      'request',
      reason === undefined ? { method, route, status } : { method, route, status, reason },
    );
  };

  // Dev-only token minter: structurally unavailable (404, same as any unknown route) unless explicitly enabled
  // and non-production. It only ISSUES a signed token; it is not an authorization path. The production check is
  // independent of `devMinterEnabled` (defense in depth): in production the route is a 404 no matter what.
  if (method === 'POST' && path === DEV_TOKEN_PATH) {
    if (ctx.isProduction || !ctx.devMinterEnabled) {
      logReq(DEV_TOKEN_PATH, 404);
      send(res, 404, { error: 'not_found' });
      return;
    }
    const minted = await mintDevToken(req, ctx);
    if (minted === undefined) {
      logReq(DEV_TOKEN_PATH, 400);
      send(res, 400, { error: 'unknown_role' });
      return;
    }
    // The token is returned to the caller (a dev login); it is never logged.
    res.setHeader(
      'set-cookie',
      `${SESSION_COOKIE}=${minted.token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800`,
    );
    logReq(DEV_TOKEN_PATH, 200);
    send(res, 200, { token: minted.token, role: minted.role });
    return;
  }

  const route = matchRoute(method, path);
  if (route === undefined) {
    logReq(UNMATCHED_ROUTE, 404);
    send(res, 404, { error: 'not_found' });
    return;
  }

  // Public route (health): no identity required.
  if (route.permission === null) {
    logReq(route.path, 200);
    send(res, 200, { status: 'ok' });
    return;
  }

  // Protected route: identity MUST come from a verified session. Any failure → 401 with a safe reason code.
  let role: string;
  try {
    const identity = await authenticate(req, ctx);
    role = identity.role;
  } catch (e) {
    const reason = e instanceof SessionError ? e.reason : 'malformed';
    logReq(route.path, 401, reason);
    send(res, 401, { error: 'unauthenticated' });
    return;
  }

  const outcome = authorizeRequest(method, path, role);
  if (outcome.status !== 200) {
    logReq(route.path, 403, 'forbidden');
    send(res, 403, { error: 'forbidden' });
    return;
  }
  // Authorized — but the business logic is not implemented in Phase 1.
  logReq(route.path, 501);
  send(res, 501, { error: 'not_implemented' });
}

export function start(config: AppConfig): ReturnType<typeof createServer> {
  const log = createLogger({ level: config.logLevel, events: API_EVENTS });
  const auth = buildAuthContext(config); // resolves the signing key (fails closed in production)
  const deps: HandlerDeps = { log, auth };
  const server = createServer((req, res) => {
    handle(req, res, deps).catch(() => {
      try {
        if (!res.headersSent) send(res, 500, { error: 'internal' });
      } catch {
        /* response already torn down */
      }
    });
  });
  server.listen(config.apiPort, config.apiHost, () => {
    log.info('api_listening', {
      host: config.apiHost,
      port: config.apiPort,
      env: config.nodeEnv,
      issuer: config.authIssuer,
      audience: config.authAudience,
      keyEphemeral: auth.signingKey.ephemeral,
      devTokenMinter: config.devTokenMinterEnabled,
    });
  });
  return server;
}

// Boot when run directly. loadConfig / key resolution throw (fail-closed) on missing/invalid config or an
// unresolved production key → the process exits non-zero with a clear, secret-free message. This is a thin
// process-entry shim; the fail-closed boot behavior it delegates to is proven deterministically by
// config.test.ts (loadConfig) and boot.test.ts (buildAuthContext / key resolution).
/* v8 ignore start -- process entry shim; exercised only as a spawned process, not in-process */
if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    start(loadConfig());
  } catch (err) {
    // ConfigError / KeyResolutionError messages are secret-free by construction.
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  }
}
/* v8 ignore stop */
