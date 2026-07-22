import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { loadConfig, createLogger, type AppConfig, type Logger } from '@pentest/shared';
import { authorizeRequest, UNMATCHED_ROUTE } from './router.js';
import { API_EVENTS } from './logevents.js';

/**
 * Phase 1 API skeleton on the Node standard library (no framework dependency yet). It demonstrates the
 * load-bearing foundations: fail-closed config boot, per-request correlation id + minimized structured logging,
 * and DEFAULT-DENY route authorization. Business endpoints are stubbed (501) — they arrive in later phases.
 *
 * DEV-ONLY role injection (NOT authentication): when `devAuthEnabled` is true (opt-in, never in production), the
 * caller's role may be supplied via the `x-dev-role` header purely so the default-deny wiring is demonstrable
 * before real authN lands. When disabled, the header is ignored entirely and every protected route returns 401.
 * Real authN (a signed session) replaces this later; the authorization decision (`authorizeRequest`) is already
 * the single, framework-agnostic choke point.
 */

export interface HandlerDeps {
  readonly log: Logger;
  readonly devAuthEnabled: boolean;
}

function injectedDevRole(req: IncomingMessage, devAuthEnabled: boolean): string | undefined {
  if (!devAuthEnabled) return undefined; // header ignored unless dev role-injection is explicitly enabled
  const h = req.headers['x-dev-role'];
  return typeof h === 'string' && h.length > 0 ? h : undefined;
}

export function handle(req: IncomingMessage, res: ServerResponse, deps: HandlerDeps): void {
  // Authoritative per-request correlation id: it becomes the record's reserved `correlationId`, and because it is
  // set via childWithCorrelationId (not context) it cannot be spoofed or overridden by any caller-supplied field.
  const rlog = deps.log.childWithCorrelationId(randomUUID());
  const method = req.method ?? 'GET';
  const path = (req.url ?? '/').split('?')[0] ?? '/';
  const role = injectedDevRole(req, deps.devAuthEnabled);

  const outcome = authorizeRequest(method, path, role);
  // SI-045 allowlist: the `request` event permits ONLY method, the MATCHED route template (from the frozen
  // allowlist — never the raw URL/path/query), and a numeric status. Headers, query, body and cookies have no
  // field to land in and are structurally impossible to log.
  rlog.info('request', {
    method,
    route: outcome.status === 404 ? UNMATCHED_ROUTE : outcome.route,
    status: outcome.status,
  });

  res.setHeader('content-type', 'application/json');
  if (outcome.status === 200) {
    if (outcome.route === '/healthz') {
      res.statusCode = 200;
      res.end(JSON.stringify({ status: 'ok' }));
      return;
    }
    // Authorized, but the business logic is not implemented in Phase 1.
    res.statusCode = 501;
    res.end(JSON.stringify({ error: 'not_implemented' }));
    return;
  }
  res.statusCode = outcome.status;
  res.end(JSON.stringify({ error: statusError(outcome.status) }));
}

function statusError(status: number): string {
  switch (status) {
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    default:
      return 'error';
  }
}

export function start(config: AppConfig): ReturnType<typeof createServer> {
  const log = createLogger({ level: config.logLevel, events: API_EVENTS });
  const deps: HandlerDeps = { log, devAuthEnabled: config.devAuthEnabled };
  const server = createServer((req, res) => handle(req, res, deps));
  server.listen(config.apiPort, config.apiHost, () => {
    log.info('api_listening', {
      host: config.apiHost,
      port: config.apiPort,
      env: config.nodeEnv,
      devAuthEnabled: config.devAuthEnabled,
    });
  });
  return server;
}

// Boot when run directly. loadConfig throws (fail-closed) on missing/invalid config → the process exits non-zero
// with a clear, secret-free message rather than serving with partial config.
if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    start(loadConfig());
  } catch (err) {
    // ConfigError message is secret-free by construction.
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  }
}
