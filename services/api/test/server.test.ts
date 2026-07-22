import { describe, it, expect } from 'vitest';
import { handle, type HandlerDeps } from '../src/server.js';
import { createLogger } from '@pentest/shared';
import { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * Phase 1 exit tests at the server layer:
 *  - x-dev-role is honored ONLY when dev role-injection is enabled; ignored otherwise (item 6).
 *  - request logging is minimized: it never contains the raw URL, headers, or a role value (item 4 / SI-045).
 */

interface Captured {
  statusCode: number;
  body: string;
}

function invoke(opts: {
  method: string;
  url: string;
  headers?: Record<string, string>;
  devAuthEnabled: boolean;
  logSink: (line: string) => void;
}): Captured {
  const req = Object.assign(new EventEmitter(), {
    method: opts.method,
    url: opts.url,
    headers: opts.headers ?? {},
  }) as unknown as IncomingMessage;

  const captured: Captured = { statusCode: 0, body: '' };
  const res = {
    statusCode: 0,
    setHeader(): void {},
    end(chunk?: string): void {
      captured.statusCode = res.statusCode;
      captured.body = chunk ?? '';
    },
  } as unknown as ServerResponse;

  const deps: HandlerDeps = {
    log: createLogger({ level: 'info', sink: opts.logSink, now: () => new Date(0) }),
    devAuthEnabled: opts.devAuthEnabled,
  };
  handle(req, res, deps);
  return captured;
}

describe('x-dev-role gating (item 6)', () => {
  it('is honored when dev role-injection is enabled', () => {
    const r = invoke({
      method: 'GET',
      url: '/audit',
      headers: { 'x-dev-role': 'administrator' },
      devAuthEnabled: true,
      logSink: () => {},
    });
    expect(r.statusCode).toBe(501); // authorized (admin has audit.read) → business stub
  });

  it('is IGNORED when dev role-injection is disabled → protected route is 401', () => {
    const r = invoke({
      method: 'GET',
      url: '/audit',
      headers: { 'x-dev-role': 'administrator' },
      devAuthEnabled: false,
      logSink: () => {},
    });
    expect(r.statusCode).toBe(401);
  });

  it('health stays public regardless', () => {
    const r = invoke({ method: 'GET', url: '/healthz', devAuthEnabled: false, logSink: () => {} });
    expect(r.statusCode).toBe(200);
  });
});

describe('minimized request logging (item 4 / SI-045)', () => {
  it('logs only method/route/status — never the raw URL, headers, or role', () => {
    const lines: string[] = [];
    invoke({
      method: 'GET',
      url: '/engagements?token=SECRET-IN-URL&id=42',
      headers: { authorization: 'Bearer super.secret', 'x-dev-role': 'tester' },
      devAuthEnabled: true,
      logSink: (l) => lines.push(l),
    });
    const raw = lines.find((l) => l.includes('"msg":"request"'))!;
    expect(raw).not.toContain('SECRET-IN-URL');
    expect(raw).not.toContain('super.secret');
    expect(raw).not.toContain('tester'); // the role value is not logged
    const rec = JSON.parse(raw) as { ctx: Record<string, unknown> };
    expect(rec.ctx.method).toBe('GET');
    expect(rec.ctx.route).toBe('/engagements'); // matched template, not the raw URL
    expect(rec.ctx.status).toBe(200);
    expect(rec.ctx.headers).toBeUndefined();
  });

  it('an unmatched route logs the safe placeholder, not the raw path', () => {
    const lines: string[] = [];
    invoke({
      method: 'GET',
      url: '/secret/internal/path',
      devAuthEnabled: false,
      logSink: (l) => lines.push(l),
    });
    const raw = lines.find((l) => l.includes('"msg":"request"'))!;
    expect(raw).not.toContain('/secret/internal/path');
    const rec = JSON.parse(raw) as { ctx: Record<string, unknown> };
    expect(rec.ctx.route).toBe('(unmatched)');
    expect(rec.ctx.status).toBe(404);
  });
});
