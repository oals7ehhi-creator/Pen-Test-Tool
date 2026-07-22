import { describe, it, expect } from 'vitest';
import { handle, type HandlerDeps } from '../src/server.js';
import { createLogger } from '@pentest/shared';
import { API_EVENTS } from '../src/logevents.js';
import { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * Phase 1 exit tests at the server layer:
 *  - x-dev-role is honored ONLY when dev role-injection is enabled; ignored otherwise (item 6).
 *  - each request gets an AUTHORITATIVE per-request correlation id, never "root" (item 1).
 *  - request logging is a strict allowlist: method / matched-route-template / numeric status ONLY, and no raw
 *    URL, query, header, cookie, body or role value can appear (item 2 / SI-045).
 */

interface Captured {
  statusCode: number;
  body: string;
  lines: string[];
}

interface LogRec {
  correlationId: string;
  event: string;
  fields: Record<string, unknown>;
}

function invoke(opts: {
  method: string;
  url: string;
  headers?: Record<string, string>;
  devAuthEnabled: boolean;
}): Captured {
  const req = Object.assign(new EventEmitter(), {
    method: opts.method,
    url: opts.url,
    headers: opts.headers ?? {},
  }) as unknown as IncomingMessage;

  const captured: Captured = { statusCode: 0, body: '', lines: [] };
  const res = {
    statusCode: 0,
    setHeader(): void {},
    end(chunk?: string): void {
      captured.statusCode = res.statusCode;
      captured.body = chunk ?? '';
    },
  } as unknown as ServerResponse;

  const deps: HandlerDeps = {
    log: createLogger({
      level: 'info',
      events: API_EVENTS,
      sink: (l) => captured.lines.push(l),
      now: () => new Date(0),
    }),
    devAuthEnabled: opts.devAuthEnabled,
  };
  handle(req, res, deps);
  return captured;
}

function requestRecord(c: Captured): LogRec {
  const raw = c.lines.find((l) => l.includes('"event":"request"'));
  if (raw === undefined) throw new Error('no request log line emitted');
  return JSON.parse(raw) as LogRec;
}

describe('x-dev-role gating (item 6)', () => {
  it('is honored when dev role-injection is enabled', () => {
    const r = invoke({
      method: 'GET',
      url: '/audit',
      headers: { 'x-dev-role': 'administrator' },
      devAuthEnabled: true,
    });
    expect(r.statusCode).toBe(501); // authorized (admin has audit.read) → business stub
  });

  it('is IGNORED when dev role-injection is disabled → protected route is 401', () => {
    const r = invoke({
      method: 'GET',
      url: '/audit',
      headers: { 'x-dev-role': 'administrator' },
      devAuthEnabled: false,
    });
    expect(r.statusCode).toBe(401);
  });

  it('health stays public regardless', () => {
    const r = invoke({ method: 'GET', url: '/healthz', devAuthEnabled: false });
    expect(r.statusCode).toBe(200);
  });
});

describe('authoritative per-request correlation id (item 1)', () => {
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

  it('a request log never uses "root" — it carries a real per-request id', () => {
    const rec = requestRecord(invoke({ method: 'GET', url: '/healthz', devAuthEnabled: false }));
    expect(rec.correlationId).not.toBe('root');
    expect(rec.correlationId).toMatch(UUID);
  });

  it('two requests receive different correlation ids', () => {
    const a = requestRecord(invoke({ method: 'GET', url: '/healthz', devAuthEnabled: false }));
    const b = requestRecord(invoke({ method: 'GET', url: '/healthz', devAuthEnabled: false }));
    expect(a.correlationId).not.toBe(b.correlationId);
  });
});

describe('SI-045 request logging is a strict allowlist (item 2)', () => {
  it('logs only method / matched-route-template / numeric status — never URL, headers, or role', () => {
    const c = invoke({
      method: 'GET',
      url: '/engagements?token=SECRET-IN-URL&id=42',
      headers: { authorization: 'Bearer super.secret', 'x-dev-role': 'tester' },
      devAuthEnabled: true,
    });
    const joined = c.lines.join('\n');
    expect(joined).not.toContain('SECRET-IN-URL');
    expect(joined).not.toContain('super.secret');
    expect(joined).not.toContain('tester'); // the role value is never logged
    const rec = requestRecord(c);
    expect(rec.fields).toEqual({ method: 'GET', route: '/engagements', status: 200 }); // exactly these
  });

  it('an unmatched route logs the safe placeholder, never the raw path', () => {
    const c = invoke({ method: 'GET', url: '/secret/internal/path', devAuthEnabled: false });
    expect(c.lines.join('\n')).not.toContain('/secret/internal/path');
    const rec = requestRecord(c);
    expect(rec.fields.route).toBe('(unmatched)');
    expect(rec.fields.status).toBe(404);
  });

  it('a bizarre method string is dropped by the allowlist (not echoed)', () => {
    const c = invoke({ method: 'TRACE-<script>', url: '/healthz', devAuthEnabled: false });
    expect(c.lines.join('\n')).not.toContain('<script>');
    expect(requestRecord(c).fields.method).toBeUndefined(); // unknown method → omitted, not logged
  });
});
