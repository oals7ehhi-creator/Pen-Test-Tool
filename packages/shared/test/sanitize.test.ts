import { describe, it, expect } from 'vitest';
import { sanitizeContext, REDACTED, createLogger, type LogRecord } from '../src/index.js';

/**
 * Phase 1 exit test — SI-045 allowlist/minimized logging. Structural values (headers, bodies, URLs-as-objects,
 * cookie jars, class instances) are NEVER serialized; sensitive keys are masked; reserved fields are protected.
 */

describe('sanitizeContext (allowlist / minimization)', () => {
  it('omits objects, arrays, and class instances — they are never serialized', () => {
    const out = sanitizeContext({
      headers: { Authorization: 'Bearer x', accept: 'application/json' }, // full header map
      body: { password: 'hunter2' },
      list: [1, 2, 3],
      when: new Date('2026-01-01T00:00:00Z'), // class instance
      fn: () => 1,
    });
    expect(out.headers).toBe('[omitted:object]');
    expect(out.body).toBe('[omitted:object]');
    expect(out.list).toBe('[omitted:array]');
    expect(out.when).toBe('[omitted:object]');
    expect(out.fn).toBe('[omitted:function]');
  });

  it('keeps minimal scalars and masks sensitive keys / credential values', () => {
    const out = sanitizeContext({
      method: 'POST',
      status: 403,
      ok: false,
      nothing: null,
      authorization: 'Bearer leak', // sensitive key → masked
      'x-api-token': 'abc', // sensitive key → masked
      note: 'Bearer looks-like-a-credential', // credential-looking value → masked
    });
    expect(out.method).toBe('POST');
    expect(out.status).toBe(403);
    expect(out.ok).toBe(false);
    expect(out.nothing).toBe(null);
    expect(out.authorization).toBe(REDACTED);
    expect(out['x-api-token']).toBe(REDACTED);
    expect(out.note).toBe(REDACTED);
  });

  it('truncates long strings (never logs a full URL/body-as-string)', () => {
    const long = 'https://example.com/' + 'a'.repeat(500);
    expect(String(sanitizeContext({ url: long }).url)).toContain('…[truncated]');
    expect(String(sanitizeContext({ url: long }).url).length).toBeLessThan(long.length);
  });

  it('never lets context set a reserved field', () => {
    const out = sanitizeContext({
      time: 'evil',
      level: 'evil',
      correlationId: 'evil',
      msg: 'evil',
      ctx: 'evil',
    });
    expect(Object.keys(out)).toHaveLength(0);
  });
});

describe('logger (end-to-end allowlist)', () => {
  it('emits reserved fields plus a scalar-only ctx; a full header map is omitted, not logged', () => {
    const lines: string[] = [];
    const log = createLogger({
      level: 'info',
      correlationId: 'req-1',
      sink: (l) => lines.push(l),
      now: () => new Date('2026-01-01T00:00:00.000Z'),
    });

    log.info('request', {
      method: 'POST',
      status: 401,
      headers: { Authorization: 'Bearer super.secret.jwt', 'Set-Cookie': 'sid=abc' },
    });

    const raw = lines[0]!;
    expect(raw).not.toContain('super.secret.jwt');
    expect(raw).not.toContain('sid=abc');

    const rec = JSON.parse(raw) as LogRecord;
    expect(rec.time).toBe('2026-01-01T00:00:00.000Z');
    expect(rec.correlationId).toBe('req-1');
    expect(rec.msg).toBe('request');
    expect(rec.ctx.method).toBe('POST');
    expect(rec.ctx.status).toBe(401);
    expect(rec.ctx.headers).toBe('[omitted:object]'); // header map never serialized
  });

  it('context cannot override reserved fields (msg/correlationId stay authoritative)', () => {
    const lines: string[] = [];
    const log = createLogger({ level: 'info', correlationId: 'real', sink: (l) => lines.push(l) });
    log.info('real-msg', { msg: 'spoof', correlationId: 'spoof', level: 'error' });
    const rec = JSON.parse(lines[0]!) as LogRecord;
    expect(rec.msg).toBe('real-msg');
    expect(rec.correlationId).toBe('real');
    expect(rec.level).toBe('info');
    expect(rec.ctx.msg).toBeUndefined();
  });
});
