import { describe, it, expect } from 'vitest';
import { redact, REDACTED, createLogger, type LogRecord } from '../src/index.js';

/**
 * Phase 1 exit test — logging redaction. A log call carrying an Authorization header, a Set-Cookie, and an API
 * token must render with all three masked before reaching the sink.
 */

describe('redact', () => {
  it('masks sensitive keys recursively and leaves benign values intact', () => {
    const out = redact({
      Authorization: 'Bearer abc.def.ghi',
      headers: {
        'set-cookie': 'sid=deadbeef; HttpOnly',
        'x-api-token': 't0ken',
        accept: 'application/json',
      },
      user: { id: 'u1', password: 'hunter2' },
      note: 'ok',
    });
    expect(out.Authorization).toBe(REDACTED);
    expect(out.headers['set-cookie']).toBe(REDACTED);
    expect(out.headers['x-api-token']).toBe(REDACTED);
    expect(out.headers.accept).toBe('application/json');
    expect(out.user.password).toBe(REDACTED);
    expect(out.user.id).toBe('u1');
    expect(out.note).toBe('ok');
  });

  it('masks a credential-looking string value even under a benign key', () => {
    expect(redact({ h: 'Bearer sometoken' }).h).toBe(REDACTED);
  });

  it('does not mutate the input', () => {
    const input = { Authorization: 'Bearer x' };
    redact(input);
    expect(input.Authorization).toBe('Bearer x');
  });

  it('handles cycles without throwing', () => {
    const a: Record<string, unknown> = { name: 'a' };
    a.self = a;
    expect(() => redact(a)).not.toThrow();
  });
});

describe('logger redaction (end-to-end through the sink)', () => {
  it('never writes an Authorization header, Set-Cookie, or token to the sink', () => {
    const lines: string[] = [];
    const log = createLogger({
      level: 'info',
      correlationId: 'req-123',
      sink: (l) => lines.push(l),
      now: () => new Date('2026-01-01T00:00:00.000Z'),
    });

    log.info('inbound request', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer super.secret.jwt',
        'Set-Cookie': 'session=abc; HttpOnly',
        'x-api-token': 'tok_live_should_not_leak',
      },
    });

    expect(lines).toHaveLength(1);
    const raw = lines[0]!;
    // Nothing secret in the serialized line.
    expect(raw).not.toContain('super.secret.jwt');
    expect(raw).not.toContain('session=abc');
    expect(raw).not.toContain('tok_live_should_not_leak');

    const record = JSON.parse(raw) as LogRecord;
    expect(record.correlationId).toBe('req-123');
    expect(record.level).toBe('info');
    expect(record.time).toBe('2026-01-01T00:00:00.000Z');
    const headers = (record.headers ?? {}) as Record<string, unknown>;
    expect(headers.Authorization).toBe(REDACTED);
    expect(headers['Set-Cookie']).toBe(REDACTED);
    expect(headers['x-api-token']).toBe(REDACTED);
  });

  it('respects the level threshold', () => {
    const lines: string[] = [];
    const log = createLogger({ level: 'warn', sink: (l) => lines.push(l) });
    log.info('should be dropped');
    log.warn('should appear');
    expect(lines).toHaveLength(1);
    expect(lines[0]).toContain('should appear');
  });
});
