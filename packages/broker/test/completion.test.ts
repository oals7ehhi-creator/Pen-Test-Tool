import { describe, it, expect } from 'vitest';
import { Buffer } from 'node:buffer';
import {
  buildCompletionEvent,
  recordCompletion,
  type AuditEmitter,
  type CompletionAppend,
  type Stage2Outcome,
} from '../src/index.js';

/**
 * The informational completion event (§7.1 step 14 / §9, slice 5j). Proves the two properties that define it: the
 * payload is SECRET-FREE BY CONSTRUCTION (nothing is copied out of the response body, the response headers, or the
 * secret-bearing request URL), and recording is INFORMATIONAL — it never changes the charge and never throws, because
 * the bytes have already left and an audit-emit failure must not mask the response the caller still has to handle.
 */

const SECRET_BODY = 'SESSION=super-secret-token; account=alice@example.com';
const SECRET_HEADER = 'sk_live_51NqAbCdEfGhIjKlMnOp';

const okOutcome = (over: Record<string, unknown> = {}): Stage2Outcome =>
  ({
    ok: true,
    claims: { tenantId: 't1', engagementId: 'e1' },
    request: {
      host: 'example.com',
      // reconstruction injects SECRET query values into the URL — this must never reach the audit payload.
      targetUrl: `https://example.com/api?api_key=${SECRET_HEADER}`,
      method: 'GET',
    },
    pinnedIp: '93.184.216.34',
    response: {
      statusCode: 200,
      reasonPhrase: 'OK',
      httpVersion: 'HTTP/1.1',
      headers: [
        { name: 'set-cookie', value: SECRET_BODY },
        { name: 'authorization', value: SECRET_HEADER },
      ],
      body: new Uint8Array(Buffer.from(SECRET_BODY, 'utf8')),
      truncated: false,
      bytesRead: 1234,
      ...(over.response as object),
    },
    redirect: null,
    ...over,
  }) as unknown as Stage2Outcome;

const failOutcome = (stage: string, reason: string): Stage2Outcome =>
  ({ ok: false, stage, reason }) as unknown as Stage2Outcome;

const emitterOf = (
  behaviour?: () => Promise<never>,
): { emitter: AuditEmitter; appended: CompletionAppend[] } => {
  const appended: CompletionAppend[] = [];
  const emitter: AuditEmitter = {
    append: async (event) => {
      appended.push(event);
      if (behaviour) return behaviour();
      return 'evt-1';
    },
  };
  return { emitter, appended };
};

describe('buildCompletionEvent — what a finished run records', () => {
  it('a success becomes request.completed with the pinned IP, status and byte counts', () => {
    expect(buildCompletionEvent(okOutcome())).toEqual({
      eventType: 'request.completed',
      payload: {
        pinnedIp: '93.184.216.34',
        statusCode: 200,
        bytesRead: 1234,
        truncated: false,
        stage: null,
        reason: null,
      },
    });
  });

  it('records truncation (the body cap fired) as a fact, still without content', () => {
    const e = buildCompletionEvent(
      okOutcome({ response: { statusCode: 200, bytesRead: 4096, truncated: true } }),
    );
    expect(e.payload.truncated).toBe(true);
    expect(e.payload.bytesRead).toBe(4096);
  });

  it('a denial becomes request.failed carrying ONLY the fixed stage/reason codes', () => {
    expect(buildCompletionEvent(failOutcome('interlock', 'budget_exhausted'))).toEqual({
      eventType: 'request.failed',
      payload: {
        pinnedIp: null,
        statusCode: null,
        bytesRead: 0,
        truncated: false,
        stage: 'interlock',
        reason: 'budget_exhausted',
      },
    });
  });

  it('a pre-egress denial records NO pinned IP — nothing was dialed', () => {
    const e = buildCompletionEvent(failOutcome('resolve', 'forbidden_address'));
    expect(e.payload.pinnedIp).toBeNull();
    expect(e.payload.bytesRead).toBe(0);
  });
});

describe('SECRET-FREE BY CONSTRUCTION — the redaction proof', () => {
  it('no response body, header value, or secret-bearing URL can appear in the payload', () => {
    const { payload } = buildCompletionEvent(okOutcome());
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain(SECRET_BODY);
    expect(serialized).not.toContain(SECRET_HEADER);
    expect(serialized).not.toContain('set-cookie');
    expect(serialized).not.toContain('example.com'); // not even the target — the intent event already binds it
  });

  it('the payload carries EXACTLY the allowlisted keys — a new response field cannot leak in', () => {
    // an allowlist, not a filter: adding fields to the response must not widen the audit payload.
    const { payload } = buildCompletionEvent(
      okOutcome({
        response: {
          statusCode: 200,
          bytesRead: 10,
          truncated: false,
          leakedSecret: SECRET_HEADER,
        },
      }),
    );
    expect(Object.keys(payload).sort()).toEqual([
      'bytesRead',
      'pinnedIp',
      'reason',
      'stage',
      'statusCode',
      'truncated',
    ]);
    expect(JSON.stringify(payload)).not.toContain(SECRET_HEADER);
  });

  it('what reaches the emitter is the same redacted payload — nothing is added on the way out', async () => {
    const { emitter, appended } = emitterOf();
    await recordCompletion(okOutcome(), 'intent-evt-9', emitter);
    const sent = JSON.stringify(appended[0]);
    expect(sent).not.toContain(SECRET_BODY);
    expect(sent).not.toContain(SECRET_HEADER);
  });
});

describe('recordCompletion — informational, chained to the intent, never throwing', () => {
  it('appends the event linked to the intent via relatedEventId (same chain)', async () => {
    const { emitter, appended } = emitterOf();
    const r = await recordCompletion(okOutcome(), 'intent-evt-9', emitter);
    expect(r.recorded).toBe(true);
    if (r.recorded) expect(r.eventId).toBe('evt-1');
    expect(appended).toEqual([
      {
        eventType: 'request.completed',
        relatedEventId: 'intent-evt-9',
        payload: {
          pinnedIp: '93.184.216.34',
          statusCode: 200,
          bytesRead: 1234,
          truncated: false,
          stage: null,
          reason: null,
        },
      },
    ]);
  });

  it('a FAILED run is recorded too — a denial is evidence, not silence', async () => {
    const { emitter, appended } = emitterOf();
    await recordCompletion(failOutcome('interlock', 'emergency_stop'), 'intent-evt-2', emitter);
    expect(appended[0]?.eventType).toBe('request.failed');
    expect(appended[0]?.payload.reason).toBe('emergency_stop');
  });

  it('NEVER THROWS when the audit append fails — the gap is reported, not raised', async () => {
    const boom = new Error('audit_chain_unavailable');
    const { emitter } = emitterOf(() => Promise.reject(boom));
    const r = await recordCompletion(okOutcome(), 'intent-evt-9', emitter);
    // the bytes already left; raising here could not un-send them and would mask the caller's real outcome.
    expect(r.recorded).toBe(false);
    if (!r.recorded) expect(r.error).toBe(boom);
    // the event it TRIED to record is still returned, so the caller can alarm with the actual content.
    expect(r.event.eventType).toBe('request.completed');
  });
});
