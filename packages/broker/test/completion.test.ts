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

  it('records an unlinked completion when there is NO intent to point at (pre-charge denial)', async () => {
    // intent is committed at step 10, so an ingress/reconstruct/pre-charge-interlock denial never produced one.
    // A denial with no intent is still evidence and is still recorded — unlinked, not dropped or fabricated.
    const { emitter, appended } = emitterOf();
    const r = await recordCompletion(failOutcome('ingress', 'spec_mismatch'), null, emitter);
    expect(r.recorded).toBe(true);
    expect(appended[0]?.relatedEventId).toBeNull();
    expect(appended[0]?.payload.reason).toBe('spec_mismatch');
  });

  it('is TOTAL — a synchronously throwing emitter, a non-Error rejection, and a malformed outcome all report', async () => {
    const syncThrow: AuditEmitter = {
      append: () => {
        throw new TypeError('sync boom');
      },
    };
    const r1 = await recordCompletion(okOutcome(), 'i-1', syncThrow);
    expect(r1.recorded).toBe(false);

    const nonError: AuditEmitter = { append: () => Promise.reject('just a string') };
    const r2 = await recordCompletion(okOutcome(), 'i-1', nonError);
    expect(r2.recorded).toBe(false);
    if (!r2.recorded) expect(r2.error).toBe('just a string');

    // a malformed outcome would make buildCompletionEvent throw a raw TypeError — the contract says it must not
    // escape, and the fallback event must still be a valid, secret-free shape.
    const { emitter } = emitterOf();
    const r3 = await recordCompletion(
      { ok: true } as unknown as Stage2Outcome, // no `response` — reading it throws
      'i-1',
      emitter,
    );
    expect(r3.recorded).toBe(false);
    expect(r3.event.payload.reason).toBe('unrecognized_reason');
    expect(JSON.stringify(r3.event.payload)).not.toContain('undefined');
  });
});

describe('the reason field is the ONLY producer-controlled string — it is bounded, not echoed', () => {
  it("replaces a hostile free-form reason (Node's TLS error names the peer's cert SANs)", () => {
    // runStage2's reasonOf surfaces ANY error's `.reason`, and the interlocks are INJECTED ports, so a dependency's
    // error really can reach here. ERR_TLS_CERT_ALTNAME_INVALID carries internal hostnames in exactly that field.
    const hostile =
      "Host: example.com. is not in the cert's altnames: DNS:secret-internal.corp, DNS:vault.internal";
    const { payload } = buildCompletionEvent(failOutcome('send', hostile));
    expect(payload.reason).toBe('unrecognized_reason');
    expect(JSON.stringify(payload)).not.toContain('secret-internal.corp');
    expect(JSON.stringify(payload)).not.toContain('altnames');
  });

  it('replaces anything with whitespace, punctuation, URLs, newlines, or excess length', () => {
    for (const bad of [
      'a b',
      'a"b',
      'a\nb',
      'https://evil.example/x?k=sk_live_secret',
      'SELECT * FROM operator_query_value WHERE v=$1',
      'Reason: Denied',
      'x'.repeat(200),
    ]) {
      expect(buildCompletionEvent(failOutcome('read', bad)).payload.reason).toBe(
        'unrecognized_reason',
      );
    }
  });

  it('does NOT over-redact: every legitimate in-tree reason round-trips unchanged', () => {
    for (const good of [
      'budget_exhausted',
      'emergency_stop',
      'concurrency_exceeded',
      'rate_limited_host',
      'ws_connection_limit',
      'connection_closed_early',
      'restricted_range_elevation_not_granted',
      'network_guard:cloud_metadata', // resolvePin composes this
      'redirect_out_of_scope:no_host_match', // redirect composes this
    ]) {
      expect(buildCompletionEvent(failOutcome('resolve', good)).payload.reason).toBe(good);
    }
  });

  it('reduces an unrecognized stage rather than echoing it', () => {
    expect(buildCompletionEvent(failOutcome('ledger' as never, 'x_y')).payload.stage).toBe(
      'unknown_stage',
    );
    expect(buildCompletionEvent(failOutcome('interlock', 'x_y')).payload.stage).toBe('interlock');
  });

  it('STRUCTURAL: every payload value is a scalar — bytes or nested objects cannot slip past in any encoding', () => {
    const scalar = (v: unknown): boolean =>
      v === null || ['string', 'number', 'boolean'].includes(typeof v);
    for (const outcome of [okOutcome(), failOutcome('read', 'body_too_large')]) {
      const { payload } = buildCompletionEvent(outcome);
      for (const [k, v] of Object.entries(payload)) {
        expect(scalar(v), `payload.${k} must be a scalar`).toBe(true);
      }
      expect(Number.isInteger(payload.bytesRead)).toBe(true);
      if (payload.pinnedIp !== null) expect(payload.pinnedIp).toMatch(/^[0-9a-f.:]+$/i);
    }
  });
});
