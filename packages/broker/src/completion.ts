/**
 * The informational completion event (Phase 0 doc 04 §7.1 step 14 / §9, slice 5j). After a Stage-2 run resolves — sent
 * and read, or denied at some step — the broker records `request.completed` / `request.failed` on the engagement's
 * hash-chained audit stream, referencing the durable `request.intent` (committed BEFORE any egress, slice 5a) via
 * `related_event_id` on the same chain.
 *
 * TWO PROPERTIES DEFINE THIS MODULE, and both are the opposite of how a naive "log the result" would be written:
 *
 * 1. INFORMATIONAL — it does NOT change the charge. §7.1 step 14 and §8.1 are explicit: budget was charged at step 10,
 *    irreversibly, before any byte was sent, so "sent ⇒ charged" already holds. Completion records what happened; it
 *    never releases, re-charges, or amends a lease. Consequently `recordCompletion` NEVER THROWS: the bytes have
 *    already left, so failing here could not un-send them, and letting an audit-emit error propagate would mask a
 *    response the caller must still handle. The failure is REPORTED (`{recorded:false, error}`) rather than swallowed
 *    or raised — an audit gap must be visible, but it must not manufacture a second failure.
 *
 * 2. SECRET-FREE BY CONSTRUCTION — the payload is built from an ALLOWLIST of scalars, never by filtering a response.
 *    A denylist ("strip the sensitive headers") is the wrong shape here: the response body is attacker-influenced
 *    content, header values carry session material, and even the request's own URL is unsafe because reconstruction
 *    injects SECRET query values into it (`query_value_ref`, doc 04 §7.0). So none of those are copied at all. What is
 *    recorded is exactly what §7.1 step 14 names — the resolved+pinned IP, the status, and byte counts — plus, on a
 *    denial, the fixed `{stage, reason}` codes. The request's identity is not duplicated here: the intent event already
 *    binds `spec_sha256` and the canonical target, and this event points at it, so re-recording the target would add
 *    leak surface for no evidentiary gain.
 *
 * The audit append itself is INJECTED (`AuditEmitter`), so this module performs no I/O and the chained write stays in
 * the database (`audit_append`, migration `0004`) where seq / prev_hash / event_hash are derived and cannot be forged.
 */

import type { Stage2Outcome } from './stage2.js';

/** The two informational lifecycle event types (§9 engagement stream). */
export type CompletionEventType = 'request.completed' | 'request.failed';

/**
 * The redacted completion payload. Every field is a scalar chosen deliberately; there is no pass-through of response
 * or request content. `null` where a fact does not apply (a denial never reached an IP or a status).
 */
export interface CompletionPayload {
  /** The IP the broker actually dialed, pinned before connect (§7.1 step 11). Null when no socket was opened. */
  readonly pinnedIp: string | null;
  /** The HTTP status line code. Null on a denial or a transport failure. */
  readonly statusCode: number | null;
  /** Total bytes read off the socket — a COUNT, never content. */
  readonly bytesRead: number;
  /** True when the body hit the engagement's `max_response_body_bytes` cap and reading stopped. */
  readonly truncated: boolean;
  /** Which step denied, for a failure (`ingress` | `reconstruct` | `interlock` | `resolve` | `send` | `read`). */
  readonly stage: string | null;
  /** The failing step's FIXED reason code — never response or secret content. */
  readonly reason: string | null;
}

/** The event to append: its type and its redacted payload. */
export interface CompletionEvent {
  readonly eventType: CompletionEventType;
  readonly payload: CompletionPayload;
}

/**
 * Build the informational completion event from a Stage-2 outcome (pure). A success becomes `request.completed`
 * carrying the pinned IP, status and byte counts; a denial at any step becomes `request.failed` carrying only the
 * fixed `{stage, reason}` codes. Nothing is copied out of the response body, the response headers, or the (secret-
 * bearing) request URL — the payload is assembled field by field from the allowlist above.
 */
export function buildCompletionEvent(outcome: Stage2Outcome): CompletionEvent {
  if (outcome.ok) {
    return {
      eventType: 'request.completed',
      payload: {
        pinnedIp: outcome.pinnedIp,
        statusCode: outcome.response.statusCode,
        bytesRead: outcome.response.bytesRead,
        truncated: outcome.response.truncated,
        stage: null,
        reason: null,
      },
    };
  }
  return {
    eventType: 'request.failed',
    payload: {
      pinnedIp: null,
      statusCode: null,
      bytesRead: 0,
      truncated: false,
      stage: outcome.stage,
      reason: outcome.reason,
    },
  };
}

/** What the injected emitter is asked to append — mirrors `audit_append`'s chained-write parameters. */
export interface CompletionAppend {
  readonly eventType: CompletionEventType;
  /** The `request.intent` event this completion refers to, on the SAME chain (§9). */
  readonly relatedEventId: string;
  readonly payload: CompletionPayload;
}

/**
 * The injected audit port: performs the §9 hash-chained append (`audit_append`, migration `0004`), which derives
 * seq / prev_hash / event_hash under the chain lock — the caller cannot choose them. Returns the new event's id.
 */
export interface AuditEmitter {
  append(event: CompletionAppend): Promise<string>;
}

/** Whether the completion event reached the audit chain — reported, never thrown. */
export type CompletionRecord =
  | { readonly recorded: true; readonly eventId: string; readonly event: CompletionEvent }
  | { readonly recorded: false; readonly error: unknown; readonly event: CompletionEvent };

/**
 * Record the informational completion for a finished Stage-2 run, linked to its durable intent event.
 *
 * NEVER THROWS (see property 1 above): the request already happened, so an audit-emit failure cannot be repaired by
 * raising — it would only replace a real outcome the caller must handle with a secondary error. The failure is
 * returned as `{recorded:false, error}` so the caller can alarm on the audit gap while still processing the response.
 */
export async function recordCompletion(
  outcome: Stage2Outcome,
  intentEventId: string,
  emitter: AuditEmitter,
): Promise<CompletionRecord> {
  const event = buildCompletionEvent(outcome);
  try {
    const eventId = await emitter.append({
      eventType: event.eventType,
      relatedEventId: intentEventId,
      payload: event.payload,
    });
    return { recorded: true, eventId, event };
  } catch (error) {
    return { recorded: false, error, event };
  }
}
