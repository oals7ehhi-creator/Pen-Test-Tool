/**
 * WebSocket per-connection bounds (Phase 0 doc 04 §8 / §7.2, slice 5f). A `kind='websocket'` spec authorizes only the
 * HTTP Upgrade handshake, which is scoped / resolved / IP-pinned / connected EXACTLY like an HTTP request (Stage-2);
 * scope is frozen at the pinned handshake and an established socket can never change target. What this module governs
 * is the ESTABLISHED connection: it is bounded by three per-connection caps —
 *   - `ws_max_duration_s`      the connection's maximum wall-clock lifetime,
 *   - `ws_max_messages`        the maximum number of messages over the connection,
 *   - `ws_max_message_bytes`   the maximum size of any single message,
 * and the FIRST breach terminates the connection with a fixed reason (never destructive fuzzing, SI-063). This is the
 * PURE governor: a per-connection budget the broker's (future) WebSocket wire path consults for every frame it relays,
 * in either direction — it holds only in-memory live state for one connection, so unlike the persisted interlocks
 * (budget / rate / concurrency) there is no database layer. e-stop / window-close / expiry termination of active
 * connections is the live-state gate's job (slice 5b), re-checked out of band; this module governs the size/count/time
 * envelope. The `ws_in_flight <= max_ws_connections` admission semaphore and the approved-frame-set (`ws_frame_set`)
 * source restriction are separate controls (a later slice).
 */

/** Why an established WebSocket connection was terminated — a fixed code (never a byte count / connection detail). */
export type WsBoundsReason =
  | 'ws_duration_exceeded'
  | 'ws_message_count_exceeded'
  | 'ws_message_too_large';

/** A fixed-reason WebSocket-bounds termination. Carries only the reason code — never sizes / counts / peer detail. */
export class WsBoundsError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason); // the message IS the fixed reason code
    this.name = 'WsBoundsError';
    this.reason = reason;
  }
}

/**
 * The per-connection caps, derived from the engagement. `maxDurationMs` is `ws_max_duration_s * 1000` (this module works
 * in milliseconds, like the rest of the broker); `maxMessages` is `ws_max_messages`; `maxMessageBytes` is
 * `ws_max_message_bytes`.
 */
export interface WsCaps {
  readonly maxDurationMs: number;
  readonly maxMessages: number;
  readonly maxMessageBytes: number;
}

/** A WebSocket connection's live budget state: when it opened and how many messages it has relayed so far. */
export interface WsConnectionState {
  readonly openedAtMs: number;
  readonly messagesSeen: number;
}

export type WsFrameDecision =
  | { readonly allow: true; readonly state: WsConnectionState }
  | { readonly allow: false; readonly reason: WsBoundsReason };

/**
 * Decide whether one more message may be relayed on an established connection NOW (pure). Checks, in order:
 *   (1) DURATION — a connection at or past its lifetime (`now - openedAt >= maxDurationMs`) terminates regardless of the
 *       message, so a silent/idle-then-active peer cannot outlive the cap;
 *   (2) COUNT    — this message must not push the total past `maxMessages` (`messagesSeen + 1 > maxMessages`);
 *   (3) SIZE     — this message's payload must not exceed `maxMessageBytes`.
 * The first failing check wins (deterministic reason). On allow, returns the advanced state (`messagesSeen + 1`) for the
 * caller to thread into the next frame; on denial the connection must be closed and no further frame relayed.
 */
export function evaluateWsFrame(
  state: WsConnectionState,
  caps: WsCaps,
  frame: { readonly bytes: number },
  nowMs: number,
): WsFrameDecision {
  if (nowMs - state.openedAtMs >= caps.maxDurationMs) {
    return { allow: false, reason: 'ws_duration_exceeded' };
  }
  if (state.messagesSeen + 1 > caps.maxMessages) {
    return { allow: false, reason: 'ws_message_count_exceeded' };
  }
  if (frame.bytes > caps.maxMessageBytes) {
    return { allow: false, reason: 'ws_message_too_large' };
  }
  return {
    allow: true,
    state: { openedAtMs: state.openedAtMs, messagesSeen: state.messagesSeen + 1 },
  };
}

/** A stateful per-connection governor: threads the budget across frames and THROWS a fixed-reason error on any breach. */
export interface WsGovernor {
  /**
   * Admit one message of `frameBytes` bytes at `nowMs`, or THROW a `WsBoundsError` with the fixed termination reason.
   * On success the connection's message count advances; on a throw the caller must close the connection (no frame is
   * relayed after a breach).
   */
  admit(frameBytes: number, nowMs: number): void;
  /** How many messages have been admitted so far (for observability / audit). */
  readonly messages: number;
}

/**
 * Build a stateful governor for one established connection opened at `openedAtMs`, enforcing `caps`. It wraps the pure
 * `evaluateWsFrame`, holding the running `messagesSeen` internally so the wire path can simply call `admit` per frame
 * and let a breach fail closed (terminate the connection) via a fixed-reason `WsBoundsError`.
 */
export function createWsGovernor(caps: WsCaps, openedAtMs: number): WsGovernor {
  let state: WsConnectionState = { openedAtMs, messagesSeen: 0 };
  return {
    admit(frameBytes: number, nowMs: number): void {
      const decision = evaluateWsFrame(state, caps, { bytes: frameBytes }, nowMs);
      if (!decision.allow) throw new WsBoundsError(decision.reason);
      state = decision.state;
    },
    get messages(): number {
      return state.messagesSeen;
    },
  };
}
