/**
 * WebSocket connection admission (Phase 0 doc 04 §8 / §7.2, slice 5g). The interlock that bounds how many WebSocket
 * connections an engagement may hold at once: on a successful ws/wss handshake the broker takes ONE connection slot, and
 * the number of live slots may never exceed `engagement.max_ws_connections` (the authoritative `ws_in_flight`). A slot
 * is a CRASH-SAFE LEASE whose lifetime is bounded to the connection's max permitted lifetime (`ws_max_duration_s`): it
 * counts only while unexpired, so a broker that crashes mid-connection stops occupying its slot when the lease expires —
 * capacity self-heals without a heartbeat (the per-connection governor, slice 5f, terminates a well-behaved connection
 * at or before that bound and RELEASES the slot early on close).
 *
 * This module is the PURE decision layer (`evaluateWsAdmission`) + the broker `beforeEgress` gate over an injected
 * `WsSlotController` port; the atomic count-under-lock + lease insert of the persisted slots lives in the database
 * (`acquire_ws_slot` / `release_ws_slot`, migration `0009`), so the broker package stays I/O-free and unit-testable,
 * exactly like the other interlocks. The gate acts ONLY on ws/wss requests — an HTTP request consumes no connection
 * slot and passes straight through. A denial opens NO socket.
 */

import type { ReconstructedRequest } from './reconstruct.js';

/** Why a WebSocket handshake was refused admission — a fixed code the caller queues/retries on (never a live count). */
export type WsAdmissionReason = 'ws_connection_limit';

/** A fixed-reason WebSocket-admission denial. Carries only the reason code — never counts / engagement detail. */
export class WsConnectionLimitError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason); // the message IS the fixed reason code
    this.name = 'WsConnectionLimitError';
    this.reason = reason;
  }
}

/** A snapshot of the engagement's WebSocket occupancy (the count of LIVE, unexpired connection leases). */
export interface WsAdmissionSnapshot {
  readonly liveConnections: number;
}

/** The WebSocket connection cap (from `engagement.max_ws_connections`; 0 disables WebSockets entirely). */
export interface WsAdmissionConfig {
  readonly maxWsConnections: number;
}

export type WsAdmissionDecision =
  | { readonly allow: true }
  | { readonly allow: false; readonly reason: WsAdmissionReason };

/**
 * Decide whether one more WebSocket connection may be admitted NOW (pure). Admit only while the live-connection count is
 * strictly below `max_ws_connections`; expired leases are already excluded from `liveConnections` by the caller (the DB
 * counts only `expires_at > now()`), so a crashed owner's stale connection never blocks. A cap of 0 refuses every
 * connection. Mirrors the `v_live >= v_cap` check in `acquire_ws_slot`.
 */
export function evaluateWsAdmission(
  snapshot: WsAdmissionSnapshot,
  config: WsAdmissionConfig,
): WsAdmissionDecision {
  if (snapshot.liveConnections >= config.maxWsConnections) {
    return { allow: false, reason: 'ws_connection_limit' };
  }
  return { allow: true };
}

/** Identifies the engagement whose WebSocket connection slot is being acquired (`ws_in_flight` is per-engagement). */
export interface WsSlotRef {
  readonly tenantId: string;
  readonly engagementId: string;
}

/** Identifies a specific held connection lease to release. */
export interface WsSlotReleaseRef {
  readonly tenantId: string;
  readonly engagementId: string;
  /** The lease handle returned by a successful `acquire`. */
  readonly slotId: string;
}

export type WsSlotOutcome =
  | { readonly ok: true; readonly slotId: string }
  | { readonly ok: false; readonly reason: WsAdmissionReason };

/**
 * The injected WebSocket-slot port: performs the §8 atomic count-under-lock + lease insert (`acquire_ws_slot`) under the
 * per-engagement runtime lock, minting a lease id and returning it on success, or `{ok:false}` with the fixed reason
 * when the engagement is at `max_ws_connections`. `release` deletes the held lease (idempotent — a slot already
 * reclaimed by the sweeper is a no-op), freeing capacity on connection close.
 */
export interface WsSlotController {
  acquire(ref: WsSlotRef): Promise<WsSlotOutcome>;
  release(ref: WsSlotReleaseRef): Promise<void>;
}

/** The `beforeEgress`-shaped hook signature (matches `runStage2`'s interlock). */
export type BeforeEgressHook = (ctx: {
  readonly claims: { readonly tenantId: string; readonly engagementId: string };
  readonly request: ReconstructedRequest;
}) => void | Promise<void>;

/**
 * Build the WebSocket admission gate as a `beforeEgress` hook. For a ws/wss request it ACQUIRES a connection slot via
 * the injected controller and DENIES with a fixed-reason `WsConnectionLimitError` when the engagement is at its cap (or
 * on any controller throw — fail closed), so `runStage2` records `{stage:'interlock', reason}` and opens no socket. An
 * HTTP request consumes no connection slot and passes straight through (the gate is a no-op). The lease must be RELEASED
 * by the caller when the connection closes (`controller.release`); a slot the caller never releases is reclaimed at its
 * deadline, so a crash cannot wedge the engagement below its cap.
 */
export function createWsAdmissionGate(controller: WsSlotController): BeforeEgressHook {
  return async ({ claims, request }): Promise<void> => {
    if (request.scheme !== 'ws' && request.scheme !== 'wss') return; // only WS handshakes consume a connection slot
    const outcome = await controller.acquire({
      tenantId: claims.tenantId,
      engagementId: claims.engagementId,
    });
    if (!outcome.ok) throw new WsConnectionLimitError(outcome.reason);
  };
}
