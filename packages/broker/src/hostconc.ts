/**
 * Per-host concurrency interlock (Phase 0 doc 04 §8, slice 5e). The per-HOST version of the 5c egress-slot semaphore,
 * reworked as a CRASH-SAFE LEASE: before a request leaves, the broker must hold one live slot for its target host, and
 * the number of live slots per (engagement, host) may never exceed `engagement.per_host_concurrency`. Each slot is a
 * lease with a deadline — a slot counts only while unexpired — so a broker that crashes between acquire and release
 * stops occupying its slot the instant the lease expires; capacity self-heals without any sweeper (like the budget
 * ledger's availability excluding past-deadline claims, §8.1).
 *
 * This module is the PURE decision layer (`evaluateHostSlot`) + the broker `beforeEgress` gate over an injected
 * `HostSlotController` port; the atomic count-under-lock + insert of the persisted leases lives in the database
 * (`acquire_host_slot` / `release_host_slot`, migration `0008`), so the broker package stays I/O-free and
 * unit-testable, exactly like the budget, live-state, throttle, and rate-limit interlocks. A denial opens NO socket.
 */

import type { ReconstructedRequest } from './reconstruct.js';

/** Why a per-host slot acquire was refused — a fixed code the caller queues/retries on (never a live-slot count). */
export type HostConcurrencyReason = 'host_concurrency_exceeded';

/** A fixed-reason per-host concurrency denial. Carries only the reason code — never counts / engagement detail. */
export class HostConcurrencyError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason); // the message IS the fixed reason code
    this.name = 'HostConcurrencyError';
    this.reason = reason;
  }
}

/** A snapshot of the per-host slot occupancy (the count of LIVE, unexpired leases for one engagement+host). */
export interface HostSlotSnapshot {
  readonly liveSlots: number;
}

/** The per-host concurrency cap (from `engagement.per_host_concurrency`). */
export interface HostSlotConfig {
  readonly perHostConcurrency: number;
}

export type HostSlotDecision =
  | { readonly allow: true }
  | { readonly allow: false; readonly reason: HostConcurrencyReason };

/**
 * Decide whether one more per-host slot may be taken NOW (pure). Admit only while the live-slot count is strictly below
 * the cap; expired leases are already excluded from `liveSlots` by the caller (the DB counts only `expires_at > now()`),
 * so a crashed owner's stale slot never blocks. Mirrors the `v_live >= v_cap` check in `acquire_host_slot`.
 */
export function evaluateHostSlot(
  snapshot: HostSlotSnapshot,
  config: HostSlotConfig,
): HostSlotDecision {
  if (snapshot.liveSlots >= config.perHostConcurrency) {
    return { allow: false, reason: 'host_concurrency_exceeded' };
  }
  return { allow: true };
}

/** Identifies the engagement + target host whose per-host slot is being acquired. */
export interface HostSlotRef {
  readonly tenantId: string;
  readonly engagementId: string;
  /** The canonical target host (the per-host slot key). */
  readonly host: string;
}

/** Identifies a specific held slot lease to release. */
export interface HostSlotReleaseRef {
  readonly tenantId: string;
  readonly engagementId: string;
  /** The lease handle returned by a successful `acquire`. */
  readonly slotId: string;
}

export type HostSlotOutcome =
  | { readonly ok: true; readonly slotId: string }
  | { readonly ok: false; readonly reason: HostConcurrencyReason };

/**
 * The injected per-host slot port: performs the §8 atomic count-under-lock + lease insert (`acquire_host_slot`) under
 * the per-engagement runtime lock, minting a lease id and returning it on success, or `{ok:false}` with the fixed
 * reason when the host is at its cap. `release` deletes the held lease (idempotent — a slot already reclaimed by the
 * sweeper is a no-op), freeing capacity immediately.
 */
export interface HostSlotController {
  acquire(ref: HostSlotRef): Promise<HostSlotOutcome>;
  release(ref: HostSlotReleaseRef): Promise<void>;
}

/** The `beforeEgress`-shaped hook signature (matches `runStage2`'s interlock). */
export type BeforeEgressHook = (ctx: {
  readonly claims: { readonly tenantId: string; readonly engagementId: string };
  readonly request: ReconstructedRequest;
}) => void | Promise<void>;

/**
 * Build the per-host concurrency gate as a `beforeEgress` hook. It ACQUIRES a slot for the request's engagement +
 * target host via the injected controller and DENIES with a fixed-reason `HostConcurrencyError` when refused (or on any
 * controller throw — fail closed), so `runStage2` records `{stage:'interlock', reason}` and opens no socket. The slot
 * is keyed by the RECONSTRUCTED request's canonical host (the address family the broker will actually dial). The lease
 * must be RELEASED by the caller after the request completes (`controller.release`) — a slot the caller never releases
 * is reclaimed at its deadline, so a crash cannot wedge the host below its cap.
 */
export function createHostConcurrencyGate(controller: HostSlotController): BeforeEgressHook {
  return async ({ claims, request }): Promise<void> => {
    const outcome = await controller.acquire({
      tenantId: claims.tenantId,
      engagementId: claims.engagementId,
      host: request.host,
    });
    if (!outcome.ok) throw new HostConcurrencyError(outcome.reason);
  };
}
