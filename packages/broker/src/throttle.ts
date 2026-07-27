/**
 * Concurrency / spacing / circuit-breaker interlock (Phase 0 doc 04 §8, slice 5c). The third pre-egress interlock:
 * before a request leaves, the broker must ACQUIRE an egress slot bounded by the engagement's runtime posture — the
 * in-flight concurrency cap (`max_concurrency` / `in_flight`), the minimum spacing between dispatches
 * (`min_request_interval_ms` vs `last_request_at`), and the per-engagement CIRCUIT BREAKER (`circuit_state` auto-pauses
 * a failing target). On completion the slot is RELEASED and the request's success/failure feeds the breaker.
 *
 * This module is the PURE decision layer (`evaluateAcquire`) + the breaker transition (`recordResult`) + the broker
 * `beforeEgress` gate over an injected `ThrottleController` port; the atomic read-modify-write of the runtime counter
 * lives in the database (`acquire_egress_slot` / `release_egress_slot`, migration `0006`), so the broker package stays
 * I/O-free and unit-testable, exactly like the budget and live-state interlocks. A denial opens NO socket.
 *
 * SCOPE: per-ENGAGEMENT concurrency + spacing + circuit only. Per-HOST concurrency and RPS token buckets
 * (`per_host_concurrency`, `global_max_rps`, `per_host_max_rps`) need per-host runtime state and land in a later slice.
 */

import type { GrantClaims } from '@pentest/spec';
import type { ReconstructedRequest } from './reconstruct.js';

export type CircuitState = 'closed' | 'open' | 'half_open';

/** Why an egress-slot acquire was refused — a fixed code the caller queues/retries on (never a counter value). */
export type ThrottleReason = 'circuit_open' | 'concurrency_exceeded' | 'min_interval';

/** A fixed-reason throttle denial. Carries only the reason code — never counters / engagement detail. */
export class ThrottleError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason); // the message IS the fixed reason code
    this.name = 'ThrottleError';
    this.reason = reason;
  }
}

/** The engagement's throttle posture (from `engagement` + circuit-breaker policy). */
export interface ThrottleConfig {
  /** `engagement.max_concurrency` — the max HTTP requests allowed in flight at once. */
  readonly maxConcurrency: number;
  /** `engagement.min_request_interval_ms` — the minimum spacing between dispatches. */
  readonly minRequestIntervalMs: number;
  /** Consecutive failures that trip the breaker `closed → open`. */
  readonly circuitErrorThreshold: number;
  /** How long the breaker stays `open` before a `half_open` probe is allowed. */
  readonly circuitCooldownMs: number;
}

/** A snapshot of the engagement runtime counter's throttle-relevant fields. */
export interface ThrottleSnapshot {
  readonly inFlight: number;
  readonly lastRequestAtMs: number | null;
  readonly circuitState: CircuitState;
  readonly consecutiveErrors: number;
  readonly circuitOpenedAtMs: number | null;
}

export type AcquireDecision =
  | { readonly allow: true; readonly openedToHalfOpen: boolean }
  | { readonly allow: false; readonly reason: ThrottleReason };

/**
 * Decide whether an egress slot may be acquired NOW (pure). Order: CIRCUIT (an `open` breaker still within its cooldown
 * denies; once the cooldown elapses a single `half_open` probe is let through — `openedToHalfOpen` tells the caller to
 * persist that transition) → CONCURRENCY (`in_flight >= max_concurrency` denies) → SPACING (`now - last_request_at <
 * min_request_interval_ms` denies). Only a full allow reserves a slot.
 */
export function evaluateAcquire(
  snapshot: ThrottleSnapshot,
  config: ThrottleConfig,
  nowMs: number,
): AcquireDecision {
  let openedToHalfOpen = false;
  if (snapshot.circuitState === 'open') {
    // A never-stamped open breaker (circuitOpenedAtMs null) is treated as just-opened ⇒ still cooling down.
    const openedAt = snapshot.circuitOpenedAtMs ?? nowMs;
    if (nowMs - openedAt >= config.circuitCooldownMs) {
      openedToHalfOpen = true; // cooldown elapsed ⇒ allow one probe, transitioning open → half_open
    } else {
      return { allow: false, reason: 'circuit_open' };
    }
  }
  if (snapshot.inFlight >= config.maxConcurrency) {
    return { allow: false, reason: 'concurrency_exceeded' };
  }
  if (
    snapshot.lastRequestAtMs !== null &&
    nowMs - snapshot.lastRequestAtMs < config.minRequestIntervalMs
  ) {
    return { allow: false, reason: 'min_interval' };
  }
  return { allow: true, openedToHalfOpen };
}

/** The circuit-breaker fields after a request completes. */
export interface CircuitUpdate {
  readonly circuitState: CircuitState;
  readonly consecutiveErrors: number;
  readonly circuitOpenedAtMs: number | null;
}

/**
 * The breaker transition when a request COMPLETES (pure). A success closes the breaker and clears the error run. A
 * failure increments the run and: a failed `half_open` probe RE-OPENS immediately; a `closed` breaker OPENS once the
 * run reaches `circuitErrorThreshold`; otherwise the breaker stays where it is (accumulating).
 */
export function recordResult(
  snapshot: ThrottleSnapshot,
  success: boolean,
  nowMs: number,
  config: ThrottleConfig,
): CircuitUpdate {
  if (success) {
    return { circuitState: 'closed', consecutiveErrors: 0, circuitOpenedAtMs: null };
  }
  const errors = snapshot.consecutiveErrors + 1;
  if (snapshot.circuitState === 'half_open') {
    return { circuitState: 'open', consecutiveErrors: errors, circuitOpenedAtMs: nowMs };
  }
  if (snapshot.circuitState === 'closed' && errors >= config.circuitErrorThreshold) {
    return { circuitState: 'open', consecutiveErrors: errors, circuitOpenedAtMs: nowMs };
  }
  return {
    circuitState: snapshot.circuitState,
    consecutiveErrors: errors,
    circuitOpenedAtMs: snapshot.circuitOpenedAtMs,
  };
}

/** Identifies the engagement whose runtime slot is being acquired/released. */
export interface EngagementRef {
  readonly tenantId: string;
  readonly engagementId: string;
}

export type AcquireOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: ThrottleReason };

/**
 * The injected throttle port: performs the §8 atomic read-modify-write of the engagement runtime counter under its
 * `FOR UPDATE` lock. `acquire` returns `{ok:false}` for an expected refusal (circuit/concurrency/spacing) and reserves
 * a slot on success; `release` frees the slot and feeds the request result to the breaker.
 */
export interface ThrottleController {
  acquire(ref: EngagementRef): Promise<AcquireOutcome>;
  release(ref: EngagementRef, success: boolean): Promise<void>;
}

/** The `beforeEgress`-shaped hook signature (matches `runStage2`'s interlock). */
export type BeforeEgressHook = (ctx: {
  readonly claims: GrantClaims;
  readonly request: ReconstructedRequest;
}) => void | Promise<void>;

/**
 * Build the concurrency/spacing/circuit gate as a `beforeEgress` hook. It ACQUIRES a slot via the injected controller
 * and DENIES with a fixed-reason `ThrottleError` when refused (or when the controller throws — fail closed), so
 * `runStage2` records `{stage:'interlock', reason}` and opens no socket. The slot must be RELEASED by the caller after
 * the request completes (`controller.release`), which also feeds the breaker.
 */
export function createThrottleGate(controller: ThrottleController): BeforeEgressHook {
  return async ({ claims }): Promise<void> => {
    const outcome = await controller.acquire({
      tenantId: claims.tenantId,
      engagementId: claims.engagementId,
    });
    if (!outcome.ok) throw new ThrottleError(outcome.reason);
  };
}
