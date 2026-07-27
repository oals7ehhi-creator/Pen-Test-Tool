/**
 * Request-rate token buckets (Phase 0 doc 04 §8, slice 5d). The rate-limiting pre-egress interlock: before a request
 * leaves, it must draw a token from BOTH the engagement-GLOBAL bucket (`global_max_rps`) and the PER-HOST bucket for
 * its target host (`per_host_max_rps`). A bucket refills at its rate up to a burst capacity; a request that cannot
 * draw from either bucket is refused (the caller queues/retries — "excess queued, not dropped", §8). This module is
 * the PURE decision layer (`refillAndTake` / `evaluateRateLimit`) + the broker `beforeEgress` gate over an injected
 * `RateLimiter` port; the atomic read-modify-write of the persisted buckets lives in the database (`take_rate_tokens`,
 * migration `0007`), so the broker package stays I/O-free and unit-testable, exactly like the other interlocks.
 *
 * Tokens are drawn CHECK-BOTH-THEN-CONSUME-BOTH: a request only consumes a token from each bucket when BOTH can
 * satisfy it, so a global-allowed / host-denied request never leaks a global token (and vice-versa).
 */

import type { ReconstructedRequest } from './reconstruct.js';

/** Why a rate draw was refused — a fixed code the caller queues/retries on (never a token count). */
export type RateLimitReason = 'rate_limited_global' | 'rate_limited_host';

/** A fixed-reason rate-limit denial. Carries only the reason code — never token counts / engagement detail. */
export class RateLimitError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason); // the message IS the fixed reason code
    this.name = 'RateLimitError';
    this.reason = reason;
  }
}

/** A token bucket's persisted state. */
export interface BucketState {
  readonly tokens: number;
  readonly refillAtMs: number;
}

/** A token bucket's rate + burst capacity. */
export interface BucketConfig {
  /** Tokens accrued per second (`*_max_rps`). */
  readonly ratePerSec: number;
  /** Max tokens the bucket can hold (the burst allowance). */
  readonly capacity: number;
}

/** The result of refilling a bucket and attempting to draw one token. */
export interface BucketResult {
  readonly allow: boolean;
  /** The bucket's tokens AFTER refill (and after the draw, when allowed). */
  readonly tokens: number;
  readonly refillAtMs: number;
}

/**
 * Refill a token bucket by the time elapsed since `refillAtMs` (capped at `capacity`) and try to draw one token
 * (pure). When ≥ 1 token is available it is consumed (`allow: true`, `tokens` reduced by one); otherwise the request
 * is refused and no token is consumed. `refillAtMs` advances to `nowMs` either way in the returned value — but the
 * CALLER persists the new state only on a full allow, so a denied draw does not lose accrued time (§8).
 */
export function refillAndTake(state: BucketState, cfg: BucketConfig, nowMs: number): BucketResult {
  const elapsedSec = Math.max(0, (nowMs - state.refillAtMs) / 1000);
  const refilled = Math.min(cfg.capacity, state.tokens + elapsedSec * cfg.ratePerSec);
  if (refilled >= 1) return { allow: true, tokens: refilled - 1, refillAtMs: nowMs };
  return { allow: false, tokens: refilled, refillAtMs: nowMs };
}

/** The persisted state of the two buckets a request must draw from. */
export interface RateSnapshot {
  readonly global: BucketState;
  readonly host: BucketState;
}

/** The two buckets' rates + capacities (from `engagement.global_max_rps` / `per_host_max_rps`). */
export interface RateConfig {
  readonly global: BucketConfig;
  readonly host: BucketConfig;
}

export type RateDecision =
  | { readonly allow: true; readonly global: BucketState; readonly host: BucketState }
  | { readonly allow: false; readonly reason: RateLimitReason };

/**
 * Decide whether a request may draw from BOTH the global and the per-host bucket (pure). The global bucket is checked
 * first, then the per-host bucket; a token is consumed from EACH only when BOTH can satisfy the request (so a denial
 * on one never leaks a token from the other). On allow, returns both buckets' new states for the caller to persist.
 */
export function evaluateRateLimit(
  snap: RateSnapshot,
  cfg: RateConfig,
  nowMs: number,
): RateDecision {
  const global = refillAndTake(snap.global, cfg.global, nowMs);
  if (!global.allow) return { allow: false, reason: 'rate_limited_global' };
  const host = refillAndTake(snap.host, cfg.host, nowMs);
  if (!host.allow) return { allow: false, reason: 'rate_limited_host' };
  return {
    allow: true,
    global: { tokens: global.tokens, refillAtMs: global.refillAtMs },
    host: { tokens: host.tokens, refillAtMs: host.refillAtMs },
  };
}

/** Identifies the engagement + target host whose rate buckets are being drawn. */
export interface RateRef {
  readonly tenantId: string;
  readonly engagementId: string;
  /** The canonical target host (the per-host bucket key). */
  readonly host: string;
}

export type RateOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: RateLimitReason };

/**
 * The injected rate-limiter port: performs the §8 atomic draw from the engagement-global + per-host buckets under
 * their `FOR UPDATE` lock (reading the rates from the engagement), persisting the new token counts only on a full
 * allow. Returns `{ok:false}` with the fixed reason when either bucket is empty.
 */
export interface RateLimiter {
  take(ref: RateRef): Promise<RateOutcome>;
}

/** The `beforeEgress`-shaped hook signature (matches `runStage2`'s interlock). */
export type BeforeEgressHook = (ctx: {
  readonly claims: { readonly tenantId: string; readonly engagementId: string };
  readonly request: ReconstructedRequest;
}) => void | Promise<void>;

/**
 * Build the rate-limit gate as a `beforeEgress` hook. It draws a token for the request's engagement + target host via
 * the injected limiter and DENIES with a fixed-reason `RateLimitError` when refused (or on any limiter throw — fail
 * closed), so `runStage2` records `{stage:'interlock', reason}` and opens no socket. The per-host bucket is keyed by
 * the RECONSTRUCTED request's canonical host (the address family the broker will actually dial).
 */
export function createRateLimitGate(limiter: RateLimiter): BeforeEgressHook {
  return async ({ claims, request }): Promise<void> => {
    const outcome = await limiter.take({
      tenantId: claims.tenantId,
      engagementId: claims.engagementId,
      host: request.host,
    });
    if (!outcome.ok) throw new RateLimitError(outcome.reason);
  };
}
