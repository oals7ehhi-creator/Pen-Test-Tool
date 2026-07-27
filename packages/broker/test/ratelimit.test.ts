import { describe, it, expect } from 'vitest';
import {
  refillAndTake,
  evaluateRateLimit,
  createRateLimitGate,
  RateLimitError,
  type BucketState,
  type BucketConfig,
  type RateSnapshot,
  type RateConfig,
  type RateLimiter,
  type RateRef,
  type RateOutcome,
  type ReconstructedRequest,
} from '../src/index.js';

/**
 * Request-rate token buckets (§8, slice 5d). Proves the pure bucket refill/draw, the global-then-host combined draw
 * (check-both-consume-both, no token leak), and the broker gate over an injected limiter (fixed-reason fail-closed
 * denial → no socket). The atomic persisted-bucket read-modify-write is proven separately in db/test.
 */

const NOW = 10_000_000;

const bucket = (tokens: number, refillAtMs = NOW): BucketState => ({ tokens, refillAtMs });
const cfg = (ratePerSec: number, capacity: number): BucketConfig => ({ ratePerSec, capacity });

describe('refillAndTake — a single token bucket', () => {
  it('draws a token when one is available (tokens reduced, refill stamp advanced)', () => {
    expect(refillAndTake(bucket(2), cfg(2, 2), NOW)).toEqual({
      allow: true,
      tokens: 1,
      refillAtMs: NOW,
    });
  });

  it('refuses when empty and no time has elapsed (no token consumed)', () => {
    expect(refillAndTake(bucket(0), cfg(2, 2), NOW)).toEqual({
      allow: false,
      tokens: 0,
      refillAtMs: NOW,
    });
  });

  it('refills by elapsed time at the rate, capped at capacity', () => {
    // empty bucket, 2 tokens/sec, 0.5s elapsed ⇒ 1 token accrued ⇒ one draw, leaving 0.
    expect(refillAndTake(bucket(0, NOW - 500), cfg(2, 2), NOW)).toEqual({
      allow: true,
      tokens: 0,
      refillAtMs: NOW,
    });
    // long idle refills only up to capacity (2), not unbounded.
    expect(refillAndTake(bucket(0, NOW - 100_000), cfg(2, 2), NOW).tokens).toBe(1); // 2 - 1 drawn
  });

  it('handles a fractional rate with a capacity floor (0.5/sec, cap 1): one burst then wait ~2s', () => {
    expect(refillAndTake(bucket(1), cfg(0.5, 1), NOW).allow).toBe(true); // the single stored token
    expect(refillAndTake(bucket(0), cfg(0.5, 1), NOW).allow).toBe(false); // empty, no time
    expect(refillAndTake(bucket(0, NOW - 2000), cfg(0.5, 1), NOW).allow).toBe(true); // 2s * 0.5 = 1 token
  });
});

describe('evaluateRateLimit — global + per-host, check-both-consume-both', () => {
  const snap = (g: BucketState, h: BucketState): RateSnapshot => ({ global: g, host: h });
  const rc = (gRate: number, gCap: number, hRate: number, hCap: number): RateConfig => ({
    global: cfg(gRate, gCap),
    host: cfg(hRate, hCap),
  });

  it('ALLOWS when both buckets have a token, consuming one from each', () => {
    const d = evaluateRateLimit(snap(bucket(2), bucket(1)), rc(2, 2, 1, 1), NOW);
    expect(d).toEqual({
      allow: true,
      global: { tokens: 1, refillAtMs: NOW },
      host: { tokens: 0, refillAtMs: NOW },
    });
  });

  it('DENY rate_limited_global when the global bucket is empty — and does NOT touch the host bucket', () => {
    // host has a token, but global is empty ⇒ global denies first; the host token is NOT consumed (no leak).
    expect(evaluateRateLimit(snap(bucket(0), bucket(5)), rc(2, 2, 5, 5), NOW)).toEqual({
      allow: false,
      reason: 'rate_limited_global',
    });
  });

  it('DENY rate_limited_host when the host bucket is empty though global has room (no global-token leak)', () => {
    expect(evaluateRateLimit(snap(bucket(2), bucket(0)), rc(2, 2, 1, 1), NOW)).toEqual({
      allow: false,
      reason: 'rate_limited_host',
    });
  });
});

describe('createRateLimitGate', () => {
  const claims = { tenantId: 't1', engagementId: 'e1' };
  const request = {
    host: 'example.com',
    targetUrl: 'https://example.com/',
  } as unknown as ReconstructedRequest;
  const arg = { claims, request };

  const limiterOf = (
    behaviour: RateOutcome | (() => Promise<never>),
  ): { limiter: RateLimiter; taken: RateRef[] } => {
    const taken: RateRef[] = [];
    const limiter: RateLimiter = {
      take: async (ref) => {
        taken.push(ref);
        if (typeof behaviour === 'function') return behaviour();
        return behaviour;
      },
    };
    return { limiter, taken };
  };

  it('draws for the engagement + the reconstructed request host, passing on success', async () => {
    const { limiter, taken } = limiterOf({ ok: true });
    await expect(createRateLimitGate(limiter)(arg)).resolves.toBeUndefined();
    expect(taken).toEqual([{ tenantId: 't1', engagementId: 'e1', host: 'example.com' }]);
  });

  it('DENY with the fixed reason (rate_limited_host) — a RateLimitError, no socket downstream', async () => {
    const { limiter } = limiterOf({ ok: false, reason: 'rate_limited_host' });
    await expect(createRateLimitGate(limiter)(arg)).rejects.toBeInstanceOf(RateLimitError);
    await expect(createRateLimitGate(limiter)(arg)).rejects.toThrow(/rate_limited_host/);
  });

  it('fails closed when the limiter throws', async () => {
    const { limiter } = limiterOf(() => Promise.reject(new Error('db_down')));
    await expect(createRateLimitGate(limiter)(arg)).rejects.toThrow(/db_down/);
  });

  it('the RateLimitError message is exactly the fixed reason code (no leak)', () => {
    const err = new RateLimitError('rate_limited_global');
    expect(err).toBeInstanceOf(RateLimitError);
    expect(err.message).toBe('rate_limited_global');
    expect(err.reason).toBe('rate_limited_global');
  });
});
