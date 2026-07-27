import { describe, it, expect } from 'vitest';
import type { GrantClaims } from '@pentest/spec';
import {
  evaluateAcquire,
  recordResult,
  createThrottleGate,
  ThrottleError,
  type ThrottleConfig,
  type ThrottleSnapshot,
  type ThrottleController,
  type EngagementRef,
  type AcquireOutcome,
  type ReconstructedRequest,
} from '../src/index.js';

/**
 * Concurrency / spacing / circuit-breaker interlock (§8, slice 5c). Proves the pure acquire decision + the breaker
 * transition + the broker gate over an injected controller: circuit → concurrency → spacing order, the half-open
 * probe after cooldown, breaker open/close on completion, and fail-closed denial (no socket) at the gate. The atomic
 * runtime-counter read-modify-write is proven separately in db/test.
 */

const CFG: ThrottleConfig = {
  maxConcurrency: 2,
  minRequestIntervalMs: 250,
  circuitErrorThreshold: 3,
  circuitCooldownMs: 30_000,
};

const NOW = 1_000_000;

const snap = (over: Partial<ThrottleSnapshot> = {}): ThrottleSnapshot => ({
  inFlight: 0,
  lastRequestAtMs: null,
  circuitState: 'closed',
  consecutiveErrors: 0,
  circuitOpenedAtMs: null,
  ...over,
});

describe('evaluateAcquire — circuit → concurrency → spacing', () => {
  it('ALLOWS a closed breaker with capacity and adequate spacing (no half-open transition)', () => {
    expect(evaluateAcquire(snap(), CFG, NOW)).toEqual({ allow: true, openedToHalfOpen: false });
    // spacing satisfied when the last dispatch is old enough.
    expect(evaluateAcquire(snap({ lastRequestAtMs: NOW - 250 }), CFG, NOW)).toEqual({
      allow: true,
      openedToHalfOpen: false,
    });
  });

  it('DENY concurrency_exceeded at the in-flight cap', () => {
    expect(evaluateAcquire(snap({ inFlight: 2 }), CFG, NOW)).toEqual({
      allow: false,
      reason: 'concurrency_exceeded',
    });
  });

  it('DENY min_interval when the last dispatch is too recent', () => {
    expect(evaluateAcquire(snap({ lastRequestAtMs: NOW - 249 }), CFG, NOW)).toEqual({
      allow: false,
      reason: 'min_interval',
    });
  });

  it('DENY circuit_open while an open breaker is within its cooldown (incl. a never-stamped open)', () => {
    expect(
      evaluateAcquire(snap({ circuitState: 'open', circuitOpenedAtMs: NOW - 29_999 }), CFG, NOW),
    ).toEqual({ allow: false, reason: 'circuit_open' });
    // circuitOpenedAtMs null ⇒ treated as just-opened ⇒ still cooling ⇒ deny.
    expect(
      evaluateAcquire(snap({ circuitState: 'open', circuitOpenedAtMs: null }), CFG, NOW).allow,
    ).toBe(false);
  });

  it('lets ONE half-open probe through once the cooldown elapses (openedToHalfOpen=true)', () => {
    expect(
      evaluateAcquire(snap({ circuitState: 'open', circuitOpenedAtMs: NOW - 30_000 }), CFG, NOW),
    ).toEqual({ allow: true, openedToHalfOpen: true });
  });

  it('a half_open breaker DENIES further acquires (a probe is outstanding — exactly one probe, no flood)', () => {
    // Only the open→half_open TRANSITION admits the single probe; while half_open, every other acquire is refused
    // until the probe completes and resolves the breaker.
    expect(evaluateAcquire(snap({ circuitState: 'half_open' }), CFG, NOW)).toEqual({
      allow: false,
      reason: 'circuit_open',
    });
  });

  it('the circuit gate precedes concurrency/spacing (an open breaker denies even at zero in-flight)', () => {
    expect(
      evaluateAcquire(
        snap({ circuitState: 'open', circuitOpenedAtMs: NOW - 1000, inFlight: 0 }),
        CFG,
        NOW,
      ).allow,
    ).toBe(false);
  });

  it('concurrency precedes spacing (both violated ⇒ concurrency_exceeded, not min_interval)', () => {
    expect(evaluateAcquire(snap({ inFlight: 2, lastRequestAtMs: NOW - 10 }), CFG, NOW)).toEqual({
      allow: false,
      reason: 'concurrency_exceeded',
    });
  });
});

describe('recordResult — circuit-breaker transition on completion', () => {
  it('a success closes the breaker and clears the error run', () => {
    expect(
      recordResult(snap({ circuitState: 'half_open', consecutiveErrors: 5 }), true, NOW, CFG),
    ).toEqual({ circuitState: 'closed', consecutiveErrors: 0, circuitOpenedAtMs: null });
  });

  it('a closed breaker accumulates failures and OPENS at the threshold', () => {
    // below threshold ⇒ stays closed, run increments.
    expect(recordResult(snap({ consecutiveErrors: 1 }), false, NOW, CFG)).toEqual({
      circuitState: 'closed',
      consecutiveErrors: 2,
      circuitOpenedAtMs: null,
    });
    // reaching the threshold ⇒ opens, stamping the time.
    expect(recordResult(snap({ consecutiveErrors: 2 }), false, NOW, CFG)).toEqual({
      circuitState: 'open',
      consecutiveErrors: 3,
      circuitOpenedAtMs: NOW,
    });
  });

  it('a failed half_open probe RE-OPENS the breaker immediately', () => {
    expect(
      recordResult(snap({ circuitState: 'half_open', consecutiveErrors: 3 }), false, NOW, CFG),
    ).toEqual({ circuitState: 'open', consecutiveErrors: 4, circuitOpenedAtMs: NOW });
  });
});

describe('createThrottleGate', () => {
  const claims = { tenantId: 't1', engagementId: 'e1' } as unknown as GrantClaims;
  const request = { targetUrl: 'https://example.com/' } as unknown as ReconstructedRequest;
  const arg = { claims, request };

  const controller = (
    behaviour: AcquireOutcome | (() => Promise<never>),
  ): { c: ThrottleController; acquired: EngagementRef[] } => {
    const acquired: EngagementRef[] = [];
    const c: ThrottleController = {
      acquire: async (ref) => {
        acquired.push(ref);
        if (typeof behaviour === 'function') return behaviour();
        return behaviour;
      },
      release: async () => {},
    };
    return { c, acquired };
  };

  it('acquires the engagement slot and passes on success', async () => {
    const { c, acquired } = controller({ ok: true });
    await expect(createThrottleGate(c)(arg)).resolves.toBeUndefined();
    expect(acquired).toEqual([{ tenantId: 't1', engagementId: 'e1' }]);
  });

  it('DENY with the controller reason (circuit_open) — a fixed-reason ThrottleError, no socket downstream', async () => {
    const { c } = controller({ ok: false, reason: 'circuit_open' });
    await expect(createThrottleGate(c)(arg)).rejects.toBeInstanceOf(ThrottleError);
    await expect(createThrottleGate(c)(arg)).rejects.toThrow(/circuit_open/);
  });

  it('fails closed when the controller throws', async () => {
    const { c } = controller(() => Promise.reject(new Error('db_down')));
    await expect(createThrottleGate(c)(arg)).rejects.toThrow(/db_down/);
  });

  it('the ThrottleError message is exactly the fixed reason code (no leak)', () => {
    const err = new ThrottleError('concurrency_exceeded');
    expect(err).toBeInstanceOf(ThrottleError);
    expect(err.message).toBe('concurrency_exceeded');
    expect(err.reason).toBe('concurrency_exceeded');
  });
});
