import { describe, it, expect } from 'vitest';
import type { GrantClaims } from '@pentest/spec';
import {
  evaluateLiveState,
  createLiveStateGate,
  composeBeforeEgress,
  LiveStateError,
  type LiveStateContext,
  type TestingWindow,
  type BeforeEgressHook,
  type ReconstructedRequest,
} from '../src/index.js';

/**
 * Live-state gate (§2.3 effective-window rule / §7.1 step 9, slice 5b). Proves the pure clock-derived pre-charge gate:
 * revocation / expiry / not-yet-effective deny first; a blackout covering `now` wins over any allow-window; an
 * allow-window is REQUIRED (deny-by-default `window_closed`); timezone + midnight-wrap are resolved in the engagement
 * timezone. The gate throws a fixed-reason LiveStateError (surfaced by runStage2 as {stage:'interlock', reason}).
 */

// Reference instants (UTC). 2026-01-05 is a MONDAY.
const MON_1200_UTC = Date.UTC(2026, 0, 5, 12, 0, 0); // Mon 12:00:00 UTC → dow=0, sec=43200
const MON_2000_UTC = Date.UTC(2026, 0, 5, 20, 0, 0); // Mon 20:00:00 UTC → sec=72000
const FRI_2300_UTC = Date.UTC(2026, 0, 9, 23, 0, 0); // Fri 23:00 UTC (dow=4, sec=82800)
const SAT_0100_UTC = Date.UTC(2026, 0, 10, 1, 0, 0); // Sat 01:00 UTC (dow=5, sec=3600)
const SAT_0300_UTC = Date.UTC(2026, 0, 10, 3, 0, 0); // Sat 03:00 UTC (dow=5, sec=10800)

const YEAR = 365 * 24 * 3600 * 1000;

const recurring = (days: number[], startSec: number, endSec: number): TestingWindow => ({
  kind: 'recurring_weekly',
  daysOfWeek: days,
  startLocalSec: startSec,
  endLocalSec: endSec,
});

const base = (over: Partial<LiveStateContext> = {}): LiveStateContext => ({
  nowMs: MON_1200_UTC,
  timezone: 'UTC',
  effectiveFromMs: MON_1200_UTC - YEAR,
  expiresAtMs: MON_1200_UTC + YEAR,
  revoked: false,
  windows: [recurring([0], 9 * 3600, 17 * 3600)], // Mon 09:00–17:00
  ...over,
});

describe('evaluateLiveState — validity + window rule (§2.3)', () => {
  it('ALLOWS an in-validity instant inside a recurring allow-window with no blackout', () => {
    expect(evaluateLiveState(base())).toEqual({ allowed: true });
  });

  it('DENY authorization_revoked (checked first)', () => {
    expect(evaluateLiveState(base({ revoked: true }))).toEqual({
      allowed: false,
      reason: 'authorization_revoked',
    });
  });

  it('DENY not_yet_effective when now < effective_from', () => {
    expect(evaluateLiveState(base({ effectiveFromMs: MON_1200_UTC + 1 }))).toEqual({
      allowed: false,
      reason: 'not_yet_effective',
    });
  });

  it('DENY authorization_expired when now >= expires_at (boundary is expired, fail-closed)', () => {
    expect(evaluateLiveState(base({ expiresAtMs: MON_1200_UTC }))).toEqual({
      allowed: false,
      reason: 'authorization_expired',
    });
  });

  it('DENY window_closed when no allow-window covers now (deny-by-default, incl. empty window set)', () => {
    expect(evaluateLiveState(base({ windows: [] }))).toEqual({
      allowed: false,
      reason: 'window_closed',
    });
    // a recurring window on the wrong day / time also closes.
    expect(evaluateLiveState(base({ nowMs: MON_2000_UTC })).allowed).toBe(false); // 20:00 > 17:00
  });

  it('DENY blackout — a blackout covering now WINS over an allow-window', () => {
    const blackout: TestingWindow = {
      kind: 'blackout',
      startAtMs: MON_1200_UTC - 3600_000,
      endAtMs: MON_1200_UTC + 3600_000,
    };
    expect(evaluateLiveState(base({ windows: [recurring([0], 0, 86_399), blackout] }))).toEqual({
      allowed: false,
      reason: 'blackout',
    });
  });

  it('ALLOWS via a one_off window covering now', () => {
    const oneOff: TestingWindow = {
      kind: 'one_off',
      startAtMs: MON_1200_UTC - 60_000,
      endAtMs: MON_1200_UTC + 60_000,
    };
    expect(evaluateLiveState(base({ windows: [oneOff] }))).toEqual({ allowed: true });
    // just outside the one_off ⇒ window_closed.
    expect(
      evaluateLiveState(base({ nowMs: MON_1200_UTC + 120_000, windows: [oneOff] })).allowed,
    ).toBe(false);
  });

  it('handles a midnight-WRAPPING recurring window (start > end): open Fri 22:00 → Sat 02:00', () => {
    const wrap = recurring([4], 22 * 3600, 2 * 3600); // Fri 22:00 → 02:00 next day
    expect(evaluateLiveState(base({ nowMs: FRI_2300_UTC, windows: [wrap] }))).toEqual({
      allowed: true,
    }); // Fri 23:00 (>= start)
    expect(evaluateLiveState(base({ nowMs: SAT_0100_UTC, windows: [wrap] }))).toEqual({
      allowed: true,
    }); // Sat 01:00 (< end, prev day Fri listed)
    expect(evaluateLiveState(base({ nowMs: SAT_0300_UTC, windows: [wrap] })).allowed).toBe(false); // Sat 03:00 (past end)
  });

  it('resolves the window in the ENGAGEMENT timezone (America/New_York), not UTC', () => {
    // 2026-01-05 02:00 UTC = 2026-01-04 21:00 EST → in New York it is SUNDAY 21:00 (dow=6, sec=75600).
    const nyNight = Date.UTC(2026, 0, 5, 2, 0, 0);
    const sunEvening = recurring([6], 20 * 3600, 23 * 3600); // Sun 20:00–23:00 local
    expect(
      evaluateLiveState(
        base({ nowMs: nyNight, timezone: 'America/New_York', windows: [sunEvening] }),
      ),
    ).toEqual({ allowed: true });
    // the same instant is MONDAY 02:00 in UTC ⇒ the Sun-evening window does NOT cover it.
    expect(
      evaluateLiveState(base({ nowMs: nyNight, timezone: 'UTC', windows: [sunEvening] })).allowed,
    ).toBe(false);
  });
});

describe('createLiveStateGate + composeBeforeEgress', () => {
  const claims = { tenantId: 't', engagementId: 'e' } as unknown as GrantClaims;
  const request = { targetUrl: 'https://example.com/' } as unknown as ReconstructedRequest;
  const arg = { claims, request };

  it('passes when the live state allows, and throws a fixed-reason LiveStateError when it denies', async () => {
    const openGate = createLiveStateGate(() => base());
    await expect(openGate(arg)).resolves.toBeUndefined();

    const closedGate = createLiveStateGate(() => base({ windows: [] }));
    await expect(closedGate(arg)).rejects.toBeInstanceOf(LiveStateError);
    await expect(closedGate(arg)).rejects.toThrow(/window_closed/);
  });

  it('awaits an async context loader', async () => {
    const gate = createLiveStateGate(async () => base({ revoked: true }));
    await expect(gate(arg)).rejects.toThrow(/authorization_revoked/);
  });

  it('composeBeforeEgress runs hooks in order and short-circuits on the first throw', async () => {
    const calls: string[] = [];
    const a: BeforeEgressHook = () => {
      calls.push('a');
    };
    const b: BeforeEgressHook = () => {
      calls.push('b');
      throw new LiveStateError('window_closed');
    };
    const c: BeforeEgressHook = () => {
      calls.push('c');
    };
    await expect(composeBeforeEgress(a, b, c)(arg)).rejects.toThrow(/window_closed/);
    expect(calls).toEqual(['a', 'b']); // c never runs after b throws
  });

  it('composeBeforeEgress with all-passing hooks runs every one', async () => {
    const calls: string[] = [];
    const mk =
      (n: string): BeforeEgressHook =>
      async () => {
        calls.push(n);
      };
    await composeBeforeEgress(mk('x'), mk('y'), mk('z'))(arg);
    expect(calls).toEqual(['x', 'y', 'z']);
  });

  it('the LiveStateError message is exactly the fixed reason code (no value leak)', () => {
    const err = new LiveStateError('blackout');
    expect(err).toBeInstanceOf(LiveStateError);
    expect(err.message).toBe('blackout');
    expect(err.reason).toBe('blackout');
  });
});
