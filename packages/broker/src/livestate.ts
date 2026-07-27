/**
 * Live-state gate (Phase 0 doc 04 §2.3 effective-window rule / §8 / §7.1 step 9, slice 5b). Before the budget is
 * charged, the broker re-checks — on the trusted clock — that the request is still permitted RIGHT NOW: the
 * authorization is within its validity window (not revoked, not yet expired, already effective) AND the current
 * instant falls inside at least one allow-window (`recurring_weekly` / `one_off`) AND inside NO `blackout` window.
 * Blackout always wins, and an allow-window is REQUIRED (deny-by-default: an engagement with no allow-window can test
 * at no time). This module is the PURE evaluator + the `beforeEgress` gate that wraps it; the engagement timezone,
 * authorization validity, and window rows are injected by the caller (the broker package performs no I/O). e-stop is
 * the DB hard-gate re-checked UNDER the charge lock (slice 5a); this gate covers the clock-derived checks that precede
 * the charge, so a request outside its window / after expiry is denied with NO budget charged and NO socket opened.
 *
 * Timezone + DST are resolved in the engagement timezone via `Intl.DateTimeFormat` before any comparison, per §2.3.
 * The trusted-clock instant (`nowMs`) is injected so the decision is deterministic and unit-testable (SI-049: the
 * caller supplies the authenticated clock; an unverifiable time must fail closed before reaching here).
 */

import type { GrantClaims } from '@pentest/spec';
import type { ReconstructedRequest } from './reconstruct.js';

export type LiveStateReason =
  | 'authorization_revoked'
  | 'not_yet_effective'
  | 'authorization_expired'
  | 'blackout'
  | 'window_closed';

/** A recurring weekly window: active on `daysOfWeek` (0=Mon..6=Sun) between two local-time-of-day seconds. */
export interface RecurringWindow {
  readonly kind: 'recurring_weekly';
  /** Days the window STARTS on, 0=Mon..6=Sun (matches the DB `days_of_week`). */
  readonly daysOfWeek: readonly number[];
  /** Local seconds-of-day the window opens (0..86399), interpreted in the engagement timezone. */
  readonly startLocalSec: number;
  /** Local seconds-of-day the window closes; `< startLocalSec` means it wraps past midnight into the next day. */
  readonly endLocalSec: number;
}

/** A one-off allow window or a blackout, both as absolute instants (the DB `TIMESTAMPTZ` start/end). */
export interface AbsoluteWindow {
  readonly kind: 'one_off' | 'blackout';
  readonly startAtMs: number;
  readonly endAtMs: number;
}

export type TestingWindow = RecurringWindow | AbsoluteWindow;

/** The injected live-state context, evaluated on the trusted clock at `nowMs`. */
export interface LiveStateContext {
  readonly nowMs: number;
  /** IANA timezone of the engagement (e.g. `'UTC'`, `'America/New_York'`). */
  readonly timezone: string;
  readonly effectiveFromMs: number;
  readonly expiresAtMs: number;
  /** True when the authorization has been revoked (a status the caller resolved). */
  readonly revoked: boolean;
  readonly windows: readonly TestingWindow[];
}

export type LiveStateResult =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly reason: LiveStateReason };

/** A fixed-reason live-state denial. Carries only the reason code — never engagement/window values. */
export class LiveStateError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason); // the message IS the fixed reason code
    this.name = 'LiveStateError';
    this.reason = reason;
  }
}

const WEEKDAY_TO_MON0: Record<string, number> = {
  Mon: 0,
  Tue: 1,
  Wed: 2,
  Thu: 3,
  Fri: 4,
  Sat: 5,
  Sun: 6,
};

/** Resolve the local weekday (0=Mon..6=Sun) and seconds-of-day at `nowMs` in `timeZone` (DST-correct via Intl). */
function localParts(nowMs: number, timeZone: string): { dow: number; sec: number } {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date(nowMs));
  const map: Record<string, string> = {};
  for (const p of parts) map[p.type] = p.value;
  // `weekday` is always one of the seven short names for a real instant+timezone; the `?? 0` is an unreachable guard.
  /* v8 ignore next */
  const dow = WEEKDAY_TO_MON0[map.weekday ?? ''] ?? 0;
  const h = Number(map.hour);
  const m = Number(map.minute);
  const s = Number(map.second);
  return { dow, sec: h * 3600 + m * 60 + s };
}

/** Is the local (dow, sec) inside this recurring window — including the midnight-wrapping case? */
function inRecurring(dow: number, sec: number, w: RecurringWindow): boolean {
  if (w.startLocalSec < w.endLocalSec) {
    // same-day window: active on a listed day between [start, end).
    return w.daysOfWeek.includes(dow) && sec >= w.startLocalSec && sec < w.endLocalSec;
  }
  // wraps midnight: open from `start` on a listed day, through midnight, until `end` on the following day.
  const prevDow = (dow + 6) % 7;
  return (
    (w.daysOfWeek.includes(dow) && sec >= w.startLocalSec) ||
    (w.daysOfWeek.includes(prevDow) && sec < w.endLocalSec)
  );
}

/**
 * Evaluate the effective-window rule (§2.3) on the trusted clock. Fail-closed and deny-by-default: revocation /
 * expiry / not-yet-effective deny first; a `blackout` covering `now` denies (blackout wins); and if `now` is inside
 * NO allow-window the request is denied `window_closed`. Only an in-validity, in-allow-window, no-blackout instant
 * is `{ allowed: true }`.
 */
export function evaluateLiveState(ctx: LiveStateContext): LiveStateResult {
  const { nowMs } = ctx;
  if (ctx.revoked) return { allowed: false, reason: 'authorization_revoked' };
  if (nowMs < ctx.effectiveFromMs) return { allowed: false, reason: 'not_yet_effective' };
  if (nowMs >= ctx.expiresAtMs) return { allowed: false, reason: 'authorization_expired' };

  // Blackout wins over any allow-window: a blackout covering `now` denies outright.
  for (const w of ctx.windows) {
    if (w.kind === 'blackout' && nowMs >= w.startAtMs && nowMs < w.endAtMs) {
      return { allowed: false, reason: 'blackout' };
    }
  }

  // An allow-window is REQUIRED — `now` must fall inside at least one recurring_weekly / one_off window.
  const { dow, sec } = localParts(nowMs, ctx.timezone);
  let insideAllow = false;
  for (const w of ctx.windows) {
    if (w.kind === 'recurring_weekly') {
      if (inRecurring(dow, sec, w)) insideAllow = true;
    } else if (w.kind === 'one_off') {
      if (nowMs >= w.startAtMs && nowMs < w.endAtMs) insideAllow = true;
    }
  }
  if (!insideAllow) return { allowed: false, reason: 'window_closed' };
  return { allowed: true };
}

/** The `beforeEgress`-shaped hook signature (matches `runStage2`'s interlock). */
export type BeforeEgressHook = (ctx: {
  readonly claims: GrantClaims;
  readonly request: ReconstructedRequest;
}) => void | Promise<void>;

/**
 * Build the live-state gate as a `beforeEgress` hook. It loads the trusted-clock context (injected — the caller reads
 * the engagement timezone, the authorization validity, and the window rows) and DENIES with a fixed-reason
 * `LiveStateError` when the effective-window rule refuses `now`. `runStage2` maps the throw to
 * `{ stage: 'interlock', reason }` and opens no socket.
 */
export function createLiveStateGate(
  load: (ctx: {
    readonly claims: GrantClaims;
    readonly request: ReconstructedRequest;
  }) => LiveStateContext | Promise<LiveStateContext>,
): BeforeEgressHook {
  return async (ctx): Promise<void> => {
    const live = await load(ctx);
    const result = evaluateLiveState(live);
    if (!result.allowed) throw new LiveStateError(result.reason);
  };
}

/**
 * Compose several `beforeEgress` hooks into one that runs them IN ORDER and fail-closed: the first throw short-circuits
 * (so a live-state denial runs — and denies — BEFORE the budget charge, and neither opens a socket). Use it to place
 * the live-state gate ahead of the budget interlock: `composeBeforeEgress(liveStateGate, budgetInterlock)`.
 */
export function composeBeforeEgress(...hooks: readonly BeforeEgressHook[]): BeforeEgressHook {
  return async (ctx): Promise<void> => {
    for (const hook of hooks) await hook(ctx);
  };
}
