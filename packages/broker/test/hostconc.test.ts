import { describe, it, expect } from 'vitest';
import {
  evaluateHostSlot,
  createHostConcurrencyGate,
  HostConcurrencyError,
  type HostSlotSnapshot,
  type HostSlotConfig,
  type HostSlotController,
  type HostSlotRef,
  type HostSlotReleaseRef,
  type HostSlotOutcome,
  type ReconstructedRequest,
} from '../src/index.js';

/**
 * Per-host concurrency (§8, slice 5e). Proves the pure admission decision (admit only strictly below the per-host cap)
 * and the broker gate over an injected slot controller (keyed by the reconstructed request host, fixed-reason
 * fail-closed denial → no socket). The atomic crash-safe lease read-modify-write is proven separately in db/test.
 */

const snap = (liveSlots: number): HostSlotSnapshot => ({ liveSlots });
const cfg = (perHostConcurrency: number): HostSlotConfig => ({ perHostConcurrency });

describe('evaluateHostSlot — admit only below the per-host cap', () => {
  it('ALLOWS when live slots are below the cap', () => {
    expect(evaluateHostSlot(snap(0), cfg(1))).toEqual({ allow: true });
    expect(evaluateHostSlot(snap(2), cfg(3))).toEqual({ allow: true });
  });

  it('DENIES host_concurrency_exceeded exactly at the cap', () => {
    expect(evaluateHostSlot(snap(1), cfg(1))).toEqual({
      allow: false,
      reason: 'host_concurrency_exceeded',
    });
  });

  it('DENIES above the cap (defensive: a stale over-count never admits)', () => {
    expect(evaluateHostSlot(snap(5), cfg(3))).toEqual({
      allow: false,
      reason: 'host_concurrency_exceeded',
    });
  });
});

describe('createHostConcurrencyGate', () => {
  const claims = { tenantId: 't1', engagementId: 'e1' };
  const request = {
    host: 'example.com',
    targetUrl: 'https://example.com/',
  } as unknown as ReconstructedRequest;
  const arg = { claims, request };

  const controllerOf = (
    behaviour: HostSlotOutcome | (() => Promise<never>),
  ): {
    controller: HostSlotController;
    acquired: HostSlotRef[];
    released: HostSlotReleaseRef[];
  } => {
    const acquired: HostSlotRef[] = [];
    const released: HostSlotReleaseRef[] = [];
    const controller: HostSlotController = {
      acquire: async (ref) => {
        acquired.push(ref);
        if (typeof behaviour === 'function') return behaviour();
        return behaviour;
      },
      release: async (ref) => {
        released.push(ref);
      },
    };
    return { controller, acquired, released };
  };

  it('acquires for the engagement + the reconstructed request host, passing on success', async () => {
    const { controller, acquired } = controllerOf({ ok: true, slotId: 's-123' });
    await expect(createHostConcurrencyGate(controller)(arg)).resolves.toBeUndefined();
    expect(acquired).toEqual([{ tenantId: 't1', engagementId: 'e1', host: 'example.com' }]);
  });

  it('DENY with the fixed reason — a HostConcurrencyError, no socket downstream', async () => {
    const { controller } = controllerOf({ ok: false, reason: 'host_concurrency_exceeded' });
    await expect(createHostConcurrencyGate(controller)(arg)).rejects.toBeInstanceOf(
      HostConcurrencyError,
    );
    await expect(createHostConcurrencyGate(controller)(arg)).rejects.toThrow(
      /host_concurrency_exceeded/,
    );
  });

  it('fails closed when the controller throws', async () => {
    const { controller } = controllerOf(() => Promise.reject(new Error('db_down')));
    await expect(createHostConcurrencyGate(controller)(arg)).rejects.toThrow(/db_down/);
  });

  it('the HostConcurrencyError message is exactly the fixed reason code (no leak)', () => {
    const err = new HostConcurrencyError('host_concurrency_exceeded');
    expect(err).toBeInstanceOf(HostConcurrencyError);
    expect(err.message).toBe('host_concurrency_exceeded');
    expect(err.reason).toBe('host_concurrency_exceeded');
  });
});
