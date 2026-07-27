import { describe, it, expect } from 'vitest';
import type { GrantClaims } from '@pentest/spec';
import {
  createBudgetInterlock,
  BudgetError,
  type BudgetLedger,
  type ChargeRequest,
  type ChargeOutcome,
  type ChargeReceipt,
  type ReconstructedRequest,
} from '../src/index.js';

/**
 * Budget charge-before-send interlock (§8.1 / §7.1 steps 9–10). Proves the pure broker-side orchestrator over an
 * injected ledger port: it assembles the charge from the verified claims + reconstructed request, DENIES (throws a
 * fixed-reason BudgetError) on an exhaustion/e-stop outcome OR any ledger throw (fail-closed), and only on a committed
 * charge hands the receipt to the completion sink. The atomic DB transaction is proven separately in db/test.
 */

const CLAIMS: GrantClaims = {
  runId: 'run-1',
  jobId: 'job-1',
  tenantId: 'tenant-1',
  engagementId: 'eng-1',
  authorizationId: 'authz-1',
  scopeHash: 'a'.repeat(64),
  specSha256: 'f'.repeat(64),
  requestClass: 'native',
};

const REQUEST: ReconstructedRequest = {
  method: 'GET',
  scheme: 'https',
  host: 'example.com',
  port: 443,
  path: '/api',
  query: '',
  targetUrl: 'https://example.com/api',
  headers: [],
  body: null,
};

const RECEIPT: ChargeReceipt = {
  reservationId: 'res-1',
  fenceToken: '7',
  intentEventId: 'evt-1',
};

/** A ledger stub that records the charge request and returns a fixed outcome (or throws). */
function stubLedger(behaviour: ChargeOutcome | (() => Promise<never>)): {
  ledger: BudgetLedger;
  calls: ChargeRequest[];
} {
  const calls: ChargeRequest[] = [];
  const ledger: BudgetLedger = {
    charge: async (req: ChargeRequest): Promise<ChargeOutcome> => {
      calls.push(req);
      if (typeof behaviour === 'function') return behaviour();
      return behaviour;
    },
  };
  return { ledger, calls };
}

describe('createBudgetInterlock', () => {
  it('charges from the claims + reconstructed request and passes on a success', async () => {
    const { ledger, calls } = stubLedger({ ok: true, receipt: RECEIPT });
    const received: ChargeReceipt[] = [];
    const interlock = createBudgetInterlock({
      ledger,
      owner: 'broker-A',
      grantJti: 'jti-9',
      specId: 'spec-9',
      onCharged: (r) => received.push(r),
    });

    await expect(interlock({ claims: CLAIMS, request: REQUEST })).resolves.toBeUndefined();

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      tenantId: 'tenant-1',
      engagementId: 'eng-1',
      specId: 'spec-9',
      grantJti: 'jti-9',
      owner: 'broker-A',
      canonicalTarget: 'https://example.com/api',
    });
    expect(received).toEqual([RECEIPT]);
  });

  it('DENY budget_exhausted — throws a fixed-reason BudgetError and never calls the completion sink', async () => {
    const { ledger } = stubLedger({ ok: false, reason: 'budget_exhausted' });
    let charged = false;
    const interlock = createBudgetInterlock({
      ledger,
      owner: 'broker-A',
      grantJti: 'jti-1',
      specId: 'spec-1',
      onCharged: () => {
        charged = true;
      },
    });
    await expect(interlock({ claims: CLAIMS, request: REQUEST })).rejects.toBeInstanceOf(
      BudgetError,
    );
    await expect(interlock({ claims: CLAIMS, request: REQUEST })).rejects.toThrow(
      /budget_exhausted/,
    );
    expect(charged).toBe(false);
  });

  it('DENY emergency_stop — throws a fixed-reason BudgetError', async () => {
    const { ledger } = stubLedger({ ok: false, reason: 'emergency_stop' });
    const interlock = createBudgetInterlock({ ledger, owner: 'b', grantJti: 'j', specId: 's' });
    await expect(interlock({ claims: CLAIMS, request: REQUEST })).rejects.toThrow(/emergency_stop/);
  });

  it('fail-closed: a ledger throw propagates (the interlock denies, so no egress follows)', async () => {
    const { ledger } = stubLedger(() => Promise.reject(new Error('db_unavailable')));
    const interlock = createBudgetInterlock({ ledger, owner: 'b', grantJti: 'j', specId: 's' });
    await expect(interlock({ claims: CLAIMS, request: REQUEST })).rejects.toThrow(/db_unavailable/);
  });

  it('the BudgetError message is exactly the fixed reason code (no budget/engagement value leak)', () => {
    const err = new BudgetError('budget_exhausted');
    expect(err).toBeInstanceOf(BudgetError);
    expect(err.message).toBe('budget_exhausted');
    expect(err.reason).toBe('budget_exhausted');
    expect(err.message).not.toMatch(/tenant|eng|spec|[0-9]{2,}/);
  });
});
