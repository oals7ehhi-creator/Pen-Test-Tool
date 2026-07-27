/**
 * Budget charge-before-send interlock (Phase 0 doc 04 §8.1 / §7.1 steps 9–10, slice 5a). This is the broker-side
 * decision layer that fills `runStage2`'s REQUIRED `beforeEgress` hook with the conservative charge-before-send
 * guarantee: no byte is sent until the budget is IRREVERSIBLY charged and the durable `request.intent` is committed
 * (SI-017, SI-055, SI-062). The atomic ledger transaction itself lives in the database (`budget_charge_and_intent`,
 * migration `0004`); this module is the pure orchestrator over an injected `BudgetLedger` port, so nothing here talks
 * to Postgres directly — the broker package stays I/O-free and unit-testable, exactly like the socket/DNS layers.
 *
 * The interlock is fail-closed by construction: a `{ok:false}` outcome (exhaustion / e-stop) or ANY thrown ledger
 * error DENIES — it throws a fixed-reason error, so `runStage2` records `{stage:'interlock', reason}` and opens NO
 * socket. On success it hands the charge receipt (reservation id + fence token + intent event id) to an optional sink
 * for the later informational `request.completed` step, which never changes the charge.
 */

import type { GrantClaims } from '@pentest/spec';
import type { ReconstructedRequest } from './reconstruct.js';

/** A charge denial reason from the ledger — a fixed code, never budget values or engagement detail. */
export type BudgetDenyReason = 'budget_exhausted' | 'emergency_stop';

/** A fixed-reason budget-interlock failure. Carries only the reason code — never budget/engagement/target values. */
export class BudgetError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(reason); // the message IS the fixed reason code
    this.name = 'BudgetError';
    this.reason = reason;
  }
}

/** Everything the atomic ledger charge needs, assembled from the verified grant claims + the reconstructed request. */
export interface ChargeRequest {
  readonly tenantId: string;
  readonly engagementId: string;
  /** The `request_spec` row id being charged (per-request; not carried in the grant claims). */
  readonly specId: string;
  /** The single-use grant's `jti` — one lease per grant (per-request). */
  readonly grantJti: string;
  /** This broker instance's lease owner id. */
  readonly owner: string;
  /** The canonical target recorded in the durable intent (non-secret). */
  readonly canonicalTarget: string;
}

/** The receipt of a committed charge — the lease + fence + the durable intent event it was recorded under. */
export interface ChargeReceipt {
  readonly reservationId: string;
  /** BIGINT fence token; a string to avoid precision loss. */
  readonly fenceToken: string;
  readonly intentEventId: string;
}

export type ChargeOutcome =
  | { readonly ok: true; readonly receipt: ChargeReceipt }
  | { readonly ok: false; readonly reason: BudgetDenyReason };

/**
 * The injected ledger port: performs the §8.1 atomic transaction (availability check under lock → fence allocation →
 * claim → charge `used += 1` → durable `request.intent`), all BEFORE any egress. Returns `{ok:false}` for an expected
 * denial (exhaustion / e-stop); THROWS for an unexpected failure (the interlock treats a throw as a fail-closed DENY).
 */
export interface BudgetLedger {
  charge(req: ChargeRequest): Promise<ChargeOutcome>;
}

/** Per-request config: the ledger + this broker's owner id + the two identifiers not carried in the grant claims. */
export interface BudgetInterlockConfig {
  readonly ledger: BudgetLedger;
  /** This broker instance's lease-owner id. */
  readonly owner: string;
  /** The single-use grant's `jti` for THIS request. */
  readonly grantJti: string;
  /** The `request_spec` row id for THIS request. */
  readonly specId: string;
  /** Optional receipt sink for the later informational completion step (never alters the charge). */
  readonly onCharged?: (receipt: ChargeReceipt) => void;
}

/**
 * Build the `beforeEgress` interlock for one request. It charges the budget (atomic, in the ledger) BEFORE returning;
 * a denial or any ledger error THROWS a `BudgetError`, so `runStage2` denies at the interlock stage and opens no
 * socket. The two per-request identifiers the grant claims do not carry (`grantJti`, `specId`) are bound in here by
 * the caller, which constructs a fresh interlock per dispatch.
 */
export function createBudgetInterlock(
  cfg: BudgetInterlockConfig,
): (ctx: {
  readonly claims: GrantClaims;
  readonly request: ReconstructedRequest;
}) => Promise<void> {
  return async ({ claims, request }): Promise<void> => {
    const outcome = await cfg.ledger.charge({
      tenantId: claims.tenantId,
      engagementId: claims.engagementId,
      specId: cfg.specId,
      grantJti: cfg.grantJti,
      owner: cfg.owner,
      canonicalTarget: request.targetUrl,
    });
    if (!outcome.ok) throw new BudgetError(outcome.reason);
    cfg.onCharged?.(outcome.receipt);
  };
}
