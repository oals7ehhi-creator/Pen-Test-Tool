/**
 * Broker authenticated ingress (Phase 0 doc 10 §4.3 / §7.1 step 6–7). The broker is NOT a generic CONNECT proxy:
 * it accepts a request ONLY when a valid per-job identity (established out-of-band by the ingress mTLS / capability)
 * is presented together with a valid, unconsumed, spec-bound egress grant whose `tenant/engagement/run/job` EQUAL
 * that identity's. This module is the pure decision: verify the grant (delegated to @pentest/spec) and require the
 * identity match. The transport (mTLS termination, socket) is wired separately; here we prove authorization.
 *
 * A grant is single-use: `verifyGrant` consumes its `jti` as the final step of a successful verification. A grant
 * presented under a MISMATCHED identity is rejected here AFTER the grant itself verified — i.e. its jti is consumed
 * (spent), a deliberate defensive stance: a grant that surfaces under the wrong job is treated as compromised and
 * burned, never reusable. (The network topology of §4 makes presenting someone else's grant impractical to begin
 * with; this is defence in depth.)
 */

import { verifyGrant, type GrantClaims, type VerifyGrantParams } from '@pentest/spec';

export interface JobIdentity {
  readonly tenantId: string;
  readonly engagementId: string;
  readonly runId: string;
  readonly jobId: string;
}

export class IngressError extends Error {
  readonly reason: 'identity_mismatch';
  constructor() {
    super('identity_mismatch'); // fixed reason code — never the token/claims/identity values
    this.name = 'IngressError';
    this.reason = 'identity_mismatch';
  }
}

/**
 * Authorize a broker ingress request: verify the grant against this broker's audience + the presented spec digest,
 * then require the grant's engagement-identity to equal the calling job's identity. Returns the grant claims on
 * success; throws a typed `GrantError` (grant invalid) or `IngressError` (identity mismatch) otherwise.
 */
export async function authorizeIngress(
  identity: JobIdentity,
  token: string,
  verifyParams: VerifyGrantParams,
): Promise<GrantClaims> {
  const claims = await verifyGrant(token, verifyParams);
  if (
    claims.tenantId !== identity.tenantId ||
    claims.engagementId !== identity.engagementId ||
    claims.runId !== identity.runId ||
    claims.jobId !== identity.jobId
  ) {
    throw new IngressError();
  }
  return claims;
}
