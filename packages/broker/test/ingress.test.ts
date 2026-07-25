import { describe, it, expect } from 'vitest';
import { mintGrant, GrantError, type GrantClaims } from '@pentest/spec';
import { authorizeIngress, IngressError, type JobIdentity } from '../src/index.js';

/**
 * Broker authenticated ingress (Phase 0 doc 10 §4.3 / §7.1 step 6–7). Proves the broker accepts a request only with
 * a valid, spec-bound, single-use grant AND a per-job identity whose tenant/engagement/run/job equal the grant's;
 * a grant surfacing under a mismatched identity is rejected (and, being verified, single-use-consumed).
 */

const KEY = new TextEncoder().encode('k'.repeat(32));
const ISS = 'scope-authority';
const AUD = 'egress-broker';
const NOW = 2_000_000;
const SPEC = 'f'.repeat(64);

const identity: JobIdentity = {
  tenantId: 'tenant-1',
  engagementId: 'eng-1',
  runId: 'run-1',
  jobId: 'job-1',
};
const claims: GrantClaims = {
  ...identity,
  authorizationId: 'auth-1',
  scopeHash: 'a'.repeat(64),
  specSha256: SPEC,
  requestClass: 'native',
};

function jtiStore(): (jti: string) => boolean {
  const used = new Set<string>();
  return (jti) => (used.has(jti) ? false : (used.add(jti), true));
}

async function grant(jti = 'jti-1'): Promise<string> {
  return mintGrant({
    claims,
    key: KEY,
    kid: 'k',
    issuer: ISS,
    audience: AUD,
    ttlSeconds: 30,
    nowSeconds: NOW,
    jti,
  });
}

const verifyParams = (consume: (jti: string) => boolean) => ({
  key: KEY,
  issuer: ISS,
  audience: AUD,
  presentedSpecSha256: SPEC,
  nowSeconds: NOW,
  consumeJti: consume,
});

describe('authorizeIngress', () => {
  it('accepts a valid grant whose identity matches the calling job', async () => {
    const token = await grant();
    const out = await authorizeIngress(identity, token, verifyParams(jtiStore()));
    expect(out).toMatchObject(identity);
  });

  it('rejects a valid grant presented under a mismatched job identity', async () => {
    const token = await grant();
    const wrong: JobIdentity = { ...identity, jobId: 'job-2' };
    await expect(authorizeIngress(wrong, token, verifyParams(jtiStore()))).rejects.toBeInstanceOf(
      IngressError,
    );
    const err = await authorizeIngress(wrong, token, verifyParams(jtiStore())).catch(
      (e: unknown) => e,
    );
    expect(err).toMatchObject({ reason: 'identity_mismatch' });
    // Invariant 8 (no leak): the error carries only the fixed code — never the offending identity or the token.
    expect((err as Error).message).toBe('identity_mismatch');
    expect((err as Error).message).not.toContain('job-2');
    expect((err as Error).message).not.toContain(token);
  });

  it('burns the jti of a grant rejected for identity mismatch (defensive single-use, invariant 6)', async () => {
    // verifyGrant consumes the jti BEFORE the identity check, so a grant surfacing under the wrong job is spent:
    // re-presenting the SAME token even under the correct identity must now fail `replayed`, never succeed.
    const token = await grant();
    const consume = jtiStore();
    const wrong: JobIdentity = { ...identity, jobId: 'job-2' };
    await expect(authorizeIngress(wrong, token, verifyParams(consume))).rejects.toBeInstanceOf(
      IngressError,
    );
    await expect(authorizeIngress(identity, token, verifyParams(consume))).rejects.toMatchObject({
      reason: 'replayed',
    });
  });

  it('rejects each mismatched identity dimension (tenant / engagement / run)', async () => {
    for (const wrong of [
      { ...identity, tenantId: 'tenant-2' },
      { ...identity, engagementId: 'eng-2' },
      { ...identity, runId: 'run-2' },
    ]) {
      const token = await grant();
      await expect(authorizeIngress(wrong, token, verifyParams(jtiStore()))).rejects.toBeInstanceOf(
        IngressError,
      );
    }
  });

  it('propagates a grant failure (wrong key → bad_signature)', async () => {
    const token = await grant();
    const badKey = new TextEncoder().encode('z'.repeat(32));
    await expect(
      authorizeIngress(identity, token, { ...verifyParams(jtiStore()), key: badKey }),
    ).rejects.toBeInstanceOf(GrantError);
  });

  it('propagates a spec-mismatch failure', async () => {
    const token = await grant();
    await expect(
      authorizeIngress(identity, token, {
        ...verifyParams(jtiStore()),
        presentedSpecSha256: 'e'.repeat(64),
      }),
    ).rejects.toMatchObject({ reason: 'spec_mismatch' });
  });

  it('a consumed grant cannot be re-authorized (single-use)', async () => {
    const token = await grant();
    const consume = jtiStore();
    await authorizeIngress(identity, token, verifyParams(consume));
    await expect(authorizeIngress(identity, token, verifyParams(consume))).rejects.toMatchObject({
      reason: 'replayed',
    });
  });
});
