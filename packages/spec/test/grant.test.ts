import { describe, it, expect } from 'vitest';
import {
  mintGrant,
  verifyGrant,
  GrantError,
  MAX_GRANT_TTL_SECONDS,
  type GrantClaims,
  type MintGrantParams,
} from '../src/index.js';

/**
 * Stage-1 egress grant (Phase 0 §7.1). Proves the mint/verify round-trip, the single-use (replay) defense, the
 * spec-digest binding, and that a tampered / expired / not-yet-valid / wrong-audience / wrong-issuer / wrong-key
 * grant is rejected with a fixed reason — and that a rejected grant never burns its jti.
 */

const KEY = new TextEncoder().encode('k'.repeat(32));
const OTHER_KEY = new TextEncoder().encode('z'.repeat(32));
const ISS = 'scope-authority';
const AUD = 'egress-broker';
const NOW = 1_000_000;
const SPEC = 'f'.repeat(64);

const claims: GrantClaims = {
  runId: 'run-1',
  jobId: 'job-1',
  tenantId: 'tenant-1',
  engagementId: 'eng-1',
  authorizationId: 'auth-1',
  scopeHash: 'a'.repeat(64),
  specSha256: SPEC,
  requestClass: 'native',
};

function mintParams(over: Partial<MintGrantParams> = {}): MintGrantParams {
  return {
    claims,
    key: KEY,
    kid: 'k_test',
    issuer: ISS,
    audience: AUD,
    ttlSeconds: 30,
    nowSeconds: NOW,
    jti: 'jti-1',
    ...over,
  };
}

/** A single-use jti store: true iff the jti was previously unused. */
function jtiStore(): (jti: string) => boolean {
  const used = new Set<string>();
  return (jti) => {
    if (used.has(jti)) return false;
    used.add(jti);
    return true;
  };
}

describe('mintGrant / verifyGrant round-trip', () => {
  it('verifies a fresh grant against the matching spec digest and returns its claims', async () => {
    const token = await mintGrant(mintParams());
    const out = await verifyGrant(token, {
      key: KEY,
      issuer: ISS,
      audience: AUD,
      presentedSpecSha256: SPEC,
      nowSeconds: NOW + 5,
      consumeJti: jtiStore(),
    });
    expect(out).toMatchObject(claims);
  });

  it('carries an optional approval_ref only when present', async () => {
    const withRef = await mintGrant(mintParams({ claims: { ...claims, approvalRef: 'appr-1' } }));
    const out = await verifyGrant(withRef, {
      key: KEY,
      issuer: ISS,
      audience: AUD,
      presentedSpecSha256: SPEC,
      nowSeconds: NOW,
      consumeJti: jtiStore(),
    });
    expect(out.approvalRef).toBe('appr-1');
    // absent by default
    const noRef = await mintGrant(mintParams());
    const out2 = await verifyGrant(noRef, {
      key: KEY,
      issuer: ISS,
      audience: AUD,
      presentedSpecSha256: SPEC,
      nowSeconds: NOW,
      consumeJti: jtiStore(),
    });
    expect('approvalRef' in out2).toBe(false);
  });
});

describe('single-use (replay)', () => {
  it('rejects the second verification of the same grant', async () => {
    const token = await mintGrant(mintParams());
    const consume = jtiStore();
    await verifyGrant(token, {
      key: KEY,
      issuer: ISS,
      audience: AUD,
      presentedSpecSha256: SPEC,
      nowSeconds: NOW,
      consumeJti: consume,
    });
    await expect(
      verifyGrant(token, {
        key: KEY,
        issuer: ISS,
        audience: AUD,
        presentedSpecSha256: SPEC,
        nowSeconds: NOW,
        consumeJti: consume,
      }),
    ).rejects.toMatchObject({ reason: 'replayed' });
  });

  it('does NOT consume the jti when an earlier check fails (spec mismatch)', async () => {
    const token = await mintGrant(mintParams());
    const consume = jtiStore();
    // wrong presented digest ⇒ spec_mismatch, jti must remain unused
    await expect(
      verifyGrant(token, {
        key: KEY,
        issuer: ISS,
        audience: AUD,
        presentedSpecSha256: 'e'.repeat(64),
        nowSeconds: NOW,
        consumeJti: consume,
      }),
    ).rejects.toMatchObject({ reason: 'spec_mismatch' });
    // the correct verification still succeeds afterwards (jti was not burned)
    const out = await verifyGrant(token, {
      key: KEY,
      issuer: ISS,
      audience: AUD,
      presentedSpecSha256: SPEC,
      nowSeconds: NOW,
      consumeJti: consume,
    });
    expect(out.specSha256).toBe(SPEC);
  });
});

describe('rejections (each a fixed reason)', () => {
  const good = {
    key: KEY,
    issuer: ISS,
    audience: AUD,
    presentedSpecSha256: SPEC,
    nowSeconds: NOW,
  } as const;

  it('spec digest mismatch → spec_mismatch', async () => {
    const token = await mintGrant(mintParams());
    await expect(
      verifyGrant(token, { ...good, presentedSpecSha256: 'e'.repeat(64), consumeJti: jtiStore() }),
    ).rejects.toMatchObject({ reason: 'spec_mismatch' });
  });

  it('wrong signing key → bad_signature', async () => {
    const token = await mintGrant(mintParams());
    await expect(
      verifyGrant(token, { ...good, key: OTHER_KEY, consumeJti: jtiStore() }),
    ).rejects.toMatchObject({ reason: 'bad_signature' });
  });

  it('expired grant → expired', async () => {
    const token = await mintGrant(mintParams({ ttlSeconds: 10 }));
    await expect(
      verifyGrant(token, { ...good, nowSeconds: NOW + 10 + 6, consumeJti: jtiStore() }),
    ).rejects.toMatchObject({ reason: 'expired' });
  });

  it('not-yet-valid grant → not_yet_valid', async () => {
    const token = await mintGrant(mintParams());
    await expect(
      verifyGrant(token, { ...good, nowSeconds: NOW - 10, consumeJti: jtiStore() }),
    ).rejects.toMatchObject({ reason: 'not_yet_valid' });
  });

  it('wrong audience → wrong_audience', async () => {
    const token = await mintGrant(mintParams());
    await expect(
      verifyGrant(token, { ...good, audience: 'someone-else', consumeJti: jtiStore() }),
    ).rejects.toMatchObject({ reason: 'wrong_audience' });
  });

  it('wrong issuer → wrong_issuer', async () => {
    const token = await mintGrant(mintParams());
    await expect(
      verifyGrant(token, { ...good, issuer: 'not-the-authority', consumeJti: jtiStore() }),
    ).rejects.toMatchObject({ reason: 'wrong_issuer' });
  });

  it('garbage token → malformed', async () => {
    await expect(
      verifyGrant('not.a.jwt', { ...good, consumeJti: jtiStore() }),
    ).rejects.toBeInstanceOf(GrantError);
    await expect(
      verifyGrant('not.a.jwt', { ...good, consumeJti: jtiStore() }),
    ).rejects.toMatchObject({ reason: 'malformed' });
  });
});

describe('mint TTL policy (§7.1: ≤ 30 s)', () => {
  it('rejects a non-positive or over-max TTL', async () => {
    await expect(mintGrant(mintParams({ ttlSeconds: 0 }))).rejects.toMatchObject({
      reason: 'invalid_claims',
    });
    await expect(mintGrant(mintParams({ ttlSeconds: -1 }))).rejects.toMatchObject({
      reason: 'invalid_claims',
    });
    await expect(
      mintGrant(mintParams({ ttlSeconds: MAX_GRANT_TTL_SECONDS + 1 })),
    ).rejects.toMatchObject({ reason: 'invalid_claims' });
  });

  it('accepts the maximum TTL', async () => {
    const token = await mintGrant(mintParams({ ttlSeconds: MAX_GRANT_TTL_SECONDS }));
    const out = await verifyGrant(token, {
      key: KEY,
      issuer: ISS,
      audience: AUD,
      presentedSpecSha256: SPEC,
      nowSeconds: NOW + MAX_GRANT_TTL_SECONDS,
      consumeJti: jtiStore(),
    });
    expect(out.jobId).toBe('job-1');
  });
});

describe('claim integrity', () => {
  it('a grant missing a required claim → invalid_claims', async () => {
    // Forge a token with the right signature but a missing required claim, by minting with an empty runId.
    const token = await mintGrant(mintParams({ claims: { ...claims, runId: '' } }));
    await expect(
      verifyGrant(token, {
        key: KEY,
        issuer: ISS,
        audience: AUD,
        presentedSpecSha256: SPEC,
        nowSeconds: NOW,
        consumeJti: jtiStore(),
      }),
    ).rejects.toMatchObject({ reason: 'invalid_claims' });
  });
});
