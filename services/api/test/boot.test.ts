import { describe, it, expect } from 'vitest';
import { KeyResolutionError, type AppConfig } from '@pentest/shared';
import { buildAuthContext } from '../src/auth.js';
import { TEST_KEY_MATERIAL } from './factories.js';

/**
 * Boot-fail exit test for authentication: in production the API refuses to start when the signing-key reference
 * cannot be resolved to strong material, with a secret-free error. Non-production boots on an ephemeral key.
 */

const base: Omit<AppConfig, 'nodeEnv'> = {
  apiHost: '127.0.0.1',
  apiPort: 8080,
  logLevel: 'info',
  databaseUrl: 'postgresql://u:p@127.0.0.1:5432/db',
  sessionSigningKeyRef: 'prod-signing-key-ref',
  authIssuer: 'pentest-tool',
  authAudience: 'pentest-api',
  devTokenMinterEnabled: false,
};

describe('authentication boot / key resolution', () => {
  it('production FAILS CLOSED when the key reference cannot be resolved (no material)', () => {
    let err: unknown;
    try {
      buildAuthContext({ ...base, nodeEnv: 'production' }, {});
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(KeyResolutionError);
    // Secret-free: names the reference, not any material.
    expect((err as Error).message).toContain('prod-signing-key-ref');
    expect((err as Error).message).not.toContain(TEST_KEY_MATERIAL);
  });

  it('production FAILS CLOSED on weak resolved material', () => {
    expect(() =>
      buildAuthContext(
        { ...base, nodeEnv: 'production' },
        { SESSION_SIGNING_KEY_MATERIAL: 'too-short' },
      ),
    ).toThrow(KeyResolutionError);
  });

  it('production BOOTS with strong resolved material (non-ephemeral key)', () => {
    const ctx = buildAuthContext(
      { ...base, nodeEnv: 'production' },
      { SESSION_SIGNING_KEY_MATERIAL: TEST_KEY_MATERIAL },
    );
    expect(ctx.signingKey.ephemeral).toBe(false);
    expect(ctx.issuer).toBe('pentest-tool');
  });

  it('non-production boots on an ephemeral key when no material is present (Compose stays usable)', () => {
    const ctx = buildAuthContext({ ...base, nodeEnv: 'development' }, {});
    expect(ctx.signingKey.ephemeral).toBe(true);
  });
});
