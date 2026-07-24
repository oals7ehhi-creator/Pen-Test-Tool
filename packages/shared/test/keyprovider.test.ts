import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import {
  resolveSigningKey,
  loadSigningKey,
  KeyResolutionError,
  MIN_KEY_BYTES,
} from '../src/index.js';

/**
 * Key-provider boundary: production FAILS CLOSED on missing/weak material; non-production uses an ephemeral key.
 * The reference is never treated as material and errors are secret-free.
 */

const STRONG = createHash('sha256').update('keyprovider-test-strong-material').digest('base64url'); // 43 high-entropy chars
const fixedBytes = (n: number): Uint8Array => new Uint8Array(n).fill(9);

describe('resolveSigningKey', () => {
  it('accepts strong material and derives a non-secret kid from the reference (not the material)', () => {
    const k = resolveSigningKey({ ref: 'primary', material: STRONG, nodeEnv: 'production' });
    expect(k.ephemeral).toBe(false);
    expect(k.key.length).toBeGreaterThanOrEqual(MIN_KEY_BYTES);
    expect(k.kid).toMatch(/^k_[0-9a-f]{12}$/);
    // kid is derived from the ref, and is stable per-ref and independent of the material.
    const k2 = resolveSigningKey({
      ref: 'primary',
      material: STRONG + 'zzz',
      nodeEnv: 'production',
    });
    expect(k2.kid).toBe(k.kid);
    expect(
      resolveSigningKey({ ref: 'other', material: STRONG, nodeEnv: 'production' }).kid,
    ).not.toBe(k.kid);
  });

  it('production FAILS CLOSED when material is missing (unresolved reference)', () => {
    let err: unknown;
    try {
      resolveSigningKey({ ref: 'primary', material: undefined, nodeEnv: 'production' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(KeyResolutionError);
    expect((err as KeyResolutionError).ref).toBe('primary');
    // secret-free: names the reference and a generic reason, nothing else.
    expect((err as Error).message).toContain('primary');
    expect((err as Error).message).not.toContain(STRONG);
  });

  it('production FAILS CLOSED on weak material (too short, low entropy, or a placeholder)', () => {
    const weak = [
      'short',
      'a'.repeat(40),
      'dev-insecure-session-key-change-me-0123456789',
      STRONG + '-changeme',
    ];
    for (const material of weak) {
      expect(() => resolveSigningKey({ ref: 'primary', material, nodeEnv: 'production' })).toThrow(
        KeyResolutionError,
      );
    }
    // ...and the thrown message never contains the offending material value.
    let msg = '';
    try {
      resolveSigningKey({ ref: 'primary', material: 'a'.repeat(40), nodeEnv: 'production' });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).not.toContain('aaaa');
  });

  it('non-production uses a deterministic-in-test EPHEMERAL key when material is absent or weak', () => {
    for (const nodeEnv of ['development', 'test'] as const) {
      const k = resolveSigningKey({
        ref: 'primary',
        material: undefined,
        nodeEnv,
        randomBytes: fixedBytes,
      });
      expect(k.ephemeral).toBe(true);
      expect(k.kid).toBe('ephemeral');
      expect(k.key.length).toBe(MIN_KEY_BYTES);
    }
    // weak material in dev also falls back to ephemeral (does not throw)
    const w = resolveSigningKey({
      ref: 'p',
      material: 'short',
      nodeEnv: 'development',
      randomBytes: fixedBytes,
    });
    expect(w.ephemeral).toBe(true);
  });

  it('loadSigningKey reads material from SESSION_SIGNING_KEY_MATERIAL', () => {
    const k = loadSigningKey('primary', 'production', { SESSION_SIGNING_KEY_MATERIAL: STRONG });
    expect(k.ephemeral).toBe(false);
    expect(() => loadSigningKey('primary', 'production', {})).toThrow(KeyResolutionError);
  });
});
