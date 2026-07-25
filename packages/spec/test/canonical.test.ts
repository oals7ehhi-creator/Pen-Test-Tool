import { describe, it, expect } from 'vitest';
import { canonicalJson, sha256Hex, canonicalDigest, type JsonValue } from '../src/index.js';

/**
 * Canonical JSON + SHA-256 (Phase 0 §1). Proves the serialization is deterministic and order-independent, that a
 * cosmetic difference never changes the digest, that a semantic difference always does, and that `undefined` is
 * rejected (so an absent field can never silently vanish from a content address).
 */

describe('canonicalJson', () => {
  it('sorts object keys recursively and is insertion-order-independent', () => {
    const a = canonicalJson({ b: 1, a: 2, nested: { y: 1, x: 2 } });
    const b = canonicalJson({ nested: { x: 2, y: 1 }, a: 2, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"b":1,"nested":{"x":2,"y":1}}');
  });

  it('preserves array order (order is significant)', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
    expect(canonicalJson([1, 2, 3])).not.toBe(canonicalJson([3, 2, 1]));
  });

  it('emits explicit null and distinguishes it from an absent key', () => {
    expect(canonicalJson({ a: null })).toBe('{"a":null}');
    expect(canonicalJson({ a: null })).not.toBe(canonicalJson({}));
  });

  it('encodes primitives via standard JSON', () => {
    expect(canonicalJson('a"b')).toBe('"a\\"b"');
    expect(canonicalJson(true)).toBe('true');
    expect(canonicalJson(false)).toBe('false');
    expect(canonicalJson(0)).toBe('0');
    expect(canonicalJson(null)).toBe('null');
  });

  it('rejects undefined values (would silently drop from the digest)', () => {
    expect(() => canonicalJson({ a: undefined } as unknown as JsonValue)).toThrow(/undefined/);
  });

  it('rejects non-finite numbers', () => {
    expect(() => canonicalJson(Number.POSITIVE_INFINITY as unknown as JsonValue)).toThrow(
      /non-finite/,
    );
    expect(() => canonicalJson(Number.NaN as unknown as JsonValue)).toThrow(/non-finite/);
  });
});

describe('sha256Hex / canonicalDigest', () => {
  it('sha256Hex matches the well-known empty-string digest', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('canonicalDigest is stable across key order and changes with any value change', () => {
    const d1 = canonicalDigest({ b: 1, a: 'x' });
    const d2 = canonicalDigest({ a: 'x', b: 1 });
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^[0-9a-f]{64}$/);
    expect(canonicalDigest({ a: 'x', b: 2 })).not.toBe(d1);
  });
});
