/**
 * Canonical JSON + SHA-256, the primitive under content-addressing (Phase 0 §1 "Hashing", §7.0). A `request_spec`
 * (and any hashed document) must serialize to ONE canonical byte sequence so that two logically-identical objects
 * always produce the same digest, regardless of key insertion order or cosmetic whitespace. The rules (from §1):
 *
 *   - object keys are emitted in sorted (code-unit) order, recursively;
 *   - arrays keep their order (order is significant);
 *   - `null` is explicit; `undefined` is not representable (reject it, so an absent field is never silently dropped);
 *   - strings/numbers/booleans use the standard JSON encoding; non-finite numbers are rejected.
 *
 * This mirrors what the database trigger computes for the same fields, so the app and the DB agree byte-for-byte.
 */

import { createHash } from 'node:crypto';

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };

/** Serialize a JSON value to its canonical string form (sorted keys, no insignificant whitespace). */
export function canonicalJson(value: JsonValue): string {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(value as number)) throw new Error('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (t === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalJson(v)).join(',') + ']';
  if (t === 'object') {
    const obj = value as { readonly [key: string]: JsonValue };
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      const v = obj[k];
      // An `undefined` field would silently vanish from the digest — reject it so callers must pass explicit null.
      if (v === undefined) throw new Error(`canonicalJson: undefined value at key "${k}"`);
      parts.push(JSON.stringify(k) + ':' + canonicalJson(v));
    }
    return '{' + parts.join(',') + '}';
  }
  /* v8 ignore next -- unreachable: JsonValue admits no other runtime type */
  throw new Error(`canonicalJson: unsupported value type ${t}`);
}

/** Lowercase-hex SHA-256 of a UTF-8 string. */
export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** Canonical-JSON-serialize a value and return its lowercase-hex SHA-256 (the content address). */
export function canonicalDigest(value: JsonValue): string {
  return sha256Hex(canonicalJson(value));
}
