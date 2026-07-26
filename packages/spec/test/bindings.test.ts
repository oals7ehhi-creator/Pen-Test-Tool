import { describe, it, expect } from 'vitest';
import { createHash, createHmac } from 'node:crypto';
import {
  operatorSessionDigest,
  operatorQueryValueBinding,
  computeQueryValueDigest,
  canonicalJson,
} from '../src/index.js';

/**
 * Operator-secret bindings (§7.0). These are the single source of truth the spec builder and the broker share, and
 * the two colon-joined digests must equal the DB's GENERATED columns byte-for-byte (migration `0003`). The
 * known-answer vectors below lock the EXACT pre-image format (`tenant:engagement:account:version`, etc.) that the DB's
 * `digest(convert_to(... ,'utf8'),'sha256')` hashes, so an app/DB divergence would fail here.
 */

const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

describe('operatorSessionDigest', () => {
  it('is SHA-256 of tenant:engagement:account:version (mirrors the DB GENERATED column exactly)', () => {
    const id = { tenantId: 't1', engagementId: 'e1', accountId: 'acct', sessionVersion: 2 };
    expect(operatorSessionDigest(id)).toBe(sha256Hex('t1:e1:acct:2'));
  });

  it('changes when ANY identity field or the version changes (rotation / re-account invalidates it)', () => {
    const base = { tenantId: 't1', engagementId: 'e1', accountId: 'acct', sessionVersion: 2 };
    const d = operatorSessionDigest(base);
    expect(operatorSessionDigest({ ...base, tenantId: 't2' })).not.toBe(d);
    expect(operatorSessionDigest({ ...base, engagementId: 'e2' })).not.toBe(d);
    expect(operatorSessionDigest({ ...base, accountId: 'acct2' })).not.toBe(d);
    expect(operatorSessionDigest({ ...base, sessionVersion: 3 })).not.toBe(d);
  });
});

describe('operatorQueryValueBinding', () => {
  it('is SHA-256 of tenant:engagement:value_set:version (mirrors the DB GENERATED column exactly)', () => {
    const id = { tenantId: 't1', engagementId: 'e1', valueSetName: 'creds', valueVersion: 5 };
    expect(operatorQueryValueBinding(id)).toBe(sha256Hex('t1:e1:creds:5'));
  });

  it('changes with the version (a withdrawn/rotated version no longer matches the spec binding)', () => {
    const id = { tenantId: 't1', engagementId: 'e1', valueSetName: 'creds', valueVersion: 5 };
    expect(operatorQueryValueBinding({ ...id, valueVersion: 6 })).not.toBe(
      operatorQueryValueBinding(id),
    );
  });
});

describe('computeQueryValueDigest (keyed HMAC)', () => {
  const key = new TextEncoder().encode('k'.repeat(32));
  const entries = [
    { key: 'a', value: '1' },
    { key: 'b', value: '2' },
  ];

  it('is HMAC-SHA256(key, canonicalJson(ordered [{key,value}]))', () => {
    const expected = createHmac('sha256', key)
      .update(canonicalJson(entries.map((e) => ({ key: e.key, value: e.value }))), 'utf8')
      .digest('hex');
    expect(computeQueryValueDigest(key, entries)).toBe(expected);
  });

  it('is deterministic', () => {
    expect(computeQueryValueDigest(key, entries)).toBe(computeQueryValueDigest(key, entries));
  });

  it('depends on the key — an attacker without it cannot forge a matching digest', () => {
    const other = new TextEncoder().encode('z'.repeat(32));
    expect(computeQueryValueDigest(other, entries)).not.toBe(computeQueryValueDigest(key, entries));
  });

  it('is order-sensitive (parameter wire order is significant)', () => {
    const reversed = [...entries].reverse();
    expect(computeQueryValueDigest(key, reversed)).not.toBe(computeQueryValueDigest(key, entries));
  });

  it('binds BOTH keys and values (a key-substitution or a value change alters the digest)', () => {
    const keySwapped = [
      { key: 'X', value: '1' },
      { key: 'b', value: '2' },
    ];
    const valueChanged = [
      { key: 'a', value: '9' },
      { key: 'b', value: '2' },
    ];
    expect(computeQueryValueDigest(key, keySwapped)).not.toBe(
      computeQueryValueDigest(key, entries),
    );
    expect(computeQueryValueDigest(key, valueChanged)).not.toBe(
      computeQueryValueDigest(key, entries),
    );
  });
});
