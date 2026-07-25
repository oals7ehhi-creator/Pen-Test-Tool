import { describe, it, expect } from 'vitest';
import type { ScopeVersion, ScopeEntry } from '@pentest/scope';
import { guardResolvedIp, resolveAndPin, type ResolveContext } from '../src/index.js';

/**
 * Resolve → validate → PIN (Phase 0 §7.1 step 11). This is the broker's connect-time DNS-rebinding / SSRF defense.
 * Proves: every resolved address is guarded (§6) + exclusion-checked + Tier-B-gated; a MIXED A/AAAA set (one bad
 * record) refuses the whole connection rather than picking the good one; an empty resolution and an unparseable
 * address fail closed; and the pinned address is one that actually passed.
 */

const scope = (...entries: ScopeEntry[]): ScopeVersion => ({ entries });

/** A resolver that always returns the given fixed address list. */
const resolveTo =
  (...ips: string[]) =>
  (): Promise<readonly string[]> =>
    Promise.resolve(ips);

const ctx = (over: Partial<ResolveContext> = {}): ResolveContext => ({
  scope: scope({
    class: 'domain',
    hostAscii: 'example.com',
    wildcard: false,
    includeSubdomains: false,
  }),
  resolve: resolveTo('93.184.216.34'),
  ...over,
});

describe('guardResolvedIp (§6 at connect time)', () => {
  it('permits a public address', () => {
    expect(guardResolvedIp('93.184.216.34', ctx())).toEqual({ ok: true });
  });

  it('hard-denies Tier A addresses (loopback, metadata, unspecified, obfuscated)', () => {
    for (const [ip, reason] of [
      ['127.0.0.1', 'network_guard:loopback'],
      ['169.254.169.254', 'network_guard:cloud_metadata'],
      ['0.0.0.0', 'network_guard:unspecified'],
      ['::1', 'network_guard:loopback'],
      ['::ffff:169.254.169.254', 'network_guard:embedded_v4:cloud_metadata'],
    ] as const) {
      expect(guardResolvedIp(ip, ctx()), ip).toEqual({ ok: false, reason });
    }
  });

  it('fails closed on an unparseable resolver answer', () => {
    expect(guardResolvedIp('not-an-ip', ctx())).toEqual({ ok: false, reason: 'unparseable_ip' });
  });

  it('denies a resolved address that hits an ip/cidr exclusion (exclusions always win)', () => {
    const s = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      { class: 'ip', ip: '93.184.216.34', isExclusion: true },
    );
    expect(guardResolvedIp('93.184.216.34', ctx({ scope: s }))).toEqual({
      ok: false,
      reason: 'excluded',
    });
  });

  it('a v4 exclusion catches the IPv4-mapped IPv6 form (embedded-v4 cannot evade an exclusion)', () => {
    // Regression: `::ffff:8.8.8.8` decodes to the excluded public 8.8.8.8; the guard classifies it via the embedded
    // v4, so the exclusion match MUST decode the same way — otherwise the mapped form bypasses the deny.
    const byIp = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      { class: 'ip', ip: '8.8.8.8', isExclusion: true },
    );
    expect(guardResolvedIp('::ffff:8.8.8.8', ctx({ scope: byIp }))).toEqual({
      ok: false,
      reason: 'excluded',
    });
    // …and via a v4 CIDR exclusion covering it.
    const byCidr = scope(
      { class: 'domain', hostAscii: 'example.com', wildcard: false, includeSubdomains: false },
      { class: 'cidr', version: 4, base: '8.8.8.0', prefix: 24, isExclusion: true },
    );
    expect(guardResolvedIp('::ffff:8.8.8.8', ctx({ scope: byCidr }))).toEqual({
      ok: false,
      reason: 'excluded',
    });
  });

  describe('Tier B (private) gating', () => {
    const tierB = '10.0.0.5';
    it('denies a Tier B address with no elevated entry', () => {
      const s = scope({ class: 'cidr', version: 4, base: '10.0.0.0', prefix: 8 });
      expect(guardResolvedIp(tierB, ctx({ scope: s }))).toEqual({
        ok: false,
        reason: 'restricted_range_not_elevated',
      });
    });
    it('denies a Tier B address with an elevated entry but no granted elevation', () => {
      const s = scope({ class: 'cidr', version: 4, base: '10.0.0.0', prefix: 8, elevated: true });
      expect(guardResolvedIp(tierB, ctx({ scope: s }))).toEqual({
        ok: false,
        reason: 'restricted_range_elevation_not_granted',
      });
    });
    it('permits a Tier B address with an elevated entry AND granted elevation', () => {
      const s = scope({ class: 'cidr', version: 4, base: '10.0.0.0', prefix: 8, elevated: true });
      expect(guardResolvedIp(tierB, ctx({ scope: s, elevationGranted: true }))).toEqual({
        ok: true,
      });
    });
    it('an elevated DOMAIN entry does NOT grant Tier B reachability (only an ip/cidr elevation counts)', () => {
      // A broad elevated domain must never open a private resolution — network-tier elevation is enumerated as ip/cidr.
      const s = scope({
        class: 'domain',
        hostAscii: 'example.com',
        wildcard: true,
        includeSubdomains: true,
        elevated: true,
      });
      expect(guardResolvedIp(tierB, ctx({ scope: s, elevationGranted: true }))).toEqual({
        ok: false,
        reason: 'restricted_range_not_elevated',
      });
    });
    it('permits via an elevated single-IP entry, and denies a non-matching elevated IP', () => {
      // The class:'ip' elevated-allow path (not just cidr): an exact elevated ip + granted elevation permits…
      const match = scope({ class: 'ip', ip: '10.0.0.5', elevated: true });
      expect(guardResolvedIp(tierB, ctx({ scope: match, elevationGranted: true }))).toEqual({
        ok: true,
      });
      // …but an elevated ip for a DIFFERENT address does not cover this one.
      const other = scope({ class: 'ip', ip: '10.0.0.6', elevated: true });
      expect(guardResolvedIp(tierB, ctx({ scope: other, elevationGranted: true }))).toEqual({
        ok: false,
        reason: 'restricted_range_not_elevated',
      });
    });
    it('an exclusion still wins over an elevated Tier B allow', () => {
      const s = scope(
        { class: 'cidr', version: 4, base: '10.0.0.0', prefix: 8, elevated: true },
        { class: 'ip', ip: '10.0.0.5', isExclusion: true },
      );
      expect(guardResolvedIp(tierB, ctx({ scope: s, elevationGranted: true }))).toEqual({
        ok: false,
        reason: 'excluded',
      });
    });
  });

  describe('Tier A absoluteness (invariant 3 — no elevation/allow ever reaches it)', () => {
    // Tier A wins by ORDERING (hard_deny returns before the exclusion + elevation blocks). These pin that: a reorder
    // that consulted elevation/allow first would dial loopback/metadata and every OTHER test would still pass.
    it('hard-denies loopback even under an elevated CIDR covering it + granted elevation', () => {
      const s = scope({ class: 'cidr', version: 4, base: '127.0.0.0', prefix: 8, elevated: true });
      expect(guardResolvedIp('127.0.0.1', ctx({ scope: s, elevationGranted: true }))).toEqual({
        ok: false,
        reason: 'network_guard:loopback',
      });
    });
    it('hard-denies cloud metadata even under an elevated exact-IP entry + granted elevation', () => {
      const s = scope({ class: 'ip', ip: '169.254.169.254', elevated: true });
      expect(guardResolvedIp('169.254.169.254', ctx({ scope: s, elevationGranted: true }))).toEqual(
        { ok: false, reason: 'network_guard:cloud_metadata' },
      );
    });
    it('hard-denies the IPv4-mapped metadata form even under an elevated entry for it', () => {
      const s = scope({ class: 'ip', ip: '169.254.169.254', elevated: true });
      expect(
        guardResolvedIp('::ffff:169.254.169.254', ctx({ scope: s, elevationGranted: true })),
      ).toEqual({ ok: false, reason: 'network_guard:embedded_v4:cloud_metadata' });
    });
    it('a non-exclusion positive IP allow for a Tier A address does not override the network guard', () => {
      const s = scope({ class: 'ip', ip: '127.0.0.1' });
      expect(guardResolvedIp('127.0.0.1', ctx({ scope: s }))).toEqual({
        ok: false,
        reason: 'network_guard:loopback',
      });
    });
  });
});

describe('resolveAndPin', () => {
  it('pins the validated address for a clean single-record resolution', async () => {
    const d = await resolveAndPin('example.com', ctx({ resolve: resolveTo('93.184.216.34') }));
    expect(d).toEqual({ ok: true, pinnedIp: '93.184.216.34', resolved: ['93.184.216.34'] });
  });

  it('refuses the WHOLE connection when a mixed A-record set contains a forbidden address (rebinding defense)', async () => {
    // A legitimate public record AND a smuggled metadata record ⇒ deny, never "pick the good one".
    const d = await resolveAndPin(
      'example.com',
      ctx({ resolve: resolveTo('93.184.216.34', '169.254.169.254') }),
    );
    expect(d).toMatchObject({
      ok: false,
      reason: 'network_guard:cloud_metadata',
      ip: '169.254.169.254',
    });
    // Invariant 8 (no leak): the REASON is a fixed code — it must never embed the offending address value.
    if (!d.ok) {
      expect(d.reason).not.toContain('169.254.169.254');
      expect(d.reason).toMatch(/^[a-z0-9_:]+$/);
    }
  });

  it('denies an empty resolution (fail closed)', async () => {
    const d = await resolveAndPin('example.com', ctx({ resolve: resolveTo() }));
    expect(d).toEqual({ ok: false, reason: 'no_resolution' });
  });

  it('pins the FIRST validated address in canonical form (and echoes the intact raw resolution)', async () => {
    // both public + in scope; the pin is the first, canonicalized (obfuscated forms normalize). The `resolved`
    // echo is the RAW resolver answer, pinned in full so a truncated/rewritten echo would fail.
    const d = await resolveAndPin(
      'example.com',
      ctx({ resolve: resolveTo('0x5db8d822', '93.184.216.35') }),
    );
    expect(d).toEqual({
      ok: true,
      pinnedIp: '93.184.216.34',
      resolved: ['0x5db8d822', '93.184.216.35'],
    });
  });

  it('denies when any resolved address is a private range without elevation (rebinding to internal)', async () => {
    const s = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: false,
      includeSubdomains: false,
    });
    const d = await resolveAndPin(
      'example.com',
      ctx({ scope: s, resolve: resolveTo('93.184.216.34', '192.168.1.10') }),
    );
    expect(d).toMatchObject({
      ok: false,
      reason: 'restricted_range_not_elevated',
      ip: '192.168.1.10',
    });
  });
});

describe('IPv6 resolution', () => {
  it('permits a public IPv6 address and pins its RFC 5952 canonical form', async () => {
    const d = await resolveAndPin(
      'example.com',
      ctx({ resolve: resolveTo('2606:2800:0220:0001::1') }),
    );
    expect(d).toEqual({
      ok: true,
      pinnedIp: '2606:2800:220:1::1',
      resolved: ['2606:2800:0220:0001::1'],
    });
  });

  it('hard-denies IPv6 loopback / ULA-without-elevation and honours a v6 exclusion', () => {
    expect(guardResolvedIp('::1', ctx())).toEqual({ ok: false, reason: 'network_guard:loopback' });
    // ULA fd00::/8 is Tier B: denied without an elevated entry.
    const ula = scope({
      class: 'domain',
      hostAscii: 'example.com',
      wildcard: false,
      includeSubdomains: false,
    });
    expect(guardResolvedIp('fd00::1', ctx({ scope: ula }))).toEqual({
      ok: false,
      reason: 'restricted_range_not_elevated',
    });
    // a v4 elevated cidr must NOT elevate a v6 Tier B address (no cross-version matching).
    const v4only = scope({
      class: 'cidr',
      version: 4,
      base: '10.0.0.0',
      prefix: 8,
      elevated: true,
    });
    expect(guardResolvedIp('fd00::1', ctx({ scope: v4only, elevationGranted: true }))).toEqual({
      ok: false,
      reason: 'restricted_range_not_elevated',
    });
    // an elevated v6 cidr + granted elevation permits it…
    const elevated = scope({
      class: 'cidr',
      version: 6,
      base: 'fd00::',
      prefix: 8,
      elevated: true,
    });
    expect(guardResolvedIp('fd00::1', ctx({ scope: elevated, elevationGranted: true }))).toEqual({
      ok: true,
    });
    // …unless a v6 exclusion covers it.
    const excluded = scope(
      { class: 'cidr', version: 6, base: 'fd00::', prefix: 8, elevated: true },
      { class: 'cidr', version: 6, base: 'fd00::', prefix: 16, isExclusion: true },
    );
    expect(guardResolvedIp('fd00::1', ctx({ scope: excluded, elevationGranted: true }))).toEqual({
      ok: false,
      reason: 'excluded',
    });
  });

  it('refuses a mixed v4+v6 set where the v6 record is metadata-embedded (rebinding)', async () => {
    const d = await resolveAndPin(
      'example.com',
      ctx({ resolve: resolveTo('93.184.216.34', '::ffff:169.254.169.254') }),
    );
    expect(d).toMatchObject({ ok: false, ip: '::ffff:169.254.169.254' });
    if (!d.ok) expect(d.reason).toMatch(/^network_guard:/);
  });
});
