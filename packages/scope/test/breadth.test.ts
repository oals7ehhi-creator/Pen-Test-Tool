import { describe, it, expect } from 'vitest';
import {
  computeScopeBreadth,
  evaluateBreadth,
  ABSOLUTE_MIN_IPV4_PREFIX,
  ABSOLUTE_MIN_IPV6_PREFIX,
  type BreadthCeilings,
  type ScopeVersion,
  type ScopeEntry,
} from '../src/index.js';

/**
 * Scope-breadth accounting (Phase 0 §4.6, §4.2 absolute floors). Proves the four breadth metrics are computed over
 * ALLOW entries only, that IPv4 breadth is an exact worst-case address sum (Σ 2^(32−prefix)), that IPv6 breadth is
 * governed by a prefix floor (never a sum), and that absolute floors are hard-rejects while over-ceiling / broad
 * entries require elevation.
 */

const scope = (...entries: ScopeEntry[]): ScopeVersion => ({ entries });

const CEILINGS: BreadthCeilings = {
  maxScopeHosts: 1024,
  maxIpv4EquivAddresses: 65536,
  maxCidrEntries: 64,
  minIpv4Prefix: 24,
  minIpv6Prefix: 48,
};

describe('computeScopeBreadth (§4.6)', () => {
  it('an empty scope has zero breadth', () => {
    expect(computeScopeBreadth(scope())).toEqual({
      hostCount: 0,
      ipv4EquivAddresses: 0,
      cidrEntryCount: 0,
      ipv6MinPrefix: null,
    });
  });

  it('counts distinct domain + ip hosts (dedup identical entries)', () => {
    const b = computeScopeBreadth(
      scope(
        { class: 'domain', hostAscii: 'a.example', wildcard: false, includeSubdomains: false },
        { class: 'domain', hostAscii: 'a.example', wildcard: false, includeSubdomains: false },
        { class: 'domain', hostAscii: 'b.example', wildcard: false, includeSubdomains: false },
        { class: 'ip', ip: '93.184.216.34' },
      ),
    );
    expect(b.hostCount).toBe(3); // a.example, b.example, 93.184.216.34
    expect(b.ipv4EquivAddresses).toBe(1); // the single ip
  });

  it('IPv4 equivalent addresses is Σ 2^(32−prefix) over ip/cidr (ip = 1)', () => {
    const b = computeScopeBreadth(
      scope(
        { class: 'ip', ip: '93.184.216.34' }, // 1
        { class: 'cidr', version: 4, base: '198.51.100.0', prefix: 24 }, // 256
        { class: 'cidr', version: 4, base: '203.0.113.0', prefix: 30 }, // 4
      ),
    );
    expect(b.ipv4EquivAddresses).toBe(1 + 256 + 4);
    expect(b.cidrEntryCount).toBe(2);
  });

  it('IPv6 breadth is the broadest (smallest) prefix, never an address sum', () => {
    const b = computeScopeBreadth(
      scope(
        { class: 'cidr', version: 6, base: '2001:db8:1::', prefix: 48 },
        { class: 'cidr', version: 6, base: '2001:db8::', prefix: 40 }, // broader
        { class: 'ip', ip: '2606:2800:220::1' }, // /128
      ),
    );
    expect(b.ipv6MinPrefix).toBe(40);
    expect(b.ipv4EquivAddresses).toBe(0); // IPv6 never contributes to the v4 sum
    expect(b.cidrEntryCount).toBe(2);
    expect(b.hostCount).toBe(1); // only the single ip literal counts as a host
  });

  it('exclusions do not contribute to breadth', () => {
    const b = computeScopeBreadth(
      scope(
        { class: 'domain', hostAscii: 'a.example', wildcard: false, includeSubdomains: false },
        {
          class: 'cidr',
          version: 4,
          base: '10.0.0.0',
          prefix: 8,
          isExclusion: true,
        },
        { class: 'ip', ip: '10.1.2.3', isExclusion: true },
      ),
    );
    expect(b.hostCount).toBe(1);
    expect(b.ipv4EquivAddresses).toBe(0);
    expect(b.cidrEntryCount).toBe(0);
  });

  it('port / protocol / path entries do not contribute to breadth', () => {
    const b = computeScopeBreadth(
      scope(
        { class: 'port', low: 1, high: 65535 },
        { class: 'protocol', scheme: 'http' },
        {
          class: 'path_prefix',
          boundHostAscii: 'a.example',
          boundHostWildcard: false,
          pathPrefix: '/',
        },
      ),
    );
    expect(b).toEqual({
      hostCount: 0,
      ipv4EquivAddresses: 0,
      cidrEntryCount: 0,
      ipv6MinPrefix: null,
    });
  });
});

describe('evaluateBreadth — floors & ceilings (§4.2, §4.6)', () => {
  it('a scope within all limits has no violations', () => {
    const r = evaluateBreadth(
      scope(
        { class: 'domain', hostAscii: 'a.example', wildcard: false, includeSubdomains: false },
        { class: 'cidr', version: 4, base: '198.51.100.0', prefix: 24 },
      ),
      CEILINGS,
    );
    expect(r.hardRejects).toEqual([]);
    expect(r.elevationRequired).toEqual([]);
  });

  it('a CIDR broader than the absolute IPv4 floor is a hard reject (no approval lifts it)', () => {
    const r = evaluateBreadth(
      scope({ class: 'cidr', version: 4, base: '10.0.0.0', prefix: 8 }),
      CEILINGS,
    );
    expect(r.hardRejects).toHaveLength(1);
    expect(r.hardRejects[0]?.dimension).toBe('ipv4_prefix');
    expect(ABSOLUTE_MIN_IPV4_PREFIX).toBe(16);
  });

  it('a CIDR at the absolute floor but below the engagement floor requires elevation', () => {
    // /20 is >= absolute /16 but < engagement /24 → elevation, not hard reject.
    const r = evaluateBreadth(
      scope({ class: 'cidr', version: 4, base: '198.51.96.0', prefix: 20 }),
      CEILINGS,
    );
    expect(r.hardRejects).toEqual([]);
    expect(r.elevationRequired.some((v) => v.dimension === 'ipv4_prefix')).toBe(true);
  });

  it('a CIDR broader than the absolute IPv6 floor is a hard reject', () => {
    const r = evaluateBreadth(
      scope({ class: 'cidr', version: 6, base: '2001:db8::', prefix: 24 }),
      CEILINGS,
    );
    expect(r.hardRejects).toHaveLength(1);
    expect(r.hardRejects[0]?.dimension).toBe('ipv6_prefix');
    expect(ABSOLUTE_MIN_IPV6_PREFIX).toBe(32);
  });

  it('an IPv6 CIDR below the engagement floor (but above absolute) requires elevation', () => {
    const r = evaluateBreadth(
      scope({ class: 'cidr', version: 6, base: '2001:db8::', prefix: 40 }),
      CEILINGS,
    );
    expect(r.hardRejects).toEqual([]);
    expect(r.elevationRequired.some((v) => v.dimension === 'ipv6_prefix')).toBe(true);
  });

  it('a wildcard domain always requires elevation (§4.4)', () => {
    const r = evaluateBreadth(
      scope({
        class: 'domain',
        hostAscii: 'example.com',
        wildcard: true,
        includeSubdomains: false,
      }),
      CEILINGS,
    );
    expect(r.elevationRequired.some((v) => v.dimension === 'wildcard_domain')).toBe(true);
  });

  it('exceeding the host-count ceiling requires elevation', () => {
    const entries: ScopeEntry[] = [];
    for (let i = 0; i < 3; i++)
      entries.push({
        class: 'domain',
        hostAscii: `h${i}.example`,
        wildcard: false,
        includeSubdomains: false,
      });
    const tight: BreadthCeilings = { ...CEILINGS, maxScopeHosts: 2 };
    const r = evaluateBreadth(scope(...entries), tight);
    expect(r.elevationRequired.some((v) => v.dimension === 'host_count')).toBe(true);
  });

  it('exceeding the IPv4-address ceiling requires elevation', () => {
    // /16 = 65536 addresses; ceiling is 65536, so /15 (131072) exceeds it. /15 is >= absolute /16? No — /15 < /16.
    // Use two /16s to exceed the address ceiling without tripping the absolute floor.
    const r = evaluateBreadth(
      scope(
        { class: 'cidr', version: 4, base: '198.18.0.0', prefix: 16 },
        { class: 'cidr', version: 4, base: '198.19.0.0', prefix: 16 },
      ),
      CEILINGS,
    );
    expect(r.breadth.ipv4EquivAddresses).toBe(131072);
    expect(r.elevationRequired.some((v) => v.dimension === 'ipv4_equiv_addresses')).toBe(true);
  });

  it('exceeding the CIDR-entry-count ceiling requires elevation', () => {
    const entries: ScopeEntry[] = [];
    for (let i = 0; i < 3; i++)
      entries.push({ class: 'cidr', version: 4, base: `198.51.${100 + i}.0`, prefix: 24 });
    const tight: BreadthCeilings = { ...CEILINGS, maxCidrEntries: 2 };
    const r = evaluateBreadth(scope(...entries), tight);
    expect(r.elevationRequired.some((v) => v.dimension === 'cidr_entry_count')).toBe(true);
  });
});
