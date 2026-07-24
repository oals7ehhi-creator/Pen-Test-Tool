import { describe, it, expect } from 'vitest';
import {
  parseIpv4Loose,
  parseStrictDottedQuad,
  parseIpv6,
  parseIpLiteral,
  guardIp,
  classifyBytes,
} from '../src/index.js';

/**
 * Network-guard battery (Phase 0 §5.2 / §6). Proves the SSRF chokepoint: every obfuscated / transition form of a
 * dangerous address is decoded to canonical bytes and hard-denied, Tier B is classified `restricted`, and only
 * genuinely public addresses are `permitted`. The guard fails closed on anything it cannot decode.
 */

const dq = (b: Uint8Array | null): string | null =>
  b === null ? null : `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;

describe('parseIpv4Loose — inet_aton / obfuscated forms decode to canonical bytes', () => {
  it('dotted-quad', () => expect(dq(parseIpv4Loose('127.0.0.1'))).toBe('127.0.0.1'));
  it('single decimal (2130706433)', () =>
    expect(dq(parseIpv4Loose('2130706433'))).toBe('127.0.0.1'));
  it('single hex (0x7f000001)', () => expect(dq(parseIpv4Loose('0x7f000001'))).toBe('127.0.0.1'));
  it('octal parts (0177.0.0.1)', () => expect(dq(parseIpv4Loose('0177.0.0.1'))).toBe('127.0.0.1'));
  it('hex parts (0x7f.0.0.1)', () => expect(dq(parseIpv4Loose('0x7f.0.0.1'))).toBe('127.0.0.1'));
  it('short form (10.0 → 10.0.0.0)', () => expect(dq(parseIpv4Loose('10.0'))).toBe('10.0.0.0'));
  it('short form (0x0a000001 → 10.0.0.1)', () =>
    expect(dq(parseIpv4Loose('0x0a000001'))).toBe('10.0.0.1'));

  it('rejects out-of-range and malformed', () => {
    expect(parseIpv4Loose('256.1.1.1')).toBeNull(); // non-final part > 255
    expect(parseIpv4Loose('1.2.3.4.5')).toBeNull(); // too many parts
    expect(parseIpv4Loose('0x100.0.0.1')).toBeNull(); // non-final part > 255
    expect(parseIpv4Loose('4294967296')).toBeNull(); // > 2^32-1
    expect(parseIpv4Loose('1.2.3.')).toBeNull(); // empty part
    expect(parseIpv4Loose('08.0.0.1')).toBeNull(); // invalid octal
    expect(parseIpv4Loose('')).toBeNull();
    expect(parseIpv4Loose('example.com')).toBeNull();
  });
});

describe('parseStrictDottedQuad — no obfuscation, no leading zeros', () => {
  it('accepts a plain quad', () =>
    expect(dq(parseStrictDottedQuad('192.168.1.1'))).toBe('192.168.1.1'));
  it('rejects obfuscated / leading-zero forms', () => {
    expect(parseStrictDottedQuad('0177.0.0.1')).toBeNull();
    expect(parseStrictDottedQuad('0x7f.0.0.1')).toBeNull();
    expect(parseStrictDottedQuad('2130706433')).toBeNull();
    expect(parseStrictDottedQuad('1.2.3')).toBeNull();
    expect(parseStrictDottedQuad('256.0.0.1')).toBeNull();
  });
});

describe('parseIpv6 — compression, embedded IPv4, zone-id rejection', () => {
  it('parses loopback and unspecified', () => {
    expect(parseIpLiteral('::1')?.canonical).toBe('::1');
    expect(parseIpLiteral('::')?.canonical).toBe('::');
  });
  it('compresses to RFC 5952', () => {
    expect(parseIpLiteral('2001:0db8:0000:0000:0000:0000:0000:0001')?.canonical).toBe(
      '2001:db8::1',
    );
  });
  it('parses embedded IPv4 tail', () => {
    expect(parseIpv6('::ffff:127.0.0.1')).not.toBeNull();
  });
  it('rejects zone ids and junk', () => {
    expect(parseIpv6('fe80::1%eth0')).toBeNull();
    expect(parseIpv6('1:2:3')).toBeNull(); // too few groups, no '::'
    expect(parseIpv6('12345::1')).toBeNull(); // group too long
    expect(parseIpv6(':::')).toBeNull();
  });
});

describe('guardIp — Tier A hard deny (SSRF), never reachable by any means', () => {
  const hardDeny: Array<[string, string]> = [
    ['127.0.0.1', 'loopback'],
    ['0177.0.0.1', 'loopback'], // octal
    ['0x7f000001', 'loopback'], // hex
    ['2130706433', 'loopback'], // decimal
    ['::1', 'loopback'],
    ['0.0.0.0', 'unspecified'],
    ['::', 'unspecified'],
    ['169.254.169.254', 'cloud_metadata'],
    ['169.254.170.2', 'cloud_metadata'],
    ['[::ffff:169.254.169.254]', 'embedded_v4:cloud_metadata'], // IPv4-mapped
    ['224.0.0.1', 'multicast'],
    ['ff02::1', 'multicast'],
    ['255.255.255.255', 'broadcast'],
    ['240.0.0.1', 'reserved'],
    ['192.0.2.5', 'documentation'],
    ['198.18.0.1', 'documentation'],
    ['2001:db8::1', 'documentation'],
    ['fd00:ec2::254', 'cloud_metadata'],
  ];
  for (const [addr, reason] of hardDeny) {
    it(`${addr} → hard_deny (${reason})`, () => {
      const v = guardIp(addr);
      expect(v.tier).toBe('hard_deny');
      expect(v.reason).toBe(reason);
    });
  }

  it('decodes transition forms and hard-denies the embedded loopback', () => {
    expect(guardIp('2002:7f00:0001::').tier).toBe('hard_deny'); // 6to4 → 127.0.0.1
    expect(guardIp('64:ff9b::7f00:1').tier).toBe('hard_deny'); // NAT64 → 127.0.0.1
    // Teredo 2001:0000::/32; last 32 bits are the client IPv4 XOR 0xffffffff. 127.0.0.1 ^ ffffffff = 80ff:fffe.
    expect(guardIp('2001:0:0:0:0:0:80ff:fffe').tier).toBe('hard_deny');
  });
});

describe('guardIp — Tier B restricted (reachable only under full elevation)', () => {
  const restricted: Array<[string, string]> = [
    ['10.1.2.3', 'rfc1918'],
    ['172.16.5.5', 'rfc1918'],
    ['192.168.1.1', 'rfc1918'],
    ['100.64.0.1', 'cgnat'],
    ['169.254.5.5', 'link_local'], // link-local minus the Tier A metadata addresses
    ['fc00::1', 'ula'],
    ['fe80::1', 'link_local'],
  ];
  for (const [addr, reason] of restricted) {
    it(`${addr} → restricted (${reason})`, () => {
      const v = guardIp(addr);
      expect(v.tier).toBe('restricted');
      expect(v.reason).toBe(reason);
    });
  }

  it('metadata inside link-local stays Tier A (never downgraded to Tier B)', () => {
    expect(guardIp('169.254.169.254').tier).toBe('hard_deny');
    expect(guardIp('169.254.5.5').tier).toBe('restricted');
  });
});

describe('guardIp — permitted public addresses, and fail-closed on the undecodable', () => {
  it('permits genuine public addresses', () => {
    expect(guardIp('8.8.8.8')).toEqual({ tier: 'permitted', reason: 'public' });
    expect(guardIp('2606:4700:4700::1111').tier).toBe('permitted');
  });
  it('fails closed on anything it cannot parse', () => {
    expect(guardIp('not-an-ip').tier).toBe('hard_deny');
    expect(guardIp('').tier).toBe('hard_deny');
    expect(guardIp('999.999.999.999').tier).toBe('hard_deny');
  });
});

describe('classifyBytes works on already-parsed literals', () => {
  it('classifies a parsed v4', () => {
    const ip = parseIpLiteral('10.0.0.1')!;
    expect(classifyBytes(ip).reason).toBe('rfc1918');
  });
});
