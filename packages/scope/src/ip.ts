/**
 * IP parsing + the two-tier deny-by-default network guard (Phase 0 §5.2, §6). This is the SSRF / network-policy
 * chokepoint: every candidate target address — however obfuscated — is decoded to canonical bytes and classified.
 *
 *  - Tier A (`hard_deny`): NEVER reachable by any means (no allowlist entry, no elevated flag, no approval):
 *    loopback, unspecified, cloud/link-local metadata, multicast, broadcast, reserved/future, documentation/benchmark.
 *  - Tier B (`restricted`): RFC1918 / ULA / link-local / CGNAT — reachable ONLY under full elevation (an explicit
 *    elevated scope entry + a dual-approved restricted-range approval + internal_testing_granted). The guard only
 *    CLASSIFIES; the elevation decision lives in the scope evaluator / Scope Authority.
 *  - Everything else: `permitted` by the guard (still subject to allowlist matching elsewhere).
 *
 * Transition/embedding IPv6 forms (IPv4-mapped, deprecated compat, 6to4, Teredo, NAT64) are decoded and the embedded
 * IPv4 is re-classified, so an address like `::ffff:169.254.169.254` is hard-denied. Tier A always wins.
 */

export type NetworkTier = 'hard_deny' | 'restricted' | 'permitted';

/** A fixed, safe reason code — never echoes untrusted input. */
export interface GuardVerdict {
  readonly tier: NetworkTier;
  readonly reason: string;
}

export interface ParsedIp {
  readonly version: 4 | 6;
  /** Canonical string form (dotted-quad for v4, RFC 5952 for v6). */
  readonly canonical: string;
  /** Raw address bytes: 4 for v4, 16 for v6. */
  readonly bytes: Uint8Array;
}

// ---------------------------------------------------------------------------------------------------------------
// IPv4 parsing
// ---------------------------------------------------------------------------------------------------------------

/** Parse a strict dotted-quad `a.b.c.d`, each part a decimal 0–255. Returns 4 bytes or null. */
export function parseStrictDottedQuad(input: string): Uint8Array | null {
  const parts = input.split('.');
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const p = parts[i]!;
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null; // no leading zeros, decimal only
    const v = Number(p);
    if (v > 255) return null;
    bytes[i] = v;
  }
  return bytes;
}

function parseUintPart(p: string): number | null {
  if (/^0[xX][0-9a-fA-F]+$/.test(p)) return parseInt(p.slice(2), 16);
  if (/^0[0-7]+$/.test(p)) return parseInt(p.slice(1), 8); // leading-zero octal (inet_aton)
  if (/^0$/.test(p)) return 0;
  if (/^[1-9][0-9]*$/.test(p)) return Number(p);
  return null;
}

/**
 * Parse an IPv4 address in ANY inet_aton form — dotted-quad, and the obfuscated decimal (`2130706433`),
 * octal (`0177.0.0.1`), hex (`0x7f.0.0.1`), mixed, and short (`a.b`, `a.b.c`, `a`) forms. Returns 4 canonical
 * bytes or null. This is what defeats `http://0x7f000001/`-style guard bypasses.
 */
export function parseIpv4Loose(input: string): Uint8Array | null {
  if (input.length === 0 || !/^[0-9a-fA-FxX.]+$/.test(input)) return null;
  const parts = input.split('.');
  if (parts.length < 1 || parts.length > 4) return null;
  const nums: number[] = [];
  for (const p of parts) {
    const v = parseUintPart(p);
    if (v === null || !Number.isFinite(v) || v < 0) return null;
    nums.push(v);
  }
  const n = nums.length;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < n - 1; i++) {
    if (nums[i]! > 255) return null; // every non-final part is a single byte
    bytes[i] = nums[i]!;
  }
  const trailingBytes = 4 - (n - 1);
  const last = nums[n - 1]!;
  const maxVal = trailingBytes === 4 ? 0xffffffff : 2 ** (8 * trailingBytes) - 1;
  if (last > maxVal) return null;
  for (let i = 0; i < trailingBytes; i++) {
    bytes[3 - i] = Math.floor(last / 2 ** (8 * i)) & 0xff;
  }
  return bytes;
}

// ---------------------------------------------------------------------------------------------------------------
// IPv6 parsing
// ---------------------------------------------------------------------------------------------------------------

/** Parse an IPv6 address (with optional embedded dotted-quad tail) to 16 bytes, or null. Zone IDs are rejected. */
export function parseIpv6(input: string): Uint8Array | null {
  if (input.length === 0 || input.includes('%')) return null; // §5.2: zone IDs rejected everywhere
  if (!/^[0-9a-fA-F:.]+$/.test(input)) return null;

  let text = input;
  let embeddedTail: Uint8Array | null = null;
  const lastColon = text.lastIndexOf(':');
  if (lastColon >= 0 && text.slice(lastColon + 1).includes('.')) {
    const v4 = parseStrictDottedQuad(text.slice(lastColon + 1));
    if (v4 === null) return null;
    embeddedTail = v4;
    const g1 = ((v4[0]! << 8) | v4[1]!).toString(16);
    const g2 = ((v4[2]! << 8) | v4[3]!).toString(16);
    text = text.slice(0, lastColon + 1) + g1 + ':' + g2;
  }

  const halves = text.split('::');
  if (halves.length > 2) return null;

  const toGroups = (s: string): number[] | null => {
    if (s === '') return [];
    const gs = s.split(':');
    const out: number[] = [];
    for (const g of gs) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };

  const head = toGroups(halves[0]!);
  if (head === null) return null;
  let groups: number[];
  if (halves.length === 2) {
    const tail = toGroups(halves[1]!);
    if (tail === null) return null;
    const zeros = 8 - head.length - tail.length;
    if (zeros < 1) return null; // '::' must stand for at least one 16-bit group
    groups = [...head, ...new Array<number>(zeros).fill(0), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    bytes[i * 2] = (groups[i]! >> 8) & 0xff;
    bytes[i * 2 + 1] = groups[i]! & 0xff;
  }
  void embeddedTail;
  return bytes;
}

// ---------------------------------------------------------------------------------------------------------------
// Canonical string forms
// ---------------------------------------------------------------------------------------------------------------

function v4Canonical(b: Uint8Array): string {
  return `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
}

/** RFC 5952 canonical IPv6 text (lowercase, longest-run-of-zeros compressed to `::`). */
function v6Canonical(b: Uint8Array): string {
  const groups: number[] = [];
  for (let i = 0; i < 8; i++) groups.push((b[i * 2]! << 8) | b[i * 2 + 1]!);
  // longest run of >=2 consecutive zero groups (leftmost on tie)
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) {
    return groups.map((g) => g.toString(16)).join(':');
  }
  const before = groups.slice(0, bestStart).map((g) => g.toString(16));
  const after = groups.slice(bestStart + bestLen).map((g) => g.toString(16));
  return `${before.join(':')}::${after.join(':')}`;
}

// ---------------------------------------------------------------------------------------------------------------
// CIDR membership helpers
// ---------------------------------------------------------------------------------------------------------------

function v4ToInt(b: Uint8Array): number {
  return ((b[0]! << 24) >>> 0) + (b[1]! << 16) + (b[2]! << 8) + b[3]!;
}

/** True if v4 `b` is inside `base/prefix`. */
export function inCidrV4(b: Uint8Array, base: string, prefix: number): boolean {
  const baseBytes = parseStrictDottedQuad(base);
  if (baseBytes === null) return false;
  if (prefix === 0) return true;
  const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
  return (v4ToInt(b) & mask) >>> 0 === (v4ToInt(baseBytes) & mask) >>> 0;
}

/** True if v6 `b` is inside `base/prefix`, comparing the first `prefix` bits. */
export function inCidrV6(b: Uint8Array, base: Uint8Array, prefix: number): boolean {
  const fullBytes = prefix >> 3;
  for (let i = 0; i < fullBytes; i++) if (b[i] !== base[i]) return false;
  const rem = prefix & 7;
  if (rem === 0) return true;
  const mask = (0xff << (8 - rem)) & 0xff;
  return (b[fullBytes]! & mask) === (base[fullBytes]! & mask);
}

function v6Base(text: string): Uint8Array {
  const b = parseIpv6(text);
  /* v8 ignore next -- all call sites pass valid literals */
  if (b === null) throw new Error('invalid internal v6 base');
  return b;
}

// ---------------------------------------------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------------------------------------------

function classifyV4(b: Uint8Array): GuardVerdict {
  // Tier A — permanent hard deny (order matters: metadata before the broader link-local Tier B range).
  if (inCidrV4(b, '127.0.0.0', 8)) return { tier: 'hard_deny', reason: 'loopback' };
  if (inCidrV4(b, '0.0.0.0', 8)) return { tier: 'hard_deny', reason: 'unspecified' };
  if (inCidrV4(b, '169.254.169.254', 32) || inCidrV4(b, '169.254.170.2', 32))
    return { tier: 'hard_deny', reason: 'cloud_metadata' };
  if (inCidrV4(b, '224.0.0.0', 4)) return { tier: 'hard_deny', reason: 'multicast' };
  if (inCidrV4(b, '255.255.255.255', 32)) return { tier: 'hard_deny', reason: 'broadcast' };
  if (inCidrV4(b, '240.0.0.0', 4) || inCidrV4(b, '192.0.0.0', 24))
    return { tier: 'hard_deny', reason: 'reserved' };
  if (
    inCidrV4(b, '192.0.2.0', 24) ||
    inCidrV4(b, '198.51.100.0', 24) ||
    inCidrV4(b, '203.0.113.0', 24) ||
    inCidrV4(b, '198.18.0.0', 15)
  )
    return { tier: 'hard_deny', reason: 'documentation' };
  // Tier B — restricted (reachable only under full elevation).
  if (inCidrV4(b, '10.0.0.0', 8) || inCidrV4(b, '172.16.0.0', 12) || inCidrV4(b, '192.168.0.0', 16))
    return { tier: 'restricted', reason: 'rfc1918' };
  if (inCidrV4(b, '100.64.0.0', 10)) return { tier: 'restricted', reason: 'cgnat' };
  if (inCidrV4(b, '169.254.0.0', 16)) return { tier: 'restricted', reason: 'link_local' };
  return { tier: 'permitted', reason: 'public' };
}

/**
 * Extract an embedded IPv4 from a transition/embedding IPv6 form (IPv4-mapped, deprecated compat, 6to4, Teredo,
 * NAT64), or null if this is a native v6 address. Exported so any component that must decide an address on the SAME
 * decoded representation the guard classifies (e.g. the broker's connect-time ip/cidr exclusion + elevation match)
 * shares this one decoder rather than re-deriving it — a mapped form must never evade a v4 scope entry.
 */
export function embeddedV4(b: Uint8Array): Uint8Array | null {
  const isZero = (from: number, to: number): boolean => {
    for (let i = from; i < to; i++) if (b[i] !== 0) return false;
    return true;
  };
  // IPv4-mapped ::ffff:a.b.c.d
  if (isZero(0, 10) && b[10] === 0xff && b[11] === 0xff) return b.slice(12, 16);
  // Deprecated IPv4-compatible ::a.b.c.d  (::/96, excluding :: and ::1 which classify as native Tier A)
  if (isZero(0, 12) && !(isZero(12, 15) && (b[15] === 0 || b[15] === 1))) return b.slice(12, 16);
  // 6to4 2002:V4::/16  → embedded V4 in bytes 2..5
  if (b[0] === 0x20 && b[1] === 0x02) return b.slice(2, 6);
  // Teredo 2001:0000::/32 → embedded V4 in the last 32 bits, bit-inverted
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) {
    const v = new Uint8Array(4);
    for (let i = 0; i < 4; i++) v[i] = b[12 + i]! ^ 0xff;
    return v;
  }
  // NAT64 64:ff9b::/96 → embedded V4 in the last 32 bits
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && isZero(4, 12))
    return b.slice(12, 16);
  return null;
}

function classifyV6(b: Uint8Array): GuardVerdict {
  const emb = embeddedV4(b);
  if (emb !== null) {
    const v = classifyV4(emb);
    return { tier: v.tier, reason: `embedded_v4:${v.reason}` };
  }
  // Tier A native v6.
  if (inCidrV6(b, v6Base('fd00:ec2::254'), 128))
    return { tier: 'hard_deny', reason: 'cloud_metadata' };
  if (inCidrV6(b, v6Base('::1'), 128)) return { tier: 'hard_deny', reason: 'loopback' };
  if (inCidrV6(b, v6Base('::'), 128)) return { tier: 'hard_deny', reason: 'unspecified' };
  if (inCidrV6(b, v6Base('ff00::'), 8)) return { tier: 'hard_deny', reason: 'multicast' };
  if (inCidrV6(b, v6Base('2001:20::'), 28)) return { tier: 'hard_deny', reason: 'reserved' };
  if (inCidrV6(b, v6Base('2001:db8::'), 32)) return { tier: 'hard_deny', reason: 'documentation' };
  if (inCidrV6(b, v6Base('100::'), 64)) return { tier: 'hard_deny', reason: 'discard' };
  if (inCidrV6(b, v6Base('::'), 96)) return { tier: 'hard_deny', reason: 'reserved' }; // deprecated ::/96 compat space
  // Tier B native v6.
  if (inCidrV6(b, v6Base('fc00::'), 7)) return { tier: 'restricted', reason: 'ula' };
  if (inCidrV6(b, v6Base('fe80::'), 10)) return { tier: 'restricted', reason: 'link_local' };
  return { tier: 'permitted', reason: 'public' };
}

/** Classify already-parsed bytes. */
export function classifyBytes(ip: ParsedIp): GuardVerdict {
  return ip.version === 4 ? classifyV4(ip.bytes) : classifyV6(ip.bytes);
}

/**
 * Parse an IP literal (any obfuscated IPv4 form, or IPv6 with transition forms) into canonical bytes, or null if it
 * is not an IP literal. Bracketed IPv6 (`[::1]`) is accepted (brackets stripped).
 */
export function parseIpLiteral(input: string): ParsedIp | null {
  const trimmed = input.trim();
  if (trimmed.length === 0) return null;
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    const inner = trimmed.slice(1, -1);
    const v6 = parseIpv6(inner);
    return v6 === null ? null : { version: 6, canonical: v6Canonical(v6), bytes: v6 };
  }
  if (trimmed.includes(':')) {
    const v6 = parseIpv6(trimmed);
    return v6 === null ? null : { version: 6, canonical: v6Canonical(v6), bytes: v6 };
  }
  const v4 = parseIpv4Loose(trimmed);
  return v4 === null ? null : { version: 4, canonical: v4Canonical(v4), bytes: v4 };
}

/**
 * Classify an IP literal string end-to-end (parse → guard). An unparseable input is treated as `hard_deny`
 * (`unparseable`) — fail closed: the guard never returns `permitted` for something it could not decode.
 */
export function guardIp(input: string): GuardVerdict {
  const ip = parseIpLiteral(input);
  if (ip === null) return { tier: 'hard_deny', reason: 'unparseable' };
  return classifyBytes(ip);
}
