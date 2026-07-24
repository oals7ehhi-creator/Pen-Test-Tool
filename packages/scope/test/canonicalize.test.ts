import { describe, it, expect } from 'vitest';
import {
  canonicalizeScheme,
  canonicalizePort,
  canonicalizeHost,
  canonicalizePath,
  canonicalizeUrl,
  guardUrl,
} from '../src/index.js';

/**
 * Canonicalization battery (Phase 0 §5). Proves that alternate encodings — obfuscated IPs, mixed case, trailing
 * dots, IDN homoglyphs, @-embedded userinfo, encoded path traversal — cannot smuggle a different host/path past the
 * canonical form the scope checker compares against.
 */

describe('scheme / port', () => {
  it('lowercases and validates the scheme', () => {
    expect(canonicalizeScheme('HTTPS')).toBe('https');
    expect(canonicalizeScheme('WSS')).toBe('wss');
    expect(canonicalizeScheme('file')).toBeNull();
    expect(canonicalizeScheme('javascript')).toBeNull();
  });
  it('applies the scheme default when no port is given, and normalizes explicit defaults', () => {
    expect(canonicalizePort('https', undefined)).toBe(443);
    expect(canonicalizePort('http', undefined)).toBe(80);
    expect(canonicalizePort('https', '443')).toBe(443);
    expect(canonicalizePort('https', '8443')).toBe(8443);
    expect(canonicalizePort('https', '0')).toBeNull();
    expect(canonicalizePort('https', '70000')).toBeNull();
    expect(canonicalizePort('https', 'x')).toBeNull();
  });
});

describe('host canonicalization', () => {
  it('lowercases, strips a single trailing dot, and IDNA-normalizes', () => {
    expect(canonicalizeHost('Example.COM')).toEqual({ kind: 'domain', hostAscii: 'example.com' });
    expect(canonicalizeHost('example.com.')).toEqual({ kind: 'domain', hostAscii: 'example.com' });
    // IDN → punycode (ToASCII). "bücher.example" → xn--bcher-kva.example
    expect(canonicalizeHost('bücher.example')).toEqual({
      kind: 'domain',
      hostAscii: 'xn--bcher-kva.example',
    });
  });

  it('classifies IP-literal hosts as IPs (not domains), in any obfuscated form', () => {
    expect(canonicalizeHost('127.0.0.1')).toMatchObject({ kind: 'ip' });
    expect(canonicalizeHost('0x7f000001')).toMatchObject({ kind: 'ip' });
    expect(canonicalizeHost('[::1]')).toMatchObject({ kind: 'ip' });
    const ip = canonicalizeHost('0177.0.0.1');
    expect(ip).toMatchObject({ kind: 'ip' });
    if (ip?.kind === 'ip') expect(ip.ip.canonical).toBe('127.0.0.1');
  });

  it('accepts hyphenated hostnames (hyphens are valid in labels)', () => {
    expect(canonicalizeHost('foo-bar.example.com')).toEqual({
      kind: 'domain',
      hostAscii: 'foo-bar.example.com',
    });
  });

  it('rejects hosts with whitespace / control chars / empty', () => {
    expect(canonicalizeHost('exa mple.com')).toBeNull();
    expect(canonicalizeHost('a\tb.com')).toBeNull();
    expect(canonicalizeHost('a\x00b.com')).toBeNull(); // NUL / control char
    expect(canonicalizeHost(' ')).toBeNull();
    expect(canonicalizeHost('')).toBeNull();
  });
});

describe('path canonicalization (§5.5)', () => {
  it('resolves dot-segments so traversal cannot bypass a prefix', () => {
    expect(canonicalizePath('/api/../admin')).toBe('/admin');
    expect(canonicalizePath('/a/b/../../c')).toBe('/c');
    expect(canonicalizePath('/a/./b')).toBe('/a/b');
    expect(canonicalizePath('')).toBe('/');
    expect(canonicalizePath('relative')).toBe('/relative');
  });
  it('decodes only unreserved percent-escapes and rejects encoded NUL/CR/LF', () => {
    expect(canonicalizePath('/%61%62')).toBe('/ab'); // unreserved decoded
    expect(canonicalizePath('/a%2Fb')).toBe('/a%2Fb'); // reserved '/' stays encoded, uppercased
    expect(canonicalizePath('/%00')).toBeNull();
    expect(canonicalizePath('/%0d%0a')).toBeNull();
    expect(canonicalizePath('/%zz')).toBeNull();
  });
  it('encoded traversal decodes then resolves (no bypass)', () => {
    // %2e = '.', so /api/%2e%2e/admin → /api/../admin → /admin
    expect(canonicalizePath('/api/%2e%2e/admin')).toBe('/admin');
  });
});

describe('full URL canonicalization (§5.6)', () => {
  it('canonicalizes scheme/host/port/path and strips userinfo', () => {
    const r = canonicalizeUrl('HTTPS://User:Pass@Example.COM/api/../v1');
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.url.scheme).toBe('https');
      expect(r.url.host).toEqual({ kind: 'domain', hostAscii: 'example.com' });
      expect(r.url.port).toBe(443);
      expect(r.url.path).toBe('/v1');
      expect(r.url.hadUserinfo).toBe(true);
    }
  });

  it('a @-embedded userinfo host cannot smuggle a different authority', () => {
    // The real host is evil-after-at.example, NOT the userinfo "trusted.example".
    const r = canonicalizeUrl('https://trusted.example@10.0.0.1/');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.url.host).toMatchObject({ kind: 'ip' });
  });

  it('rejects unsupported schemes and malformed input', () => {
    expect(canonicalizeUrl('file:///etc/passwd').ok).toBe(false);
    expect(canonicalizeUrl('javascript:alert(1)').ok).toBe(false);
    expect(canonicalizeUrl('not a url').ok).toBe(false);
    expect(canonicalizeUrl('https://exa mple.com/').ok).toBe(false);
  });

  it('parses bracketed IPv6 authority with an explicit port', () => {
    const r = canonicalizeUrl('http://[::1]:8080/x');
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.url.host).toMatchObject({ kind: 'ip' });
      expect(r.url.port).toBe(8080);
    }
  });

  it('rejects a malformed bracketed authority (unclosed / trailing junk)', () => {
    expect(canonicalizeUrl('http://[::1/').ok).toBe(false); // unclosed bracket
    const r = canonicalizeUrl('http://[::1]junk/');
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe('malformed_authority');
  });
});

describe('guardUrl — SSRF through a full URL, in obfuscated forms', () => {
  const denied = [
    'http://127.0.0.1/',
    'http://0x7f000001/',
    'http://2130706433/',
    'http://0177.0.0.1/',
    'https://[::1]/',
    'http://169.254.169.254/latest/meta-data/',
    'https://user@169.254.169.254/', // userinfo can't hide the metadata host
    'http://[::ffff:169.254.169.254]/',
    'gopher://127.0.0.1/', // unsupported scheme also fails closed
  ];
  for (const u of denied) {
    it(`denies ${u}`, () => expect(guardUrl(u).tier).toBe('hard_deny'));
  }

  it('a Tier B host through a URL is classified restricted (not permitted)', () => {
    expect(guardUrl('http://10.0.0.5/').tier).toBe('restricted');
  });

  it('a public domain host is permitted pending resolution (resolved+pinned by the Broker later)', () => {
    const v = guardUrl('https://example.com/');
    expect(v.tier).toBe('permitted');
    expect(v.reason).toBe('domain_pending_resolution');
  });
});
