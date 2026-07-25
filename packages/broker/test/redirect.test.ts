import { describe, it, expect } from 'vitest';
import type { ScopeVersion, ScopeEntry } from '@pentest/scope';
import { guardRedirect, type RedirectContext } from '../src/index.js';

/**
 * Redirect re-guard (Phase 0 §7.1 step 13). Proves the broker never auto-follows: a 3xx Location is re-decided by
 * the same deny-by-default scope evaluator (so a 200-in-scope page cannot 302 to metadata / loopback / off-scope),
 * the hop budget is bounded, and a followed target is only ever a NEW candidate for a fresh spec + grant.
 */

const scope = (...entries: ScopeEntry[]): ScopeVersion => ({ entries });
const inScope = scope({
  class: 'domain',
  hostAscii: 'example.com',
  wildcard: true,
  includeSubdomains: true,
});

const ctx = (over: Partial<RedirectContext> = {}): RedirectContext => ({
  scope: inScope,
  hop: 0,
  maxHops: 5,
  ...over,
});

describe('guardRedirect', () => {
  it('follows an in-scope Location and returns the canonical next target (never opening a socket)', () => {
    const d = guardRedirect('https://api.example.com/v2', ctx());
    expect(d.follow).toBe(true);
    if (d.follow) {
      expect(d.next.host).toMatchObject({ kind: 'domain', hostAscii: 'api.example.com' });
      expect(d.next.path).toBe('/v2');
    }
  });

  it('refuses a redirect to cloud metadata via the NETWORK GUARD (https ⇒ scheme passes, guard fires)', () => {
    // https so the scheme gate does NOT short-circuit — this proves the re-guard actually runs the §6 network guard
    // on the redirect target, not merely the scheme allow-list. Exact code, and no address value leaked into it.
    const d = guardRedirect('https://169.254.169.254/latest/meta-data/', ctx());
    expect(d.follow).toBe(false);
    if (!d.follow) {
      expect(d.reason).toBe('redirect_out_of_scope:network_guard:cloud_metadata');
      expect(d.reason).not.toContain('169.254.169.254');
    }
  });

  it('refuses a redirect to an obfuscated IP-literal loopback host (canonicalization + guard)', () => {
    // 0x7f000001 must canonicalize to 127.0.0.1 and be network-guarded — again over https so the guard, not the
    // scheme gate, is what refuses it.
    const d = guardRedirect('https://0x7f000001/', ctx());
    expect(d.follow).toBe(false);
    if (!d.follow) expect(d.reason).toBe('redirect_out_of_scope:network_guard:loopback');
  });

  it('refuses a non-https scheme at the scheme gate', () => {
    const d = guardRedirect('http://169.254.169.254/latest/meta-data/', ctx());
    expect(d.follow).toBe(false);
    if (!d.follow) expect(d.reason).toBe('redirect_out_of_scope:scheme_not_allowed');
  });

  it('refuses a redirect to an out-of-scope host (exact code, host value not leaked)', () => {
    const d = guardRedirect('https://evil.test/', ctx());
    expect(d.follow).toBe(false);
    if (!d.follow) {
      expect(d.reason).toBe('redirect_out_of_scope:no_host_match');
      expect(d.reason).not.toContain('evil.test');
    }
  });

  it('follows the final legitimate hop (hop == maxHops - 1) but stops at the budget', () => {
    // Boundary: the last allowed hop must still follow; the off-by-one (truncate one hop early) fails here.
    const last = guardRedirect('https://api.example.com/', ctx({ hop: 4, maxHops: 5 }));
    expect(last.follow).toBe(true);
    const over = guardRedirect('https://api.example.com/', ctx({ hop: 5, maxHops: 5 }));
    expect(over).toEqual({ follow: false, reason: 'redirect_depth_exceeded' });
  });

  it('refuses an uncanonicalizable Location with an exact reason code', () => {
    const d = guardRedirect('not a url', ctx());
    expect(d.follow).toBe(false);
    if (!d.follow) expect(d.reason).toBe('redirect_uncanonicalizable:malformed_url');
  });
});
