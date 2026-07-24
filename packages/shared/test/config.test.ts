import { describe, it, expect } from 'vitest';
import { loadConfig, loadDbConfig, ConfigError } from '../src/index.js';

/**
 * Phase 1 exit test — boot-fail on missing/invalid config, with a clear SECRET-FREE message.
 */

const VALID = {
  NODE_ENV: 'test',
  API_HOST: '127.0.0.1',
  API_PORT: '8080',
  LOG_LEVEL: 'info',
  DATABASE_URL: 'postgresql://u:p@127.0.0.1:5432/db',
  SESSION_SIGNING_KEY_REF: 'a-sufficiently-long-key-ref',
} as const;

describe('loadConfig', () => {
  it('parses a valid environment', () => {
    const cfg = loadConfig({ ...VALID });
    expect(cfg.apiHost).toBe('127.0.0.1');
    expect(cfg.apiPort).toBe(8080);
    expect(cfg.nodeEnv).toBe('test');
    expect(cfg.databaseUrl).toContain('postgresql://');
  });

  it('defaults host to loopback (not a public interface)', () => {
    const { API_HOST: _omit, ...rest } = VALID;
    void _omit;
    expect(loadConfig({ ...rest }).apiHost).toBe('127.0.0.1');
  });

  it('fails closed when a required value is missing', () => {
    const { DATABASE_URL: _o, ...rest } = VALID;
    void _o;
    expect(() => loadConfig({ ...rest })).toThrow(ConfigError);
  });

  it('fails closed on an invalid port and names the key without echoing a value', () => {
    let err: unknown;
    try {
      loadConfig({ ...VALID, API_PORT: '70000' });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConfigError);
    const ce = err as ConfigError;
    expect(ce.issues.some((i) => i.includes('API_PORT'))).toBe(true);
  });

  it('rejects a too-short signing-key ref (blank/placeholder fails closed)', () => {
    expect(() => loadConfig({ ...VALID, SESSION_SIGNING_KEY_REF: 'short' })).toThrow(ConfigError);
  });

  it('devTokenMinterEnabled is opt-in and force-disabled in production', () => {
    expect(loadConfig({ ...VALID, DEV_TOKEN_MINTER: 'true' }).devTokenMinterEnabled).toBe(true); // NODE_ENV=test
    expect(loadConfig({ ...VALID }).devTokenMinterEnabled).toBe(false); // default off
    expect(
      loadConfig({ ...VALID, NODE_ENV: 'production', DEV_TOKEN_MINTER: 'true' })
        .devTokenMinterEnabled,
    ).toBe(false);
  });

  it('pins issuer/audience with safe defaults and rejects malformed values', () => {
    const def = loadConfig({ ...VALID });
    expect(def.authIssuer).toBe('pentest-tool');
    expect(def.authAudience).toBe('pentest-api');
    const custom = loadConfig({ ...VALID, AUTH_ISSUER: 'my-issuer', AUTH_AUDIENCE: 'my-aud' });
    expect(custom.authIssuer).toBe('my-issuer');
    expect(custom.authAudience).toBe('my-aud');
    expect(() => loadConfig({ ...VALID, AUTH_ISSUER: 'has space' })).toThrow(ConfigError);
  });

  it('the error message never contains the offending secret VALUE', () => {
    const leaky = 'super-secret-value-should-not-appear-in-error';
    let msg = '';
    try {
      // invalid DB url forces an error while a secret-ish value is present in env
      loadConfig({ ...VALID, DATABASE_URL: 'not-a-db-url', SESSION_SIGNING_KEY_REF: leaky });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toContain('DATABASE_URL');
    expect(msg).not.toContain(leaky);
    expect(msg).not.toContain('not-a-db-url'); // values are never echoed, only key + reason
  });
});

describe('loadDbConfig (DB-only, item 2)', () => {
  it('validates DATABASE_URL alone — no session key or API host required', () => {
    const cfg = loadDbConfig({
      DATABASE_URL: 'postgresql://u:p@127.0.0.1:5432/db',
      LOG_LEVEL: 'warn',
    });
    expect(cfg.databaseUrl).toContain('postgresql://');
    expect(cfg.logLevel).toBe('warn');
  });

  it('fails closed on a missing/invalid DATABASE_URL', () => {
    expect(() => loadDbConfig({})).toThrow(ConfigError);
    expect(() => loadDbConfig({ DATABASE_URL: 'mysql://x' })).toThrow(ConfigError);
  });

  it('does NOT require SESSION_SIGNING_KEY_REF (unlike the full app config)', () => {
    // Absent session key would make loadConfig throw, but loadDbConfig must succeed.
    expect(() => loadConfig({ DATABASE_URL: 'postgresql://u:p@h:5432/db' })).toThrow(ConfigError);
    expect(() => loadDbConfig({ DATABASE_URL: 'postgresql://u:p@h:5432/db' })).not.toThrow();
  });
});
