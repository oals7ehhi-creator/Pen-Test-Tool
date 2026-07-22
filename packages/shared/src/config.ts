/**
 * Typed configuration, validated at startup. The service refuses to boot on missing/invalid required config and
 * the error is CLEAR and SECRET-FREE: it names the offending keys and the reason, never echoing a value. This is
 * the fail-closed foundation the whole platform relies on.
 */

export class ConfigError extends Error {
  readonly issues: readonly string[];
  constructor(issues: readonly string[]) {
    super(`Invalid configuration:\n  - ${issues.join('\n  - ')}`);
    this.name = 'ConfigError';
    this.issues = issues;
  }
}

export const LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

export const NODE_ENVS = ['development', 'test', 'production'] as const;
export type NodeEnv = (typeof NODE_ENVS)[number];

export interface AppConfig {
  readonly nodeEnv: NodeEnv;
  readonly apiHost: string;
  readonly apiPort: number;
  readonly logLevel: LogLevel;
  readonly databaseUrl: string;
  /** Reference/handle to the session signing key. NOT the raw key material in production. */
  readonly sessionSigningKeyRef: string;
  /**
   * When true, the API honors the `x-dev-role` request header as an INSECURE development-only role injection
   * (NOT authentication). It is force-disabled in production regardless of env, and defaults off.
   */
  readonly devAuthEnabled: boolean;
}

/** DB-only configuration — everything the migration CLI needs and nothing it does not (no session key, no API host). */
export interface DbConfig {
  readonly databaseUrl: string;
  readonly logLevel: LogLevel;
}

type Env = Record<string, string | undefined>;

function validateDatabaseUrl(raw: string | undefined, issues: string[]): string {
  const url = requiredString('DATABASE_URL', raw, 1, issues);
  if (url !== '' && !/^postgres(ql)?:\/\//.test(url)) {
    issues.push('DATABASE_URL must be a postgresql:// connection string');
  }
  return url;
}

function oneOf<T extends string>(
  name: string,
  raw: string | undefined,
  allowed: readonly T[],
  fallback: T,
  issues: string[],
): T {
  if (raw === undefined || raw === '') return fallback;
  if ((allowed as readonly string[]).includes(raw)) return raw as T;
  issues.push(`${name} must be one of ${allowed.join('|')}`);
  return fallback;
}

function requiredString(
  name: string,
  raw: string | undefined,
  minLen: number,
  issues: string[],
): string {
  if (raw === undefined || raw.trim() === '') {
    issues.push(`${name} is required but missing/empty`);
    return '';
  }
  if (raw.length < minLen) {
    issues.push(`${name} must be at least ${minLen} characters`);
  }
  return raw;
}

/**
 * Parse + validate config from an environment record (defaults to `process.env`). THROWS `ConfigError` — with a
 * secret-free message — if any required value is missing or invalid. Callers should let this propagate at boot so
 * the process exits fast rather than running with partial/insecure config.
 */
export function loadConfig(env: Env = process.env): AppConfig {
  const issues: string[] = [];

  const nodeEnv = oneOf('NODE_ENV', env.NODE_ENV, NODE_ENVS, 'development', issues);
  const logLevel = oneOf('LOG_LEVEL', env.LOG_LEVEL, LOG_LEVELS, 'info', issues);

  const apiHost = env.API_HOST && env.API_HOST.trim() !== '' ? env.API_HOST : '127.0.0.1';

  let apiPort = 8080;
  if (env.API_PORT !== undefined && env.API_PORT !== '') {
    const n = Number(env.API_PORT);
    if (!Number.isInteger(n) || n < 1 || n > 65535) {
      issues.push('API_PORT must be an integer between 1 and 65535');
    } else {
      apiPort = n;
    }
  }

  const databaseUrl = validateDatabaseUrl(env.DATABASE_URL, issues);

  // Required and long enough that a blank/placeholder value fails closed.
  const sessionSigningKeyRef = requiredString(
    'SESSION_SIGNING_KEY_REF',
    env.SESSION_SIGNING_KEY_REF,
    16,
    issues,
  );

  // Dev-role injection is opt-in AND never available in production.
  const devAuthEnabled = env.DEV_AUTH_ENABLED === 'true' && nodeEnv !== 'production';

  if (issues.length > 0) {
    throw new ConfigError(issues);
  }

  return { nodeEnv, apiHost, apiPort, logLevel, databaseUrl, sessionSigningKeyRef, devAuthEnabled };
}

/**
 * Validate ONLY the configuration the migration CLI needs (DATABASE_URL + LOG_LEVEL). It deliberately does NOT
 * require the API host/port or the session signing key, so migrations can run in contexts (CI, one-off jobs) that
 * have database access but none of the API's secrets. Fails closed on a missing/invalid DATABASE_URL.
 */
export function loadDbConfig(env: Env = process.env): DbConfig {
  const issues: string[] = [];
  const logLevel = oneOf('LOG_LEVEL', env.LOG_LEVEL, LOG_LEVELS, 'info', issues);
  const databaseUrl = validateDatabaseUrl(env.DATABASE_URL, issues);
  if (issues.length > 0) {
    throw new ConfigError(issues);
  }
  return { databaseUrl, logLevel };
}
