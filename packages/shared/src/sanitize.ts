/**
 * Allowlist / minimized log-context sanitization (SI-045). Log context is constrained to PRIMITIVE SCALARS only:
 * strings (length-capped, credential-masked), finite numbers, booleans, and null. Anything structural — objects,
 * arrays, class instances, functions, bigint, symbol, undefined — is NEVER serialized; it is replaced by a type
 * marker. This makes it structurally impossible to log complete headers, URLs-as-objects, request/response bodies,
 * cookie jars, or arbitrary class instances: callers must extract the specific, minimal scalar fields they need.
 * Sensitive key names are masked regardless of value. Reserved log fields cannot be supplied via context.
 */

export const REDACTED = '[REDACTED]';

/** Fields owned by the log record; context may never set or override them. */
export const RESERVED_FIELDS = new Set(['time', 'level', 'correlationId', 'msg', 'ctx']);

const MAX_STRING = 256;
const MAX_KEYS = 32;

const SENSITIVE_KEY =
  /authorization|cookie|token|secret|password|passwd|api[-_]?key|session[-_]?key|credential|private[-_]?key/i;

const CREDENTIAL_VALUE = /^\s*(bearer|basic|digest)\s+\S/i;

export type Scalar = string | number | boolean | null;

function toScalar(value: unknown): Scalar {
  if (value === null) return null;
  switch (typeof value) {
    case 'boolean':
      return value;
    case 'number':
      return Number.isFinite(value) ? value : `[omitted:number:${String(value)}]`;
    case 'string': {
      if (CREDENTIAL_VALUE.test(value)) return REDACTED;
      return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…[truncated]` : value;
    }
    default:
      // object | array | function | bigint | symbol | undefined → never serialized
      return `[omitted:${Array.isArray(value) ? 'array' : typeof value}]`;
  }
}

/**
 * Reduce an arbitrary context object to a flat, minimized, scalar-only record safe to serialize. Reserved fields
 * are dropped; sensitive keys are masked; non-scalar values become type markers; the key count is capped.
 */
export function sanitizeContext(ctx: Record<string, unknown>): Record<string, Scalar> {
  const out: Record<string, Scalar> = {};
  let n = 0;
  for (const [key, value] of Object.entries(ctx)) {
    if (RESERVED_FIELDS.has(key)) continue; // context can never override a reserved log field
    if (n >= MAX_KEYS) {
      out._truncated = '[context-key-limit]';
      break;
    }
    out[key] = SENSITIVE_KEY.test(key) ? REDACTED : toScalar(value);
    n++;
  }
  return out;
}
