/**
 * Redaction: masks secret-bearing fields BEFORE anything reaches a log sink (Phase 0 SI-045). Matching is
 * case-insensitive and applied recursively to objects/arrays. Anything matching a sensitive key name, or a value
 * that looks like a bearer/basic credential, is replaced with a fixed marker — the raw value never leaves memory.
 */
export const REDACTED = '[REDACTED]';

const SENSITIVE_KEY_PATTERNS: readonly RegExp[] = [
  /authorization/i,
  /cookie/i, // covers cookie + set-cookie
  /(^|[-_.])token($|[-_.])/i,
  /secret/i,
  /password/i,
  /passwd/i,
  /api[-_]?key/i,
  /session[-_]?key/i,
  /credential/i,
  /private[-_]?key/i,
];

function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERNS.some((re) => re.test(key));
}

/** Redact a string value that itself carries a credential (e.g. an `Authorization` header value). */
function redactValueString(value: string): string {
  if (/^\s*(bearer|basic|digest)\s+\S+/i.test(value)) return REDACTED;
  return value;
}

/**
 * Return a deep copy of `input` with every sensitive field masked. Non-plain values (Date, etc.) are passed
 * through. Guards against cycles. The original object is never mutated.
 */
export function redact<T>(input: T, seen: WeakSet<object> = new WeakSet()): T {
  if (typeof input === 'string') return redactValueString(input) as unknown as T;
  if (input === null || typeof input !== 'object') return input;

  if (seen.has(input as object)) return '[Circular]' as unknown as T;
  seen.add(input as object);

  if (Array.isArray(input)) {
    return input.map((v) => redact(v, seen)) as unknown as T;
  }

  // Only descend into plain objects; leave class instances (Date, Buffer, …) untouched.
  const proto = Object.getPrototypeOf(input);
  if (proto !== Object.prototype && proto !== null) return input;

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
    out[key] = isSensitiveKey(key) ? REDACTED : redact(value, seen);
  }
  return out as unknown as T;
}
