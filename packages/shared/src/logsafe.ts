/**
 * SI-045 log ALLOWLIST. Structured logs are emitted as { time, level, correlationId, event, fields } where:
 *
 *  - `event` is a FIXED name that MUST be a key of the per-service EventRegistry. An unregistered or dynamic
 *    event name (e.g. one with a secret interpolated into it) is replaced by the sentinel `UNKNOWN_EVENT` and
 *    all of its fields are dropped, so untrusted text can never enter the event/message position.
 *
 *  - `fields` are produced by an EXPLICIT PER-EVENT ALLOWLIST (`buildFields`): only field names DECLARED in that
 *    event's schema are ever considered, and each value must additionally pass that field's strict validator or
 *    it is OMITTED. The default classification of any value is UNSAFE — there is no code path that serializes an
 *    arbitrary string, object, array, Buffer, Error, URL, class instance, header, cookie, raw path, query, body,
 *    or credential. A value is logged only when a schema explicitly permits a CONSTRAINED shape (a known HTTP
 *    method, an integer status in range, a bounded safe token, an enum member, a boolean). This is an allowlist,
 *    not minimization-plus-denylist: truncation is never used, because a truncated secret is still a secret.
 *
 *  - reserved record fields (time / level / correlationId / event / fields) can never be set from context.
 */

export type Scalar = string | number | boolean | null;

/** Returns the SAFE value to log, or `undefined` to OMIT the field. Omission is the default for anything unsafe. */
export type FieldValidator = (value: unknown) => Scalar | undefined;

/** The allowlist of fields for a single named event. Only these keys are ever considered for that event. */
export type EventSchema = Readonly<Record<string, FieldValidator>>;

/** The allowlist of events for a service. Any event name absent from the registry is rejected. */
export type EventRegistry = Readonly<Record<string, EventSchema>>;

/** Emitted in the `event` position when the caller supplied an unregistered/dynamic event name. */
export const UNKNOWN_EVENT = 'unknown_event';

/** Record fields owned by the logger; never settable from caller context or child bindings. */
export const RESERVED_FIELDS: ReadonlySet<string> = new Set([
  'time',
  'level',
  'correlationId',
  'event',
  'fields',
]);

const MAX_FIELDS = 64;

// A bounded identifier: letters, digits, dot, underscore, hyphen only. Deliberately excludes '/', ':', '?', '=',
// '&', '%', '@', whitespace and quotes, so a token can never carry a URL, path, query string, header or cookie.
const SAFE_TOKEN = /^[A-Za-z0-9._-]{1,128}$/;

const HTTP_METHODS: ReadonlySet<string> = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS',
]);

/**
 * Reusable strict field validators. Each accepts `unknown` and returns the safe value or `undefined` (omit).
 * They never coerce: a value of the wrong type/shape is dropped, not stringified.
 */
export const field = {
  bool: (v: unknown): Scalar | undefined => (typeof v === 'boolean' ? v : undefined),
  int:
    (min: number, max: number): FieldValidator =>
    (v: unknown): Scalar | undefined =>
      typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max ? v : undefined,
  httpStatus: (v: unknown): Scalar | undefined =>
    typeof v === 'number' && Number.isInteger(v) && v >= 100 && v <= 599 ? v : undefined,
  httpMethod: (v: unknown): Scalar | undefined =>
    typeof v === 'string' && HTTP_METHODS.has(v) ? v : undefined,
  /** Membership in a fixed, caller-provided allowlist (e.g. known route templates, enum values). */
  oneOf:
    (allowed: readonly string[]): FieldValidator =>
    (v: unknown): Scalar | undefined =>
      typeof v === 'string' && allowed.includes(v) ? v : undefined,
  /** A short, opaque, structurally-safe identifier (component name, migration name/version, bind host). */
  token: (v: unknown): Scalar | undefined =>
    typeof v === 'string' && SAFE_TOKEN.test(v) ? v : undefined,
} as const;

/**
 * Reduce caller-supplied context to a safe, scalar-only record by ALLOWLIST. Iteration is over the SCHEMA's keys,
 * never the input's, so a field the schema does not declare is structurally impossible to emit. Declared fields
 * are additionally validated; a value that fails its validator is omitted. Reserved keys are never emitted.
 */
export function buildFields(
  schema: EventSchema,
  input: Record<string, unknown>,
): Record<string, Scalar> {
  const out: Record<string, Scalar> = {};
  let n = 0;
  for (const key of Object.keys(schema)) {
    if (RESERVED_FIELDS.has(key)) continue; // a schema may never re-declare a reserved record field
    if (n >= MAX_FIELDS) break;
    if (!Object.prototype.hasOwnProperty.call(input, key)) continue;
    const validate = schema[key];
    if (validate === undefined) continue;
    const safe = validate(input[key]);
    if (safe !== undefined) {
      out[key] = safe;
      n++;
    }
  }
  return out;
}

/** Fields allowed on EVERY event (i.e. safe child-binding fields), merged ahead of each event's own schema. */
export const BASE_EVENT_FIELDS: EventSchema = { component: field.token };
