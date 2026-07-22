import { type LogLevel } from './config.js';
import {
  buildFields,
  BASE_EVENT_FIELDS,
  UNKNOWN_EVENT,
  type EventRegistry,
  type Scalar,
} from './logsafe.js';

/**
 * Minimal structured JSON logger built on the SI-045 allowlist (see logsafe.ts). Each record is one JSON line:
 *   { time, level, correlationId, event, fields }
 * where `event` is a fixed, registered name and `fields` are the allowlisted, validated, scalar-only safe fields.
 *
 * The `correlationId` is AUTHORITATIVE: it is taken from the logger's own base, never from caller context, and it
 * is a reserved field so it can never be supplied or overridden through `fields`/bindings. A per-request id is set
 * with `childWithCorrelationId(id)`, which returns a logger bound to that id; ordinary `child(bindings)` inherits
 * the parent's id. Kept dependency-free: it is on the safety-critical path and must be trivially auditable.
 */

const LEVEL_ORDER: Record<LogLevel, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
};

export interface LogRecord {
  time: string;
  level: LogLevel;
  correlationId: string;
  event: string;
  fields: Record<string, Scalar>;
}

export interface LoggerOptions {
  level: LogLevel;
  /** The per-service event allowlist. Events not present here are emitted as `unknown_event` with no fields. */
  events: EventRegistry;
  /** Authoritative correlation id for this logger (defaults to 'root'; set per request via childWithCorrelationId). */
  correlationId?: string;
  /** Sink for rendered JSON lines. Defaults to stdout. Injectable for tests. */
  sink?: (line: string) => void;
  /** Clock, injectable for deterministic tests. */
  now?: () => Date;
}

export interface Logger {
  readonly level: LogLevel;
  /** The authoritative correlation id stamped on every record this logger emits. */
  readonly correlationId: string;
  /** Derive a logger with additional safe bindings (e.g. `{ component }`), inheriting the correlation id. */
  child(bindings: Record<string, unknown>): Logger;
  /** Derive a logger bound to a NEW authoritative correlation id (context can never override it). */
  childWithCorrelationId(correlationId: string, bindings?: Record<string, unknown>): Logger;
  trace(event: string, fields?: Record<string, unknown>): void;
  debug(event: string, fields?: Record<string, unknown>): void;
  info(event: string, fields?: Record<string, unknown>): void;
  warn(event: string, fields?: Record<string, unknown>): void;
  error(event: string, fields?: Record<string, unknown>): void;
}

interface Resolved {
  level: LogLevel;
  correlationId: string;
  sink: (line: string) => void;
  now: () => Date;
  events: EventRegistry;
}

function build(base: Resolved, bindings: Record<string, unknown>): Logger {
  function emit(level: LogLevel, event: string, fields?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[base.level]) return;
    // OWN-property lookup only: a prototype-chain access (`base.events[event]`) would treat inherited Object
    // members ('constructor', 'toString', '__proto__', 'hasOwnProperty', …) as registered events and leak the
    // verbatim name + fields. hasOwnProperty closes the allowlist so those names become UNKNOWN_EVENT.
    const known = Object.prototype.hasOwnProperty.call(base.events, event);
    const schema = known ? base.events[event] : undefined;
    const merged = { ...bindings, ...(fields ?? {}) };
    // Reserved fields are written literally from the base; `event` is a registered name or the safe sentinel;
    // `fields` are allowlisted. Nothing in `merged` can reach a reserved position or the event name.
    const record: LogRecord = {
      time: base.now().toISOString(),
      level,
      correlationId: base.correlationId,
      event: known ? event : UNKNOWN_EVENT,
      fields: known ? buildFields({ ...BASE_EVENT_FIELDS, ...schema }, merged) : {},
    };
    base.sink(JSON.stringify(record));
  }

  return {
    level: base.level,
    correlationId: base.correlationId,
    child: (childBindings) => build(base, { ...bindings, ...childBindings }),
    childWithCorrelationId: (correlationId, childBindings) =>
      build({ ...base, correlationId }, { ...bindings, ...(childBindings ?? {}) }),
    trace: (e, f) => emit('trace', e, f),
    debug: (e, f) => emit('debug', e, f),
    info: (e, f) => emit('info', e, f),
    warn: (e, f) => emit('warn', e, f),
    error: (e, f) => emit('error', e, f),
  };
}

export function createLogger(opts: LoggerOptions): Logger {
  const base: Resolved = {
    level: opts.level,
    correlationId: opts.correlationId ?? 'root',
    sink: opts.sink ?? ((line: string) => process.stdout.write(line + '\n')),
    now: opts.now ?? (() => new Date()),
    events: opts.events,
  };
  return build(base, {});
}
