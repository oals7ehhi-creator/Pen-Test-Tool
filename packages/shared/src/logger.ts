import { type LogLevel } from './config.js';
import { sanitizeContext, type Scalar } from './sanitize.js';

/**
 * Minimal structured JSON logger. Each record is one JSON line with reserved fields — time, level, correlationId,
 * msg — plus a `ctx` object holding the ALLOWLISTED, minimized, scalar-only context (see sanitizeContext). Reserved
 * fields are written last and context is namespaced under `ctx`, so caller context can never override them. Kept
 * dependency-free: it is on the safety-critical path and must be trivially auditable.
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
  msg: string;
  ctx: Record<string, Scalar>;
}

export interface LoggerOptions {
  level: LogLevel;
  correlationId?: string;
  /** Sink for rendered JSON lines. Defaults to stdout. Injectable for tests. */
  sink?: (line: string) => void;
  /** Clock, injectable for deterministic tests. */
  now?: () => Date;
}

export interface Logger {
  readonly level: LogLevel;
  child(bindings: Record<string, unknown>): Logger;
  trace(msg: string, ctx?: Record<string, unknown>): void;
  debug(msg: string, ctx?: Record<string, unknown>): void;
  info(msg: string, ctx?: Record<string, unknown>): void;
  warn(msg: string, ctx?: Record<string, unknown>): void;
  error(msg: string, ctx?: Record<string, unknown>): void;
}

interface Resolved {
  level: LogLevel;
  correlationId: string;
  sink: (line: string) => void;
  now: () => Date;
}

function build(base: Resolved, bindings: Record<string, unknown>): Logger {
  function emit(level: LogLevel, msg: string, ctx?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[base.level]) return;
    const merged = { ...bindings, ...(ctx ?? {}) };
    // Reserved fields are literal and come first; `ctx` carries only sanitized scalars. Because sanitizeContext
    // strips reserved keys and everything is namespaced under `ctx`, context can never override a reserved field.
    const record: LogRecord = {
      time: base.now().toISOString(),
      level,
      correlationId: base.correlationId,
      msg,
      ctx: sanitizeContext(merged),
    };
    base.sink(JSON.stringify(record));
  }

  return {
    level: base.level,
    child: (childBindings) => build(base, { ...bindings, ...childBindings }),
    trace: (m, c) => emit('trace', m, c),
    debug: (m, c) => emit('debug', m, c),
    info: (m, c) => emit('info', m, c),
    warn: (m, c) => emit('warn', m, c),
    error: (m, c) => emit('error', m, c),
  };
}

export function createLogger(opts: LoggerOptions): Logger {
  const base: Resolved = {
    level: opts.level,
    correlationId: opts.correlationId ?? 'root',
    sink: opts.sink ?? ((line: string) => process.stdout.write(line + '\n')),
    now: opts.now ?? (() => new Date()),
  };
  return build(base, {});
}
