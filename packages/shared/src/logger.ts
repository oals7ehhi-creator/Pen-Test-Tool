import { type LogLevel } from './config.js';
import { redact } from './redact.js';

/**
 * Minimal structured JSON logger. Every record is a single JSON line with a correlation id, level, timestamp,
 * message, and redacted context. All context passes through `redact()` so secrets never reach the sink. Kept
 * dependency-free on purpose: it is on the safety-critical path and must be trivially auditable.
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
  [key: string]: unknown;
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
    const record: LogRecord = {
      time: base.now().toISOString(),
      level,
      correlationId: base.correlationId,
      msg,
      // Redact the entire context payload before serialization — the last line of defense before the sink.
      ...redact(merged),
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
