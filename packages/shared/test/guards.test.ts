import { describe, it, expect } from 'vitest';
import {
  isRole,
  isPermission,
  createLogger,
  field,
  type LogLevel,
  type EventRegistry,
} from '../src/index.js';

describe('type guards', () => {
  it('isRole', () => {
    expect(isRole('tester')).toBe(true);
    expect(isRole('root')).toBe(false);
    expect(isRole(42)).toBe(false);
  });

  it('isPermission', () => {
    expect(isPermission('report.read')).toBe(true);
    expect(isPermission('report.delete_everything')).toBe(false);
    expect(isPermission(null)).toBe(false);
  });
});

describe('logger emits at every level and supports child bindings', () => {
  const EVENTS: EventRegistry = { ping: { seq: field.int(0, 1_000_000) } };

  it('renders trace..error and merges child bindings into the allowlisted fields', () => {
    const lines: string[] = [];
    const base = createLogger({
      level: 'trace',
      events: EVENTS,
      sink: (l) => lines.push(l),
      now: () => new Date(0),
    });
    const child = base.child({ component: 'api' });
    const levels: LogLevel[] = ['trace', 'debug', 'info', 'warn', 'error'];
    for (const lvl of levels) child[lvl]('ping', { seq: 1 });
    expect(lines).toHaveLength(5);
    for (const line of lines) {
      const rec = JSON.parse(line) as { event: string; fields: Record<string, unknown> };
      expect(rec.event).toBe('ping');
      expect(rec.fields.component).toBe('api');
      expect(rec.fields.seq).toBe(1);
    }
  });
});
