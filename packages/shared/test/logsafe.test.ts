import { describe, it, expect } from 'vitest';
import {
  createLogger,
  buildFields,
  field,
  RESERVED_FIELDS,
  UNKNOWN_EVENT,
  type EventRegistry,
  type EventSchema,
} from '../src/index.js';

/**
 * SI-045 exit tests: the log allowlist is CLOSED (only declared, validated fields are emitted; nothing else can
 * reach a sink), event names are fixed, and the correlation id is authoritative (item 1).
 */

const EVENTS: EventRegistry = {
  request: {
    method: field.httpMethod,
    route: field.oneOf(['/a', '/b', '(unmatched)']),
    status: field.httpStatus,
  },
  op: { name: field.token, count: field.int(0, 1000), ok: field.bool },
};

function capture(events: EventRegistry = EVENTS, correlationId?: string) {
  const lines: string[] = [];
  const log = createLogger({
    level: 'trace',
    events,
    ...(correlationId !== undefined ? { correlationId } : {}),
    sink: (l) => lines.push(l),
    now: () => new Date(0),
  });
  return { lines, log };
}

describe('buildFields — explicit per-event allowlist', () => {
  it('emits only declared fields that pass their validator; every unknown field is omitted', () => {
    const out = buildFields(EVENTS.op as EventSchema, {
      name: 'sync',
      count: 3,
      ok: true,
      secret: 'nope',
      authorization: 'Bearer x',
      body: { pw: 'x' },
    });
    expect(out).toEqual({ name: 'sync', count: 3, ok: true });
  });

  it('omits declared fields whose values fail validation — no coercion, no truncation', () => {
    const out = buildFields(EVENTS.op as EventSchema, {
      name: 'has space', // fails token shape
      count: 3.5, // not an integer
      ok: 'yes', // not a boolean
    });
    expect(out).toEqual({});
  });

  it('never emits a reserved field, even if a schema tries to declare it', () => {
    const sneaky = {
      name: field.token,
      correlationId: field.token,
      event: field.token,
    } as unknown as EventSchema;
    const out = buildFields(sneaky, { name: 'ok', correlationId: 'x', event: 'y' });
    expect(out).toEqual({ name: 'ok' });
    for (const r of RESERVED_FIELDS) expect(out).not.toHaveProperty(r);
  });
});

describe('field validators reject unsafe shapes', () => {
  it('httpMethod, httpStatus, int, oneOf, token, bool', () => {
    expect(field.httpMethod('GET')).toBe('GET');
    expect(field.httpMethod('CONNECT')).toBeUndefined();
    expect(field.httpStatus(200)).toBe(200);
    expect(field.httpStatus(99)).toBeUndefined();
    expect(field.int(0, 10)(5)).toBe(5);
    expect(field.int(0, 10)(11)).toBeUndefined();
    expect(field.oneOf(['/a'])('/a')).toBe('/a');
    expect(field.oneOf(['/a'])('/a?x=1')).toBeUndefined();
    expect(field.token('db-migrate')).toBe('db-migrate');
    expect(field.token('/etc/passwd')).toBeUndefined();
    expect(field.token('a b')).toBeUndefined();
    expect(field.bool(true)).toBe(true);
    expect(field.bool('true')).toBeUndefined();
  });
});

describe('SI-045 negative battery — no planted value ever reaches the sink', () => {
  const SECRET = 'S3CR3T-must-never-be-logged';

  it('a secret in a URL/query/path (as a route) is rejected — route must be a known template', () => {
    const { lines, log } = capture();
    log.info('request', { method: 'GET', route: `/a?token=${SECRET}`, status: 200 });
    expect(lines.join('\n')).not.toContain(SECRET);
    expect(JSON.parse(lines[0]!).fields.route).toBeUndefined();
    expect(JSON.parse(lines[0]!).fields).toEqual({ method: 'GET', status: 200 });
  });

  it('unknown auth header names, opaque tokens, bodies and nested objects are all omitted', () => {
    const { lines, log } = capture();
    log.info('op', {
      name: 'ok',
      authorization: `Bearer ${SECRET}`,
      'x-tenant-authorization': SECRET,
      token: SECRET,
      body: `password=${SECRET}`,
      payload: { a: SECRET },
    });
    expect(lines.join('\n')).not.toContain(SECRET);
    expect(JSON.parse(lines[0]!).fields).toEqual({ name: 'ok' });
  });

  it('a secret hidden under an innocent-looking but DECLARED field is rejected by the validator', () => {
    const { lines, log } = capture();
    log.info('op', { name: `user=admin;pw=${SECRET}` }); // 'name' is declared, but the value fails the token shape
    expect(lines.join('\n')).not.toContain(SECRET);
    expect(JSON.parse(lines[0]!).fields.name).toBeUndefined();
  });

  it('a secret interpolated into the event NAME never appears; the event becomes unknown_event', () => {
    const { lines, log } = capture();
    log.info(`request-${SECRET}`, { method: 'GET' });
    expect(lines.join('\n')).not.toContain(SECRET);
    expect(JSON.parse(lines[0]!).event).toBe(UNKNOWN_EVENT);
    expect(JSON.parse(lines[0]!).fields).toEqual({});
  });

  it('Object.prototype member names are NOT registered events (closed allowlist)', () => {
    // Prototype-chain lookup would treat these as known events and leak the verbatim name + fields.
    const { lines, log } = capture();
    for (const name of [
      'constructor',
      'toString',
      'valueOf',
      'hasOwnProperty',
      '__proto__',
      'isPrototypeOf',
      'propertyIsEnumerable',
      'toLocaleString',
    ]) {
      log.info(name, { component: 'api', method: 'GET' });
    }
    for (const line of lines) {
      const rec = JSON.parse(line) as { event: string; fields: Record<string, unknown> };
      expect(rec.event).toBe(UNKNOWN_EVENT);
      expect(rec.fields).toEqual({});
    }
  });

  it('arrays, Buffers, Errors, URLs and custom class instances are never serialized', () => {
    const { lines, log } = capture();
    class Custom {
      secret = SECRET;
    }
    log.info('op', {
      count: [1, 2, SECRET], // array
      name: Buffer.from(SECRET), // Buffer
      ok: new Error(SECRET), // Error
      extra: new URL(`https://h/p?token=${SECRET}`), // URL (also not a declared field)
      obj: new Custom(), // class instance
    });
    expect(lines.join('\n')).not.toContain(SECRET);
    expect(JSON.parse(lines[0]!).fields).toEqual({}); // count/name/ok fail validation; extra/obj undeclared
  });
});

describe('authoritative correlation id (item 1)', () => {
  it('childWithCorrelationId stamps the record id; child() inherits it and still binds safe fields (d)', () => {
    const { lines, log } = capture();
    const req = log.childWithCorrelationId('cid-abc');
    req.info('op', { name: 'x' });
    expect(JSON.parse(lines[0]!).correlationId).toBe('cid-abc');

    const kid = req.child({ component: 'api' });
    kid.info('op', { name: 'y' });
    const rec = JSON.parse(lines[1]!);
    expect(rec.correlationId).toBe('cid-abc'); // inherited
    expect(rec.fields.component).toBe('api'); // child bindings still work
  });

  it('a spoofed correlationId in context cannot replace the authoritative id (c)', () => {
    const { lines, log } = capture({ op: { name: field.token } }, 'authoritative');
    log.info('op', { name: 'x', correlationId: 'attacker-controlled' });
    const rec = JSON.parse(lines[0]!);
    expect(rec.correlationId).toBe('authoritative');
    expect(JSON.stringify(rec)).not.toContain('attacker-controlled');
  });

  it('two childWithCorrelationId loggers carry different ids', () => {
    const { lines, log } = capture();
    log.childWithCorrelationId('id-1').info('op', { name: 'a' });
    log.childWithCorrelationId('id-2').info('op', { name: 'b' });
    expect(JSON.parse(lines[0]!).correlationId).toBe('id-1');
    expect(JSON.parse(lines[1]!).correlationId).toBe('id-2');
  });
});
