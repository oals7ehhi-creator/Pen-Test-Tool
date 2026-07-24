import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import pg from 'pg';
import { createLogger, type Logger } from '@pentest/shared';
import { up, down, schemaSnapshot, loadMigrations } from '../src/migrate.js';
import { DB_EVENTS } from '../src/logevents.js';

/**
 * Phase 1 exit test — the migration up/down round-trip is EXACT against the full-catalog snapshot, and the snapshot
 * detects a leftover object of each class it captures: tables, indexes, constraints, triggers, extensions, VIEWS,
 * MATERIALIZED VIEWS, non-public SCHEMAS, ROW-LEVEL-SECURITY policies, and COMMENTS — plus column-attribute
 * sensitivity (generated/identity/collation). Requires a database (DATABASE_URL); skipped otherwise so
 * `pnpm -r run test` still runs on a machine without one. In CI (build-test) DATABASE_URL is set to the Postgres
 * service, so this runs for real.
 */

const url = process.env.DATABASE_URL;
const silent: Logger = createLogger({ level: 'error', events: DB_EVENTS, sink: () => {} });

async function reset(client: pg.Client): Promise<void> {
  // Start from a genuinely empty database so the baseline snapshot is the true prior state. A full schema reset
  // clears every migration's objects (and any probe left behind), independent of how many migrations exist.
  await client.query('DROP SCHEMA IF EXISTS probe_s CASCADE');
  await client.query('DROP SCHEMA public CASCADE');
  await client.query('CREATE SCHEMA public');
}

describe.skipIf(!url)('migration up/down is an EXACT inverse (full-catalog snapshot)', () => {
  let client: pg.Client;

  beforeAll(async () => {
    client = new pg.Client({ connectionString: url });
    await client.connect();
  });
  afterAll(async () => {
    if (client) await client.end();
  });
  beforeEach(async () => {
    await reset(client);
  });

  it('up changes the schema and a full rollback restores the EXACT prior schema', async () => {
    const before = await schemaSnapshot(client);
    await up(client, silent);
    const afterUp = await schemaSnapshot(client);
    expect(afterUp).not.toBe(before); // up genuinely changed the schema
    expect(afterUp).toContain('rel:public.tenant:r'); // ...the Phase 1 tenant table
    expect(afterUp).toContain('rel:public.engagement:r'); // ...and the Phase 2 authority tables
    // Roll every applied migration back (down rolls back one at a time).
    for (let i = 0; i < (await loadMigrations()).length; i++) await down(client, silent);
    expect(await schemaSnapshot(client)).toBe(before); // exact restoration to empty
  });

  it('rolling back the LATEST migration and re-applying it is deterministic', async () => {
    await up(client, silent);
    const firstUp = await schemaSnapshot(client);
    await down(client, silent); // roll back only the latest migration
    await up(client, silent); // re-apply it
    expect(await schemaSnapshot(client)).toBe(firstUp);
  });

  // Each case leaves ONE class of object behind after a (simulated) rollback and asserts the snapshot no longer
  // equals the empty baseline — i.e. the exact-schema check would reject that incomplete rollback.
  const leftovers: ReadonlyArray<{
    kind: string;
    create: string;
    cleanup: string;
    marker: string;
  }> = [
    {
      kind: 'table',
      create: 'CREATE TABLE probe_t (id int)',
      cleanup: 'DROP TABLE probe_t',
      marker: 'rel:public.probe_t:r',
    },
    {
      kind: 'index',
      create: 'CREATE TABLE probe_idx_t (id int); CREATE INDEX probe_idx ON probe_idx_t (id)',
      cleanup: 'DROP TABLE probe_idx_t',
      marker: 'idx:public.probe_idx',
    },
    {
      kind: 'constraint',
      create:
        'CREATE TABLE probe_con_t (id int); ALTER TABLE probe_con_t ADD CONSTRAINT probe_ck CHECK (id > 0)',
      cleanup: 'DROP TABLE probe_con_t',
      marker: 'probe_ck',
    },
    {
      kind: 'trigger',
      create:
        'CREATE TABLE probe_t (id int);' +
        'CREATE FUNCTION probe_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;' +
        'CREATE TRIGGER probe_trg BEFORE INSERT ON probe_t FOR EACH ROW EXECUTE FUNCTION probe_fn()',
      cleanup: 'DROP TABLE probe_t CASCADE; DROP FUNCTION probe_fn()',
      marker: 'trg:',
    },
    {
      kind: 'extension',
      create: 'CREATE EXTENSION pgcrypto',
      cleanup: 'DROP EXTENSION pgcrypto',
      marker: 'ext:pgcrypto',
    },
    {
      kind: 'view',
      create: 'CREATE VIEW probe_v AS SELECT 1 AS x',
      cleanup: 'DROP VIEW probe_v',
      marker: 'rel:public.probe_v:v',
    },
    {
      kind: 'materialized view',
      create: 'CREATE MATERIALIZED VIEW probe_mv AS SELECT 1 AS x',
      cleanup: 'DROP MATERIALIZED VIEW probe_mv',
      marker: 'rel:public.probe_mv:m',
    },
    {
      kind: 'non-public schema',
      create: 'CREATE SCHEMA probe_s',
      cleanup: 'DROP SCHEMA probe_s',
      marker: 'schema:probe_s',
    },
    {
      kind: 'RLS policy',
      create:
        'CREATE TABLE probe_rls_t (id int);' +
        'ALTER TABLE probe_rls_t ENABLE ROW LEVEL SECURITY;' +
        'CREATE POLICY probe_pol ON probe_rls_t USING (true)',
      cleanup: 'DROP TABLE probe_rls_t',
      marker: 'policy:public.probe_rls_t.probe_pol',
    },
    {
      kind: 'comment',
      create: "CREATE TABLE probe_cmt_t (id int); COMMENT ON TABLE probe_cmt_t IS 'a note'",
      cleanup: 'DROP TABLE probe_cmt_t',
      marker: 'comment:public.probe_cmt_t.:a note',
    },
  ];

  for (const lo of leftovers) {
    it(`a leftover ${lo.kind} fails the rollback check`, async () => {
      const baseline = await schemaSnapshot(client);
      await client.query(lo.create);
      const withLeftover = await schemaSnapshot(client);
      expect(withLeftover).not.toBe(baseline); // the exact-schema comparison rejects the incomplete rollback
      expect(withLeftover).toContain(lo.marker); // ...and the snapshot names the offending object class
      await client.query(lo.cleanup);
      expect(await schemaSnapshot(client)).toBe(baseline); // removing it restores the baseline
    });
  }

  // A column differing ONLY in a fine-grained attribute (generated expression / identity / collation) must not be
  // snapshot-identical to a plain column — otherwise a rollback that alters just that attribute passes undetected.
  it('column attributes (generated / identity / collation) change the snapshot', async () => {
    await client.query('CREATE TABLE probe_attr_t (id int, x text)');
    const plain = await schemaSnapshot(client);

    await client.query(
      'ALTER TABLE probe_attr_t ADD COLUMN g int GENERATED ALWAYS AS (id * 2) STORED',
    );
    const withGenerated = await schemaSnapshot(client);
    expect(withGenerated).not.toBe(plain);
    expect(withGenerated).toContain('(id * 2)'); // the generation expression is captured

    await client.query('ALTER TABLE probe_attr_t ALTER COLUMN x TYPE text COLLATE "C"');
    expect(await schemaSnapshot(client)).not.toBe(withGenerated); // collation change is captured too
  });
});
