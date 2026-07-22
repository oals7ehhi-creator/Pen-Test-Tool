import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pg from 'pg';
import { loadDbConfig, createLogger, type Logger } from '@pentest/shared';
import { DB_EVENTS } from './logevents.js';

/**
 * Minimal forward+rollback migration runner. Each migration is a pair `NNNN_name.up.sql` / `NNNN_name.down.sql`.
 * Applied versions are tracked in `schema_migrations`. Every migration + its bookkeeping runs in ONE transaction,
 * so a failure leaves the database unchanged (no partial migrations).
 *
 * Commands:
 *   up     apply all pending migrations
 *   down   roll back the most recently applied migration
 *   ci     prove reversibility on a clean DB: up -> down (to empty) -> up, asserting via a FULL-CATALOG schema
 *          snapshot that the down truly restores the exact prior database state.
 *
 * Extensions are intentionally NOT created by these migrations: `gen_random_uuid()` is in core PostgreSQL (>= 13),
 * and any extension a later phase needs (e.g. pgcrypto for digest()) is provisioned as a documented operator
 * prerequisite by the migration that first requires it. Keeping migrations extension-free means a down migration
 * is an exact inverse of its up, which `ci` verifies against the snapshot (which includes extensions).
 */

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'migrations');

export interface Migration {
  version: string; // e.g. '0001'
  name: string; // e.g. '0001_init'
  up: string;
  down: string;
}

export async function loadMigrations(): Promise<Migration[]> {
  const files = await readdir(MIGRATIONS_DIR);
  const bases = [
    ...new Set(files.filter((f) => f.endsWith('.up.sql')).map((f) => f.replace('.up.sql', ''))),
  ].sort();
  const out: Migration[] = [];
  for (const base of bases) {
    const version = base.split('_')[0] ?? base;
    out.push({
      version,
      name: base,
      up: await readFile(join(MIGRATIONS_DIR, `${base}.up.sql`), 'utf8'),
      down: await readFile(join(MIGRATIONS_DIR, `${base}.down.sql`), 'utf8'),
    });
  }
  return out;
}

export async function ensureTracking(client: pg.Client): Promise<void> {
  await client.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       version    TEXT PRIMARY KEY,
       name       TEXT NOT NULL,
       applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
     )`,
  );
}

export async function appliedVersions(client: pg.Client): Promise<Set<string>> {
  const { rows } = await client.query<{ version: string }>('SELECT version FROM schema_migrations');
  return new Set(rows.map((r) => r.version));
}

async function applyUp(client: pg.Client, m: Migration): Promise<void> {
  await client.query('BEGIN');
  try {
    await client.query(m.up);
    await client.query('INSERT INTO schema_migrations (version, name) VALUES ($1, $2)', [
      m.version,
      m.name,
    ]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

async function applyDown(client: pg.Client, m: Migration): Promise<void> {
  await client.query('BEGIN');
  try {
    await client.query(m.down);
    await client.query('DELETE FROM schema_migrations WHERE version = $1', [m.version]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  }
}

export async function up(client: pg.Client, log: Logger): Promise<void> {
  await ensureTracking(client);
  const applied = await appliedVersions(client);
  for (const m of await loadMigrations()) {
    if (applied.has(m.version)) continue;
    await applyUp(client, m);
    log.info('migration_applied', { version: m.version, name: m.name });
  }
}

export async function down(client: pg.Client, log: Logger): Promise<void> {
  await ensureTracking(client);
  const applied = await appliedVersions(client);
  const migrations = await loadMigrations();
  const last = [...migrations].reverse().find((m) => applied.has(m.version));
  if (!last) {
    log.info('migration_none');
    return;
  }
  await applyDown(client, last);
  log.info('migration_rolled_back', { version: last.version, name: last.name });
}

/**
 * FULL-CATALOG snapshot of the migration-controlled state of every USER schema (everything except the built-in
 * pg_* schemas and information_schema), excluding the runner's own `schema_migrations` bookkeeping. The result is a
 * single canonical, deterministically-ordered string, so two calls are `===` iff the database is in the same
 * structural state — a true exact-prior-schema comparison across schemas, not just `public`.
 *
 * Captured object classes:
 *   - schemas (so a leftover CREATE SCHEMA is detected);
 *   - relations: tables, partitioned tables, views, materialized views and sequences — with relkind, storage
 *     params (reloptions) and, for (materialized) views, the full definition;
 *   - columns: type, nullability, default, GENERATED expression, identity, and collation;
 *   - constraints (PK/FK/unique/check, via pg_get_constraintdef), indexes;
 *   - user types (enums with ordered labels, domains, standalone composites);
 *   - functions and triggers (full definitions);
 *   - row-level security: per-table RLS enabled/forced flags and every policy (cmd, roles, USING, WITH CHECK);
 *   - object comments (relations + columns); and installed extensions (name + version).
 *
 * Not captured (out of scope for Phase 1; add a CTE here when a migration first introduces one): foreign
 * data wrappers / servers / user mappings, custom operators / casts / operator classes, ALTER DEFAULT PRIVILEGES
 * grants, event triggers, and publications / subscriptions.
 */
export async function schemaSnapshot(client: pg.Client): Promise<string> {
  // User-schema predicate: exclude the built-in pg_* schemas (pg_catalog, pg_toast, pg_temp_*) and information_schema.
  const { rows } = await client.query<{ sig: string }>(`
    WITH
    nsp AS (
      SELECT string_agg(format('schema:%s', nspname), E'\n' ORDER BY nspname) AS s
      FROM pg_namespace
      WHERE nspname NOT LIKE 'pg\\_%' AND nspname <> 'information_schema'
    ),
    rel AS (
      SELECT string_agg(
               format('rel:%s.%s:%s:%s:%s', n.nspname, cl.relname, cl.relkind,
                      coalesce(array_to_string(cl.reloptions, ','), ''),
                      CASE WHEN cl.relkind IN ('v', 'm') THEN pg_get_viewdef(cl.oid) ELSE '' END),
               E'\n' ORDER BY n.nspname, cl.relname) AS s
      FROM pg_class cl
      JOIN pg_namespace n ON n.oid = cl.relnamespace
      WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
        AND cl.relkind IN ('r', 'p', 'v', 'm', 'S') AND cl.relname <> 'schema_migrations'
    ),
    c AS (
      SELECT string_agg(
               format('col:%s.%s.%s:%s:%s:%s:%s:%s:%s', table_schema, table_name, column_name, data_type,
                      is_nullable, coalesce(column_default, ''), coalesce(generation_expression, ''),
                      is_identity, coalesce(collation_name, '')),
               E'\n' ORDER BY table_schema, table_name, ordinal_position) AS s
      FROM information_schema.columns
      WHERE table_schema NOT LIKE 'pg\\_%' AND table_schema <> 'information_schema'
        AND table_name <> 'schema_migrations'
    ),
    con AS (
      SELECT string_agg(format('con:%s.%s.%s:%s', n.nspname, cl.relname, con.conname,
                               pg_get_constraintdef(con.oid)),
                        E'\n' ORDER BY n.nspname, cl.relname, con.conname) AS s
      FROM pg_constraint con
      JOIN pg_class cl ON cl.oid = con.conrelid
      JOIN pg_namespace n ON n.oid = cl.relnamespace
      WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
        AND cl.relname <> 'schema_migrations'
    ),
    idx AS (
      SELECT string_agg(format('idx:%s.%s:%s', schemaname, indexname, indexdef),
                        E'\n' ORDER BY schemaname, indexname) AS s
      FROM pg_indexes
      WHERE schemaname NOT LIKE 'pg\\_%' AND schemaname <> 'information_schema'
        AND tablename <> 'schema_migrations'
    ),
    typ AS (
      SELECT string_agg(
               format('type:%s.%s:%s:%s', n.nspname, ty.typname, ty.typtype,
                      coalesce((SELECT string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder)
                                FROM pg_enum e WHERE e.enumtypid = ty.oid), '')),
               E'\n' ORDER BY n.nspname, ty.typname) AS s
      FROM pg_type ty
      JOIN pg_namespace n ON n.oid = ty.typnamespace
      WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
        AND (ty.typtype IN ('e', 'd')
             OR (ty.typtype = 'c'
                 AND EXISTS (SELECT 1 FROM pg_class k WHERE k.oid = ty.typrelid AND k.relkind = 'c')))
    ),
    fn AS (
      SELECT string_agg(format('fn:%s', pg_get_functiondef(p.oid)), E'\n' ORDER BY n.nspname, p.proname, p.oid) AS s
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
    ),
    trg AS (
      SELECT string_agg(format('trg:%s', pg_get_triggerdef(tg.oid)), E'\n' ORDER BY tg.tgname) AS s
      FROM pg_trigger tg
      JOIN pg_class cl ON cl.oid = tg.tgrelid
      JOIN pg_namespace n ON n.oid = cl.relnamespace
      WHERE NOT tg.tgisinternal AND n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
        AND cl.relname <> 'schema_migrations'
    ),
    rls AS (
      SELECT string_agg(format('rls:%s.%s:%s:%s', n.nspname, cl.relname, cl.relrowsecurity,
                               cl.relforcerowsecurity),
                        E'\n' ORDER BY n.nspname, cl.relname) AS s
      FROM pg_class cl
      JOIN pg_namespace n ON n.oid = cl.relnamespace
      WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
        AND cl.relkind IN ('r', 'p') AND (cl.relrowsecurity OR cl.relforcerowsecurity)
    ),
    pol AS (
      SELECT string_agg(
               format('policy:%s.%s.%s:%s:%s:%s:%s:%s', schemaname, tablename, policyname, permissive, cmd,
                      array_to_string(roles, ','), coalesce(qual, ''), coalesce(with_check, '')),
               E'\n' ORDER BY schemaname, tablename, policyname) AS s
      FROM pg_policies
      WHERE schemaname NOT LIKE 'pg\\_%' AND schemaname <> 'information_schema'
    ),
    cmt AS (
      SELECT string_agg(
               format('comment:%s.%s.%s:%s', n.nspname, cl.relname, coalesce(a.attname, ''), d.description),
               E'\n' ORDER BY n.nspname, cl.relname, coalesce(a.attname, '')) AS s
      FROM pg_description d
      JOIN pg_class cl ON cl.oid = d.objoid AND d.classoid = 'pg_class'::regclass
      JOIN pg_namespace n ON n.oid = cl.relnamespace
      LEFT JOIN pg_attribute a ON a.attrelid = cl.oid AND a.attnum = d.objsubid
      WHERE n.nspname NOT LIKE 'pg\\_%' AND n.nspname <> 'information_schema'
        AND cl.relname <> 'schema_migrations'
    ),
    ext AS (
      SELECT string_agg(format('ext:%s:%s', extname, extversion), E'\n' ORDER BY extname) AS s
      FROM pg_extension
    )
    SELECT concat_ws(E'\n',
      coalesce((SELECT s FROM nsp), ''), coalesce((SELECT s FROM rel), ''),
      coalesce((SELECT s FROM c), ''),   coalesce((SELECT s FROM con), ''),
      coalesce((SELECT s FROM idx), ''), coalesce((SELECT s FROM typ), ''),
      coalesce((SELECT s FROM fn), ''),  coalesce((SELECT s FROM trg), ''),
      coalesce((SELECT s FROM rls), ''), coalesce((SELECT s FROM pol), ''),
      coalesce((SELECT s FROM cmt), ''), coalesce((SELECT s FROM ext), '')) AS sig
  `);
  return rows[0]?.sig ?? '';
}

export async function ci(client: pg.Client, log: Logger): Promise<void> {
  const migrations = await loadMigrations();
  await ensureTracking(client);
  const before = await schemaSnapshot(client); // the DEFINED prior schema (empty on a clean DB)
  await up(client, log);
  const afterUp = await schemaSnapshot(client);
  if (afterUp === before) throw new Error('up applied no schema change (nothing to verify)');
  for (let i = 0; i < migrations.length; i++) await down(client, log); // roll all the way back
  const applied = await appliedVersions(client);
  if (applied.size !== 0)
    throw new Error(`rollback incomplete: ${[...applied].join(',')} still applied`);
  const afterDown = await schemaSnapshot(client);
  if (afterDown !== before) {
    throw new Error(
      `rollback did not restore the prior schema.\n  before: ${before}\n  after:  ${afterDown}`,
    );
  }
  await up(client, log); // re-apply to prove up->down->up is deterministic
  const afterUp2 = await schemaSnapshot(client);
  if (afterUp2 !== afterUp)
    throw new Error('re-applied schema differs from the first up (non-deterministic)');
  log.info('migrate_ci_ok');
}

async function main(): Promise<void> {
  const config = loadDbConfig();
  const log = createLogger({ level: config.logLevel, events: DB_EVENTS }).child({
    component: 'db-migrate',
  });
  const cmd = process.argv[2] ?? 'up';
  const client = new pg.Client({ connectionString: config.databaseUrl });
  await client.connect();
  try {
    if (cmd === 'up') await up(client, log);
    else if (cmd === 'down') await down(client, log);
    else if (cmd === 'ci') await ci(client, log);
    else throw new Error(`unknown command: ${cmd} (use up|down|ci)`);
  } finally {
    await client.end();
  }
}

// Run only when invoked directly, so the module can be imported by tests without connecting to a database.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err: unknown) => {
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  });
}
