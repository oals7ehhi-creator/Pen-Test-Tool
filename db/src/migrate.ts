import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import pg from 'pg';
import { loadDbConfig, createLogger } from '@pentest/shared';

/**
 * Minimal forward+rollback migration runner. Each migration is a pair `NNNN_name.up.sql` / `NNNN_name.down.sql`.
 * Applied versions are tracked in `schema_migrations`. Every migration + its bookkeeping runs in ONE transaction,
 * so a failure leaves the database unchanged (no partial migrations).
 *
 * Commands:
 *   up     apply all pending migrations
 *   down   roll back the most recently applied migration
 *   ci     prove reversibility on a clean DB: up → down (to empty) → up, asserting the tracking table matches
 */

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'migrations');

interface Migration {
  version: string; // e.g. '0001'
  name: string; // e.g. '0001_init'
  up: string;
  down: string;
}

async function loadMigrations(): Promise<Migration[]> {
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

async function ensureTracking(client: pg.Client): Promise<void> {
  await client.query(
    `CREATE TABLE IF NOT EXISTS schema_migrations (
       version    TEXT PRIMARY KEY,
       name       TEXT NOT NULL,
       applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
     )`,
  );
}

async function appliedVersions(client: pg.Client): Promise<Set<string>> {
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

async function up(client: pg.Client, log: ReturnType<typeof createLogger>): Promise<void> {
  await ensureTracking(client);
  const applied = await appliedVersions(client);
  for (const m of await loadMigrations()) {
    if (applied.has(m.version)) continue;
    await applyUp(client, m);
    log.info('migration applied', { version: m.version, name: m.name });
  }
}

async function down(client: pg.Client, log: ReturnType<typeof createLogger>): Promise<void> {
  await ensureTracking(client);
  const applied = await appliedVersions(client);
  const migrations = await loadMigrations();
  const last = [...migrations].reverse().find((m) => applied.has(m.version));
  if (!last) {
    log.info('no migration to roll back');
    return;
  }
  await applyDown(client, last);
  log.info('migration rolled back', { version: last.version, name: last.name });
}

/** Snapshot of the public-schema shape (user tables + their columns), excluding the runner's own tracking table. */
async function schemaSnapshot(client: pg.Client): Promise<string> {
  const { rows } = await client.query<{ sig: string }>(
    `SELECT string_agg(table_name || '.' || column_name || ':' || data_type, ',' ORDER BY table_name, ordinal_position) AS sig
       FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name <> 'schema_migrations'`,
  );
  return rows[0]?.sig ?? '';
}

async function ci(client: pg.Client, log: ReturnType<typeof createLogger>): Promise<void> {
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
  await up(client, log); // re-apply to prove up→down→up is deterministic
  const afterUp2 = await schemaSnapshot(client);
  if (afterUp2 !== afterUp)
    throw new Error('re-applied schema differs from the first up (non-deterministic)');
  log.info(
    'migrate:ci ok — up/down/up round-trip verified; rollback restored the exact prior schema',
  );
}

async function main(): Promise<void> {
  const config = loadDbConfig();
  const log = createLogger({ level: config.logLevel }).child({ component: 'db-migrate' });
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

main().catch((err: unknown) => {
  process.stderr.write(`${(err as Error).message}\n`);
  process.exit(1);
});
