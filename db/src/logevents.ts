import { field, type EventRegistry } from '@pentest/shared';

/** The migration runner's SI-045 event allowlist. Only bounded, safe migration identifiers are ever logged. */
export const DB_EVENTS: EventRegistry = {
  migration_applied: { version: field.token, name: field.token },
  migration_rolled_back: { version: field.token, name: field.token },
  migration_none: {},
  migrate_ci_ok: {},
};
