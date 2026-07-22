import { loadConfig, createLogger } from '@pentest/shared';

/**
 * Phase 1 worker skeleton. Boots on the same fail-closed config and redacted structured logging as the API.
 * The data-plane job loop (queue consumption, the Guarded Egress Broker) is implemented in later phases; this
 * process exists so the full stack comes up and the shared foundations are exercised end-to-end.
 */
export function main(): void {
  const config = loadConfig();
  const log = createLogger({ level: config.logLevel }).child({ component: 'worker' });
  log.info('worker started', { env: config.nodeEnv });
  // No job processing yet (Phase 4+). The process stays idle; a real loop replaces this.
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (err) {
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  }
}
