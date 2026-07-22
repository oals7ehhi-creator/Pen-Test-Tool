import { writeFileSync } from 'node:fs';
import { loadConfig, createLogger } from '@pentest/shared';
import { WORKER_EVENTS } from './logevents.js';

/**
 * Phase 1 worker skeleton. Boots on the same fail-closed config and minimized structured logging as the API.
 * The data-plane job loop (queue consumption, the Guarded Egress Broker) lands in later phases; until then this
 * process stays alive with a periodic liveness heartbeat so the full stack runs and the shared foundations are
 * exercised end-to-end. The heartbeat also drives the container health check: each tick rewrites a liveness file,
 * and the health check fails once that file goes stale (i.e. the loop has stopped) — see services/worker/Dockerfile.
 */

const HEARTBEAT_MS = 15_000;

export interface WorkerHandle {
  /** Stop the heartbeat loop so the process can exit. Used by tests; the service runs until the container stops it. */
  stop(): void;
}

export function main(): WorkerHandle {
  const config = loadConfig();
  const log = createLogger({ level: config.logLevel, events: WORKER_EVENTS }).child({
    component: 'worker',
  });
  const livenessFile = process.env.WORKER_READINESS_FILE;

  const beat = (): void => {
    // Rewriting the file bumps its mtime; the health check treats a fresh mtime as a live heartbeat.
    if (livenessFile !== undefined && livenessFile !== '') writeFileSync(livenessFile, 'alive');
  };

  beat(); // config validated + first heartbeat written = ready
  log.info('worker_started', { env: config.nodeEnv });
  const timer = setInterval(() => {
    beat();
    log.debug('worker_heartbeat', { env: config.nodeEnv });
  }, HEARTBEAT_MS);

  return { stop: () => clearInterval(timer) };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main(); // the heartbeat interval keeps the process alive until the container stops it
  } catch (err) {
    process.stderr.write(`${(err as Error).message}\n`);
    process.exit(1);
  }
}
