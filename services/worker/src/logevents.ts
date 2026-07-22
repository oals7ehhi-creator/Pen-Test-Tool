import { field, NODE_ENVS, type EventRegistry } from '@pentest/shared';

/** The worker's SI-045 event allowlist. Only the (validated) runtime environment is ever logged. */
export const WORKER_EVENTS: EventRegistry = {
  worker_started: { env: field.oneOf(NODE_ENVS) },
  worker_heartbeat: { env: field.oneOf(NODE_ENVS) },
};
