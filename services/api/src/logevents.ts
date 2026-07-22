import { field, NODE_ENVS, type EventRegistry } from '@pentest/shared';
import { ROUTE_TEMPLATES } from './router.js';

/**
 * The API's SI-045 event allowlist. Every field is constrained to a safe shape:
 *  - `request` logs only the HTTP method, the MATCHED route template (from the frozen allowlist — never the raw
 *    URL/path/query), and a numeric HTTP status. There is deliberately no field for headers, query, or body.
 *  - `api_listening` logs the bind host/port and environment (operator config, validated), not request data.
 */
export const API_EVENTS: EventRegistry = {
  request: {
    method: field.httpMethod,
    route: field.oneOf(ROUTE_TEMPLATES),
    status: field.httpStatus,
  },
  api_listening: {
    host: field.token,
    port: field.int(1, 65535),
    env: field.oneOf(NODE_ENVS),
    devAuthEnabled: field.bool,
  },
};
