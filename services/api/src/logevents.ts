import { field, NODE_ENVS, SESSION_ERROR_REASONS, type EventRegistry } from '@pentest/shared';
import { ROUTE_TEMPLATES } from './router.js';

/**
 * The API's SI-045 event allowlist. Every field is constrained to a safe shape:
 *  - `request` logs only the HTTP method, the MATCHED route template (from the frozen allowlist — never the raw
 *    URL/path/query), a numeric HTTP status, and an optional SAFE authz `reason` enum. There is deliberately no
 *    field for headers, query, body, cookies, tokens, claims, or key material.
 *  - `api_listening` logs the bind host/port, environment, pinned issuer/audience, and whether the signing key is
 *    ephemeral / the dev minter is on — operator config, never request data or secrets.
 */

/** The safe, closed set of `reason` values loggable on an authz outcome (session reject reasons + `forbidden`). */
const AUTHZ_REASONS: readonly string[] = [...SESSION_ERROR_REASONS, 'forbidden'];

export const API_EVENTS: EventRegistry = {
  request: {
    method: field.httpMethod,
    route: field.oneOf(ROUTE_TEMPLATES),
    status: field.httpStatus,
    reason: field.oneOf(AUTHZ_REASONS),
  },
  api_listening: {
    host: field.token,
    port: field.int(1, 65535),
    env: field.oneOf(NODE_ENVS),
    issuer: field.token,
    audience: field.token,
    keyEphemeral: field.bool,
    devTokenMinter: field.bool,
  },
};
