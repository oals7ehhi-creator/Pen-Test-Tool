/**
 * Runtime scope model (Phase 0 §4). A `ScopeVersion` is an immutable set of typed `allow`/`exclude` entries; the
 * evaluator (evaluate.ts) decides a canonical candidate against it. These are the in-memory shapes the Scope
 * Authority reasons over; the persisted `scope_version` / `scope_entry` tables (slice 3) serialize to the same
 * semantics and bind a canonical `scope_hash`.
 */

import type { Scheme } from './canonicalize.js';

export type EntryClass =
  | 'domain'
  | 'ip'
  | 'cidr'
  | 'port'
  | 'protocol'
  | 'path_prefix'
  | 'api_resource';

interface EntryCommon {
  /** Exclusions always win over any allow (§4.5); exclusions can never be elevated. */
  readonly isExclusion?: boolean;
  /** Deliberately allows a Tier B range or a broad/wildcard entry (§4.6). Never on an exclusion. */
  readonly elevated?: boolean;
}

/** A hostname family. `wildcard` = leftmost-label `*.host`; `includeSubdomains` extends to the apex + subtree. */
export interface DomainEntry extends EntryCommon {
  readonly class: 'domain';
  readonly hostAscii: string;
  readonly wildcard: boolean;
  readonly includeSubdomains: boolean;
}

/** A single literal IP (canonical string form). */
export interface IpEntry extends EntryCommon {
  readonly class: 'ip';
  readonly ip: string;
}

/** An IP range: `base/prefix` of the given version. */
export interface CidrEntry extends EntryCommon {
  readonly class: 'cidr';
  readonly version: 4 | 6;
  readonly base: string;
  readonly prefix: number;
}

/** An inclusive allowed port range. */
export interface PortEntry extends EntryCommon {
  readonly class: 'port';
  readonly low: number;
  readonly high: number;
}

/** An allowed URL scheme. */
export interface ProtocolEntry extends EntryCommon {
  readonly class: 'protocol';
  readonly scheme: Scheme;
}

/** A URL sub-tree on a bound host (§4.3): matches at a segment boundary. */
export interface PathPrefixEntry extends EntryCommon {
  readonly class: 'path_prefix';
  readonly boundHostAscii: string;
  readonly boundHostWildcard: boolean;
  readonly pathPrefix: string;
}

/** Operations from an API spec on a bound host: `operations` are `"METHOD /path"` strings. */
export interface ApiResourceEntry extends EntryCommon {
  readonly class: 'api_resource';
  readonly boundHostAscii: string;
  readonly boundHostWildcard: boolean;
  readonly operations: readonly string[];
}

export type ScopeEntry =
  | DomainEntry
  | IpEntry
  | CidrEntry
  | PortEntry
  | ProtocolEntry
  | PathPrefixEntry
  | ApiResourceEntry;

export interface ScopeVersion {
  readonly entries: readonly ScopeEntry[];
}

/** The default-allowed scheme when no `protocol` allow entry is present (§4.3). */
export const DEFAULT_ALLOWED_SCHEME: Scheme = 'https';
