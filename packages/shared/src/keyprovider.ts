import { randomBytes as nodeRandomBytes, createHash } from 'node:crypto';
import { type NodeEnv } from './config.js';

/**
 * Session signing-key resolution boundary. `SESSION_SIGNING_KEY_REF` is a REFERENCE (a logical name), never key
 * material; the actual material is resolved here from a secret source. Production FAILS CLOSED when the reference
 * cannot be resolved or the resolved material is weak. Non-production may fall back to a process-random EPHEMERAL
 * key so the one-command Compose stack is usable without a secret manager. The reference is safe to log/audit; the
 * key material and any error detail derived from it are never exposed.
 */

/** HMAC-SHA256 keys should be at least the hash output size (32 bytes) of entropy. */
export const MIN_KEY_BYTES = 32;

export class KeyResolutionError extends Error {
  readonly ref: string;
  constructor(ref: string, detail: string) {
    // SECRET-FREE by construction: names the reference and a generic reason, never any key material.
    super(`signing key for reference "${ref}" could not be resolved: ${detail}`);
    this.name = 'KeyResolutionError';
    this.ref = ref;
  }
}

export interface ResolvedSigningKey {
  /** A short, non-secret key id derived from the reference (for token headers / audit), never from material. */
  readonly kid: string;
  /** Raw HS256 key material. */
  readonly key: Uint8Array;
  /** True when this is a process-random development key (impossible in production). */
  readonly ephemeral: boolean;
}

/** Returns a generic, secret-free reason string if the material is unusable, else null. */
function weaknessOf(material: string): string | null {
  if (material.length < MIN_KEY_BYTES) return `must be at least ${MIN_KEY_BYTES} characters`;
  if (new Set(material).size < 16) return 'insufficient key entropy (too few distinct characters)';
  if (
    /insecure|change[-_]?me|example|placeholder|dev[-_]?key|test[-_]?key|dummy|sample/i.test(
      material,
    )
  )
    return 'resolved material looks like a non-production placeholder';
  return null;
}

function keyIdFor(ref: string): string {
  // Non-secret label derived only from the reference (a hash prefix), used as the JWT `kid`.
  return `k_${createHash('sha256').update(ref).digest('hex').slice(0, 12)}`;
}

export interface ResolveOptions {
  /** SESSION_SIGNING_KEY_REF — a reference, never material. */
  readonly ref: string;
  /** Raw material resolved from the secret source (e.g. a secret manager; here, an env var). May be undefined. */
  readonly material: string | undefined;
  readonly nodeEnv: NodeEnv;
  /** Injectable CSPRNG for deterministic tests. */
  readonly randomBytes?: (n: number) => Uint8Array;
}

/**
 * Resolve the signing key from a reference plus resolved material. Fails closed in production; ephemeral in
 * non-production. Never throws a message containing key material.
 */
export function resolveSigningKey(opts: ResolveOptions): ResolvedSigningKey {
  const rand = opts.randomBytes ?? ((n: number) => new Uint8Array(nodeRandomBytes(n)));
  const material = opts.material;

  if (material !== undefined && material !== '') {
    const weak = weaknessOf(material);
    if (weak === null) {
      return { kid: keyIdFor(opts.ref), key: new TextEncoder().encode(material), ephemeral: false };
    }
    if (opts.nodeEnv === 'production') throw new KeyResolutionError(opts.ref, weak);
    // Non-production with weak material → ephemeral fallback (below).
  } else if (opts.nodeEnv === 'production') {
    throw new KeyResolutionError(opts.ref, 'no key material is available for this reference');
  }

  // Non-production ephemeral key: usable, isolated to this process, and never mistaken for a real secret.
  return { kid: 'ephemeral', key: rand(MIN_KEY_BYTES), ephemeral: true };
}

/** The env var that carries resolved signing-key MATERIAL (distinct from the REF, which is only a name). */
export const SIGNING_KEY_MATERIAL_ENV = 'SESSION_SIGNING_KEY_MATERIAL';

/** Convenience resolver that reads material from the environment secret source for a given reference. */
export function loadSigningKey(
  ref: string,
  nodeEnv: NodeEnv,
  env: Record<string, string | undefined> = process.env,
  randomBytes?: (n: number) => Uint8Array,
): ResolvedSigningKey {
  return resolveSigningKey({
    ref,
    material: env[SIGNING_KEY_MATERIAL_ENV],
    nodeEnv,
    ...(randomBytes ? { randomBytes } : {}),
  });
}
