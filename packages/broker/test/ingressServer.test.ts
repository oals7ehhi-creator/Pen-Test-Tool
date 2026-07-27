import { describe, it, expect } from 'vitest';
import type { PeerCertificate } from 'node:tls';
import {
  extractJobIdentity,
  authorizeConnection,
  buildIngressServerOptions,
  IngressAuthError,
  type VerifiedTlsSocket,
} from '../src/index.js';

/**
 * mTLS ingress auth (doc 10 §4.3 / §7.1 step 6). Proves the broker's ingress decision layer: the server options force
 * Node to verify a client cert against the per-job CA; an established connection is authorized only when Node verified
 * it (`authorized`) AND the client cert carries exactly one well-formed per-job identity (a SPIFFE URI SAN binding the
 * connection to tenant/engagement/run/job). Everything unverified / missing / malformed / ambiguous fails closed.
 */

const JOB_URI = 'spiffe://broker.pentest/tenant/t1/engagement/e1/run/r1/job/j1';
const IDENTITY = { tenantId: 't1', engagementId: 'e1', runId: 'r1', jobId: 'j1' };

const certWith = (subjectaltname: string | undefined): PeerCertificate =>
  ({ subjectaltname }) as unknown as PeerCertificate;

const socket = (authorized: boolean, cert: PeerCertificate): VerifiedTlsSocket => ({
  authorized,
  getPeerCertificate: () => cert,
});

describe('extractJobIdentity', () => {
  it('extracts the identity from a SPIFFE URI SAN (ignoring DNS/IP SANs)', () => {
    expect(
      extractJobIdentity(certWith(`URI:${JOB_URI}, DNS:worker.internal, IP:10.0.0.9`)),
    ).toEqual(IDENTITY);
  });

  it('decodes percent-encoded identity segments', () => {
    const uri = 'spiffe://d/tenant/t%201/engagement/e1/run/r1/job/j1';
    expect(extractJobIdentity(certWith(`URI:${uri}`)).tenantId).toBe('t 1');
  });

  it('DENY no_job_identity when there is no URI SAN at all', () => {
    expect(() => extractJobIdentity(certWith('DNS:worker.internal, IP:10.0.0.9'))).toThrow(
      IngressAuthError,
    );
    expect(() => extractJobIdentity(certWith(undefined))).toThrow(/no_job_identity/);
  });

  it('DENY no_job_identity for a non-SPIFFE URI, a wrong path shape, wrong keys, or an empty segment', () => {
    const bad = [
      'URI:https://broker/tenant/t1/engagement/e1/run/r1/job/j1', // not spiffe
      'URI:spiffe://d/tenant/t1/engagement/e1/run/r1', // too few segments
      'URI:spiffe://d/tenant/t1/engagement/e1/run/r1/job/j1/extra/x', // too many
      'URI:spiffe://d/org/t1/engagement/e1/run/r1/job/j1', // wrong key (org)
      'URI:spiffe://d/tenant//engagement/e1/run/r1/job/j1', // empty tenant value (filtered ⇒ too few segments)
      'URI:spiffe://d tenant t1', // malformed URI (URL throws)
      'URI:spiffe://d/tenant/%ZZ/engagement/e1/run/r1/job/j1', // malformed percent-escape (decodeURIComponent throws)
    ];
    for (const san of bad) {
      expect(() => extractJobIdentity(certWith(san)), san).toThrow(/no_job_identity/);
    }
  });

  it('DENY ambiguous_identity when two DISTINCT job URIs are present, but dedupes identical ones', () => {
    const other = 'spiffe://d/tenant/t2/engagement/e1/run/r1/job/j1';
    expect(() => extractJobIdentity(certWith(`URI:${JOB_URI}, URI:${other}`))).toThrow(
      /ambiguous_identity/,
    );
    // two identical URIs collapse to one identity.
    expect(extractJobIdentity(certWith(`URI:${JOB_URI}, URI:${JOB_URI}`))).toEqual(IDENTITY);
  });

  it('DENY ambiguous_identity for two DISTINCT identities that would collide on a naive space-joined key', () => {
    // `x%20y`→tenant `x y` (engagement `z`) vs `x`+`y%20z`→engagement `y z`: a space-joined dedupe key would fold
    // both to "x y z w v" and hide the ambiguity. A collision-free key keeps them distinct ⇒ ambiguous_identity.
    const a = 'spiffe://d/tenant/x%20y/engagement/z/run/w/job/v';
    const b = 'spiffe://d/tenant/x/engagement/y%20z/run/w/job/v';
    expect(() => extractJobIdentity(certWith(`URI:${a}, URI:${b}`))).toThrow(/ambiguous_identity/);
  });

  it('DENY no_job_identity for a SPIFFE URI with an empty trust domain (authority)', () => {
    // `spiffe:///tenant/…` parses with an 8-segment path but an EMPTY authority — not a valid SPIFFE ID, no pin needed.
    expect(() =>
      extractJobIdentity(certWith('URI:spiffe:///tenant/t1/engagement/e1/run/r1/job/j1')),
    ).toThrow(/no_job_identity/);
  });

  it('applies URL dot-segment normalization: traversal that breaks the job shape DENY; `x/..` collapses to the same job', () => {
    // `new URL` normalizes `..` (and its percent-encoded form `%2e%2e`) BEFORE we split — a traversal that pops a real
    // path segment leaves a 6-segment path ⇒ no_job_identity. There is no way to smuggle a different job through it.
    for (const san of [
      'URI:spiffe://d/tenant/../engagement/e1/run/r1/job/j1',
      'URI:spiffe://d/tenant/t1/engagement/e1/run/r1/job/%2e%2e',
    ]) {
      expect(() => extractJobIdentity(certWith(san)), san).toThrow(/no_job_identity/);
    }
    // `…/job/j1/x/..` normalizes back to `…/job/j1` — the SAME legitimate identity, never an escalation.
    expect(
      extractJobIdentity(certWith('URI:spiffe://d/tenant/t1/engagement/e1/run/r1/job/j1/x/..')),
    ).toEqual({ tenantId: 't1', engagementId: 'e1', runId: 'r1', jobId: 'j1' });
  });

  it('pins the SPIFFE trust domain when one is expected', () => {
    expect(extractJobIdentity(certWith(`URI:${JOB_URI}`), 'broker.pentest')).toEqual(IDENTITY);
    expect(() => extractJobIdentity(certWith(`URI:${JOB_URI}`), 'other.domain')).toThrow(
      /wrong_trust_domain/,
    );
  });
});

describe('authorizeConnection', () => {
  it('returns the identity for a Node-verified socket with a valid client cert', () => {
    expect(authorizeConnection(socket(true, certWith(`URI:${JOB_URI}`)))).toEqual(IDENTITY);
  });

  it('DENY not_authorized when Node did not verify the client cert', () => {
    expect(() => authorizeConnection(socket(false, certWith(`URI:${JOB_URI}`)))).toThrow(
      /not_authorized/,
    );
  });

  it('DENY no_client_cert when the peer presented no certificate (empty object)', () => {
    expect(() => authorizeConnection(socket(true, {} as PeerCertificate))).toThrow(
      /no_client_cert/,
    );
  });

  it('propagates the identity-extraction denial (verified socket, but no job SAN)', () => {
    expect(() => authorizeConnection(socket(true, certWith('DNS:worker.internal')))).toThrow(
      /no_job_identity/,
    );
  });

  it('honours the trust-domain pin', () => {
    expect(() =>
      authorizeConnection(socket(true, certWith(`URI:${JOB_URI}`)), { trustDomain: 'nope' }),
    ).toThrow(/wrong_trust_domain/);
  });

  it('the error is an IngressAuthError whose message is the fixed reason code (no leak)', () => {
    const err = (() => {
      try {
        authorizeConnection(socket(false, certWith(`URI:${JOB_URI}`)));
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(IngressAuthError);
    expect((err as IngressAuthError).message).toBe('not_authorized');
    expect((err as IngressAuthError).message).not.toContain('t1');
  });
});

describe('buildIngressServerOptions', () => {
  it('demands + verifies a client cert against the per-job CA over TLS >= 1.2', () => {
    const opts = buildIngressServerOptions({ ca: 'CA', key: 'KEY', cert: 'CERT' });
    expect(opts).toMatchObject({
      ca: 'CA',
      key: 'KEY',
      cert: 'CERT',
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
    });
  });
});
