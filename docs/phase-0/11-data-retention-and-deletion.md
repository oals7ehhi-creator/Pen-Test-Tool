> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

# Data Retention, Raw-Output Handling & Secure Deletion

Resolves two Phase 0-review blockers:

- **Blocker 8** — raw-output retention vs minimization: prefer **no persistent raw output by default**; if a quarantine is kept, require encryption, strict access, size limits, short retention, and redaction before any long-term storage.
- **Blocker 9** — reconcile **secure deletion** with **WORM storage, audit retention, and backups** using explicit retention rules and **per-engagement cryptographic erasure**.

## 1. Data classes & retention

Every persisted artifact belongs to exactly one class. Class determines encryption, retention, and how it is deleted.

| Class | Examples | Encryption | Default retention | Delete mechanism |
|---|---|---|---|---|
| **Audit trail** | `audit_event` (all three streams) | At rest (storage/TDE); hash-chained; **contains no secrets/PII/bodies by construction** (SI-045) | Legal/contractual (default 1 yr, configurable 90 d – 7 yr); legal-hold overrides | **Not** crypto-erased with engagement data — it must survive to prove authorized, in-scope operation. Purged only after its own retention expires, preserving chain integrity. |
| **Findings & reports** | normalized findings, rendered reports, minimized evidence | **Per-engagement DEK** (envelope encryption) | `engagement.evidence_retention_days` (default 90) | **Cryptographic erasure** — destroy the engagement DEK (§3). |
| **Minimized evidence** | allowlisted, redacted request/response fields; discriminators for access-control checks (SI-048) | Per-engagement DEK | Same as findings | Cryptographic erasure. |
| **Raw quarantine** (opt-in, off by default) | raw tool stdout/JSON, raw response bodies for debugging | Per-engagement DEK | **Short TTL** (default 72 h; hard cap 7 d) | Auto-purge on TTL **and** covered by DEK destruction. |
| **Operator secrets / sessions** | operator-supplied auth sessions, tool creds | Secret manager, short-lived leases (never in DB rows) | Lease TTL; destroyed at engagement close | Lease revocation + secret-manager delete. |
| **Backups** | encrypted backups of DB + object storage | Backup-level encryption **plus** the per-engagement DEK envelope carried through | Bounded (default 35 d rolling); keys rotated | Covered by cryptographic erasure (§3) — no per-record backup surgery required. |

## 2. Raw-output handling (blocker 8)

- **Default: raw output is not persisted.** External-tool stdout/JSON and raw target response bodies are consumed in memory, mapped to the normalized finding schema, and **only minimized, allowlisted, redacted fields** are stored as evidence (SI-045, SI-057). Findings never carry a raw body or raw tool console text.
- **Optional debug quarantine** (per-engagement `raw_quarantine_enabled`, **off by default**): when an operator explicitly enables it for troubleshooting, raw artifacts may be retained **only** under all of:
  - **Encryption** with the per-engagement DEK;
  - **Strict access** — readable only by Engagement Manager / Reviewer for that engagement (doc 09), audited on access;
  - **Size limits** — per-item and per-engagement caps (oversize is truncated, never fully buffered);
  - **Short retention** — TTL default 72 h, hard cap 7 d, auto-purged;
  - **Redaction before promotion** — nothing leaves quarantine for long-term evidence/report storage without passing the allowlist redaction pipeline first.
- Raw quarantine is **never** included in reports and never leaves the data plane un-redacted.

## 3. Secure deletion via per-engagement cryptographic erasure (blocker 9)

The tension: WORM/object-lock storage and immutable audit rows **cannot be mutated to "delete,"** yet operators and clients require verifiable deletion of engagement data. Resolution: **encrypt engagement data under a per-engagement Data Encryption Key (DEK), and delete by destroying the DEK.**

- **Envelope encryption.** Findings, reports, minimized evidence, and raw quarantine for engagement *E* are encrypted under `DEK_E`. `DEK_E` is wrapped by a KEK in the secret manager and referenced by `engagement.dek_key_ref`.
- **Cryptographic erasure = DEK destruction.** To securely delete engagement *E*, destroy `DEK_E` in the secret manager. Every ciphertext for *E* — in the primary object store, in **WORM/object-lock** copies, and in **backups** — becomes permanently undecryptable **without mutating any immutable store**. WORM protects *integrity during retention*; crypto-erasure provides *deletion at end-of-life*. The two no longer conflict.
- **Backups are covered automatically.** Because backups contain the same DEK-wrapped ciphertext (and never the unwrapped DEK), destroying `DEK_E` renders *E*'s data unreadable in every backup generation too — no per-record backup editing.
- **Audit survives, safely.** The audit trail is **not** encrypted under `DEK_E` and is **not** crypto-erased with engagement data: it must remain to prove the engagement was authorized and in-scope. This is safe because audit events contain **no secrets/PII/bodies** by construction (SI-045) — only redacted, structured metadata. The audit chain-signing key has independent custody (SI-051) and its own retention.
- **A `dek.destroyed` audit event** (engagement stream) records the erasure — who, when, why — before the key is destroyed, so the deletion itself is provable and non-repudiable.
- **Legal hold overrides erasure.** An active legal/contractual hold blocks DEK destruction until released; holds are audited.

## 4. Verifiable deletion & residual-window disclosure

- **Verifiability.** After DEK destruction, a deletion-verification job asserts that no wrapped `DEK_E` remains in the secret manager and that sampled ciphertext for *E* no longer decrypts. The result is recorded (satisfies NFR-017 "verifiable secure deletion with no recoverable residue").
- **Audit anchoring residual window (SI-051).** Between WORM/notary anchors of the audit chain there is a bounded window in which a privileged insider could in principle rewrite-and-re-sign recent audit events. This window is **documented and configurable** (default anchor cadence hourly or every N events, whichever first); shrinking it trades storage/notary cost for tighter tamper-evidence. Anchoring plus a write-only signing service (Admins cannot read the key) keeps the exposure bounded and explicit rather than hidden.
- **Key rotation.** KEKs and the audit-signing key rotate on a schedule (Phase 11); DEKs are per-engagement and destroyed at end-of-life rather than rotated.

## 5. Invariant & requirement mapping

| Concern | Invariant / requirement |
|---|---|
| No persistent raw output by default; quarantine encrypted/access-limited/size-capped/short-TTL/redacted-before-promotion | **SI-057** |
| Per-engagement cryptographic erasure reconciled with WORM/audit/backups; verifiable deletion | **SI-058**, NFR-017 |
| Audit retained (metadata-only, redacted), not crypto-erased with engagement data; anchoring residual window documented | **SI-045**, **SI-051**, **SI-056** |
| Body-size limits & bounded evidence retention | **SI-022**, NFR-016 |
| Storage-layer evidence isolation (per-engagement keys) also underpins cross-tenant isolation | **SI-050** |
