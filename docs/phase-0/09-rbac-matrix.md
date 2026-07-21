> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

# RBAC Matrix — Definitive Role / Action Authorization

**This is the single authoritative RBAC definition for the platform.** Every other document (FR-002, SI-040, `04-authorization-and-scope-schema.md` §10, `06-acceptance-criteria.md`) refers here rather than restating role permissions. The Phase 1/2 implementation and the Phase 10 authorization test matrix are generated from this table.

## 1. Roles

| Role | Purpose | Trust level |
|---|---|---|
| **Administrator** | Platform administration: users, roles, tenants, tool inventory & version pinning, retention/config policy, global emergency stop, key-management configuration. **Not an engagement approver by default.** | internal-trusted (platform), but SoD-separated from engagement legal approval |
| **Engagement Manager** | Owns engagements; defines scope, windows, rate posture; requests/attests authorization; primary approver for legal/scope actions; per-engagement emergency stop. | internal-trusted (engagement) |
| **Tester** | Executes Passive / Safe Active work; supplies operator auth sessions; requests approvals and intrusive validation. **Cannot approve, attest, or expand scope.** | internal-limited |
| **Reviewer** | Triages findings; validates/false-positives; approver for intrusive validation and a valid second approver for scope/legal actions. **Does not execute checks** (SoD from Tester). | internal-limited |
| **Read-only Auditor** | Read-only visibility into scope, authorization, findings, reports, and the audit trail for engagements they are granted. No mutations, no approvals, no execution. | internal-limited (read-only) |

**Principle:** default-deny. A principal has no capability unless this matrix grants it. Authentication is required for every action (FR-001); MFA for interactive roles (NFR-001).

## 2. Separation-of-duties (SoD) constraints

- **Requester ≠ approver.** The user who requests an approval (or executes the action) can never be one of its approvers.
- **Executing tester is excluded from approving** the validation they will run.
- **No conflicting dual role on one engagement.** A single user may not simultaneously act as Tester and Reviewer, or Tester and Engagement Manager, on the *same* engagement, even if both roles are granted globally. The engagement-scoped role assignment enforces one primary operational role per user per engagement.
- **Administrator is SoD-separated from engagement approval.** Platform power (managing users, tools, keys) is deliberately *not* the same as legal/scope approval authority. An Administrator may serve as an engagement approver only when explicitly assigned an approver role on that engagement, and even then is bound by all SoD rules (never the requester, never the tester) and can never satisfy a dual-control threshold alone.
- **Administrators cannot read the audit chain-signing key** (SI-051) — tamper-evidence stays independent of platform operators.

## 3. Action → role authorization matrix

Legend: **✔** allowed · **—** denied · **A(n)** = valid approver, contributes toward the *n*-approver threshold (subject to SoD) · **R** = read-only.

| Action | Admin | Eng. Manager | Tester | Reviewer | Auditor |
|---|:--:|:--:|:--:|:--:|:--:|
| **Platform / tenant admin** | | | | | |
| Manage users, roles, tenants | ✔ | — | — | — | — |
| Manage tool inventory / version pinning | ✔ | — | — | — | — |
| Configure retention & data-handling policy | ✔ | — | — | — | — |
| Configure key management (not read audit-signing key) | ✔ | — | — | — | — |
| Trigger **global** emergency stop | ✔ | — | — | — | — |
| Clear **global** emergency stop | ✔ | — | — | — | — |
| Read global/tenant audit streams | R | — | — | — | R |
| **Engagement lifecycle** | | | | | |
| Create / configure engagement | ✔ | ✔ | — | — | — |
| Define / edit scope (new scope_version) | — | ✔ | — | — | — |
| Set testing windows / rate posture | — | ✔ | — | — | — |
| Trigger **per-engagement** emergency stop | ✔ | ✔ | ✔ | ✔ | — |
| Clear per-engagement emergency stop | ✔ | ✔ | — | — | — |
| **Authorization (legal gate — dual control)** | | | | | |
| Request authorization attestation | — | ✔ | — | — | — |
| **Approve** authorization attestation | A(2)¹ | A(2)¹ | — | A(2) | — |
| Revoke authorization | ✔ | ✔ | — | — | — |
| **Scope changes (dual control)** | | | | | |
| Request scope expansion | — | ✔ | ✔ | — | — |
| **Approve** scope expansion | A(2)² | A(2) | — | A(2) | — |
| **Approve** restricted-range (Tier B) allow | A(2)² | A(2) | — | A(2) | — |
| **Approve** mode elevation (→ approval_gated) | A(2)² | A(2) | — | A(2) | — |
| **Testing execution** | | | | | |
| Run Passive analysis | — | ✔ | ✔ | — | — |
| Run Safe Active checks | — | ✔ | ✔ | — | — |
| Supply operator auth session | — | ✔ | ✔ | — | — |
| Request intrusive validation | — | ✔ | ✔ | — | — |
| **Approve** intrusive validation | A(1)² | A(1) | — | A(1) | — |
| Execute approved intrusive validation | — | ✔ | ✔ | — | — |
| **Approve** business-logic test template | A(2)² | A(2) | — | A(2) | — |
| **Findings & reporting** | | | | | |
| Triage / set finding status | — | ✔ | ✔ | ✔ | — |
| Mark false-positive / confirm | — | ✔ | — | ✔ | — |
| Accept risk | — | ✔ | — | ✔ | — |
| Generate / export report | — | ✔ | ✔ | ✔ | R |
| Read findings / evidence (redacted) | R | ✔ | ✔ | ✔ | R |
| Read engagement audit stream | R | ✔ | ✔ | ✔ | R |

¹ **Authorization attestation** requires **2** approvers and **at least one must be an Engagement Manager**; the second may be Engagement Manager, Reviewer, or (as break-glass, SoD-bound) Administrator.
² **Administrator as an engagement approver** counts toward a threshold *only* when explicitly assigned an approver role on that engagement, and never as the sole approver of a dual-control action.

## 4. Approval-authority summary (drives `approval_request.approver_roles` and thresholds)

| `request_type` | Threshold (floor) | Eligible approver roles |
|---|:--:|---|
| `authorization_attestation` | 2 | Engagement Manager (≥1), Reviewer, Administrator (break-glass) |
| `scope_expansion` | 2 | Engagement Manager, Reviewer |
| `restricted_range_allow` (Tier B) | 2 | Engagement Manager, Reviewer |
| `mode_elevation` | 2 | Engagement Manager, Reviewer |
| `business_logic_test` | 2 | Engagement Manager, Reviewer |
| `intrusive_validation` | 1 | Engagement Manager, Reviewer |

Thresholds are floors: a tenant/engagement may configure a *higher* `required_approvals`, never lower. `Tester` and `Read-only Auditor` are never eligible approvers. These values are the source for the `approval_request` policy table in `04` §10 and are enforced by SI-047 / SI-018 / SI-040.

## 5. Enforcement & verification

- **Enforcement point.** API authorization middleware checks role + engagement-scoped assignment on every state-changing and data-read endpoint (NFR-004); the approval state machine (`04` §10) independently verifies `approver_role` against this matrix at decision time; RLS scopes data by tenant/engagement (SI-024).
- **No shell capability** is exposed to any role via UI or API (SI-028, FR-003).
- **Test approach (Phase 10 authorization matrix).** For every (action, role) cell, an automated test asserts allow/deny exactly matches this table; negative tests assert privilege escalation, cross-engagement action, requester-self-approval, and single-actor dual-control are all rejected. This matrix file is the fixture the test suite loads, so drift between doc and code fails CI.
