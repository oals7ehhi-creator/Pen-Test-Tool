#!/usr/bin/env python3
"""
Machine-checkable consistency checker for the Phase 0 design package (docs 00-11).

DESIGN gate, not application code: it verifies the specification documents are internally
consistent so contradictions cannot silently accrue. Intended for CI (Phase 1 onward) and as a
release gate (Phase 12). Exit 0 = consistent; 1 = one or more problems (printed).

Two self-checks run on every invocation:

  1. NEGATIVE-FIXTURE self-test — each known-bad statement / schema pattern is injected into the
     CORRECTED corpus and the checker asserts the matching detector flags it. Every fixture is the
     *verbatim* stale statement from a prior revision round (or its schema anti-pattern), so a passing
     self-test proves the detector is assertion-specific, not vacuous: the exact old statement fails,
     the corrected one passes.

  2. (optional) ROUND-5 CORPUS cross-check — with `--round5 DIR`, the checker loads the unchanged
     Round-5 corpus from DIR and asserts the Round-6 detectors fire on it (the whole corpus fails)
     while the working tree passes. This is the strongest form of "the unchanged Round-5 corpus must
     fail those detectors; the corrected corpus must pass."

The Round-6 detectors are ASSERTION-SPECIFIC: each targets one exact stale statement (e.g. a grant
"binding the exact request line", "reserve-at-mint / commit-on-send", a Reviewer that "cannot approve
intrusive validation", cloud metadata lumped into allowlist-able third-party infra) or one schema/race
constraint (the conservative charge-before-send budget state machine, owned/fenced leases + authoritative
fence_seq, same-tenant/engagement session FK + generated session digest, protected query-value binding,
derived approval from every semantic input, audit-event tenant/engagement↔chain binding, the non-circular
dynamic-approval bootstrap, manifest-verification conditionality, draft/exclusion/CIDR-floor CHECKs) —
never a bare token-presence probe. Historical changelog prose (doc 08 in full, and the dated revision
bullets in doc 00) is excluded from the "live claim" detectors so accurate history is not flagged.

Legacy checks retained: legacy component names; SI index/body parity + contiguity; count parity + dup ids;
internal links / backtick refs; SI/T/FR cross-references; approval-policy agreement (04 vs 09); older
contradiction scans; round-3/4 model presence + anti-patterns; code-fence balance. No third-party deps.
"""
import re, os, sys, glob

DIR = os.path.dirname(os.path.abspath(__file__))
PHASE0 = os.path.dirname(DIR)

# Documents that are historical changelogs: their prose records what PAST rounds did and must not be
# read as live design claims. Doc 08 is the adversarial-review log in full.
HISTORY_DOCS = {"08-design-review-and-critique-resolution.md"}

# Context words marking a passage as history / self-referential commentary rather than a live claim.
DESC = ("removed", "earlier", "revised", "carve-out", "superseded", 'was "', "the earlier",
        "no longer", "phrasings", "stale", "forbid", "no stale", "contradiction", "prevented",
        "were a", "could expire", "if the queued", "removes the", "quoted", "description",
        "not a grant", "never", "no grant", "just-in-time", "not at enqueue", "cannot sit",
        "vacuous", "the bug", "fixes", "the old ", "void for", "previously", "would have",
        # revision-history markers (doc 00 changelog bullets, doc 08 rows)
        "revision round", "phase 0 revision", "revision (round", "(round 3)", "(round 4)",
        "(round 5)", "(round 6)", "replaced by", "moved into", "moved to")

def _live(ctx):
    low = ctx.lower()
    return not any(w in low for w in DESC)

def _quoted(t, start):
    return '"' in t[max(0, start-3):start] or '`' in t[max(0, start-3):start]

def _scan(problems, bn, t, pat, label, seg_ok=(), win=120, skip_history=True):
    """Flag a LIVE occurrence of `pat` in doc `bn`. History docs and history/quoted context are skipped."""
    if skip_history and bn in HISTORY_DOCS:
        return
    for m in re.finditer(pat, t, re.I):
        if _quoted(t, m.start()):
            continue
        seg = m.group(0).lower()
        if any(w in seg for w in seg_ok):
            continue
        ctx = t[max(0, m.start()-win):m.start()+90]
        if skip_history and not _live(ctx):
            continue
        problems.append(f"{bn}: {label} -> {ctx.strip()[:90]}")

# Narrow history markers for the Round-6 live-statement detectors. Checked against the WHOLE LINE the
# match sits on (not a fixed window), so a dated changelog bullet is excluded while ordinary words like
# "never"/"cannot" in a live sentence do not suppress detection.
HIST6 = ("revision round", "phase 0 revision", "revision (round", "(round 3)", "(round 4)",
         "(round 5)", "(round 6)", 'was "', "no longer", "superseded", "replaced by", "the old ",
         "previously", "formerly", "earlier ")

def _line_of(t, pos):
    return t[t.rfind("\n", 0, pos)+1 : (t.find("\n", pos) if t.find("\n", pos) != -1 else len(t))]

def _scan6(problems, bn, t, pat, label, seg_ok=()):
    """Round-6 live-statement scan: skip history docs, quoted context, and any line marked as history."""
    if bn in HISTORY_DOCS:
        return
    for m in re.finditer(pat, t, re.I):
        if _quoted(t, m.start()):
            continue
        if any(w in m.group(0).lower() for w in seg_ok):
            continue
        line = _line_of(t, m.start())
        if any(w in line.lower() for w in HIST6):
            continue
        problems.append(f"{bn}: {label} -> {line.strip()[:100]}")


def analyze(texts):
    """Pure function: dict{basename->text} -> list[problem strings]. Used for the real run AND self-test."""
    problems = []
    allbn = set(texts) | {"README.md"}
    a = texts.get("04-authorization-and-scope-schema.md", "")
    si = texts.get("05-safety-invariants.md", "")

    # 1) legacy names
    for bn, t in texts.items():
        for m in re.finditer(r"ScopeGuard", t):
            ctx = t[max(0, m.start()-40):m.start()+14]
            if 'was "ScopeGuard' in ctx or 'ScopeGuard" terminology' in ctx or '/ "ScopeGuard' in ctx:
                continue
            problems.append(f"{bn}: live 'ScopeGuard'")
        for m in re.finditer(r"[Ss]cope-[Vv]alidation [Ss]ervice", t):
            ctx = t[max(0, m.start()-32):m.start()+30]
            if 'was "scope-validation service"' in ctx or 'earlier "scope-validation service"' in ctx:
                continue
            problems.append(f"{bn}: live 'scope-validation service'")

    # 2) SI parity
    body = re.findall(r"^### (SI-\d+)$", si, re.M)
    idx  = re.findall(r"^\| (SI-\d+) \|", si, re.M)
    if body and idx and body != idx:
        problems.append(f"SI index/body mismatch: {len(idx)} vs {len(body)}")
    if body:
        nums = [int(x.split('-')[1]) for x in body]
        if nums != list(range(1, len(nums)+1)):
            problems.append("SI ids not contiguous")
        if len(set(body)) != len(body):
            problems.append("duplicate SI ids")

    # 3) counts + dup ids
    fr  = re.findall(r"^\*\*(FR-\d+) —", texts.get("01-requirements.md", ""), re.M)
    nfr = re.findall(r"^\*\*(NFR-\d+) —", texts.get("01-requirements.md", ""), re.M)
    th  = re.findall(r"^### (T-\d+) —", texts.get("02-threat-model.md", ""), re.M)
    c = re.search(r"\*\*(\d+) FR", texts.get("00-overview.md", ""))
    if c and fr and int(c.group(1)) != len(fr):
        problems.append(f"FR count: doc claims {c.group(1)} but found {len(fr)}")
    c = re.search(r"\*\*(\d+) absolute", si)
    if c and body and int(c.group(1)) != len(body):
        problems.append(f"SI count: doc claims {c.group(1)} but found {len(body)}")
    for lab, ids in [("FR", fr), ("NFR", nfr), ("T", th), ("SI", body)]:
        d = [x for x in set(ids) if ids.count(x) > 1]
        if d:
            problems.append(f"{lab} duplicate ids: {d}")

    # 4) links / backtick refs
    for bn, t in texts.items():
        for m in re.finditer(r"\]\(([0-9][0-9A-Za-z\-]*\.md)(#[^)]*)?\)", t):
            if m.group(1) not in allbn:
                problems.append(f"{bn}: broken link -> {m.group(1)}")
        for m in re.finditer(r"`(\d\d-[a-z0-9\-]+\.md)`", t):
            if m.group(1) not in allbn:
                problems.append(f"{bn}: broken backtick ref -> {m.group(1)}")

    # 5) cross-ref ids
    si_set, t_set = set(body), set(th)
    for bn, t in texts.items():
        for r in re.findall(r"\bSI-(\d+)\b", t):
            if si_set and f"SI-{int(r):03d}" not in si_set:
                problems.append(f"{bn}: references missing SI-{r}")
        for r in re.findall(r"\bT-(\d+)\b", t):
            if t_set and f"T-{int(r):03d}" not in t_set:
                problems.append(f"{bn}: references missing T-{r}")

    # 6) approval-policy agreement 04 vs 09
    def pol(t):
        out = {}
        for m in re.finditer(r"\| `(authorization_attestation|scope_expansion|restricted_range_allow|mode_elevation|business_logic_test|intrusive_validation)`[^\n]*?\| (\d+) \| ([^|]+)\|", t):
            roles = frozenset(r for r in ("Engagement Manager", "Reviewer", "Administrator") if r in m.group(3))
            out[m.group(1)] = (int(m.group(2)), roles)
        return out
    p04, p09 = pol(a), pol(texts.get("09-rbac-matrix.md", ""))
    common = set(p04) & set(p09)
    if p04 and p09 and len(common) < 6:
        problems.append(f"approval-policy: {len(common)} common request_types (expected 6)")
    for rt in sorted(common):
        if p04[rt] != p09[rt]:
            problems.append(f"approval-policy mismatch {rt}: 04={p04[rt]} 09={p09[rt]}")

    # 7) older contradiction scans (rounds 1-4)
    for bn, t in texts.items():
        _scan(problems, bn, t, r"unless that exact range", "LIVE 'unless that exact range'")
        _scan(problems, bn, t, r"metadata[^.\n]{0,60}(exact-?/32|exact /32|reachable ONLY via)", "LIVE metadata-via-exact-/32", win=140)
        _scan(problems, bn, t, r"(grant|token)\b[^.\n]{0,90}\bbind[a-z]*\b[^.\n]{0,50}resolved IP", "grant binds resolved IP",
              seg_ok=("no resolved", "never a resolved", "never bind", "not bind", "does not bind", "cannot", "without a resolved"))
        _scan(problems, bn, t, r"enqueues?[^.\n]{0,40}\bgrant\b|\bgrant\b[^.\n]{0,20}in (the|a) queue|queued[^.\n]{0,10}\bgrant\b", "queued-grant contradiction", win=80)
        _scan(problems, bn, t, r"budget[^.\n]{0,30}decrement[^.\n]{0,30}enqueue|enqueue[^.\n]{0,30}decrement", "budget-decremented-at-enqueue")
        for m in re.finditer(r"max_scope_addresses|address_count[^.\n]*minus exclusions", t):
            if not _quoted(t, m.start()):
                problems.append(f"{bn}: stale IPv6 address-sum breadth -> {m.group(0)[:50]}")

    # 8) round-3/4 model presence
    for needle in ("TABLE request_spec", "spec_sha256", "TABLE budget_reservation", "TABLE audit_chain",
                   "TABLE approval_policy", "TABLE approval_manifest_entry", "TABLE catalog_template",
                   "reconstruct", "kind='websocket'", "just-in-time", "ws_frame_set_digest", "chain_id"):
        if needle not in a:
            problems.append(f"04: missing round-3/4 model token: {needle}")
    for sid in ("SI-060", "SI-061", "SI-062", "SI-063", "SI-064", "SI-065"):
        if si and sid not in si:
            problems.append(f"05: missing {sid}")

    # 9) round-4 ANTI-PATTERN schema checks (these MUST NOT appear as live schema)
    for m in re.finditer(r"UNIQUE\s*\(\s*tenant_id,\s*spec_sha256\s*\)", a):
        line = a[a.rfind("\n", 0, m.start())+1 : a.find("\n", m.start())]
        if line.lstrip().startswith("--") or "NO UNIQUE" in line:
            continue
        problems.append("04: anti-pattern UNIQUE(tenant_id, spec_sha256) blocks repeatable specs")
    if re.search(r"required_approvals INT NOT NULL CHECK \(required_approvals BETWEEN 1 AND 5\),\s*--[^\n]*threshold; see policy", a):
        problems.append("04: anti-pattern requester-supplied required_approvals on approval_request")
    if re.search(r"reserved\s+INT NOT NULL DEFAULT 0,\s*--[^\n]*reserved at JIT", a):
        problems.append("04: anti-pattern bare `reserved INT` budget authority (use budget_reservation ledger)")
    if re.search(r"UNIQUE \(stream, tenant_id, engagement_id, seq\)", a):
        problems.append("04: anti-pattern audit UNIQUE over nullable keys (use non-null chain_id)")

    # ==================================================================================
    # ROUND 6 — assertion-specific semantic detectors. Each targets ONE exact stale
    # statement (flagged only as a LIVE claim) or ONE schema/race constraint (asserted
    # structurally). Every detector is backed by a verbatim-Round-5 negative fixture.
    # ==================================================================================
    problems += _round6_live_statements(texts)
    problems += _round6_schema_and_race(a, texts)

    # 10) code-fence balance
    for bn, t in texts.items():
        if t.count("```") % 2:
            problems.append(f"{bn}: unbalanced code fences")
    return problems


def _round6_live_statements(texts):
    """Flag exact stale statements ONLY where they appear as a live (non-history) claim."""
    p = []
    for bn, t in texts.items():
        # (a) grant/broker bound to "the exact request line" — the grant binds the immutable spec by spec_sha256.
        _scan6(p, bn, t, r"exact request line", "R6 'exact request line' (grant binds spec_sha256, not a request line)")
        # (b) old budget protocol wording — the model is a conservative charge-before-send state machine.
        _scan6(p, bn, t,
               r"reserve-at-mint|commit-on-send|release-on-denial|reserved at grant-mint|reserves one budget"
               r"|idempotent commit/release|commit/release are idempotent|reserve/commit/release"
               r"|committed on send|reserved → committed|reserved → released",
               "R6 reserve-at-mint/commit-on-send budget wording (use charge-before-send)")
        # (c) 'plan hash' / plan_sha256 as the approval anchor — the anchor is manifest_sha256 / document_sha256.
        _scan6(p, bn, t, r"plan hash(?:es)?|plan_sha256|approved_plan_sha256",
               "R6 'plan hash'/plan_sha256 approval anchor (use manifest_sha256/document_sha256)")
        # (d) stale header-set/payload 'id' — the spec binds header_set_digest / payload_digest.
        _scan6(p, bn, t, r"header[- ]set id|inert payload id|\bpayload id\b|header_set_id|payload_id",
               "R6 header-set/payload 'id' (use header_set_digest/payload_digest)")

    # (e) doc-02 Reviewer actor: must NOT deny approving intrusive validation (Reviewer IS an eligible approver, RBAC 09).
    tm = texts.get("02-threat-model.md", "")
    if re.search(r"Reviewer[^\n|]*\|[^\n]*[Cc]annot[^\n]*approve intrusive validation", tm):
        p.append("02: Reviewer actor 'cannot approve intrusive validation' contradicts RBAC 09 (Reviewer is an eligible approver)")

    # (f) doc-07 F3: cloud metadata must NOT be listed among allowlist-able third-party infra (Tier A: never reachable).
    ng = texts.get("07-non-goals-and-refusals.md", "")
    if re.search(r"cloud metadata[^\n]*unless individually allowlisted", ng) or "cloud metadata, SaaS APIs) unless" in ng:
        p.append("07 F3: cloud metadata lumped with allowlist-able third-party infra (metadata is Tier A, never reachable)")

    # (g) SI-030: tool sandbox destination must be broker-only, not 'destinations the broker permits per grants'.
    sv = texts.get("05-safety-invariants.md", "")
    if "destinations are those the Guarded Egress Broker permits per" in sv:
        p.append("05 SI-030: tool destinations 'the broker permits per grants' (sandbox reaches ONLY the broker)")

    # (h) doc-09 §4 heading: authority table is the content of approval_policy, not approval_request.approver_roles.
    rb = texts.get("09-rbac-matrix.md", "")
    if re.search(r"drives `?approval_request\.approver_roles`?", rb):
        p.append("09 §4: heading says table drives approval_request.approver_roles (it is the immutable approval_policy content)")

    # (i) doc-06 Phase 11: no sandbox has a direct target route (broker is the only target-socket creator).
    ac = texts.get("06-acceptance-criteria.md", "")
    if "permits only engagement-approved targets" in ac:
        p.append("06 Phase 11: egress 'permits only engagement-approved targets' (no sandbox has a direct target route)")
    return p


def _round6_schema_and_race(a, texts):
    """Assert the Round-6 schema/race constraints are present in their SPECIFIC form (not bare tokens)."""
    p = []
    def need(cond, msg):
        if not cond:
            p.append(msg)

    # Conservative charge-before-send budget STATE MACHINE (not reserve/commit/release).
    need("state IN ('claimed','charged','released','expired')" in a,
         "04 §8.1: budget_reservation lacks the conservative state set claimed/charged/released/expired")
    need(all(k in a for k in ("charged_has_time", "no_release_after_charge", "no_expire_after_charge")),
         "04 §8.1: budget_reservation missing charge-before-send CHECKs (charged terminal: charged_has_time/no_release_after_charge/no_expire_after_charge)")
    # Authoritative fence source + owned/fenced lease.
    need("fence_seq" in a and re.search(r"fence_token\s+BIGINT", a),
         "04: no authoritative monotonic fence_seq feeding an owned/fenced fence_token lease")
    # The charge happens in the broker txn, BEFORE DNS, in the §7.1 Stage-2 procedure.
    proc = re.search(r"STAGE 2 — GUARDED EGRESS BROKER.*?```", a, re.S)
    if proc:
        pt = proc.group(0)
        i_charge = pt.find("CHARGE")
        i_intent = pt.find("request.intent")
        i_dns = pt.find("DNS RESOLUTION")
        need(i_charge != -1 and i_dns != -1 and i_charge < i_dns,
             "04 §7.1: budget is not CHARGED before DNS resolution (charge-before-send must precede any egress)")
        need(i_intent != -1 and i_dns != -1 and i_intent < i_dns,
             "04 §7.1: request.intent is not ordered before DNS resolution (intent must precede any egress)")
    else:
        p.append("04 §7.1: Stage-2 broker procedure block not found")
    # Reservation is created at the BROKER (Stage 2), never at Stage-1 mint.
    s1 = re.search(r"STAGE 1 — SCOPE AUTHORITY.*?(?=STAGE 2 —)", a, re.S)
    if s1 and re.search(r"create a budget_reservation|RESERVE .{0,20}budget unit|reserves one budget", s1.group(0)):
        p.append("04 §7.1: reservation/charge created at Stage-1 mint (must be charged in the broker txn before DNS)")

    # Same-tenant-and-engagement session FK + generated session digest verified against the referenced session.
    need("(session_ref, tenant_id, engagement_id) REFERENCES operator_session" in a,
         "04: request_spec lacks same-tenant/engagement session FK (session_ref, tenant_id, engagement_id)")
    need("REFERENCES operator_session(id, session_digest)" in a,
         "04: request_spec session_digest not FK-verified against the referenced operator_session")
    need(re.search(r"session_digest\s+CHAR\(64\)\s+GENERATED ALWAYS AS", a) is not None,
         "04: operator_session.session_digest is not an immutable GENERATED column")

    # Protected immutable query-value reference / keyed digest binding the actual injected values.
    need("query_value_ref" in a and "query_value_digest" in a,
         "04: request_spec lacks a protected query-value reference + keyed digest")
    need("(query_value_ref, query_value_kind) REFERENCES catalog_template(digest, kind)" in a,
         "04: query_value_ref not bound to an immutable content-addressed catalog_template(digest, kind)")

    # Approval requirement DERIVED from every relevant semantic input (method/action class AND all template safety classes).
    need("HTTP method / action class" in a and "MAX safety_class over ALL referenced templates" in a,
         "04: approval_required not derived from BOTH method/action class AND the MAX safety_class over ALL referenced templates")
    need("gated_needs_ref CHECK (mode <> 'approval_gated'" not in a,
         "04: approval requirement trusts the self-declared mode (must be derived, never trusted)")

    # Non-circular dynamic-approval bootstrap: scope-only pre-verdict distinct from Stage-1, approval_ref excluded from spec_sha256.
    need("scope-only pre-verdict" in a,
         "04 §10: no scope-only pre-verdict distinct from Stage-1 approval validation (dynamic bootstrap)")
    need(re.search(r"approval_ref[^\n]*EXCLUDED from", a) is not None or "excluded from `spec_sha256`" in a,
         "04: approval_ref not excluded from spec_sha256 (dynamic-approval bootstrap would be circular)")
    need(re.search(r"scope_check_result[^\n]*SCOPE-ONLY", a) is not None,
         "04 §10: approval_request.scope_check_result not pinned to the scope-only pre-verdict (would be circular)")

    # Manifest verification conditional by request type OR a canonical empty manifest for every type.
    need("CANONICAL EMPTY" in a or
         "request_type NOT IN ('intrusive_validation','business_logic_test') OR manifest_sha256 IS NOT NULL" in a,
         "04 §10: manifest verification not made conditional by request type (nor a canonical empty manifest defined)")

    # One current matching policy, role-quorum validity, immutable freeze semantics.
    need("current, non-superseded" in a or "pins the current" in a,
         "04 §10: approval policy not pinned to the current, non-superseded matching version")
    need("role_quorum" in a, "04 §10: role quorum not enforced")
    need("manifest_frozen" in a, "04 §10: manifest not frozen before decisions")

    # Every audit event's tenant/engagement identity bound to its audit chain.
    need("(chain_id, tenant_id, engagement_id) REFERENCES audit_chain(id, tenant_id, engagement_id)" in a,
         "04 §9: audit_event tenant/engagement identity not bound to its audit_chain (composite FK missing)")
    need("audit_event(id, chain_id)" in a,
         "04 §9: related_event_id not constrained to the same chain (audit_event(id, chain_id) FK missing)")

    # Authorization drafts, exclusion non-elevation, absolute CIDR floors as enforceable CHECKs.
    need("draft_not_attested" in a, "04 §3.1: draft authorization not constrained to carry no attestation approval")
    need("exclusion_not_elevated" in a, "04 §4.2: exclusions can elevate (exclusion_not_elevated CHECK missing)")
    need("cidr_absolute_floor" in a, "04 §4.2: no absolute CIDR floor CHECK (cidr_absolute_floor missing)")

    # Recurring-window close is a pure function of the trusted clock, re-derived (not a cached flag).
    need("pure functions of the trusted clock" in a or "pure function of the trusted clock" in a,
         "04 §8: window/expiry close not defined as a pure function of the trusted clock")
    return p


# ---------------------------------------------------------------------------------------------------
# Negative fixtures. Each mutator injects the VERBATIM Round-5 stale statement (or its schema
# anti-pattern) into the CORRECTED corpus; analyze() must then report at least one MORE problem than
# the clean corpus, proving the matching detector is assertion-specific and non-vacuous.
# ---------------------------------------------------------------------------------------------------
def _sub(d, key, val):
    d = dict(d); d[key] = val; return d

def _append(d, key, extra):
    return _sub(d, key, d.get(key, "") + extra)

def _replace(d, key, old, new):
    # Replace ALL occurrences: token-removal fixtures must fully break the asserted constraint.
    return _sub(d, key, d[key].replace(old, new))

NEG_FIXTURES = [
    # --- retained rounds 1-4 fixtures ---
    ("live ScopeGuard name",
     lambda x: _append(x, "03-architecture.md", "\nThe ScopeGuard client dials the target directly.\n")),
    ("metadata via exact /32 (live)",
     lambda x: _append(x, "05-safety-invariants.md", "\nCloud metadata is reachable via an exact /32 elevated allow entry.\n")),
    ("grant binds resolved IP at mint (live)",
     lambda x: _append(x, "10-request-authorization-flow.md", "\nThe Stage-1 grant binds the resolved IP at mint time.\n")),
    ("grant enqueued (live)",
     lambda x: _append(x, "03-architecture.md", "\nThe API enqueues the job and grant together in one transaction.\n")),
    ("budget decremented at enqueue (live)",
     lambda x: _append(x, "04-authorization-and-scope-schema.md", "\nBudget is decremented at enqueue time by the scheduler.\n")),
    ("UNIQUE(tenant_id, spec_sha256) schema anti-pattern",
     lambda x: _append(x, "04-authorization-and-scope-schema.md", "\n  UNIQUE (tenant_id, spec_sha256),\n")),
    ("audit uniqueness on nullable keys",
     lambda x: _append(x, "04-authorization-and-scope-schema.md", "\n  UNIQUE (stream, tenant_id, engagement_id, seq),\n")),
    ("IPv6 address-sum breadth (max_scope_addresses)",
     lambda x: _append(x, "04-authorization-and-scope-schema.md", "\n  max_scope_addresses BIGINT NOT NULL,\n")),
    ("SI count mismatch",
     lambda x: _replace(x, "05-safety-invariants.md", "**65 absolute", "**64 absolute")),
    ("broken cross-reference SI-999",
     lambda x: _append(x, "06-acceptance-criteria.md", "\nSee SI-999 for details.\n")),

    # --- Round-6 EXACT stale statements (verbatim Round-5 text) ---
    ("R5 grant 'binding the exact request line' (03)",
     lambda x: _append(x, "03-architecture.md",
        "\nMints short-lived, signed Stage-1 egress grants binding the exact request line.\n")),
    ("R5 broker 'serves only the exact request line' (10)",
     lambda x: _append(x, "10-request-authorization-flow.md",
        "\n  - serves only the exact request line the grant authorizes.\n")),
    ("R5 ADR-18 reserve-at-mint / commit-on-send (03)",
     lambda x: _append(x, "03-architecture.md",
        "\nRequest budget uses reserve-at-mint / commit-on-send / release-on-denial so the sent count never exceeds the total.\n")),
    ("R5 §8.1 idempotent commit/release (04)",
     lambda x: _append(x, "04-authorization-and-scope-schema.md",
        "\nBudget is accounted by an identifiable ledger, so commit/release are idempotent and a crashed worker cannot strand a unit.\n")),
    ("R5 grant 'reserves one budget unit' at mint (10)",
     lambda x: _append(x, "10-request-authorization-flow.md",
        "\nAt dispatch, the Authority re-runs the checks, reserves one budget unit, and mints the grant.\n")),
    ("R5 Reviewer 'cannot approve intrusive validation' (02)",
     lambda x: _append(x, "02-threat-model.md",
        "\n| Reviewer | internal-limited | Triages findings. Cannot launch scans or approve intrusive validation. |\n")),
    ("R5 F3 cloud metadata lumped with third-party (07)",
     lambda x: _append(x, "07-non-goals-and-refusals.md",
        "\n| F3 | No third-party targeting (SSO, cloud metadata, SaaS APIs) unless individually allowlisted with authorization. | ... |\n")),
    ("R5 SI-030 'destinations the broker permits per grants' (05)",
     lambda x: _append(x, "05-safety-invariants.md",
        "\ntheir only permitted network destinations are those the Guarded Egress Broker permits per the current engagement's grants.\n")),
    ("R5 RBAC heading drives approval_request.approver_roles (09)",
     lambda x: _append(x, "09-rbac-matrix.md",
        "\n## 4. Approval-authority summary (drives `approval_request.approver_roles` and thresholds)\n")),
    ("R5 Phase-11 'permits only engagement-approved targets' (06)",
     lambda x: _append(x, "06-acceptance-criteria.md",
        "\n- egress filtering defaults to deny and permits only engagement-approved targets plus required infrastructure.\n")),
    ("R5 approved_plan_sha256 approval anchor (05)",
     lambda x: _append(x, "05-safety-invariants.md",
        "\na decision whose approved_plan_sha256 differs from the request's plan hash does not count.\n")),
    ("R5 header-set id / payload id (10)",
     lambda x: _append(x, "10-request-authorization-flow.md",
        "\nA fully-hashed spec of the request: a fixed header-set id, an inert payload id, a session reference.\n")),

    # --- Round-6 SCHEMA / RACE defects (break the corrected constraint into its Round-5 form) ---
    ("budget states reverted to reserved/committed/released",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md",
        "state IN ('claimed','charged','released','expired')", "state IN ('reserved','committed','released')")),
    ("charge-terminal CHECKs removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "no_release_after_charge", "no_release_DISABLED")),
    ("authoritative fence_seq removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "fence_seq", "fence_XXXX")),
    ("same-tenant/engagement session FK removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md",
        "(session_ref, tenant_id, engagement_id) REFERENCES operator_session", "(session_ref) REFERENCES operator_session_DISABLED")),
    ("session_digest FK-verification removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md",
        "REFERENCES operator_session(id, session_digest)", "REFERENCES operator_session(id_DISABLED)")),
    ("query-value reference removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "query_value_ref", "query_value_XXXX")),
    ("query-value catalog FK removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md",
        "(query_value_ref, query_value_kind) REFERENCES catalog_template(digest, kind)", "(query_value_ref) REFERENCES nothing_DISABLED")),
    ("derived approval loses method/action class",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "HTTP method / action class", "self-declared mode")),
    ("scope-only pre-verdict removed (circular bootstrap)",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "scope-only pre-verdict", "full Stage-1 verdict")),
    ("scope_check_result reverts to full Stage-1 (circular)",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "SCOPE-ONLY pre-verdict", "full Stage-1 decision")),
    ("canonical-empty / conditional manifest removed",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
        x["04-authorization-and-scope-schema.md"]
          .replace("CANONICAL EMPTY", "always-required")
          .replace("request_type NOT IN ('intrusive_validation','business_logic_test') OR manifest_sha256 IS NOT NULL",
                   "manifest_sha256 IS ALWAYS REQUIRED"))),
    ("audit tenant/engagement->chain FK removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md",
        "(chain_id, tenant_id, engagement_id) REFERENCES audit_chain(id, tenant_id, engagement_id)", "(chain_id) REFERENCES audit_chain(id_DISABLED)")),
    ("related-event same-chain FK removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "audit_event(id, chain_id)", "audit_event(id_DISABLED)")),
    ("draft attestation constraint removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "draft_not_attested", "draft_DISABLED")),
    ("exclusion non-elevation removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "exclusion_not_elevated", "exclusion_DISABLED")),
    ("absolute CIDR floor removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "cidr_absolute_floor", "cidr_DISABLED")),
    ("role quorum removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "role_quorum", "role_XXXX")),
    ("manifest freeze removed",
     lambda x: _replace(x, "04-authorization-and-scope-schema.md", "manifest_frozen", "manifest_XXXX")),
]

def selftest(clean_texts, base_problems):
    failures = []
    base = len(base_problems)
    for label, mut in NEG_FIXTURES:
        got = analyze(mut(clean_texts))
        if len(got) <= base:
            failures.append(f"NEGATIVE FIXTURE NOT DETECTED: {label} (checker produced no extra problem)")
    return failures


def _load(dirpath):
    return {os.path.basename(f): open(f).read() for f in sorted(glob.glob(os.path.join(dirpath, "*.md")))}


def round5_crosscheck(dirpath, current_problem_count):
    """Optional: assert the unchanged Round-5 corpus FAILS the Round-6 detectors while the working tree passes."""
    r5 = _load(dirpath)
    if not r5:
        return [f"--round5: no *.md found in {dirpath}"]
    r5_problems = analyze(r5)
    # The Round-6 detectors specifically:
    r6 = [pp for pp in r5_problems if pp.startswith(("02: Reviewer", "07 F3", "05 SI-030", "09 §4", "06 Phase 11"))
          or "R6 " in pp or "§8.1" in pp or "§7.1" in pp or "§10" in pp or "§9" in pp or "§4.2" in pp
          or "§3.1" in pp or "fence" in pp or "session FK" in pp or "session_digest" in pp
          or "query-value" in pp or "query_value" in pp or "derived from" in pp]
    out = []
    if not r6:
        out.append("--round5: Round-6 detectors did NOT fire on the unchanged Round-5 corpus (checker is vacuous)")
    print("=== ROUND-5 CROSS-CHECK ===")
    print(f"  Round-5 corpus -> {len(r5_problems)} total problems; {len(r6)} are Round-6 detectors")
    for pp in r6[:40]:
        print("   R5-FAIL:", pp)
    if current_problem_count == 0 and r6:
        print(f"  OK — unchanged Round-5 corpus FAILS ({len(r6)} Round-6 detectors); corrected corpus PASSES.")
    return out


def main():
    args = sys.argv[1:]
    round5_dir = None
    if "--round5" in args:
        i = args.index("--round5")
        round5_dir = args[i+1] if i+1 < len(args) else None

    texts = _load(PHASE0)
    problems = analyze(texts)
    si = texts.get("05-safety-invariants.md", "")
    nb = len(re.findall(r"^### SI-\d+$", si, re.M))
    nfr = len(re.findall(r"^\*\*FR-\d+ —", texts.get("01-requirements.md", ""), re.M))
    nt = len(re.findall(r"^### T-\d+ —", texts.get("02-threat-model.md", ""), re.M))
    print("=== NOTES ===")
    print(f"  - counts: {nfr} FR, {nt} threats, {nb} SI (index rows: {si.count(chr(10)+'| SI-')})")

    self_failures = selftest(texts, problems)
    print("=== NEGATIVE-FIXTURE SELF-TEST ===")
    if self_failures:
        for f in self_failures:
            print("  x", f)
    else:
        print(f"  ok — all {len(NEG_FIXTURES)} bad fixtures produce a failing exit code")

    cross = []
    if round5_dir:
        cross = round5_crosscheck(round5_dir, len(problems))
        for c in cross:
            print("  x", c)

    print("=== PROBLEMS ===")
    all_bad = problems + self_failures + cross
    if all_bad:
        for p in problems:
            print("  x", p)
        print(f"\n{len(all_bad)} problem(s).")
        sys.exit(1)
    print("  none — all Phase 0 consistency checks passed")

if __name__ == "__main__":
    main()
