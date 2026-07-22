#!/usr/bin/env python3
"""
Machine-checkable consistency checker for the Phase 0 design package (docs 00-11).

DESIGN gate, not application code: it verifies the specification documents are internally
consistent so contradictions cannot silently accrue. Intended for CI (Phase 1 onward) and as a
release gate (Phase 12). Exit 0 = consistent; 1 = one or more problems (printed).

It also runs a NEGATIVE-FIXTURE self-test (`--selftest`, and always on a normal run): each known-bad
statement / schema pattern is injected into the corpus and the checker asserts the detector flags it.
If any bad fixture does NOT produce a problem, the checker is vacuous and exits non-zero. No third-party deps.

Checks (see analyze()): legacy component names; SI index/body parity + contiguity; count parity + dup ids;
internal links / backtick refs; SI/T/FR cross-references; approval-policy agreement (04 vs 09); contradiction
scans (metadata-via-exact-/32, grant-binds-IP-at-mint, grant-in-queue, budget-at-enqueue, IPv6 address-sum);
round-3/4 model presence; round-4 anti-pattern schema checks (UNIQUE spec_sha256, requester policy fields,
bare reserved-counter budget authority, nullable audit uniqueness, intent-after-DNS ordering, WS catalog);
code-fence balance.
"""
import re, os, sys, glob, copy

DIR = os.path.dirname(os.path.abspath(__file__))
PHASE0 = os.path.dirname(DIR)

DESC = ("removed", "earlier", "revised", "carve-out", "superseded", 'was "', "the earlier",
        "no longer", "phrasings", "stale", "forbid", "no stale", "contradiction", "prevented",
        "were a", "could expire", "if the queued", "removes the", "quoted", "description",
        "not a grant", "never", "no grant", "just-in-time", "not at enqueue", "cannot sit",
        "vacuous", "the bug", "fixes", "the old ", "void for", "previously", "would have")

def _live(ctx):
    low = ctx.lower()
    return not any(w in low for w in DESC)

def _quoted(t, start):
    return '"' in t[max(0, start-3):start] or '`' in t[max(0, start-3):start]

def _scan(problems, bn, t, pat, label, seg_ok=(), win=120):
    for m in re.finditer(pat, t, re.I):
        if _quoted(t, m.start()):
            continue
        seg = m.group(0).lower()
        if any(w in seg for w in seg_ok):
            continue
        if _live(t[max(0, m.start()-win):m.start()+90]):
            problems.append(f"{bn}: {label} -> {t[max(0,m.start()-win):m.start()+90].strip()[:90]}")

def analyze(texts):
    """Pure function: dict{basename->text} -> list[problem strings]. Used for the real run AND self-test."""
    problems = []
    allbn = set(texts) | {"README.md"}

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
    si = texts.get("05-safety-invariants.md", "")
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
    p04, p09 = pol(texts.get("04-authorization-and-scope-schema.md", "")), pol(texts.get("09-rbac-matrix.md", ""))
    common = set(p04) & set(p09)
    if p04 and p09 and len(common) < 6:
        problems.append(f"approval-policy: {len(common)} common request_types (expected 6)")
    for rt in sorted(common):
        if p04[rt] != p09[rt]:
            problems.append(f"approval-policy mismatch {rt}: 04={p04[rt]} 09={p09[rt]}")

    # 7) contradiction scans
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
    a = texts.get("04-authorization-and-scope-schema.md", "")
    for needle in ("TABLE request_spec", "spec_sha256", "TABLE budget_reservation", "TABLE audit_chain",
                   "TABLE approval_policy", "TABLE approval_manifest_entry", "TABLE catalog_template",
                   "reconstruct", "kind='websocket'", "just-in-time", "ws_frame_set_digest", "chain_id"):
        if needle not in a:
            problems.append(f"04: missing round-3/4 model token: {needle}")
    for sid in ("SI-060", "SI-061", "SI-062", "SI-063", "SI-064", "SI-065"):
        if si and sid not in si:
            problems.append(f"05: missing {sid}")

    # 9) round-4 ANTI-PATTERN schema checks (these MUST NOT appear as live schema)
    #    UNIQUE(tenant_id, spec_sha256) would block legitimate repeats across jobs/runs.
    #    Skip SQL-comment lines (start with --) and explicit negations ("NO UNIQUE ...").
    for m in re.finditer(r"UNIQUE\s*\(\s*tenant_id,\s*spec_sha256\s*\)", a):
        line = a[a.rfind("\n", 0, m.start())+1 : a.find("\n", m.start())]
        if line.lstrip().startswith("--") or "NO UNIQUE" in line:
            continue
        problems.append("04: anti-pattern UNIQUE(tenant_id, spec_sha256) blocks repeatable specs")
    #    requester-supplied threshold/roles on approval_request (must live in approval_policy)
    if re.search(r"required_approvals INT NOT NULL CHECK \(required_approvals BETWEEN 1 AND 5\),\s*--[^\n]*threshold; see policy", a):
        problems.append("04: anti-pattern requester-supplied required_approvals on approval_request")
    #    bare reserved-INT budget authority in the runtime counter (must be the ledger)
    if re.search(r"reserved\s+INT NOT NULL DEFAULT 0,\s*--[^\n]*reserved at JIT", a):
        problems.append("04: anti-pattern bare `reserved INT` budget authority (use budget_reservation ledger)")
    #    audit uniqueness on nullable (stream,tenant,engagement,seq) without chain_id
    if re.search(r"UNIQUE \(stream, tenant_id, engagement_id, seq\)", a):
        problems.append("04: anti-pattern audit UNIQUE over nullable keys (use non-null chain_id)")
    #    §7.1 ordering: request.intent must come BEFORE 'RESOLUTION'/'RESOLVE DNS' in the Stage-2 procedure
    proc = re.search(r"STAGE 2 — GUARDED EGRESS BROKER.*?```", a, re.S)
    if proc:
        pt = proc.group(0)
        i_intent = pt.find("request.intent")
        i_dns = pt.find("DNS RESOLUTION")
        if i_intent == -1 or i_dns == -1 or i_intent > i_dns:
            problems.append("04 §7.1: request.intent is NOT ordered before DNS resolution (intent must precede any egress)")
    #    WebSocket must be catalog-controlled
    if "ws_frame_set" not in a or "frame gate" not in a and "outside that set" not in a:
        problems.append("04: WebSocket outbound frames not shown as catalog-controlled")

    # --- round 5: exact stale statements MUST be fixed (each is a negative-fixture-backed detector) ---
    # Reservation must be created in the broker (Stage 2) transaction, NOT at Stage-1 mint.
    s1 = re.search(r"STAGE 1 — SCOPE AUTHORITY.*?(?=STAGE 2 —)", a, re.S)
    if s1 and re.search(r"create a budget_reservation|RESERVE .{0,20}budget unit", s1.group(0)):
        problems.append("04 §7.1: reservation created at Stage-1/mint (must be created in the broker txn before DNS)")
    # Required round-5 tokens in 04 (their absence is the stale state)
    for tok, why in [
        ("session_digest", "non-secret session/account/version digest not bound into spec"),
        ("query_value_digest", "protected query-value representation not bound into spec"),
        ("kind_scheme", "bidirectional kind<->scheme constraint missing"),
        ("catalog_template(digest, kind)", "catalog kind not enforced on digest FKs"),
        ("audit_event(id, chain_id)", "related_event_id not constrained to same chain"),
        ("GENERATED ALWAYS AS", "audit chain_key not generated per scope"),
        ("fence_token", "reservation lease not owned/fenced"),
        ("FOR UPDATE", "atomic budget lock missing"),
        ("manifest_frozen", "manifest not frozen before decisions"),
        ("role_quorum", "role quorum not enforced"),
        ("start_at < end_at", "window ordering constraint missing"),
        ("status <> 'draft'", "draft active-pointer constraint missing"),
        ("approval_required", "approval requirement not derived (trusts mode)"),
    ]:
        if tok not in a:
            problems.append(f"04: round-5 token missing: {tok} ({why})")
    # Anti-patterns that must be GONE from 04
    if "gated_needs_ref CHECK (mode <> 'approval_gated'" in a:
        problems.append("04: approval requirement trusts self-declared mode (derive from catalog safety_class)")
    if "ws_is_get       CHECK (kind <> 'websocket' OR (method = 'GET' AND scheme IN ('ws','wss')))" in a:
        problems.append("04: one-directional ws_is_get (need bidirectional kind<->scheme)")
    if re.search(r"REFERENCES catalog_template\(digest\)", a):  # (digest,kind) form has no literal "(digest)"
        problems.append("04: catalog FK without kind enforcement (REFERENCES catalog_template(digest))")
    if "session_ref, run_id, job_id are EXCLUDED" in a and "session_digest" not in a:
        problems.append("04: session identity excluded without a bound non-secret session_digest")
    # pause/approve/resume for dynamic (broker-mediated) requests
    if not ("pause" in a.lower() and "resume" in a.lower()):
        problems.append("04 §7.2: pause/approve/resume for dynamic requests not defined")
    # approval policy pinned to the current matching version
    if "current, non-superseded" not in a and "pins the current" not in a:
        problems.append("04 §10: approval policy not pinned to current matching (non-superseded) version")

    # 10) code-fence balance
    for bn, t in texts.items():
        if t.count("```") % 2:
            problems.append(f"{bn}: unbalanced code fences")
    return problems


# Negative fixtures: (label, mutator). Each mutator injects a KNOWN-BAD pattern; analyze() MUST then
# report at least one MORE problem than the clean corpus, proving the detector is not vacuous.
NEG_FIXTURES = [
    ("live ScopeGuard name",
     lambda x: _sub(x, "03-architecture.md", x["03-architecture.md"] + "\nThe ScopeGuard client dials the target directly.\n")),
    ("metadata via exact /32 (live)",
     lambda x: _sub(x, "05-safety-invariants.md", x["05-safety-invariants.md"] + "\nCloud metadata is reachable via an exact /32 elevated allow entry.\n")),
    ("grant binds resolved IP at mint (live)",
     lambda x: _sub(x, "10-request-authorization-flow.md", x["10-request-authorization-flow.md"] + "\nThe Stage-1 grant binds the resolved IP at mint time.\n")),
    ("grant enqueued (live)",
     lambda x: _sub(x, "03-architecture.md", x["03-architecture.md"] + "\nThe API enqueues the job and grant together in one transaction.\n")),
    ("budget decremented at enqueue (live)",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md", x["04-authorization-and-scope-schema.md"] + "\nBudget is decremented at enqueue time by the scheduler.\n")),
    ("UNIQUE(tenant_id, spec_sha256) schema anti-pattern",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md", x["04-authorization-and-scope-schema.md"] + "\n  UNIQUE (tenant_id, spec_sha256),\n")),
    ("audit uniqueness on nullable keys",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md", x["04-authorization-and-scope-schema.md"] + "\n  UNIQUE (stream, tenant_id, engagement_id, seq),\n")),
    ("IPv6 address-sum breadth (max_scope_addresses)",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md", x["04-authorization-and-scope-schema.md"] + "\n  max_scope_addresses BIGINT NOT NULL,\n")),
    ("SI count mismatch",
     lambda x: _sub(x, "05-safety-invariants.md", x["05-safety-invariants.md"].replace("**65 absolute", "**64 absolute", 1))),
    ("broken cross-reference SI-999",
     lambda x: _sub(x, "06-acceptance-criteria.md", x["06-acceptance-criteria.md"] + "\nSee SI-999 for details.\n")),
    # round-5 stale patterns (injected into the FIXED corpus; each must be detected)
    ("reservation created at Stage-1 mint",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"].replace(
                        "STAGE 2 — GUARDED EGRESS BROKER", " → ON PASS: create a budget_reservation at mint.\n\nSTAGE 2 — GUARDED EGRESS BROKER", 1))),
    ("approval trusts self-declared mode",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"] + "\n  CONSTRAINT gated_needs_ref CHECK (mode <> 'approval_gated' OR approval_ref IS NOT NULL)\n")),
    ("catalog FK without kind",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"] + "\n  FOREIGN KEY (payload_digest) REFERENCES catalog_template(digest),\n")),
    ("session_digest token removed",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"].replace("session_digest", "session_XXXXX"))),
    ("fence_token token removed",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"].replace("fence_token", "fence_XXXXX"))),
    ("audit related-event same-chain FK removed",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"].replace("audit_event(id, chain_id)", "audit_event(id)"))),
    ("manifest_frozen removed",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"].replace("manifest_frozen", "manifest_XXXXX"))),
    ("role_quorum removed",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"].replace("role_quorum", "role_XXXXX"))),
    ("window ordering removed",
     lambda x: _sub(x, "04-authorization-and-scope-schema.md",
                    x["04-authorization-and-scope-schema.md"].replace("start_at < end_at", "start_at <= end_at_DISABLED"))),
]

def _sub(d, key, val):
    d = dict(d); d[key] = val; return d

def selftest(clean_texts, base_problems):
    failures = []
    for label, mut in NEG_FIXTURES:
        got = analyze(mut(clean_texts))
        if len(got) <= len(base_problems):
            failures.append(f"NEGATIVE FIXTURE NOT DETECTED: {label} (checker produced no extra problem)")
    return failures


def main():
    texts = {os.path.basename(f): open(f).read() for f in sorted(glob.glob(os.path.join(PHASE0, "*.md")))}
    problems = analyze(texts)
    si = texts.get("05-safety-invariants.md", "")
    nb = len(re.findall(r"^### SI-\d+$", si, re.M))
    nfr = len(re.findall(r"^\*\*FR-\d+ —", texts.get("01-requirements.md", ""), re.M))
    nt = len(re.findall(r"^### T-\d+ —", texts.get("02-threat-model.md", ""), re.M))
    print("=== NOTES ===")
    print(f"  - counts: {nfr} FR, {nt} threats, {nb} SI (index rows: {texts.get('05-safety-invariants.md','').count(chr(10)+'| SI-')})")

    self_failures = selftest(texts, problems)
    print("=== NEGATIVE-FIXTURE SELF-TEST ===")
    if self_failures:
        for f in self_failures:
            print("  x", f)
    else:
        print(f"  ok — all {len(NEG_FIXTURES)} bad fixtures produce a failing exit code")

    print("=== PROBLEMS ===")
    all_bad = problems + self_failures
    if all_bad:
        for p in problems:
            print("  x", p)
        print(f"\n{len(all_bad)} problem(s).")
        sys.exit(1)
    print("  none — all Phase 0 consistency checks passed")

if __name__ == "__main__":
    main()
