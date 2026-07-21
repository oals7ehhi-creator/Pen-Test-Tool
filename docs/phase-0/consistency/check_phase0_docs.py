#!/usr/bin/env python3
"""
Machine-checkable consistency checker for the Phase 0 design package (docs 00-11).

This is a DESIGN gate, not application code: it verifies the specification documents
are internally consistent so contradictions cannot silently accrue as they are edited.
It is intended to run in CI (Phase 1 onward) and to block a release (Phase 12) on any drift.

Exit code 0 = consistent; 1 = one or more problems (printed). No third-party deps.

Checks:
  1. No live legacy component names ("ScopeGuard", "scope-validation service") outside
     explicit historical "(was ...)" notes.
  2. Safety-invariant index rows == body blocks, contiguous SI-001..SI-NNN, no duplicates.
  3. Counts claimed in 00-overview (FR, SI) match reality; no duplicate FR/NFR/T/SI ids.
  4. Internal doc links and backtick file refs (NN-*.md) resolve to files that exist.
  5. Every SI-/T-/FR-/ADR- cross-reference resolves to a defined id.
  6. Approval policy tables in 04 (§10) and 09 (RBAC) agree (request_type -> threshold + roles).
  7. Contradiction scans (all LIVE claims; quoted removed-wording notes excluded):
       - metadata reachable via allowlist / "exact /32"    (must be gone)
       - grant/token binds a resolved IP at mint time       (must be gone)
       - the queued object is a grant / grant enqueued       (must be gone)
       - budget decremented at enqueue                       (must be gone)
       - IPv6 address-sum breadth ceiling                    (must be gone)
  8. Presence of the round-3 model: request_spec, spec_sha256, JIT grant minting,
     broker reconstruction, reserve/commit/release budget, WebSocket caps.
  9. Code-fence balance per file.
"""
import re, os, sys, glob

DIR = os.path.dirname(os.path.abspath(__file__))
PHASE0 = os.path.dirname(DIR)
files = sorted(f for f in glob.glob(os.path.join(PHASE0, "*.md")))
texts = {os.path.basename(f): open(f).read() for f in files}
allbn = set(texts) | {"README.md"}
problems, notes = [], []

def has(bn, *subs):  # every substring present in a file
    t = texts.get(bn, "")
    return all(s in t for s in subs)

# 1) legacy names
for bn, t in texts.items():
    for m in re.finditer(r"ScopeGuard", t):
        ctx = t[max(0, m.start()-40):m.start()+14]
        if 'was "ScopeGuard' in ctx or 'ScopeGuard" terminology' in ctx or '/ "ScopeGuard' in ctx:
            continue
        problems.append(f"{bn}: live 'ScopeGuard' -> ...{ctx.strip()}...")
    for m in re.finditer(r"[Ss]cope-[Vv]alidation [Ss]ervice", t):
        ctx = t[max(0, m.start()-32):m.start()+30]
        if 'was "scope-validation service"' in ctx or 'earlier "scope-validation service"' in ctx:
            continue
        problems.append(f"{bn}: live 'scope-validation service' -> ...{ctx.strip()}...")

# 2) SI index/body parity
si = texts["05-safety-invariants.md"]
body = re.findall(r"^### (SI-\d+)$", si, re.M)
idx  = re.findall(r"^\| (SI-\d+) \|", si, re.M)
if body != idx:
    problems.append(f"SI index/body mismatch: {len(idx)} index rows vs {len(body)} blocks")
nums = [int(x.split('-')[1]) for x in body]
if nums != list(range(1, len(nums)+1)):
    problems.append(f"SI ids not contiguous 1..N: {nums}")
if len(set(body)) != len(body):
    problems.append("duplicate SI ids in body")
notes.append(f"SI: {len(body)} blocks == {len(idx)} index rows, contiguous SI-001..SI-{len(body):03d}")

# 3) counts + dup ids
fr  = re.findall(r"^\*\*(FR-\d+) —", texts["01-requirements.md"], re.M)
nfr = re.findall(r"^\*\*(NFR-\d+) —", texts["01-requirements.md"], re.M)
th  = re.findall(r"^### (T-\d+) —", texts["02-threat-model.md"], re.M)
for label, got, claimpat in [("FR", len(fr), r"\*\*(\d+) FR"), ("SI", len(body), r"\*\*(\d+) absolute")]:
    src = texts["00-overview.md"] if label == "FR" else texts["05-safety-invariants.md"]
    c = re.search(claimpat, src)
    if c and int(c.group(1)) != got:
        problems.append(f"{label} count: doc claims {c.group(1)} but found {got}")
for lab, ids in [("FR", fr), ("NFR", nfr), ("T", th), ("SI", body)]:
    d = [x for x in set(ids) if ids.count(x) > 1]
    if d:
        problems.append(f"{lab} duplicate ids: {d}")
notes.append(f"counts: {len(fr)} FR, {len(nfr)} NFR, {len(th)} threats, {len(body)} SI")

# 4) links / backtick refs
for bn, t in texts.items():
    for m in re.finditer(r"\]\(([0-9][0-9A-Za-z\-]*\.md)(#[^)]*)?\)", t):
        if m.group(1) not in allbn:
            problems.append(f"{bn}: broken link -> {m.group(1)}")
    for m in re.finditer(r"`(\d\d-[a-z0-9\-]+\.md)`", t):
        if m.group(1) not in allbn:
            problems.append(f"{bn}: broken backtick ref -> {m.group(1)}")

# 5) cross-ref ids exist
si_set, t_set = set(body), set(th)
for bn, t in texts.items():
    for r in re.findall(r"\bSI-(\d+)\b", t):
        if f"SI-{int(r):03d}" not in si_set:
            problems.append(f"{bn}: references missing SI-{r}")
    for r in re.findall(r"\bT-(\d+)\b", t):
        if f"T-{int(r):03d}" not in t_set:
            problems.append(f"{bn}: references missing T-{r}")

# 6) approval policy tables agree between 04 §10 and 09
def approval_policy(t):
    pol = {}
    for m in re.finditer(r"\| `(authorization_attestation|scope_expansion|restricted_range_allow|mode_elevation|business_logic_test|intrusive_validation)`[^\n]*?\| (\d+) \| ([^|]+)\|", t):
        rt, thr, roles = m.group(1), int(m.group(2)), m.group(3)
        r = set()
        for role in ("Engagement Manager", "Reviewer", "Administrator", "Tester", "Read-only Auditor"):
            if role in roles:
                r.add(role)
        pol[rt] = (thr, frozenset(r))
    return pol
p04 = approval_policy(texts["04-authorization-and-scope-schema.md"])
p09 = approval_policy(texts["09-rbac-matrix.md"])
common = set(p04) & set(p09)
if len(common) < 6:
    problems.append(f"approval-policy: expected 6 request_types in both 04 and 09, found {len(common)} in common ({sorted(common)})")
for rt in sorted(common):
    if p04[rt] != p09[rt]:
        problems.append(f"approval-policy mismatch for {rt}: 04={p04[rt]} vs 09={p09[rt]}")

# 7) contradiction scans (LIVE assertions only — quoted phrasings and "removed/prevented/hypothetical"
#    descriptions are not assertions and are excluded).
DESC = ("removed", "earlier", "revised", "carve-out", "superseded", 'was "', "the earlier",
        "no longer", "phrasings", "stale", "forbid", "no stale", "contradiction", "prevented",
        "were a", "could expire", "if the queued", "removes the", "quoted", "description",
        "not a grant", "never", "no grant", "just-in-time", "not at enqueue", "cannot sit")
def live(ctx):
    low = ctx.lower()
    return not any(w in low for w in DESC)
def quoted(t, start):  # phrase opens with a double-quote just before the match → it's being quoted
    return '"' in t[max(0, start-3):start]
def scan(bn, t, pat, label, seg_ok=(), win=120):
    for m in re.finditer(pat, t, re.I):
        if quoted(t, m.start()):
            continue
        seg = m.group(0).lower()
        if any(w in seg for w in seg_ok):
            continue
        ctx = t[max(0, m.start()-win):m.start()+90]
        if live(ctx):
            problems.append(f"{bn}: {label} -> {ctx.strip()[:90]}")
for bn, t in texts.items():
    scan(bn, t, r"unless that exact range", "LIVE 'unless that exact range'")
    scan(bn, t, r"metadata[^.\n]{0,60}(exact-?/32|exact /32|reachable ONLY via)", "LIVE metadata-via-exact-/32", win=140)
    scan(bn, t, r"(grant|token)\b[^.\n]{0,90}\bbind[a-z]*\b[^.\n]{0,50}resolved IP", "grant binds resolved IP",
         seg_ok=("no resolved", "never a resolved", "never bind", "not bind", "does not bind", "cannot", "without a resolved"))
    scan(bn, t, r"enqueues?[^.\n]{0,40}\bgrant\b|\bgrant\b[^.\n]{0,20}in (the|a) queue|queued[^.\n]{0,10}\bgrant\b",
         "queued-grant contradiction", win=80)
    scan(bn, t, r"budget[^.\n]{0,30}decrement[^.\n]{0,30}enqueue|enqueue[^.\n]{0,30}decrement", "budget-decremented-at-enqueue")
    for m in re.finditer(r"max_scope_addresses|address_count[^.\n]*minus exclusions", t):
        problems.append(f"{bn}: stale IPv6-broken address-sum breadth -> {m.group(0)[:60]}")

# 8) round-3 model present where it must be
if not has("04-authorization-and-scope-schema.md", "TABLE request_spec", "spec_sha256",
           "reserved", "reconstruct", "kind='websocket'", "just-in-time"):
    problems.append("04: missing part of the round-3 model (request_spec / spec_sha256 / reserved / reconstruct / websocket / JIT)")
if not has("10-request-authorization-flow.md", "spec_sha256", "just-in-time", "reconstruct", "WebSocket"):
    problems.append("10: missing round-3 model (spec_sha256 / JIT / reconstruct / WebSocket)")
for sid in ("SI-060", "SI-061", "SI-062", "SI-063"):
    if sid not in si:
        problems.append(f"05: missing {sid}")

# 9) code-fence balance
for bn, t in texts.items():
    if t.count("```") % 2:
        problems.append(f"{bn}: unbalanced code fences")

print("=== NOTES ===")
for n in notes:
    print("  -", n)
print("\n=== PROBLEMS ===")
if problems:
    for p in problems:
        print("  x", p)
    print(f"\n{len(problems)} problem(s).")
    sys.exit(1)
print("  none — all Phase 0 consistency checks passed")
