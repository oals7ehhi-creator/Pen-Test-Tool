#!/usr/bin/env bash
#
# Adversarial proof that the no-shell / command-injection lint gate REALLY fails on a violation (not a gate that is
# present but toothless). It plants a TypeScript file that imports `node:child_process` — forbidden by the
# `no-restricted-imports` rule (Phase 1 no-shell safety gate) — runs ESLint, and asserts ESLint fails AND reports
# exactly that rule. The planted file is generated at runtime and always removed; the check is a hard gate and is
# never continue-on-error. It does NOT weaken the normal lint gate (that still runs over the real tree).
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
PLANT="$REPO/services/api/src/__noshell_violation__.ts"
cleanup() { rm -f "$PLANT"; }
trap cleanup EXIT

# A minimal, otherwise-clean module whose ONLY defect is the forbidden subprocess import.
cat > "$PLANT" <<'EOF'
// Runtime-generated negative fixture — see ci/lint-noshell-negative-test.sh. Never committed.
import child from 'node:child_process';
export const forbidden = child;
EOF

echo "no-shell lint negative proof:"
report="$(cd "$REPO" && npx eslint "$PLANT" --format json 2>/dev/null || true)"
status="$(cd "$REPO" && npx eslint "$PLANT" >/dev/null 2>&1; echo $?)"

rules="$(printf '%s' "$report" | python3 -c "import sys,json; d=json.load(sys.stdin); print(' '.join(m.get('ruleId') or '' for f in d for m in f['messages']))" 2>/dev/null || echo '')"

echo "  eslint exit: $status"
echo "  reported rules: $rules"

if [ "$status" -eq 0 ]; then
  echo "  FAIL — ESLint PASSED a file that imports node:child_process (no-shell gate is toothless)" >&2
  exit 1
fi
if ! printf '%s' "$rules" | grep -q 'no-restricted-imports'; then
  echo "  FAIL — ESLint failed, but NOT via the no-shell (no-restricted-imports) rule" >&2
  exit 1
fi
echo "  PASS — the no-shell rule fails a subprocess import as required"
