#!/usr/bin/env bash
#
# Adversarial proof that the dependency-audit supply-chain gate REALLY fails on a known-high-severity advisory
# (not a gate that is present but toothless). It runs the SAME command the production gate uses
# (`pnpm audit --audit-level=high`) against a THROWAWAY project whose sole dependency has a well-known critical
# advisory (minimist <0.2.4, prototype pollution — GHSA-xvch-5gv4-984h), and asserts the audit fails.
#
# The vulnerable dependency is NEVER added to the repository: the fixture manifest + its lockfile live only in a
# temp dir that is always removed. This is a hard gate (exits non-zero on any mismatch) and is never
# continue-on-error, and it does NOT weaken the real audit (that still runs over the workspace lockfile).
set -euo pipefail

WORK="$(mktemp -d)"
STORE="$(mktemp -d)"
trap 'rm -rf "$WORK" "$STORE"' EXIT

# A known-vulnerable version with a permanent high/critical advisory (assembled from parts so the exact
# vulnerable coordinate is not a committed literal that could be mistaken for a real dependency).
VULN_NAME="mini""mist"
VULN_VERSION="0.0.8" # < 0.2.4 → GHSA-xvch-5gv4-984h (critical)

cat > "$WORK/package.json" <<EOF
{
  "name": "audit-negative-fixture",
  "version": "0.0.0",
  "private": true,
  "dependencies": { "$VULN_NAME": "$VULN_VERSION" }
}
EOF

echo "dependency-audit negative proof (pnpm $(pnpm --version)):"
# lockfile-only resolution — no code is downloaded or executed for the fixture.
( cd "$WORK" && pnpm install --lockfile-only --ignore-scripts --store-dir "$STORE" >/dev/null 2>&1 )

status=0
out="$( cd "$WORK" && pnpm audit --audit-level=high 2>&1 )" || status=$?

echo "  pnpm audit --audit-level=high exit: $status"
if [ "$status" -eq 0 ]; then
  echo "  FAIL — the audit PASSED a project with a known critical advisory (supply-chain gate is toothless)" >&2
  exit 1
fi
# Guard against a FALSE PASS: a non-zero exit must be a real advisory finding, not a network/tool error. The
# fixture (minimist <0.2.4) is a CRITICAL prototype-pollution advisory, so the report must name that severity.
if ! printf '%s' "$out" | grep -qiE 'critical|high'; then
  echo "  FAIL — audit exited non-zero but reported no high/critical advisory (possible network/tool error, not a gate hit)" >&2
  printf '%s\n' "$out" | tail -20 >&2
  exit 1
fi
echo "  PASS — the audit gate fails a known high/critical advisory as required"
