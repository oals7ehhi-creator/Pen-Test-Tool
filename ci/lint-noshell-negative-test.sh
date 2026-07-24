#!/usr/bin/env bash
#
# Adversarial proof that the no-shell / command-injection lint gate REALLY fails on a violation — across EVERY way
# a module can reach child_process, not just static imports. It plants, one at a time, TypeScript files that each
# use a different subprocess-loading form, runs ESLint, and asserts ESLint fails via a no-shell rule
# (no-restricted-imports for static imports, no-restricted-syntax for dynamic import / require / createRequire).
# Every planted file is generated at runtime and always removed; the check is a hard gate and is never
# continue-on-error. It does NOT weaken the normal lint gate (that still runs over the real tree).
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
DIR="$REPO/services/api/src"
PLANTED=()
cleanup() {
  for f in "${PLANTED[@]:-}"; do rm -f "$f"; done
}
trap cleanup EXIT

# The no-shell rule ids that are an ACCEPTABLE reason for the gate to fire.
NOSHELL_RULES='no-restricted-imports|no-restricted-syntax'

FAIL=0

# check_case <name> <basename> <file-body>
check_case() {
  local name="$1" base="$2" body="$3"
  local plant="$DIR/$base.ts"
  PLANTED+=("$plant")
  printf '%s\n' "$body" > "$plant"

  local status rules
  status=0
  ( cd "$REPO" && npx eslint "$plant" >/dev/null 2>&1 ) || status=$?
  rules="$( cd "$REPO" && npx eslint "$plant" --format json 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(' '.join(m.get('ruleId') or '' for f in d for m in f['messages']))" 2>/dev/null || echo '')"

  if [ "$status" -eq 0 ]; then
    echo "  FAIL  $name — ESLint PASSED a child_process $name (no-shell gate is toothless)" >&2
    FAIL=1
  elif ! printf '%s' "$rules" | grep -qE "$NOSHELL_RULES"; then
    echo "  FAIL  $name — ESLint failed, but NOT via a no-shell rule (rules: $rules)" >&2
    FAIL=1
  else
    echo "  PASS  $name — blocked by [$rules]"
  fi
  rm -f "$plant"
}

echo "no-shell lint negative proof (static import, dynamic import, require, createRequire):"

check_case "static import" "__noshell_static__" \
  "// runtime negative fixture — never committed
import child from 'node:child_process';
export const forbidden = child;"

check_case "dynamic import" "__noshell_dynamic__" \
  "// runtime negative fixture — never committed
export async function run() {
  const cp = await import('node:child_process');
  return cp;
}"

check_case "require call" "__noshell_require__" \
  "// runtime negative fixture — never committed
declare const require: (m: string) => unknown;
export const cp = require('child_process');"

check_case "createRequire alias" "__noshell_createrequire__" \
  "// runtime negative fixture — never committed
import { createRequire } from 'node:module';
const r = createRequire(import.meta.url);
export const cp = r('child_process');"

if [ "$FAIL" -ne 0 ]; then
  echo "  no-shell gate FAILED to block one or more subprocess-loading forms" >&2
  exit 1
fi
echo "  PASS — every subprocess-loading form is blocked by the no-shell gate"
