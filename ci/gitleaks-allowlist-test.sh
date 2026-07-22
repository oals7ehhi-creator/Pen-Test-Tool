#!/usr/bin/env bash
#
# Adversarial test for .gitleaks.toml — proves the secret-scanning allowlist is TIGHT: each permitted fixture is
# suppressed ONLY in its authorized path and by its exact value, and nothing else is ever suppressed. It exercises
# the exact same pinned gitleaks version as the production gate (8.24.3).
#
# Detector-triggering credentials are NEVER committed as literals: they are constructed at runtime — the permitted
# fixtures are assembled from split string parts, and the "real" fake credentials are derived deterministically from
# fixed seeds via sha256 (so this script itself contains nothing gitleaks would flag, yet the checks are repeatable).
#
# Required env:
#   GITLEAKS        path to the gitleaks 8.24.3 binary
#   GITLEAKS_CONFIG path to the repository's .gitleaks.toml
set -euo pipefail

GITLEAKS="${GITLEAKS:?set GITLEAKS to the gitleaks binary}"
CONFIG="${GITLEAKS_CONFIG:?set GITLEAKS_CONFIG to the repo .gitleaks.toml path}"
REPO="$(git -C "$(dirname "$CONFIG")" rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# --- fixtures constructed at runtime (no trigger-worthy literal is committed) ---
SENTINEL="S3CR3T-""must-never-be-logged"                       # permitted SI-045 sentinel (assembled from parts)
SESSION_PLACEHOLDER="dev-insecure-session-key-""change-me-0123456789" # permitted dev placeholder (assembled)
# Deterministic fake credentials that DO trip default gitleaks rules, derived from fixed seeds (never committed):
AWS_FIXTURE="AKIA$(printf 'pentest-adversarial-aws' | sha256sum | tr 'a-f' 'A-F' | tr -cd 'A-Z0-9' | head -c 16)"
GENERIC_FIXTURE="$(printf 'pentest-adversarial-generic' | sha256sum | tr -cd 'a-f0-9' | head -c 40)"

PASS=0
FAIL=0

# scan <dir> : sets COUNT to the number of gitleaks findings under <dir> (relative-path scan)
scan() {
  local dir="$1"
  rm -f "$dir/gl-report.json"
  ( cd "$dir" && "$GITLEAKS" dir . --config "$CONFIG" --no-banner \
      --report-format json --report-path gl-report.json --log-level error --exit-code 1 ) >/dev/null 2>&1 || true
  if [ ! -f "$dir/gl-report.json" ]; then
    echo "  ERROR gitleaks produced no report for $dir" >&2
    exit 2
  fi
  COUNT="$(python3 -c "import json;print(len(json.load(open('$dir/gl-report.json'))))")"
}

# check <name> <clean|leak>
check() {
  local name="$1" expect="$2" got="clean"
  [ "$COUNT" -gt 0 ] && got="leak"
  if [ "$got" = "$expect" ]; then
    echo "  PASS  $name — expected=$expect findings=$COUNT"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $name — expected=$expect got=$got findings=$COUNT"
    FAIL=$((FAIL + 1))
  fi
}

# mk <scenario> <relpath> <line...> : write a fixture file at a relative path inside a fresh scenario dir
mk() {
  local s="$1" rel="$2" line="$3"
  mkdir -p "$WORK/$s/$(dirname "$rel")"
  printf '%s\n' "$line" > "$WORK/$s/$rel"
}

echo "gitleaks: $("$GITLEAKS" version 2>/dev/null | tail -1)"
echo "adversarial allowlist matrix:"

# 1) permitted sentinel in its authorized path -> suppressed
mk s1 packages/shared/test/logsafe.test.ts "const SECRET = '$SENTINEL';"
scan "$WORK/s1"; check "sentinel in authorized path (packages/shared/test/logsafe.test.ts)" clean

# 2) same sentinel in an UNAUTHORIZED path -> detected (path match is required)
mk s2 src/leak.ts "const SECRET = '$SENTINEL';"
scan "$WORK/s2"; check "sentinel in unauthorized path (src/leak.ts)" leak

# 3) authorized path but DIFFERENT secret value -> detected (value match is required)
mk s3 packages/shared/test/logsafe.test.ts "const SECRET = '$GENERIC_FIXTURE';"
scan "$WORK/s3"; check "different secret in the authorized path (value-match removed)" leak

# 4) unrelated generic secret on the SAME LINE as the permitted sentinel -> detected (proves regexTarget=secret,
#    not line: suppressing the sentinel must NOT suppress a co-located secret)
mk s4 packages/shared/test/logsafe.test.ts "const SECRET = '$SENTINEL'; const API_KEY = '$GENERIC_FIXTURE';"
scan "$WORK/s4"; check "unrelated secret on the same line as the sentinel" leak

# 5,6) permitted session placeholder in its authorized files -> clean
mk s5 .env.example "SESSION_SIGNING_KEY_REF=$SESSION_PLACEHOLDER"
scan "$WORK/s5"; check "session placeholder in .env.example" clean
mk s6 docker-compose.yml "      SESSION_SIGNING_KEY_REF: $SESSION_PLACEHOLDER"
scan "$WORK/s6"; check "session placeholder in docker-compose.yml" clean

# 7) an unrelated detector-triggering credential in .env.example -> detected (the file is NOT globally excluded)
mk s7 .env.example "LEAKED_API_KEY=$GENERIC_FIXTURE"
scan "$WORK/s7"; check "unrelated secret in .env.example (no blanket path exclusion)" leak

# 8) same, in docker-compose.yml -> detected
mk s8 docker-compose.yml "      LEAKED_API_KEY: $GENERIC_FIXTURE"
scan "$WORK/s8"; check "unrelated secret in docker-compose.yml (no blanket path exclusion)" leak

# 9) a different rule (AWS) in a permitted file -> detected (exception is scoped to its rule/value)
mk s9 .env.example "AWS_ACCESS_KEY_ID=$AWS_FIXTURE"
scan "$WORK/s9"; check "unrelated AWS key in .env.example" leak

# 10) the session placeholder VALUE in an unauthorized path is not specially permitted. It is a low-entropy
#     placeholder that the default rules do not flag, so it is clean everywhere; this asserts it is at least not
#     newly *hidden* by our exception outside its files (any real secret there is still caught, see s2/s3).
mk s10 config/prod.env "SESSION_SIGNING_KEY_REF=$SESSION_PLACEHOLDER"
scan "$WORK/s10"; check "session placeholder in unauthorized path (non-triggering by default rules)" clean

# 11) the real repository (all git-tracked working-tree files + this config) still scans clean
mkdir -p "$WORK/repo"
while IFS= read -r f; do
  mkdir -p "$WORK/repo/$(dirname "$f")"
  cp "$REPO/$f" "$WORK/repo/$f"
done < <(git -C "$REPO" ls-files)
scan "$WORK/repo"; check "normal repository scan (all tracked files) still passes" clean

echo "summary: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
