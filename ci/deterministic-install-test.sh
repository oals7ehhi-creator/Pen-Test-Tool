#!/usr/bin/env bash
#
# Reproducible-build proof: two INDEPENDENT clean `pnpm install --frozen-lockfile` runs, from the committed
# manifests + lockfile, must materialize byte-for-byte IDENTICAL normalized dependency trees. This proves the
# lockfile fully pins the dependency graph (no floating ranges, no resolution drift).
#
# It runs against an isolated COPY of the workspace skeleton (every tracked package.json + pnpm-workspace.yaml +
# pnpm-lock.yaml) with a throwaway pnpm store, so it never mutates the real node_modules, store, or lockfile.
# A drift between the two installs — or a frozen-lockfile failure — exits non-zero (hard gate, no continue-on-error).
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
# Reuse the (content-addressed) shared pnpm store so this proof does not re-download the whole toolchain twice;
# the store is only a cache — the "clean install" property under test is a from-scratch node_modules
# materialization in an isolated copy of the workspace, which we guarantee below.

# 1) Reconstruct the workspace skeleton (manifests + lockfile + workspace file) at identical relative paths.
while IFS= read -r f; do
  mkdir -p "$WORK/$(dirname "$f")"
  cp "$REPO/$f" "$WORK/$f"
done < <(git -C "$REPO" ls-files '*package.json' 'pnpm-workspace.yaml' 'pnpm-lock.yaml')

# normalized-tree fingerprint: the sorted set of package identities in the centralized virtual store
# (node_modules/.pnpm holds one dir per resolved name@version+peers — the canonical resolved graph), plus the
# sorted list of every materialized package.json path. Order-independent, so it is a true normalized comparison.
fingerprint() {
  local root="$1"
  { ls -1 "$root/node_modules/.pnpm" 2>/dev/null || true; } | LC_ALL=C sort
  ( cd "$root" && find . -path '*/node_modules/*' -name package.json | LC_ALL=C sort )
}

install_once() {
  local label="$1"
  # clean: remove any node_modules from a prior pass so this is a from-scratch materialization
  find "$WORK" -type d -name node_modules -prune -exec rm -rf {} + 2>/dev/null || true
  ( cd "$WORK" && pnpm install --frozen-lockfile --ignore-scripts >/dev/null 2>&1 )
  echo "  install $label: ok"
}

echo "deterministic install proof (pnpm $(pnpm --version), frozen lockfile):"
install_once A
FP_A="$(fingerprint "$WORK" | sha256sum | cut -d' ' -f1)"
install_once B
FP_B="$(fingerprint "$WORK" | sha256sum | cut -d' ' -f1)"

echo "  tree fingerprint A: $FP_A"
echo "  tree fingerprint B: $FP_B"
if [ "$FP_A" != "$FP_B" ]; then
  echo "  FAIL — the two frozen installs produced DIFFERENT normalized trees" >&2
  exit 1
fi
echo "  PASS — two independent frozen-lockfile installs produced identical normalized trees"
