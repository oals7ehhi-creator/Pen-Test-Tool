#!/usr/bin/env bash
#
# Reproducible-build proof: two INDEPENDENT clean `pnpm install --frozen-lockfile` runs, from the committed
# manifests + lockfile, must materialize BYTE-FOR-BYTE IDENTICAL dependency trees. This proves the lockfile fully
# pins the dependency graph (no floating ranges, no resolution drift, no content drift).
#
# Independence is real on both axes the fingerprint could otherwise fake:
#   - each install uses its OWN fresh pnpm store (so run B is not just hardlinking run A's store), and
#   - the fingerprint hashes every regular file's CONTENT (sha256) and every symlink's TARGET — not just directory
#     names or paths — so identical structure with different bytes/targets would still be detected.
#
# It runs against an isolated COPY of the workspace skeleton (every tracked package.json + pnpm-workspace.yaml +
# pnpm-lock.yaml), never mutating the real node_modules, store, or lockfile. A drift between the two installs — or a
# frozen-lockfile failure — exits non-zero (hard gate, no continue-on-error).
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
STORE_A="$(mktemp -d)"
STORE_B="$(mktemp -d)"
trap 'rm -rf "$WORK" "$STORE_A" "$STORE_B"' EXIT

# Reconstruct the workspace skeleton (manifests + lockfile + workspace file) at identical relative paths.
while IFS= read -r f; do
  mkdir -p "$WORK/$(dirname "$f")"
  cp "$REPO/$f" "$WORK/$f"
done < <(git -C "$REPO" ls-files '*package.json' 'pnpm-workspace.yaml' 'pnpm-lock.yaml')

# Byte-level normalized-tree fingerprint: for every node_modules entry, hash (relative path + file CONTENT) for
# regular files and (relative path + symlink TARGET) for symlinks. Sorted → order-independent → a true normalized,
# content-sensitive comparison. (find -printf and %P/%l are GNU coreutils, present on the CI ubuntu runners.)
#
# Excluded: pnpm's own environment-recording bookkeeping (`.modules.yaml`, `.pnpm-workspace-state-v1.json`). These
# legitimately embed the LOCAL store path, so with two independent stores they differ by design — they are not
# dependency content. Everything else (every package's files + every symlink target) is compared; a real drift in
# any dependency byte or link still fails the gate.
fingerprint() {
  local root="$1"
  (
    cd "$root" || exit 0
    {
      find node_modules -type f \
        ! -path 'node_modules/.modules.yaml' \
        ! -path 'node_modules/.pnpm-workspace-state-v1.json' \
        -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 -r sha256sum
      find node_modules -type l -printf '%p -> %l\n' 2>/dev/null | LC_ALL=C sort
    }
  ) | sha256sum | cut -d' ' -f1
}

install_once() {
  local label="$1" store="$2"
  find "$WORK" -type d -name node_modules -prune -exec rm -rf {} + 2>/dev/null || true
  ( cd "$WORK" && pnpm install --frozen-lockfile --ignore-scripts --store-dir "$store" >/dev/null 2>&1 )
  echo "  install $label: ok (independent store)"
}

echo "deterministic install proof (pnpm $(pnpm --version), frozen lockfile, independent stores, content-hashed):"
install_once A "$STORE_A"
FP_A="$(fingerprint "$WORK")"
install_once B "$STORE_B"
FP_B="$(fingerprint "$WORK")"

echo "  byte-level tree fingerprint A: $FP_A"
echo "  byte-level tree fingerprint B: $FP_B"
if [ "$FP_A" != "$FP_B" ]; then
  echo "  FAIL — the two independent frozen installs produced DIFFERENT dependency trees" >&2
  exit 1
fi
echo "  PASS — two independent frozen-lockfile installs produced byte-for-byte identical dependency trees"
