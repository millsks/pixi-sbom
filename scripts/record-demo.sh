#!/usr/bin/env bash
# Re-records docs/assets/demo.gif. Run it as `pixi run demo`.
#
# vhs is not a project dependency on purpose: it pulls ttyd and ffmpeg, which is 95 packages and
# doubles pixi.lock, for a task that runs by hand every few months and never in CI.
#   pixi global install vhs
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

command -v vhs >/dev/null || {
  echo "vhs is not on PATH. Install it once with:  pixi global install vhs" >&2
  exit 1
}

# The recording types `pixi sbom`, which is what a reader will type, so the binary has to be
# discoverable as a pixi extension rather than run by path.
echo "building the release binary the recording will run..."
pixi run --manifest-path "$here/pixi.toml" cargo build --release -q

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
bash scripts/demo-workspace.sh "$staging"
ln -sf "$here/target/release/pixi-sbom" "$staging/bin/pixi-sbom"
workspace="$staging/workspace"

# vhs records whatever the shell in `workspace` does, so the cache and the extension come from
# there. PIXI_CACHE_DIR points at nothing on purpose: the demo must not read the real package
# cache, or the output would depend on what the recorder happens to have downloaded.
cd "$workspace"
PATH="$staging/bin:$PATH" \
  PIXI_SBOM_CACHE_DIR="$staging/cache" \
  PIXI_CACHE_DIR="$staging/no-package-cache" \
  vhs "$here/docs/assets/demo.tape" --output "$here/docs/assets/demo.gif"

cd "$here"
printf 'docs/assets/demo.gif: %s\n' "$(du -h docs/assets/demo.gif | cut -f1)"
