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
DEMO_BINARY="$here/target/release/pixi-sbom" bash scripts/demo-workspace.sh "$staging"
ln -sf "$here/target/release/pixi-sbom" "$staging/bin/pixi-sbom"
workspace="$staging/workspace"

# vhs records whatever the shell in `workspace` does, so the cache and the extension come from
# there. PIXI_CACHE_DIR points at nothing on purpose: the demo must not read the real package
# cache, or the output would depend on what the recorder happens to have downloaded.
# One tape per recording: the overview at the top of the README, and one per feature embedded
# beside the prose that explains it in docs/cli.md. `pixi run demo <name>` re-records just one.
# vhs runs from the repository root so that `Source` and `Output` in a tape resolve against it.
# The recorded shell cds into the staged workspace itself, via $DEMO_WORKSPACE, which keeps the
# committed tapes free of anyone's temporary directory.
cd "$here"
export DEMO_WORKSPACE="$workspace"
wanted="${1:-}"
recorded=0
for tape in "$here"/docs/assets/*.tape; do
  name="$(basename "$tape" .tape)"
  # _common.tape is sourced by the others and has no Output of its own.
  case "$name" in _*) continue ;; esac
  [ -z "$wanted" ] || [ "$wanted" = "$name" ] || continue
  # PIXI_SBOM_OFFLINE is the whole basis of these recordings being reproducible. Without it a
  # recording quietly reaches the live OSV, anaconda.org and OpenSSF APIs, and then it shows
  # whatever those said that afternoon: different scores, today's dates, and a re-record that
  # needs connectivity and produces a different film. Set here rather than in a tape so no tape
  # can forget it.
  PATH="$staging/bin:$PATH" \
    PIXI_SBOM_OFFLINE=1 \
    PIXI_SBOM_CACHE_DIR="$staging/cache" \
    PIXI_CACHE_DIR="$staging/no-package-cache" \
    vhs "$tape" --output "$here/docs/assets/$name.gif" >/dev/null
  recorded=$((recorded + 1))
done

if [ "$recorded" -eq 0 ]; then
  echo "no tape matched '${wanted}'. Available:" >&2
  for tape in docs/assets/*.tape; do
    case "$(basename "$tape")" in _*) continue ;; esac
    basename "$tape" .tape | sed 's/^/  /' >&2
  done
  exit 1
fi
printf '%-34s %s\n' "recording" "size"
for gif in docs/assets/*.gif; do
  printf '%-34s %s\n' "$gif" "$(du -h "$gif" | cut -f1)"
done
