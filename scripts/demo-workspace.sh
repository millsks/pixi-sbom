#!/usr/bin/env bash
# Builds the throwaway workspace docs/assets/demo.tape records against.
#
# Everything the demo shows is real output from the real binary. What is staged here is only the
# *input*: a lockfile with a known-vulnerable urllib3, and the recorded OSV and CISA KEV responses
# the tests already use, placed in the cache so the run needs no network and takes the same time
# every time. A demo that reached the network would be slow, would drift as advisories change, and
# could not be re-recorded on a plane.
#
#   scripts/demo-workspace.sh <target-dir>
set -euo pipefail

target="${1:?usage: demo-workspace.sh <target-dir>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixtures="$here/tests/fixtures"

rm -rf "$target"
mkdir -p "$target/workspace" "$target/cache" "$target/bin"
cp "$fixtures/with-pypi/pixi.toml" "$fixtures/with-pypi/pixi.lock" "$target/workspace/"

# urllib3 2.8.0 -> 1.26.4, which has advisories against it. The same substitution
# `workspace_with_vulnerable_urllib3` makes in tests/cli.rs, so the two cannot drift apart
# unnoticed: if the fixture changes shape, both stop working.
python3 - "$target/workspace/pixi.lock" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
lock = path.read_text().replace("\r\n", "\n")
swaps = [
    (
        "packages/92/9d/c4e665119135114480843e7ab388fa94d8480650450e6f8e26b70d323a4c/urllib3-2.8.0-py3-none-any.whl",
        "packages/09/c6/d3e3abe5b4f4f16cf0dfc9240ab7ce10c2baa0e268989a4e3ec19e90c84e/urllib3-1.26.4-py2.py3-none-any.whl",
    ),
    ("\n  version: 2.8.0\n", "\n  version: 1.26.4\n"),
    (
        "0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3",
        "2f4da4594db7e1e110a944bb1b551fdf4e6c136ad42e4234131391e21eb5b0df",
    ),
]
for old, new in swaps:
    if old not in lock:
        raise SystemExit(f"demo fixture drifted: {old[:60]!r} is no longer in with-pypi/pixi.lock")
    lock = lock.replace(old, new)
path.write_text(lock)
PY

# The recorded API responses, where an offline run looks for them. Each one is what a different
# report needs: OSV and the CISA catalogue for --report vulnerabilities, the PyPI index documents
# for --report outdated and for the licenses the other reports show, scorecards for
# --report scorecard.
for sub in queries vulns; do
  mkdir -p "$target/cache/osv/$sub"
  cp "$fixtures/osv/$sub"/* "$target/cache/osv/$sub/"
done
mkdir -p "$target/cache/kev" "$target/cache/pypi" "$target/cache/scorecard"
cp "$fixtures/kev/known_exploited_vulnerabilities.json" "$target/cache/kev/"
cp "$fixtures/pypi-metadata"/*.json "$target/cache/pypi/"
cp "$fixtures/scorecard"/*.json "$target/cache/scorecard/" 2>/dev/null || true

# --report phantom reads the workspace's Python sources, which default to the lockfile's own
# directory. One module that imports something the manifest never declared, and something declared
# that nothing imports, so the report has both halves to show.
cat > "$target/workspace/app.py" <<'PYSRC'
"""The workspace's own code, such as it is."""

import requests          # declared in pixi.toml
import urllib3           # NOT declared: it is here only because requests pulls it in — a phantom
import yaml              # not installed at all, so no package can be blamed for it


def fetch(url: str) -> dict:
    return yaml.safe_load(requests.get(url, timeout=10).text)
PYSRC

# --report diff compares against an earlier document. It is generated here rather than committed:
# the baseline is this binary's own output from the *unmodified* fixture, so the diff the demo
# shows is a real one — urllib3 going from 2.8.0 to the 1.26.4 the rest of the demo reports on.
if [ -n "${DEMO_BINARY:-}" ]; then
  baseline="$target/baseline"
  mkdir -p "$baseline"
  cp "$fixtures/with-pypi/pixi.toml" "$fixtures/with-pypi/pixi.lock" "$baseline/"
  ( cd "$baseline" && PIXI_SBOM_OFFLINE=1 PIXI_SBOM_CACHE_DIR="$target/cache" \
      PIXI_CACHE_DIR="$target/no-package-cache" \
      "$DEMO_BINARY" -q -e web -p linux-64 --output "$target/workspace/last-release.cdx.json" )
  rm -rf "$baseline"
fi

echo "demo workspace ready: $target/workspace (cache and bin alongside it)"
