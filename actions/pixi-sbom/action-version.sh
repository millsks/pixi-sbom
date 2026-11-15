#!/usr/bin/env bash
# Prints the pixi-sbom version the action should install, without the leading `v`.
#
#   INPUT_VERSION  the action's `version` input; wins when set
#   ACTION_REF     github.action_ref: `v1.0.0` pins that release, `v1` the newest 1.x.y release,
#                  anything else (a branch, a sha, `./`) the newest release. A `pixi-sbom-` prefix,
#                  how 1.12.0 to 1.13.1 were tagged in aesir-oss/pixi-ext-contrib, is still accepted.
#   GH_TOKEN       optional, for the GitHub API rate limit
#   RELEASES_API   space-separated release-list URLs, overridable so the test can use fixtures
#
# Every release is in millsks/pixi-sbom, tagged vX.Y.Z: those first made in the original millsks/pixi-sbom (up to
# 1.11.x, now millsks/pixi-sbom.org) and aesir-oss/pixi-ext-contrib (1.12.0 to 1.13.1) were copied there, assets and all.
set -euo pipefail

apis="${RELEASES_API:-https://api.github.com/repos/millsks/pixi-sbom/releases}"

fetch() {
  if [ -n "${GH_TOKEN:-}" ]; then
    curl -sSfL -H "Authorization: Bearer $GH_TOKEN" "$@"
  else
    curl -sSfL "$@"
  fi
}

# Every page of a release list, following the Link header's rel="next": the repository's own releases (#49) fill the
# first hundred sooner, and a release past them would never be found. A file:// fixture has no headers, so one page.
fetch_all() {
  local url="$1?per_page=100" headers pages=0
  headers=$(mktemp)
  while [ -n "$url" ] && [ "$pages" -lt 50 ]; do
    fetch -D "$headers" "$url"
    echo
    url=$(tr -d '\r' < "$headers" | grep -i '^link:' | grep -oE '<[^>]+>; *rel="next"' | sed -E 's/^<([^>]+)>.*/\1/' || true)
    pages=$((pages + 1))
  done
  rm -f "$headers"
}

version="${INPUT_VERSION:-}"
version="${version#pixi-sbom-}"
version="${version#v}"
ref="${ACTION_REF:-}"
ref="${ref#pixi-sbom-}"

if [ -z "$version" ] && [[ "$ref" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  version="${ref#v}"
fi

# The newest final release, or the newest in one major for a floating major tag: that tag moves with each release
# of its major, and the newest release overall would hand a v0 user a v1 binary behind v0's inputs.
newest() {
  local api
  for api in $apis; do
    fetch_all "$api"
  done |
    grep -oE "\"tag_name\": *\"(pixi-sbom-)?v$1\.[0-9]+\.[0-9]+\"" |
    sed -E 's/.*"(pixi-sbom-)?v([^"]+)"/\2/' |
    sort -V | tail -n 1
}

if [ -z "$version" ] && [[ "$ref" =~ ^v?([0-9]+)$ ]]; then
  version=$(newest "${BASH_REMATCH[1]}" || true)
fi

if [ -z "$version" ]; then
  version=$(newest "[0-9]+")
fi

[ -n "$version" ] || { echo "::error::cannot determine the pixi-sbom version to install" >&2; exit 1; }
echo "$version"
