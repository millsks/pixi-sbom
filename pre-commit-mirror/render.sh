#!/usr/bin/env bash
# Render the mirror for VERSION (e.g. 1.7.0) into DEST: the hooks as they are, the templates with
# the version filled in. Used by the release workflow and to try the hooks locally.
set -euo pipefail
version="${1:?usage: render.sh VERSION DEST}"
dest="${2:?usage: render.sh VERSION DEST}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$dest"
cp "$here/.pre-commit-hooks.yaml" "$dest/.pre-commit-hooks.yaml"
for template in pyproject.toml README.md; do
  sed "s/@VERSION@/${version}/g" "$here/${template}.in" > "$dest/${template}"
done
