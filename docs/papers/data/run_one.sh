#!/usr/bin/env bash
# $1 = workspace dir, $2 = mapping (lock|prefix), $3 = primary purl (conda|pypi), $4 = out file
BIN=/Users/millsks/UserLocal/apps/src/code/Public-Git/millsks/pixi-sbom/target/release/pixi-sbom
"$BIN" --lockfile "$1/pixi.lock" --platform linux-64 \
  --pypi-mapping "$2" --primary-purl "$3" \
  --vulnerabilities osv --kev --output "$4" >/dev/null 2>"$4.err"
echo "$?"
