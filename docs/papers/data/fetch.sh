#!/usr/bin/env bash
repo="$1"; path="$2"
slug="${repo//\//__}"
out="corpus/$slug"
mkdir -p "$out"
if curl -sSfL --max-time 45 "https://raw.githubusercontent.com/$repo/HEAD/$path" -o "$out/pixi.lock" 2>/dev/null; then
  head -c 200 "$out/pixi.lock" | grep -q "^version:" && echo "$repo	$path	$(wc -c < "$out/pixi.lock")" || rm -rf "$out"
else
  rm -rf "$out"
fi
