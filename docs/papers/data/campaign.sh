#!/usr/bin/env bash
d="$1"
slug=$(basename "$d")
./run_one.sh "$d" lock   conda "out/$slug.A.json" > "out/$slug.A.rc"
./run_one.sh "$d" prefix pypi  "out/$slug.B.json" > "out/$slug.B.rc"
echo "done $slug"
