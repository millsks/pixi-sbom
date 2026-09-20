#!/usr/bin/env bash
# Claude Code Stop hook: the change harness gate (CLAUDE.md section 6).
#
# Runs `pixi run ci` when the working tree differs from the state that last passed, and
# blocks the stop (exit 2) with the tail of the log when it fails, so the failure reaches
# Claude instead of only the terminal. Unchanged trees are skipped, so a stop that only
# asked a question costs nothing.
set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)" || exit 0
[ -f pixi.toml ] || exit 0

marker=.pixi/.last-ci-ok
log=.pixi/.last-ci.log
mkdir -p .pixi

# Fingerprint of everything the gate can see: HEAD, staged and unstaged changes, untracked files.
state=$( {
  git rev-parse HEAD 2>/dev/null
  git diff HEAD 2>/dev/null
  git ls-files --others --exclude-standard -z 2>/dev/null | xargs -0 shasum -a 256 2>/dev/null
} | shasum -a 256 | cut -d' ' -f1 )

if [ -f "$marker" ] && [ "$(cat "$marker")" = "$state" ]; then
  exit 0
fi

if pixi run ci >"$log" 2>&1; then
  printf '%s\n' "$state" >"$marker"
  exit 0
fi

rm -f "$marker"
{
  echo "pixi run ci failed (full log: $log). Last 40 lines:"
  tail -n 40 "$log"
} >&2
exit 2
