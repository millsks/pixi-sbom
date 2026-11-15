---
name: issue-delivery-loop
description: "pixi-sbom specifics for the standard guardrail/harness (issue delivery loop), which itself lives in global CLAUDE.md §6"
metadata:
  type: feedback
---

The "standard guardrail" / "harness" (branch, CI, PR, monitor to green, merge, sync main, clean branches, then the
next queued issue) is defined in global CLAUDE.md §6 "Issue delivery loop". Follow that.

millsks/pixi-sbom specifics on top of it:

- work on branches in millsks/pixi-sbom (`origin`) and open PRs against its `main`; sync `main` from `origin/main`

- merge with `gh pr merge <n> --repo millsks/pixi-sbom --squash --admin --delete-branch` (squash is the
  convention; `--admin` because `main`'s ruleset wants an approving review)
- PR bodies state what was measured, not just what changed
- gate the merge on the checks' result, counted after the watch ends: merge only when no check is non-passing. Never
  chain the merge after `gh pr checks --watch` in one command; in aesir-oss/pixi-ext-contrib that merged PR #107 with
  cargo-deny red.
- the release Build matrix runs on `main` only, so a green PR can still turn `main` red: after every merge, watch
  `main`'s CI run to the end before starting the next issue
- `pixi run ci` does not run cargo-deny; CI's `deny` job does. A change to `Cargo.toml` dependencies or `deny.toml`
  gets `pixi run -e lint deny` locally before the PR.

**Why:** the maintainer gave standing permission to run queued issues without re-asking, and made the loop their
standard across all projects.

**How to apply:** treat "guardrail" or "harness" in a request as meaning that loop. Cutting a release is never part
of it: ask first, every time.

Related: [[releases]], [[split-from-pixi-ext-contrib]].
