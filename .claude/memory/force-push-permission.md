---
name: force-push-permission
description: Standing permission to force-push own feature branches after a rebase, and the merge-on-stale-checks trap it came from
metadata:
  type: feedback
---

Force-pushing a feature branch I created, which has an open PR and no other contributor, needs no confirmation
(`--force-with-lease` after rebasing onto main). Granted 2026-09-26 during the 0.9.5 work, when several PRs in
flight at once all needed rebasing. `main`, `gh-pages` and any shared branch still need asking, as the global
CLAUDE.md says.

**Why:** with five or six PRs open against a fast-moving main, rebasing is constant and each one is safe on a
branch nobody else touches.

**How to apply:** rebase, re-run `pixi run ci` **from the committed content** (not the working tree), then
`--force-with-lease`. Two traps that cost a broken `main` on 2026-09-26: a green `pixi run ci` run against a
working tree whose fix was never committed, and `gh pr checks` reporting the *previous* head's results seconds
after a force-push. The merge watcher in the session scratchpad now pins the head sha and refuses to merge unless
the passing checks belong to it.

A third trap broke `main` again on 2026-09-26: a background `watch-pr.sh` left running from an earlier parallel
batch merged PR #174 the moment its checks went green — but those checks had run against the base as it was
*before* PR #179 merged, and the two branches had each added a `stale`/`stale_services` pair to `src/cache.rs`.
Green checks only prove the head compiles against the base they ran on. Kill every leftover watcher before
merging anything else, and re-run the checks (or the local gate against the rebased branch) after the base
moves. Fixed by PR #180. See [[roadmap]].
