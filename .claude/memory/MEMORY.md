Project memory for millsks/pixi-sbom. Committed and public: nothing private or employer-related belongs here.
Issue and PR numbers from before 2026-10-11 refer to the original millsks/pixi-sbom (now millsks/pixi-sbom.org), and
from then until the split to aesir-oss/pixi-ext-contrib. This repository was aesir-oss/pixi-sbom until November 2026.

- [Architecture decisions](architecture-decisions.md) — rattler_lock, own CycloneDX/SPDX models, one SBOM per environment and platform, the modules once shared with pixi-policy
- [Roadmap](roadmap.md) — release-by-release history and plans, from 0.1.0 through the monorepo and back out
- [Not a scanner](not-a-scanner.md) — replace Syft, feed Grype; no new vulnerability sources or vuln DB
- [Minimal enrichment defaults](feedback-minimal-defaults.md) — the fact by default, bulky payloads behind their own flag
- [Issue delivery loop](issue-delivery-loop.md) — "guardrail"/"harness" = global CLAUDE.md §6 loop; merge with --squash --admin --delete-branch; never cut a release unasked
- [Releases](releases.md) — vX.Y.Z tags, rc to TestPyPI and final to PyPI, the action and pre-commit mirrors, where each era's releases live
- [Split from pixi-ext-contrib](split-from-pixi-ext-contrib.md) — what came with the history; pixi-ext-contrib deleted, the original millsks/pixi-sbom now millsks/pixi-sbom.org
- [Force-push permission](force-push-permission.md) — own feature branches, and the stale-check trap behind it
- [Changelog generation](release-notes-span-last-tag.md) — anchored tag_pattern; each release prepends its section, earlier ones are never regenerated
- [Marketplace listing](marketplace-listing.md) — the action ships from millsks/pixi-sbom-action; its listing needs a new name
- [Concurrent CI runs SIGKILL](concurrent-ci-sigkill.md) — SIGKILL in cov = two ci runs overlapping (mine + stop hook), not a failing test
- [Concurrent sessions and the Stop hook](concurrent-sessions-stop-hook.md) — two sessions in one tree: CI runs kill each other; mass failures may not be real
- [Dev environment](dev-environment.md) — local quirks: the Stop hook, pre-commit through pixi, tests reading repo-root files
