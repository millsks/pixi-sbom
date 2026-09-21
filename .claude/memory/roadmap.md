---
name: roadmap
description: Post-0.1.0 review findings, the accepted 0.2.0 / 0.3.0 roadmap (issues #3-#11, milestones), and the goal
metadata:
  type: project
---

Review of v0.1.0 on 2026-09-19 (tests green, CycloneDX 1.6 + SPDX 2.3 schema-valid, binaries for 5 platforms).

Key evidence: a real 120-package conda-only Python env (`~/openteams`) yields 0 `pkg:pypi` purls, yet 69/120 (58%)
map to PyPI via the conda-forge mapping pixi itself uses
(`https://conda-mapping.prefix.dev/compressed-v0/compressed_mapping.json`, ~34k entries, ~950 KB). OSV/GHSA/trivy/grype
have no conda ecosystem, so `pkg:conda/...` alone matches nothing and scans come back falsely clean.

Roadmap accepted by the user 2026-09-19; tracked as GitHub issues #3-#11 under milestones 0.2.0 and 0.3.0.
Every PR references its issue (`Closes #n`). 0.2.0 PRs #12-#17 were merged 2026-09-19 and v0.2.0 released via the release workflow.
Lesson: when merging a stacked PR with `--delete-branch`, retarget the next PR to main FIRST; GitHub closes
(not retargets) a PR whose base branch disappears, and a retarget alone does not trigger CI (close/reopen does).

Roadmap:
- 0.2.0 "reproducible & compliant": lockfile path relative to workspace (no absolute local paths in output);
  `SOURCE_DATE_EPOCH` + UUIDv5 serial number for byte-identical reruns; `--output -` (stdout); `--all-platforms`;
  CISA 2026 minimum elements (authors from `[workspace] authors`, `metadata.lifecycles` phase, component `supplier`
  = channel / PyPI, root license/homepage/repository); conda-forge feedstock: staged-recipes PR #34888 merged 2026-09-19, feedstock pending (README already advertises
  `pixi global install pixi-sbom`, which does not work yet).
- 0.3.0 "scanner-actionable": opt-in PyPI identity enrichment from the prefix.dev mapping (offline file option),
  `--primary-purl pypi` so scanners that only read `purl` can match; optional PyPI license lookup; CycloneDX 1.7 as a
  selectable spec version.

0.3.0 PRs #19 (#8), #20 (#9), #21 (#10) merged 2026-09-19 and v0.3.0 released; ureq 3.4 (rustls, gzip,
platform-verifier) approved and added as the only HTTP client (src/http.rs). Goal measured on the openteams lock with
the live mapping: enriched=69/120, syft classifies them as python, grype matches an injected vulnerable urllib3 pin.

Goal: `pixi sbom --output - | grype` on a conda-only Python environment reports real findings; on the openteams lock,
>= 60/120 components carry a PyPI purl, and two runs with `SOURCE_DATE_EPOCH` set are byte-identical.

**Why:** the SBOM is only useful to the community if scanners can act on it and CI can diff it.
**How to apply:** create an issue before starting any new work item and reference it from the PR; network features stay opt-in; adding an HTTP client is a new runtime
dependency that needs user confirmation. See [[architecture-decisions]].

## 0.4.0 (released 2026-09-20) / 0.5.0 (planned)

User direction: license details must be visible for every package regardless of kind; `--pypi-licenses` alone is
useless on conda-majority lockfiles. Replace it with one generic `--fetch-licenses`.

- 0.4.0 "License details for every package" (milestone 3): #23 umbrella `--fetch-licenses` (deprecate
  `--pypi-licenses`); #24 conda details from the local rattler package cache (`<cache>/pkgs/<n>-<v>-<b>/info/`:
  about.json + licenses/); #25 network fallback range-reading the `info-*.tar.zst` member of `.conda` zips;
  #26 wheel `dist-info/licenses` texts via the same zip range reader; #27 output mapping (CycloneDX
  `licenses[].license.text`, SPDX extracted licensing infos / licenseComments, `--license-texts` opt-in);
  #28 `--report licenses` table/markdown/csv/json.
- 0.5.0 "Compliance and ecosystem" (milestone 4): #29 `--deny-license`/`--allow-license` exit 3; #30 PEP 770
  embedded wheel SBOMs; #31 SPDX 3.0.1 JSON-LD; #32 GitHub Action.

**How to apply:** #25/#26 add dependencies (zip reader, zstd, tar) that need user confirmation; keep everything
offline-first and never fail the run on a fetch error.

0.4.0 outcome (2026-09-20): PRs #34 (#23/#24/#27), #35 (#28/#33), #37 (#25), #38 (#26) merged; `zstd`, `tar`,
`flate2` approved and added. Lessons from CI: Windows runners check out fixtures with CRLF (normalize in tests that
rewrite lockfiles); a `file://` package location comes back from rattler as a path and must be rendered as a
`file://` URL; the runner's pixi cache already holds this project's own packages, so `--fetch-licenses` e2e tests
must pin `PIXI_CACHE_DIR` to an empty dir; CycloneDX `license.id` rejects `LicenseRef-*` (use `name`);
files.pythonhosted.org answers 416 to a suffix range longer than the file; ureq's body `limit(n)` errors on a body
of exactly n bytes (use n+1). `PIXI_SBOM_OFFLINE=1` forbids all network access and keeps e2e tests deterministic.

## 0.5.0 (released 2026-09-20)

PRs #41 (#29 policy gate), #42 (#32 GitHub Action, `action.yml` at the repo root, dogfooded by the `sbom` CI job),
#43 (#31 SPDX 3.0.1 JSON-LD, `--spec-version` now spans both formats), #44 (#30 PEP 770 embedded SBOMs,
`PackageKind::Embedded`). No new dependencies. Lessons: `Licensee` in the `spdx` crate rejects the `+` shorthand
and keeps deprecated ids distinct from `-only` forms (policy.rs canonicalizes both sides); the real `with-pypi`
fixture already has a conda `openssl`, so look embedded components up by purl in tests; an action referenced by
`uses: ./` has an empty `github.action_ref` and resolves to the latest release, so new CLI flags reach the
dogfood job only after the release that ships them.

Follow-up after the 0.5.0 release: add policy inputs to the action dogfood job and bump the `@v0.5.0` examples.
Candidate 0.6.0 themes: VEX / vulnerability annotations from a scanner run, `pixi global` manifests, conda
package-level SBOM convention once one exists, SPDX 3 embedded fragments.

## 0.5.1 (2026-09-20)

Bugfix milestone 5: #48 (PR #62, conda-forge "WITH exceptions" → `WITH AdditionRef-exceptions`, raw kept as
`pixi:license-raw`), #50 (PR #63, `spdx_reason` in reports and policy messages), #49 (PR #64, `.tar.bz2` archives
≤ 2 MiB downloaded whole; `bzip2` 0.6 with its default pure-Rust `libbz2-rs-sys` backend approved and added),
#47 (the release itself). Lesson: `git branch --merged main` also deletes a feature branch that has no commits yet;
stash, then recreate the branch from main. Future milestones 0.6.0 (#51–#54), 0.7.0 (#55–#58), 0.8.0 (#59–#61).
After 0.5.1 ships: re-enable `require-license: "true"` in the action dogfood job (needs the 0.5.1 binary).
