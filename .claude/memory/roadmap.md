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

## 0.5.5 (milestone 9, planned 2026-09-20): documentation site

MkDocs Material site for `docs/` at https://millsks.github.io/pixi-sbom, deployed by a `docs.yml` workflow on
`release: published`. Issues in order: #66 scaffold (`mkdocs.yml`, `docs` pixi feature/environment, strict build
CI job), #67 content restructure, #68 Pages deploy (enabling Pages is a repo setting: confirm first), #69 `mike`
versioning, #70 links from README / Cargo.toml / action.yml / feedstock. User chose 0.5.5 (not 0.8.5) so the
milestone number keeps release order; it runs before 0.6.0.

Outcome (2026-09-21): PRs #72 (#66), #73 (#67), #75 (#68), #76 (#70 + #74 Marketplace: description cut to 116
chars), #77 (#69). Palette stays teal (user choice; light mode default). Pages enabled via API with source
"GitHub Actions"; mike deploys each MAJOR.MINOR to gh-pages with `latest` as a *copy* (Pages does not serve
symlinks) and the branch is uploaded as the Pages artifact. Links use `/latest/...`. Feedstock metadata PR
conda-forge/pixi-sbom-feedstock#7 points `about` at the site. The Marketplace listing is a one-time UI step the
user does on the 0.5.5 release. Lesson: `gh repo clone` of a fork already adds `upstream`; and `mkdocs_hooks.py`
publishes CHANGELOG.md as a page without copying it into docs/.

## 0.6.0 (2026-09-21): vulnerabilities

PRs #82 (cache moved inside the pixi cache dir so `pixi clean cache` clears it), #83 (#51 `--vulnerabilities osv`,
`src/osv.rs` + `src/cvss.rs`; GHSA/PYSEC twins merged by alias; matches grype's id set), #84 (#52 `--report
vulnerabilities`), #85 (#53 `--fail-on-severity` exit 4, `--ignore-vuln ID[:STATE][:TEXT]` → CycloneDX
`analysis`), #86 (#81 `--kev` / `--fail-on-kev`, CISA catalog cached a day, synthetic fixture entry documented),
#87 (#54 SARIF 2.1.0 + action inputs `vulnerabilities`, `kev`, `fail-on-severity`, `fail-on-kev`, `ignore-vuln`
one per line, `fail-on-vulnerabilities`, `upload-sarif`, `sarif-category`). No new crates. Lessons: OSV's
`querybatch` reports `modified` in microseconds and records in nanoseconds (compare by microsecond); OSV omits
list fields but jq-made fixtures write `null` (accept both); a `--report` run in the repo root wrote a stray
`sbom.cdx.json` once (never commit generated output); `git add -A` leaked an unrelated new file into a PR (add
paths explicitly). Test workspace with vulnerable pins: `/tmp/pixi-sbom-test-vulns` (84 OSV findings).
After the release: dogfood job gets `vulnerabilities: osv`, `kev`, `upload-sarif` (+ `security-events: write`).

## 0.7.0 (2026-09-21): inputs and configuration

PRs #90 (#57 `--exclude` / `--include` / `--exclude-kind` / `--keep-orphans`, graph re-closure from the original
roots, `pixi:excluded`), #91 (#58 config file: `[tool.pixi-sbom]` in pyproject.toml wins over `pixi-sbom.toml`,
`--config` / `--no-config`; clap `requires` on the vulnerability flags replaced by `main::validate` so the file can
supply either side; action `config` input, `pypi-mapping` / `primary-purl` inputs now empty by default), #92 (#56
`--report diff --against`, all four document flavours read back; new-side licenses normalized before comparing),
#93 (#55 `--prefix`: conda-meta + dist-info, `lock::link_dependencies` shared, `pixi:prefix`, `--name` /
`--root-version` because `--version` is clap's). Lessons: `git stash -u` + rebase conflicts twice (branch from an
up-to-date main, or rebase before writing); a typos-flagged word in a test string ("fromat") fails the gate, use a
neutral unknown key; the user's `pixi global` pixi-sbom env was still 0.3.0.

## 0.8.0 (2026-09-21): supply chain and install paths

PRs #95 (#59 action `attest` / `attest-subject`: attest-sbom with a subject, attest-build-provenance otherwise;
dogfood attests on pushes to main and runs `gh attestation verify`), #99 (#61 rescoped to cargo binstall:
`[package.metadata.binstall]` per-target overrides for the pixi-platform-named archives, crate `exclude` list,
`cargo publish --locked` in release.yml guarded by `CARGO_REGISTRY_TOKEN`, which the user added 2026-09-21).
#60 spike closed: conda-forge serves no attestations, CEP 27 defines the statement, conda/ceps#142 (open) the
`.sigs` sidecars, rattler_sigstore unreleased; implementation deferred to #96 (no milestone). Backlog: #97
Homebrew tap, #98 winget. Lesson: `cargo-binstall --manifest-path . --dry-run` validates the metadata against a
real release before publishing.

## 0.9.0 (2026-09-24/25): functionality before v1.0.0

Ten issues, each its own PR, merged in the order the user approved: #135 (#123 `--report python`), #136 (#127
manifest dependency tables → `pixi:direct` / `pixi:declared-in`, root edges are the declared set ∪ graph roots),
#137 (#128 `--report phantom`: `src/imports.rs` tokenizer, `src/stdlib.rs` table, `src/phantom.rs`), #138 (#107
`--fail-on-diff` exit 6 + action `diff-against` / `fail-on-diff` writing the comparison to the job summary),
#139 (#125 `--prefix --against pixi.lock` drift with `pip` and `build` sections; `--against` now resolves to a
document, a lockfile or a prefix), #140 (#120 `--scan <DIR>`; `main` iterates workspaces × targets), #141 (#126
`--from-sbom`, new `PackageKind::External`, `pixi:source-document`), #142 (#108 `--ignore-license`), #143 (#109
`--vex` + `--vex-open`), #144 (#106 `--tree` / `--depth` / `--group-by license`), #145 (#110 cargo auditable),
#146 (#124 `--scorecard`).

User decisions this milestone: `--scan` skips hidden dirs and a fixed list but **not** `.gitignore`d paths (no
`ignore` crate; lockfiles are committed anyway) — refile if it is ever wanted; the `object` crate (default
features off, `read_core,elf,macho,pe,std`, brings only `memchr`) was approved for #110 rather than hand-rolling
three section parsers, and `auditable-serde` was not needed on top of it.

Exit codes now in use: 3 license policy, 4 vulnerability gate, 6 `--fail-on-diff`, 7 `--fail-on-yanked`,
8 `--fail-on-phantom`, 9 `--fail-on-scorecard`.

Lessons: `bool::then_some(expr)` evaluates `expr` eagerly (a `total - MAX` underflowed at runtime; use
`then(|| ...)`); adding an `f64` field to `config::Config` means dropping its `Eq` derive (and `Loaded`'s);
`pkgcache::read_extracted` treats a directory without `info/index.json` as an incomplete extraction, so a test
fixture needs one to be read at all; `gh pr checks` output is tab-separated and BSD grep has no `\s`, so the merge
watcher parses it with awk; a squash merge leaves the local branch behind — stash the next feature's work,
`git checkout main && git pull`, delete the branch, then branch again.

Follow-ups: the action dogfood job could exercise `scorecard`, `vex` and `diff-against`; the `--scan` gitignore
question stays open; #96 (CEP 27 attestation verification), #97 (Homebrew tap), #98 (winget) and #132 (conda
channel removals) remain unscheduled.
