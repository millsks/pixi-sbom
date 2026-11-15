# CLAUDE.md

Project guidance for millsks/pixi-sbom. The global CLAUDE.md (toolchain, harness, git workflow) applies; this file
covers what is specific here. This project is **Rust**: the Python-specific parts of the global file (mypy, pytest,
structlog) apply only to the scripts in `scripts/`.

@.claude/memory/MEMORY.md

## Architecture

One crate, `pixi-sbom`, a binary pixi runs as `pixi sbom`: it writes CycloneDX and SPDX SBOMs from `pixi.lock` and
other lockfiles, and reports on them. See [docs/architecture.md](docs/architecture.md) for the pipeline and modules.

| Path | What it is |
|---|---|
| `src/` | the crate |
| `tests/` | end-to-end, matrix, network and stability tests, with fixtures and schemas |
| `benches/` | criterion benchmarks |
| `data/` | the CPE, CRAN and bundled-library tables compiled in |
| `actions/pixi-sbom/` | the GitHub Action's source, copied to `millsks/pixi-sbom-action` on each final release |
| `pre-commit-mirror/` | the templates `millsks/pixi-sbom-pre-commit` is rendered from on each final release |
| `pyproject.toml` | maturin `bindings = "bin"`: the binary as platform wheels for PyPI |
| `docs/`, `mkdocs.yml` | the docs site (MkDocs Material, versioned with mike) at millsks.github.io/pixi-sbom |
| `examples/` | example projects and lockfiles the tests and docs run against |
| `scripts/` | Python maintenance and release tooling, each with a `test_*.py` |

## Commands

Everything runs through pixi.

| Task | Command |
|---|---|
| Format, lint, check | `pixi run fmt`, `pixi run lint` (clippy `-D warnings`), `pixi run check` |
| Tests | `pixi run test`; one test: `pixi run cargo test --test cli <name>` |
| Full gate | `pixi run ci` (pre-commit, build, check, clippy, coverage ≥ 90%); the Stop hook runs it |
| Docs | `pixi run -e docs docs-build` (strict), `pixi run -e docs docs-serve` |
| Workflows | `pixi run actionlint` |
| Script tests | `pixi run action-test`, `cpe-upkeep-test`, `cran-table-test`, `whats-new-test`, … (see `pixi.toml`) |

## Releases

- Started by the Release workflow (`workflow_dispatch`, `version` input). It bumps the version, moves What's new's
  `## Unreleased` into the release's section, adds the release's section to `CHANGELOG.md`, commits and tags
  `vX.Y.Z` with the release App; the tag starts `release-artifacts.yml`.
- Release candidates go to TestPyPI, finals to PyPI, with trusted publishing.
- Ask before cutting any release. After every release candidate, the maintainer runs a private field test; see the
  private (uncommitted) project memory.

## Off-limits and traps

- `CHANGELOG.md`'s existing sections are never edited or regenerated; each release adds its own on top
  (`scripts/changelog.sh`). Fix `cliff.toml` or the script, never the file.
- Never bump versions or push tags by hand. Pushing three or fewer `v*` tags starts a release.
- `gh-pages` holds the built docs site; never merge it anywhere.
- `millsks/pixi-sbom-action` and `millsks/pixi-sbom-pre-commit` are generated: change `actions/pixi-sbom/` and
  `pre-commit-mirror/` instead.
- `examples/projects/` lockfiles are regenerated with `pixi run -e examples examples`, not edited.
- `.claude/memory/` is public. Nothing private, personal or about the maintainer's employer goes in it.
- The original `millsks/pixi-sbom` (up to 1.11.x, and the deprecated `uses: millsks/pixi-sbom@v1` wrapper) is now
  `millsks/pixi-sbom.org`; this repository, moved from `aesir-oss/pixi-sbom`, took its name. Every release, including
  those first made there and in the deleted `aesir-oss/pixi-ext-contrib`, is in this repository's release list, which
  is the only one the action reads.
- Work happens on branches in `millsks/pixi-sbom` (`origin`), with PRs to its `main`.
