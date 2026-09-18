# pixi-sbom

A [pixi](https://pixi.sh) extension that generates a Software Bill of Materials (SBOM) from a `pixi.lock` file, in
[CycloneDX](https://cyclonedx.org) 1.6 or [SPDX](https://spdx.dev) 2.3 JSON.

[![CI](https://github.com/millsks/pixi-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/millsks/pixi-sbom/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Installation

```sh
pixi global install pixi-sbom
```

Or download a binary from the [releases page](https://github.com/millsks/pixi-sbom/releases) and put it on your
`PATH`, or build from source:

```sh
pixi run build
cp target/release/pixi-sbom ~/.pixi/bin/
```

Pixi discovers any `pixi-<name>` executable on `PATH` and exposes it as `pixi <name>`; `pixi --list` shows it.

## Quick start

```sh
# CycloneDX SBOM for the default environment on this platform,
# written next to pixi.lock as sbom.cdx.json
pixi sbom

# SPDX instead (sbom.spdx.json)
pixi sbom --format spdx

# Explicit lockfile and output path
pixi sbom --lockfile /path/to/pixi.lock --output /tmp/my-project.cdx.json

# A different environment / platform
pixi sbom -e prod -p linux-64

# One SBOM per environment: sbom-default.cdx.json, sbom-prod.cdx.json, ...
pixi sbom --all-environments

# ... into a directory of your choice
pixi sbom --all-environments --format spdx --output reports/
```

| Option | Default | Description |
|---|---|---|
| `--lockfile <PATH>` | search upward from cwd | `pixi.lock` to read |
| `--format <cyclonedx\|spdx>` | `cyclonedx` | SBOM format |
| `--output <PATH>` | `<lockfile dir>/sbom.cdx.json` or `sbom.spdx.json` | Where to write the SBOM |
| `-e, --environment <NAME>` | `default` | Lock environment to describe |
| `--all-environments` | off | Write one `sbom-<environment>` file per environment instead; `--output` is then a directory |
| `-p, --platform <PLATFORM>` | current platform | Platform within that environment |
| `-v` / `-q` | info | More / less logging on stderr |

One document describes one environment on one platform, which is what SBOM consumers expect. Use
`--all-environments` to cover every environment in the lockfile in one run (each on the selected platform), or run
the command once per platform you ship.

## What goes in the SBOM

| Lockfile data | CycloneDX 1.6 | SPDX 2.3 |
|---|---|---|
| Workspace name/version (from `pixi.toml` / `pyproject.toml`) | `metadata.component` | root package, `DESCRIBES` relationship |
| conda, pixi-build source, and PyPI packages | `components[]` (`type: library`) | `packages[]` |
| Package URL (`pkg:conda/...`, `pkg:pypi/...`) | `purl`, `bom-ref` | `externalRefs[]` (PACKAGE-MANAGER / purl) |
| Download URL | `externalReferences[distribution]` | `downloadLocation` |
| SHA-256 / MD5 | `hashes[]` | `checksums[]` |
| License | `licenses[].expression`, or `.license.name` for non-SPDX text | `licenseDeclared`, with `LicenseRef-pixi-*` + `hasExtractedLicensingInfos` for non-SPDX text |
| Channel, subdir, build string, build number, size, index URL, ... | `properties[]` (`pixi:*`) | package `comment` (`key=value` lines) |
| Dependency graph (resolved within the environment) | `dependencies[]` | `DEPENDS_ON` relationships |
| Environment, platform, lockfile path | `metadata.properties[]` | root package `sourceInfo` |

License strings are checked with the SPDX license list. Valid expressions (including deprecated identifiers still used
on conda-forge) pass through unchanged; lenient spellings such as `MIT/Apache-2.0` are rewritten canonically; anything
else is preserved as free text.

## Development

```sh
pixi install            # toolchain (rust, cargo-llvm-cov, pre-commit, ...)
pixi run bootstrap      # install git hooks
pixi run test           # cargo test (unit + end-to-end)
pixi run lint           # clippy with -D warnings
pixi run cov            # coverage gate (>= 90% lines)
pixi run ci             # full gate: pre-commit, build, check, lint, cov
```

End-to-end tests validate generated documents against the official JSON schemas vendored in `tests/schemas/`.
Lockfile fixtures in `tests/fixtures/` were produced by `pixi lock` on the tiny workspaces committed next to them.

### Releasing

Tag `vX.Y.Z` on `main`. The release workflow builds binaries for linux-64, linux-aarch64, osx-64, osx-arm64 and
win-64, and publishes a GitHub release with notes from git-cliff. `recipe/recipe.yaml` is the starting point for the
conda-forge feedstock that backs `pixi global install pixi-sbom`.

## License

Apache-2.0. See [LICENSE](LICENSE).
