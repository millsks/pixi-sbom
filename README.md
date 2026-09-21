# pixi-sbom

A [pixi](https://pixi.sh) extension that generates a Software Bill of Materials (SBOM) from a `pixi.lock` file, in
[CycloneDX](https://cyclonedx.org) 1.6 / 1.7 or [SPDX](https://spdx.dev) 2.3 / 3.0.1 JSON.

[![CI](https://github.com/millsks/pixi-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/millsks/pixi-sbom/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-millsks.github.io%2Fpixi--sbom-teal.svg)](https://millsks.github.io/pixi-sbom/)

Full documentation: **https://millsks.github.io/pixi-sbom/**

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

# Pipe into a scanner instead of writing a file
pixi sbom --output - | grype

# Licenses for every package, conda and PyPI alike (add --license-texts for the full texts)
pixi sbom --fetch-licenses

# Include what maturin compiled into the wheels (PEP 770 embedded SBOMs)
pixi sbom --embedded-sboms

# Fail CI on copyleft or unlicensed packages (exit code 3, document still written)
pixi sbom --fetch-licenses --deny-license GPL-3.0-only --require-license

# Known vulnerabilities from OSV, recorded in the document (conda packages match via their PyPI purl)
pixi sbom --pypi-mapping prefix --vulnerabilities osv

# ... or as a table, worst first
pixi sbom --pypi-mapping prefix --vulnerabilities osv --report vulnerabilities

# Fail CI on anything high or critical, except a finding assessed as not affecting you (exit code 4)
pixi sbom --pypi-mapping prefix --vulnerabilities osv --fail-on-severity high --ignore-vuln "CVE-2023-43804:not reachable"

# Flag what CISA lists as actively exploited, and fail on it
pixi sbom --pypi-mapping prefix --vulnerabilities osv --kev --fail-on-kev

# Just look: an inventory or license table in the terminal, nothing written
pixi sbom --report packages
pixi sbom --fetch-licenses --report licenses --report-format markdown

# Make conda-installed Python packages scannable: add PyPI purls from the
# conda-forge mapping and use them as the primary identity
pixi sbom --pypi-mapping prefix --primary-purl pypi --output - | grype

# Explicit lockfile and output path
pixi sbom --lockfile /path/to/pixi.lock --output /tmp/my-project.cdx.json

# A different environment / platform
pixi sbom -e prod -p linux-64

# One SBOM per environment: sbom-default.cdx.json, sbom-prod.cdx.json, ...
pixi sbom --all-environments

# ... into a directory of your choice
pixi sbom --all-environments --format spdx --output reports/

# Every environment on every platform: sbom-<environment>-<platform>.cdx.json
pixi sbom --all-environments --all-platforms --output reports/
```

| Option | Default | Description |
|---|---|---|
| `--lockfile <PATH>` | search upward from cwd | `pixi.lock` to read |
| `--format <cyclonedx\|spdx>` | `cyclonedx` | SBOM format |
| `--spec-version <1.6\|1.7\|2.3\|3.0>` | `1.6` / `2.3` | CycloneDX or SPDX version (`3.0` is the SPDX 3.0.1 JSON-LD graph) |
| `--output <PATH>` | `<lockfile dir>/sbom.cdx.json` or `sbom.spdx.json` | Where to write the SBOM; `-` for stdout |
| `-e, --environment <NAME>` | `default` | Lock environment to describe |
| `--all-environments` | off | Write one `sbom-<environment>` file per environment instead; `--output` is then a directory |
| `-p, --platform <PLATFORM>` | current platform | Platform within that environment |
| `--all-platforms` | off | Write one `sbom-<platform>` file per locked platform instead (`sbom-<environment>-<platform>` with `--all-environments`) |
| `--pypi-mapping <lock\|prefix>` | `lock` | `prefix` adds `pkg:pypi` purls to conda-forge packages from the mapping pixi uses (cached daily) |
| `--pypi-mapping-file <PATH>` | | Offline copy of that mapping |
| `--primary-purl <conda\|pypi>` | `conda` | `pypi` makes the PyPI purl primary so grype / trivy / osv-scanner can match |
| `--config` / `--no-config` | auto | Read `[tool.pixi-sbom]` in `pyproject.toml` or `pixi-sbom.toml` next to the lockfile before the command line; keys mirror the flags, the command line wins |
| `--exclude` / `--include` / `--exclude-kind` | | Leave packages out (shell-style name patterns or a kind); what only they needed goes too, and the root records `pixi:excluded` |
| `--fetch-licenses` | off | Licenses for every package, conda and PyPI alike (conda from the local package cache or the channel archive, PyPI from the wheel or the index), plus license file names, summary and URLs |
| `--license-texts` | off | With `--fetch-licenses`, embed the full license texts |
| `--allow-license` / `--deny-license` / `--require-license` | | License policy; violations are listed and the run exits 3 after writing the document |
| `--vulnerabilities osv` | off | Look every package with a PyPI / crates.io / npm purl up on [OSV](https://osv.dev) and record the findings in CycloneDX `vulnerabilities[]` (severity, CVSS, fixed version, aliases) |
| `--kev` / `--fail-on-kev` | off | Mark findings in CISA's Known Exploited Vulnerabilities catalog (rated critical, with due dates); optionally exit 4 on them |
| `--fail-on-severity` / `--ignore-vuln` | | Vulnerability gate: exit 4 on open findings at or above a severity; accepted findings keep a VEX-style `analysis` block |
| `--embedded-sboms` | off | Attach the components declared by SBOMs embedded in wheels (PEP 770, e.g. Rust crates) under the wheel |
| `--report <packages\|licenses\|vulnerabilities>` | | Print a table to the terminal instead of writing a document (`--report-format table\|markdown\|csv\|json`, plus `sarif` for vulnerabilities) |
| `-v` / `-q` | info | More / less logging on stderr |

Output is reproducible: the document identifier is derived from the lockfile, and setting `SOURCE_DATE_EPOCH` pins
the timestamp so repeated runs are byte-identical.

One document describes one environment on one platform, which is what SBOM consumers expect. Use
`--all-environments` and `--all-platforms` to cover every environment and platform in the lockfile in one run.

## What goes in the SBOM

| Lockfile data | CycloneDX 1.6 / 1.7 | SPDX 2.3 |
|---|---|---|
| Workspace name, version, license, homepage, repository (from `pixi.toml` / `pyproject.toml`) | `metadata.component` | root package, `DESCRIBES` relationship |
| Workspace authors | `metadata.authors[]` | `creationInfo.creators[]` (`Person:`) |
| Generation context (`pre-build`: derived from the lockfile) | `metadata.lifecycles[]` | `creationInfo.comment` |
| conda, pixi-build source, and PyPI packages | `components[]` (`type: library`) | `packages[]` |
| Package URL (`pkg:conda/...`, `pkg:pypi/...`) | `purl`, `bom-ref` | `externalRefs[]` (PACKAGE-MANAGER / purl) |
| PyPI identity of a conda package (lockfile `purls:`, or `--pypi-mapping`) | `pixi:purl` property, or `purl` with `--primary-purl pypi` | extra `externalRefs[]` entry |
| Supplier (conda channel or PyPI index) | `supplier` | `supplier` (`Organization:`) |
| Download URL | `externalReferences[distribution]` | `downloadLocation` |
| SHA-256 / MD5 | `hashes[]` | `checksums[]` |
| License (conda: from the lockfile; PyPI: with `--fetch-licenses`) | `licenses[].expression`, or `.license.name` for non-SPDX text |
| License file names, summary, project URLs (`--fetch-licenses`); texts (`--license-texts`) | `pixi:license-file` properties, `description`, `externalReferences[]`; `licenses[].license.text` | `licenseComments`, `summary`, `homepage`; extracted licensing infos | `licenseDeclared`, with `LicenseRef-pixi-*` + `hasExtractedLicensingInfos` for non-SPDX text |
| Channel, subdir, build string, build number, size, index URL, ... | `properties[]` (`pixi:*`) | package `comment` (`key=value` lines) |
| Dependency graph (resolved within the environment) | `dependencies[]` | `DEPENDS_ON` relationships |
| Environment, platform, lockfile name | `metadata.properties[]` | root package `sourceInfo` |

The documents cover every [CISA 2026 SBOM minimum element](https://www.cisa.gov/sbom) that a lockfile can support:
author, timestamp, tool, generation context, and per component the name, version, supplier, purl, hashes, license and
dependency relationships.

License strings are checked with the SPDX license list. Valid expressions (including deprecated identifiers still used
on conda-forge) pass through unchanged; lenient spellings such as `MIT/Apache-2.0` are rewritten canonically; anything
else is preserved as free text.

## GitHub Action

The repository is also a GitHub Action that downloads the release binary, generates the documents and uploads them
as an artifact; no pixi setup needed:

```yaml
- uses: actions/checkout@v4
- uses: millsks/pixi-sbom@v0.5.1
  with:
    all-environments: "true"
    fetch-licenses: "true"
    deny-license: "GPL-3.0-only AGPL-3.0-only"
```

See the [GitHub Action page](https://millsks.github.io/pixi-sbom/latest/github-action/) for every input, or the
[Marketplace listing](https://github.com/marketplace/actions/pixi-sbom).

## Documentation

| | |
|---|---|
| [Installation](https://millsks.github.io/pixi-sbom/latest/installation/) | pixi global, release binaries, building from source |
| [Command-line reference](https://millsks.github.io/pixi-sbom/latest/cli/) | Every option, the license policy, terminal reports, batch mode, environment variables, exit codes and error messages |
| [GitHub Action](https://millsks.github.io/pixi-sbom/latest/github-action/) | The action's inputs and outputs, with a worked example |
| [CI recipes](https://millsks.github.io/pixi-sbom/latest/ci-recipes/) | Scanning with grype, license tables in PR comments, diffing SBOMs, air-gapped runners |
| [Which format to pick](https://millsks.github.io/pixi-sbom/latest/formats/) | CycloneDX 1.6 / 1.7 against SPDX 2.3 / 3.0.1 |
| [Output format reference](https://millsks.github.io/pixi-sbom/latest/output-format/) | Field-by-field reference for the CycloneDX and SPDX documents, purls, licenses, dependency graph |
| [Architecture](https://millsks.github.io/pixi-sbom/latest/architecture/) | Pipeline, modules, and the design decisions behind them |
| [Development](https://millsks.github.io/pixi-sbom/latest/development/) | Toolchain, tasks, the change harness, tests and fixtures, conventions, releasing |
| [Changelog](https://millsks.github.io/pixi-sbom/latest/changelog/) | Every release's notes |

The pages are the Markdown files in [`docs/`](docs/), so they can be read in the repository too.

## Development

```sh
pixi install            # toolchain (rust, cargo-llvm-cov, pre-commit, ...)
pixi run bootstrap      # install git hooks
pixi run test           # cargo test (unit + end-to-end)
pixi run lint           # clippy with -D warnings
pixi run cov            # coverage gate (>= 90% lines)
pixi run ci             # full gate: pre-commit, build, check, lint, cov
```

Cargo is never invoked directly; every command is a pixi task so the pinned toolchain is always used. End-to-end
tests validate generated documents against the official JSON schemas vendored in `tests/schemas/`. See
the [development page](https://millsks.github.io/pixi-sbom/latest/development/) for the full workflow, test layers, fixtures,
and the release process.

## License

Apache-2.0. See [LICENSE](LICENSE).
