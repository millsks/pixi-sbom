# pixi-sbom

A [pixi](https://pixi.sh) extension that generates a Software Bill of Materials (SBOM) from a `pixi.lock` file, in
[CycloneDX](https://cyclonedx.org) 1.6 or [SPDX](https://spdx.dev) 2.3 JSON.

[![CI](https://github.com/millsks/pixi-sbom/actions/workflows/ci.yml/badge.svg)](https://github.com/millsks/pixi-sbom/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## Installation

```sh
pixi global install pixi-sbom
```

Or build from source and put the `pixi-sbom` binary on your `PATH`:

```sh
pixi run build
cp target/release/pixi-sbom ~/.pixi/bin/
```

Pixi discovers any `pixi-<name>` executable on `PATH` and exposes it as `pixi <name>`.

## Quick start

```sh
# CycloneDX SBOM for the default environment, written next to pixi.lock as sbom.cdx.json
pixi sbom

# SPDX instead
pixi sbom --format spdx

# Explicit lockfile and output path
pixi sbom --lockfile /path/to/pixi.lock --output /tmp/my-project.cdx.json

# A different environment / platform
pixi sbom -e prod -p linux-64
```

| Option | Default | Description |
|---|---|---|
| `--lockfile <PATH>` | search upward from cwd | `pixi.lock` to read |
| `--format <cyclonedx\|spdx>` | `cyclonedx` | SBOM format |
| `--output <PATH>` | `<lockfile dir>/sbom.cdx.json` or `sbom.spdx.json` | Where to write the SBOM |
| `-e, --environment <NAME>` | `default` | Lock environment to describe |
| `-p, --platform <PLATFORM>` | current platform | Platform within that environment |

## Development

```sh
pixi install            # toolchain (rust, cargo-llvm-cov, pre-commit, ...)
pixi run bootstrap      # install git hooks
pixi run test           # cargo test
pixi run lint           # clippy with -D warnings
pixi run cov            # coverage gate (>= 90% lines)
pixi run ci             # full gate: pre-commit, build, check, lint, cov
```

## License

Apache-2.0. See [LICENSE](LICENSE).
