# Using `pixi sbom`

`pixi-sbom` is a [pixi extension](https://pixi.sh/latest/integration/extensions/introduction/): a standalone
executable named `pixi-sbom`. Pixi finds any `pixi-<name>` binary on `PATH` (or in its own global bin directory) and
runs it when you type `pixi <name>`. There is no plugin registration; installing the binary is the whole setup.

## Installing

| Method | Command |
|---|---|
| pixi global (recommended) | `pixi global install pixi-sbom` |
| Prebuilt binary | Download `pixi-sbom-<version>-<platform>.tar.gz` (or `.zip` on Windows) from the [releases page](https://github.com/millsks/pixi-sbom/releases), verify the `.sha256` next to it, and put `pixi-sbom` on your `PATH` |
| From source | `pixi run build` in a clone, then copy `target/release/pixi-sbom` to `~/.pixi/bin/` |

Check it is picked up:

```sh
pixi --list          # ...  sbom  (via pixi-sbom)
pixi sbom --version
```

`pixi-sbom --help` and `pixi sbom --help` are equivalent; the binary can be run directly without pixi.

## Running

The command reads a `pixi.lock`, picks one environment and one platform from it, and writes one JSON document.

```sh
pixi sbom
```

With no options this means:

1. Find `pixi.lock` by searching the current directory, then each parent, until one is found (the same walk pixi
   itself does for its manifest).
2. Describe the `default` environment on the platform the command is running on (for example `osx-arm64`).
3. Write CycloneDX 1.6 JSON to `sbom.cdx.json` in the directory that contains the lockfile.

### Options

| Option | Default | Effect |
|---|---|---|
| `--lockfile <PATH>` | upward search from cwd | Lockfile to read. The file must exist; there is no fallback search when this is given. |
| `--format <cyclonedx\|spdx>` | `cyclonedx` | `cyclonedx` writes CycloneDX 1.6 JSON; `spdx` writes SPDX 2.3 JSON. |
| `--output <PATH>` | `<lockfile dir>/sbom.cdx.json` or `sbom.spdx.json` | File to write. Parent directories are created. With `--all-environments` this is a directory instead. |
| `-e, --environment <NAME>` | `default` | Lock environment to describe. Must exist in the lockfile. |
| `-p, --platform <PLATFORM>` | host platform | Platform within that environment, e.g. `linux-64`, `osx-arm64`, `win-64`. Must be locked for the environment. |
| `--all-environments` | off | Write one document per environment (see below). Cannot be combined with `--environment`. |
| `-v`, `-vv` | info | Raise the log level to debug / trace. Logs go to stderr; the SBOM never goes to stdout. |
| `-q`, `-qq`, `-qqq` | info | Lower it to warnings only / errors only / silent. Error diagnostics are printed regardless. |
| `-h, --help`, `-V, --version` | | Usual meanings. |

`RUST_LOG` is also honored and overrides `-v`/`-q` (for example `RUST_LOG=pixi_sbom::lock=debug`).

### Environment variables

| Variable | Effect |
|---|---|
| `SOURCE_DATE_EPOCH` | Pins the document timestamp (seconds since the Unix epoch). With it set, repeated runs over the same lockfile are byte-identical, which lets CI diff SBOMs between commits. See [output-format.md](output-format.md#reproducibility). |
| `RUST_LOG` | Log filter, overrides `-v`/`-q`. |

### Examples

```sh
# SPDX instead of CycloneDX
pixi sbom --format spdx

# A specific lockfile and output file, from anywhere
pixi sbom --lockfile ~/proj/pixi.lock --output ~/reports/proj.cdx.json

# The environment you actually ship, for the platform you ship it on
pixi sbom -e prod -p linux-64

# Every environment, each on linux-64, into a directory
pixi sbom --all-environments -p linux-64 --output sboms/
```

### One document per environment and platform

A pixi lockfile can hold many environments, each locked for several platforms. An SBOM, by contrast, is expected to
describe one deliverable, so `pixi sbom` never merges environments or platforms into one document:

- `--environment` / `--platform` pick exactly one combination.
- `--all-environments` runs that selection once per environment. Files are named `sbom-<environment>.cdx.json` /
  `sbom-<environment>.spdx.json`, `default` first, then the rest alphabetically. `--output` names the directory that
  receives them (default: next to the lockfile).
- Covering several platforms means running the command once per platform. A shell loop is enough:

  ```sh
  for p in linux-64 osx-arm64 win-64; do
    pixi sbom -p "$p" --output "sboms/sbom-$p.cdx.json"
  done
  ```

Each document records which environment and platform it describes (`pixi:environment` / `pixi:platform` in the
CycloneDX metadata properties; the root package `sourceInfo` in SPDX), so a batch of files stays self-describing.

## Exit codes and errors

| Exit code | Meaning |
|---|---|
| 0 | Document(s) written. |
| 1 | A runtime error; a diagnostic is printed to stderr. |
| 2 | Command-line usage error (unknown option, conflicting options). |

Runtime diagnostics carry a stable code you can grep for in CI logs:

| Code | When | Fix |
|---|---|---|
| `pixi_sbom::discover::not_found` | No `pixi.lock` in the current directory or any parent | Run `pixi lock` in the workspace, or pass `--lockfile` |
| `pixi_sbom::discover::missing` | `--lockfile` points at a file that does not exist | Check the path |
| `pixi_sbom::lock::parse` | The lockfile is not valid, or is newer than this build understands | Regenerate with `pixi lock`; upgrade `pixi-sbom` if the lockfile `version:` is newer than 7 |
| `pixi_sbom::lock::environment` | `--environment` names something not in the lockfile | The message lists the available environments |
| `pixi_sbom::lock::platform` | The chosen platform is not locked for that environment | The message lists the locked platforms; pass `-p` |
| `pixi_sbom::lock::current_platform` | The host platform could not be detected | Pass `-p` explicitly |
| `pixi_sbom::purl::invalid` | A package name the purl spec cannot encode | Report it with the lockfile entry |
| `pixi_sbom::format::io` / `serialize` | The output could not be written | Check the path and permissions; `--output` must not be an existing directory in single-environment mode |

Missing or unreadable manifests (`pixi.toml` / `pyproject.toml`) are not errors: the workspace name falls back to the
lockfile's directory name and a warning is logged.

## Running in CI

The binary has no runtime dependencies, so any job that can install pixi can produce SBOMs. With GitHub Actions and
[`setup-pixi`](https://github.com/prefix-dev/setup-pixi):

```yaml
- uses: prefix-dev/setup-pixi@v0.8.1
  with:
    run-install: false
- name: Generate SBOMs
  run: |
    pixi global install pixi-sbom
    pixi sbom --all-environments -p linux-64 --output sboms/
- uses: actions/upload-artifact@v4
  with:
    name: sboms
    path: sboms/
```

The lockfile is the only input, so this step does not need `pixi install` to have run first, and it works on a
different platform from the one being described (`-p linux-64` on a macOS runner is fine).

## Consuming the output

The documents validate against the official JSON schemas and load in the usual tooling. Examples:

```sh
# Convert between formats or inspect
syft convert sbom.cdx.json -o spdx-json
cyclonedx-cli validate --input-file sbom.cdx.json --input-format json

# Vulnerability scan
grype sbom:sbom.cdx.json
```

Conda packages are identified by `pkg:conda/...` purls with `channel`, `subdir`, `build` and `type` qualifiers; PyPI
packages by `pkg:pypi/...`. Where conda-forge publishes a PyPI purl for a conda package it is included too (see
[output-format.md](output-format.md)), which lets scanners that only know PyPI match conda-installed Python packages.
