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
3. Write CycloneDX 1.6 JSON (`--spec-version 1.7` for 1.7; `--format spdx` for SPDX 2.3, with `--spec-version 3.0`
   for SPDX 3.0.1) to `sbom.cdx.json` in the directory that contains the lockfile.

### Options

| Option | Default | Effect |
|---|---|---|
| `--lockfile <PATH>` | upward search from cwd | Lockfile to read. The file must exist; there is no fallback search when this is given. |
| `--format <cyclonedx\|spdx>` | `cyclonedx` | `cyclonedx` writes CycloneDX JSON; `spdx` writes SPDX 2.3 JSON. |
| `--spec-version <1.6\|1.7\|2.3\|3.0>` | `1.6` / `2.3` | Specification version: `1.6` or `1.7` for CycloneDX (1.7 adds a `citations` entry), `2.3` or `3.0` for SPDX (3.0 is the JSON-LD graph of SPDX 3.0.1). Defaults stay at 1.6 / 2.3 until the common consumers move. A version of the other format is a usage error. |
| `--output <PATH>` | `<lockfile dir>/sbom.cdx.json` or `sbom.spdx.json` | File to write; parent directories are created. `-` writes the document to stdout (logs stay on stderr). With `--all-environments` / `--all-platforms` this is a directory instead, and `-` is rejected. |
| `-e, --environment <NAME>` | `default` | Lock environment to describe. Must exist in the lockfile. |
| `-p, --platform <PLATFORM>` | host platform | Platform within that environment, e.g. `linux-64`, `osx-arm64`, `win-64`. Must be locked for the environment. |
| `--all-environments` | off | Write one document per environment (see below). Cannot be combined with `--environment`. |
| `--all-platforms` | off | Write one document per platform the environment is locked for (see below). Cannot be combined with `--platform`. |
| `--pypi-mapping <lock\|prefix>` | `lock` | Where PyPI identities for conda packages come from. `prefix` downloads the conda-forge mapping (cached for a day) so conda-installed Python packages get a `pkg:pypi` purl. |
| `--pypi-mapping-file <PATH>` | | Offline copy of that mapping; implies the same enrichment with no network. Cannot be combined with `--pypi-mapping`. |
| `--primary-purl <conda\|pypi>` | `conda` | With `pypi`, a conda package that has a PyPI purl uses it as its primary `purl` so vulnerability scanners can match it. |
| `--fetch-licenses` | off | Fetch the license of every package, conda and PyPI alike, where the lockfile has none, plus the names of the license files it ships and its summary and project URLs. Conda details come from the local package cache pixi filled at install time, or from the archive on the channel via HTTP range requests (a few KB per package, cached); PyPI details from the wheel's `dist-info` the same way, then the index JSON API for what is still missing. Failures are logged and the run continues. |
| `--license-texts` | off | With `--fetch-licenses`, also embed the full text of every license file. |
| `--embedded-sboms` | off | Add the components declared by SBOMs embedded in wheels (PEP 770, e.g. the Rust crates maturin compiled in) as dependencies of the wheel. Reads each wheel's `dist-info` like `--fetch-licenses`. |
| `--allow-license <LICENSE>` | | Repeatable. Only these SPDX licenses are acceptable; a package whose license expression cannot be satisfied with them alone is a violation. |
| `--deny-license <LICENSE>` | | Repeatable. These SPDX licenses are unacceptable; a package whose expression cannot be satisfied without them is a violation. |
| `--require-license` | off | Every package must declare a license that is an SPDX expression. |
| `--report <packages\|licenses>` | | Print a report to the terminal instead of writing a document (see below). Cannot be combined with `--output`. |
| `--report-format <table\|markdown\|csv\|json>` | `table` | How to render the report. |
| `--pypi-licenses` | | Deprecated alias for `--fetch-licenses` (hidden from `--help`; removed in a future release). |
| `-v`, `-vv` | info | Raise the log level to debug / trace. Logs go to stderr; the SBOM never goes to stdout. |
| `-q`, `-qq`, `-qqq` | info | Lower it to warnings only / errors only / silent. Error diagnostics are printed regardless. |
| `-h, --help`, `-V, --version` | | Usual meanings. |

`RUST_LOG` is also honored and overrides `-v`/`-q` (for example `RUST_LOG=pixi_sbom::lock=debug`).

### Enforcing a license policy

Any of `--allow-license`, `--deny-license` and `--require-license` turns on the policy check. Documents (or reports)
are still produced, the violations are listed on stderr, and the run exits with code **3**, which is what a CI job
should fail on:

```sh
# Nothing copyleft, and every package must say what it is
pixi sbom --deny-license GPL-3.0-only --deny-license AGPL-3.0-only --require-license --output - > sbom.cdx.json

# Only an approved set
pixi sbom --fetch-licenses --allow-license MIT --allow-license Apache-2.0 --allow-license BSD-3-Clause
```

The check respects the structure of each license expression: `MIT OR GPL-3.0-only` passes a policy that denies
GPL-3.0-only because MIT is an option, while `MIT AND GPL-3.0-only` does not. Identifiers are compared by base
license, `-or-later` flag and exception, so the deprecated `GPL-3.0` and the current `GPL-3.0-only` mean the same
thing, an `-or-later` requirement is satisfied by any allowed later version of the same family (allowing
`GPL-3.0-only` satisfies a package under `GPL-2.0-or-later`) and matched by any denied later version, and
`GPL-2.0-only WITH Classpath-exception-2.0` is only satisfied by an entry with the same exception. `LicenseRef-`
identifiers match exactly. `GPL-2.0+` may be written for `GPL-2.0-or-later`.

Packages without a license, or with one that is not an SPDX expression, are not violations of an allow or deny
list (there is nothing to evaluate); `--require-license` makes them violations. Combine with `--fetch-licenses` so
PyPI packages have a license to check. In batch mode each violation is prefixed with its environment and platform.

### Looking instead of writing

`--report` prints a report to the terminal and writes nothing:

```sh
# The inventory: name, version, kind, source, license, purl
pixi sbom --report packages

# The license view, with a per-license summary, unlicensed and non-SPDX packages called out
# (each non-SPDX license names the token the parser rejected, e.g. "unknown term: 'PSF'")
pixi sbom --fetch-licenses --report licenses

# For a PR comment, a spreadsheet, or a script
pixi sbom --report licenses --report-format markdown
pixi sbom --report licenses --report-format csv > licenses.csv
pixi sbom --report packages --report-format json | jq '.packages[] | select(.license == null)'
```

Reports respect every selection and enrichment flag, so they show exactly what a document would contain; with
`--all-environments` / `--all-platforms` there is one section (or JSON array element) per document. `--report`
cannot be combined with `--output`. The `table` format fits the terminal width (`COLUMNS`, default 120) by
truncating the last column; the other formats are never truncated.

### Environment variables

| Variable | Effect |
|---|---|
| `COLUMNS` | Terminal width for `--report-format table` (default 120). |
| `PIXI_CACHE_DIR` / `RATTLER_CACHE_DIR` | Where pixi keeps its package cache; `--fetch-licenses` reads extracted conda packages from its `pkgs/` directory. Default: the platform cache directory's `rattler/cache` (`~/.cache/rattler/cache`, `~/Library/Caches/rattler/cache`, `%LOCALAPPDATA%\rattler\cache`). |
| `PIXI_SBOM_OFFLINE` | Set to `1` to forbid every network request: the mapping, wheel and archive caches are used when present and everything else is skipped with a warning. The run still succeeds. |
| `PIXI_SBOM_PYPI_URL` | Base of the PyPI JSON API queried by `--fetch-licenses` (default `https://pypi.org/pypi`); point it at a mirror such as devpi or Artifactory. |
| `PIXI_SBOM_CACHE_DIR` | Where downloaded data (the PyPI mapping, PyPI metadata, extracted conda `info` directories, wheel `dist-info` files) is cached. Default: `pixi-sbom` under `PIXI_CACHE_DIR` if set, else the platform cache directory (`~/.cache/pixi-sbom`, `~/Library/Caches/pixi-sbom`, `%LOCALAPPDATA%\pixi-sbom\cache`). |
| `HTTPS_PROXY` / `HTTP_PROXY` | Honored for every download. |
| `SOURCE_DATE_EPOCH` | Pins the document timestamp (seconds since the Unix epoch). With it set, repeated runs over the same lockfile are byte-identical, which lets CI diff SBOMs between commits. See [output-format.md](output-format.md#reproducibility). |
| `RUST_LOG` | Log filter, overrides `-v`/`-q`. |

### Examples

```sh
# SPDX instead of CycloneDX
pixi sbom --format spdx

# CycloneDX 1.7 instead of 1.6
pixi sbom --spec-version 1.7

# SPDX 3.0.1 (JSON-LD) instead of SPDX 2.3
pixi sbom --format spdx --spec-version 3.0

# Straight into a consumer, nothing written to disk
pixi sbom --output - | grype

# Scannable: give conda-forge Python packages their PyPI identity and make it primary
pixi sbom --pypi-mapping prefix --primary-purl pypi --output - | grype

# The same, air-gapped, from a saved copy of the mapping
pixi sbom --pypi-mapping-file /srv/mirrors/compressed_mapping.json --primary-purl pypi

# Licenses for everything: expressions and license file names
pixi sbom --fetch-licenses

# What was compiled into the wheels (PEP 770 embedded SBOMs), e.g. Rust crates
pixi sbom --embedded-sboms

# The same plus the full license texts
pixi sbom --fetch-licenses --license-texts

# A specific lockfile and output file, from anywhere
pixi sbom --lockfile ~/proj/pixi.lock --output ~/reports/proj.cdx.json

# The environment you actually ship, for the platform you ship it on
pixi sbom -e prod -p linux-64

# Every environment, each on linux-64, into a directory
pixi sbom --all-environments -p linux-64 --output sboms/

# Every platform the prod environment is locked for
pixi sbom -e prod --all-platforms --output sboms/

# Everything: one document per environment and platform
pixi sbom --all-environments --all-platforms --output sboms/
```

### One document per environment and platform

A pixi lockfile can hold many environments, each locked for several platforms. An SBOM, by contrast, is expected to
describe one deliverable, so `pixi sbom` never merges environments or platforms into one document:

- `--environment` / `--platform` pick exactly one combination.
- `--all-environments` runs that selection once per environment, `default` first, then the rest alphabetically.
- `--all-platforms` runs it once per platform the environment is locked for, alphabetically.
- Both together cover every (environment, platform) pair in the lockfile.

In batch mode `--output` names the directory that receives the files (default: next to the lockfile), and each file is
named after what it describes:

| Flags | File name |
|---|---|
| `--all-environments` | `sbom-<environment>.cdx.json` / `.spdx.json` |
| `--all-platforms` | `sbom-<platform>.cdx.json` |
| both | `sbom-<environment>-<platform>.cdx.json` |

Each document records which environment and platform it describes (`pixi:environment` / `pixi:platform` in the
CycloneDX metadata properties; the root package `sourceInfo` in SPDX), so a batch of files stays self-describing.

## Exit codes and errors

| Exit code | Meaning |
|---|---|
| 0 | Document(s) written. |
| 1 | A runtime error; a diagnostic is printed to stderr. |
| 3 | The license policy was violated; the documents were written and the violations listed on stderr. |
| 2 | Command-line usage error (unknown option, conflicting options such as `--output -` with `--all-environments` or `--all-platforms`, or a `--spec-version` of the other format, or a `--allow-license` / `--deny-license` value that is not an SPDX identifier). |

Runtime diagnostics carry a stable code you can grep for in CI logs:

| Code | When | Fix |
|---|---|---|
| `pixi_sbom::discover::not_found` | No `pixi.lock` in the current directory or any parent | Run `pixi lock` in the workspace, or pass `--lockfile` |
| `pixi_sbom::discover::missing` | `--lockfile` points at a file that does not exist | Check the path |
| `pixi_sbom::lock::parse` | The lockfile is not valid, or is newer than this build understands | Regenerate with `pixi lock`; upgrade `pixi-sbom` if the lockfile `version:` is newer than 7 |
| `pixi_sbom::lock::environment` | `--environment` names something not in the lockfile | The message lists the available environments |
| `pixi_sbom::lock::platform` | The chosen platform is not locked for that environment | The message lists the locked platforms; pass `-p` |
| `pixi_sbom::lock::current_platform` | The host platform could not be detected | Pass `-p` explicitly |
| `pixi_sbom::mapping::fetch` | `--pypi-mapping prefix` could not download the mapping and has no cached copy | Check network/proxy, or pass `--pypi-mapping-file`; a stale cache is used automatically with a warning |
| `pixi_sbom::mapping::read` / `parse` | `--pypi-mapping-file` is unreadable or not a JSON object of conda name to PyPI name | Check the file |
| `pixi_sbom::purl::invalid` | A package name the purl spec cannot encode | Report it with the lockfile entry |
| `pixi_sbom::format::io` / `serialize` | The output could not be written | Check the path and permissions; `--output` must not be an existing directory in single-environment mode |

Missing or unreadable manifests (`pixi.toml` / `pyproject.toml`) are not errors: the workspace name falls back to the
lockfile's directory name and a warning is logged.

## Running in CI

### GitHub Action

This repository doubles as a GitHub Action. It downloads the pinned release binary for the runner (verifying the
checksum), runs it, and uploads the documents as a workflow artifact; pixi itself is not needed, and neither is
`pixi install`, since the lockfile is the only input:

```yaml
- uses: actions/checkout@v4
- uses: millsks/pixi-sbom@v0.5.1
  with:
    all-environments: "true"
    fetch-licenses: "true"
    pypi-mapping: prefix
    primary-purl: pypi
    deny-license: "GPL-3.0-only AGPL-3.0-only"
    require-license: "true"
```

| Input | Default | Meaning |
|---|---|---|
| `version` | the action's own tag, else the latest release | pixi-sbom version to run |
| `lockfile`, `format`, `spec-version`, `environment`, `platform`, `all-environments`, `all-platforms` | as the CLI | Selection and format, see the options above |
| `output` | `sboms` | Output file (`*.json`, or `-` for the log) or directory; a single document lands in the directory as `sbom.cdx.json` / `sbom.spdx.json` |
| `fetch-licenses`, `license-texts`, `embedded-sboms`, `pypi-mapping`, `primary-purl` | as the CLI | Enrichment |
| `allow-license`, `deny-license`, `require-license` | | License policy; whitespace-separated lists |
| `fail-on-policy` | `true` | Fail the step on a policy violation; with `false` it becomes a warning and the `policy-violated` output is `true` |
| `extra-args` | | Any other CLI arguments |
| `upload-artifact`, `artifact-name` | `true`, `sboms` | Artifact upload |

Outputs: `version`, `output`, `policy-violated`. The action runs on Linux (x64, arm64), macOS (Intel, Apple
Silicon) and Windows runners, and describes any platform in the lockfile regardless of the runner (`platform:
linux-64` on a macOS runner is fine).

### Without the action

The binary has no runtime dependencies, so any job can download it from the
[releases page](https://github.com/millsks/pixi-sbom/releases) and run it, or install it with pixi:

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
packages by `pkg:pypi/...`.

Scanners have no conda vulnerability data, so by default a conda-only Python environment scans as clean no matter
what it contains. To get real results, give conda-forge Python packages their PyPI identity and make it the primary
purl:

```sh
pixi sbom --pypi-mapping prefix --primary-purl pypi --output - | grype
```

`--pypi-mapping prefix` consults the same conda-forge mapping pixi uses (downloaded once a day into a cache);
`--pypi-mapping-file` takes an offline copy. On a typical conda-forge Python environment this gives roughly 60% of the
components a `pkg:pypi` purl. See [output-format.md](output-format.md#pypi-identities-for-conda-packages) for exactly
what is recorded.
