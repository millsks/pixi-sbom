# What 1.0 freezes

From 1.0.0, the things on this page are covered by semantic versioning: they do not change in a
patch or minor release, and changing any of them means a new major version. Everything under
[Not covered](#not-covered) may change in any release.

This page is the contract. It is deliberately a list of **names and shapes**, not a second copy of
the reference — what each flag *does* is in [the command-line reference](cli.md), what each
document field means is in [the output format reference](output-format.md). What is frozen is that
the name exists, takes the same kind of value, and means the same thing.

Every list here is checked against the code by `tests/stability.rs`. A flag added without a line on
this page fails the build, and so does a line on this page for something that does not exist.

## Command-line flags

All 67. Their meanings are in [cli.md](cli.md); what this page promises is that none of them
disappears or changes shape before 2.0.

| `--against` | `--all-environments` | `--all-platforms` | `--allow-license` |
| `--assume-used` | `--ca-bundle` | `--color` | `--concurrency` |
| `--conda-index-kind` | `--config` | `--deny-license` | `--depth` |
| `--doctor` | `--embedded-sboms` | `--environment` | `--exclude` |
| `--exclude-kind` | `--explain` | `--fail-on-diff` | `--fail-on-kev` |
| `--fail-on-phantom` | `--fail-on-scorecard` | `--fail-on-severity` | `--fail-on-yanked` |
| `--fetch-licenses` | `--format` | `--from-sbom` | `--group-by` |
| `--help` | `--ignore-license` | `--ignore-vuln` | `--include` |
| `--keep-orphans` | `--kev` | `--license-texts` | `--lockfile` |
| `--log-format` | `--no-cache` | `--no-config` | `--outdated-min` |
| `--output` | `--platform` | `--prefix` | `--primary-purl` |
| `--pypi-mapping` | `--pypi-mapping-file` | `--quiet` | `--refresh` |
| `--report` | `--report-format` | `--require-license` | `--root-name` |
| `--root-version` | `--scan` | `--scan-depth` | `--scorecard` |
| `--scorecard-min` | `--source` | `--spec-version` | `--timings` |
| `--tree` | `--verbose` | `--version` | `--version-details` |
| `--vex` | `--vex-open` | `--vulnerabilities` |  |

### Spellings that answer to an older name

Accepted permanently, hidden from `--help` so there is one name to learn. Removing any of these
would be a major version with its own notice.

| Accepted | Canonical | Since |
|---|---|---|
| `--name` | `--root-name` | renamed in 1.0.0 |
| `--outdated-only` | `--outdated-min` | renamed in 1.0.0 |
| `--pypi-licenses` | `--fetch-licenses` | renamed in 0.4.0 |
| `--build-info` | `--version-details` | a visible alias, both shown |

### Values with a structure

`--ignore-vuln` (and the `ignore-vuln` config key and action input) takes `ID`, `ID:TEXT` or
`ID:STATE[:JUSTIFICATION][:RESPONSE,...][:TEXT]`. `STATE` is a CycloneDX impact-analysis state,
`JUSTIFICATION` a CycloneDX impact-analysis justification (only after `not_affected`) and `RESPONSE` a
comma-separated list of CycloneDX impact-analysis responses; each segment is read as one only when every word in
it names a known value, otherwise it is text. Every form keeps its meaning through 1.x; a new segment may be added only in
the same way, recognised by a fixed vocabulary, so an existing entry never changes meaning.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The document or report was written. |
| 1 | A runtime error, or `--doctor` found a problem. A diagnostic goes to stderr. |
| 2 | A command-line usage error: an unknown flag, conflicting flags, or a value the flag does not accept. |
| 3 | `--allow-license` / `--deny-license` / `--require-license` was violated. |
| 4 | `--fail-on-severity` or `--fail-on-kev` matched. |
| 6 | `--fail-on-diff` found a change it was asked to gate on. |
| 7 | `--fail-on-yanked` found a yanked release. |
| 8 | `--fail-on-phantom` found an undeclared import. |
| 9 | `--fail-on-scorecard` found a repository below the threshold. |

Every gate above 2 writes its document or report first and lists what tripped it on stderr, so a
failing gate still leaves you the artifact.

**5 is deliberately unused.** It has never been assigned — not in any release — and it stays free
rather than being filled by the next gate, so that a script testing for a specific code is never
surprised by a number that used to mean nothing. A future gate takes 10 and upward.

## Configuration keys

A key is the flag's own name without the leading `--`, so `--fetch-licenses` is `fetch-licenses`.
The command line always wins over the files.

Three layers are read, least specific first, and merged per key — a layer overrides what a less
specific one said and inherits what it did not mention:

| Layer | Where |
|---|---|
| system | `/etc/pixi/pixi-sbom-config.toml`, or `%PROGRAMDATA%\pixi\pixi-sbom-config.toml` on Windows |
| user | `$PIXI_HOME/pixi-sbom-config.toml`, else `~/.pixi/pixi-sbom-config.toml` |
| project | `<workspace>/.pixi/pixi-sbom-config.toml`, else `[tool.pixi-sbom]` in `pyproject.toml`, else `pixi-sbom.toml` |

`--config <PATH>` replaces the search with one file; `--no-config` reads none. Both keep the
meanings they have always had: ours differ from pixi's flags of similar name, which still read
project-local files, and they are frozen as the broader meaning.

**`pixi-sbom.toml` at the workspace root is deprecated.** It is read, and named as deprecated by
`--doctor` and in the logs, until 2.0. `[tool.pixi-sbom]` in `pyproject.toml` is not deprecated and
stays supported.

| | | | |
|---|---|---|---|
| `format` | `spec-version` | `pypi-mapping` | `pypi-mapping-file` |
| `primary-purl` | `fetch-licenses` | `license-texts` | `embedded-sboms` |
| `exclude` | `include` | `exclude-kind` | `keep-orphans` |
| `allow-license` | `deny-license` | `require-license` | `fail-on-yanked` |
| `vulnerabilities` | `kev` | `fail-on-kev` | `fail-on-severity` |
| `ignore-vuln` | `ignore-license` | `scorecard` | `scorecard-min` |
| `fail-on-scorecard` | `fail-on-diff` | `source` | `assume-used` |
| `fail-on-phantom` | `conda-index-kind` | `concurrency` | |

An unknown key is an error, not a warning, and the diagnostic lists every key that is accepted — so
a typo cannot pass silently and you are never left guessing at the spelling.

## Environment variables

`RATTLER_AUTH_FILE` and `NETRC` are read for credentials. They are not this project's to define,
so they are not frozen here; they are honoured with the meanings rattler and curl give them.

| Variable | |
|---|---|
| `PIXI_SBOM_CACHE_DIR` | Where the caches live. |
| `PIXI_SBOM_CONCURRENCY` | How many requests at once; `--concurrency` and the `concurrency` key say the same thing, and the command line beats the variable, which beats the file. Requests only: threads for local work follow the core count. Above 100 is honoured with a warning; above 1000 is clamped, and the run is never sized past the number of packages. |
| `PIXI_SBOM_OFFLINE` | Make no network requests. |
| `PIXI_SBOM_NO_PROGRESS` | No progress bars. |
| `PIXI_SBOM_LOG_FORMAT` | `text` or `json`. |
| `PIXI_SBOM_CA_BUNDLE` | A PEM bundle to trust. |
| `PIXI_SBOM_OSV_URL` | Where to query OSV. |
| `PIXI_SBOM_KEV_URL` | Where to fetch the CISA catalog. |
| `PIXI_SBOM_PYPI_URL` | Where to read PyPI metadata. |
| `PIXI_SBOM_ANACONDA_URL` | Where to read anaconda.org metadata. |
| `PIXI_SBOM_CONDA_FALLBACK_CHANNEL` | The channel a mirrored package is checked against, by hash. |
| `PIXI_SBOM_PREFIX_INDEX_URL` | Where to reach prefix.dev's GraphQL API. |
| `PIXI_SBOM_MAPPING_URL` | Where to download the conda-to-PyPI name mapping. |
| `PIXI_SBOM_CONDA_ARCHIVE_URL` | Base that conda package archives are read from, in place of each package's own host. |
| `PIXI_SBOM_WHEEL_ARCHIVE_URL` | Base that PyPI wheel archives are read from, in place of each wheel's own host. |
| `PIXI_SBOM_SCORECARD_URL` | Where to query OpenSSF Scorecard. |

Also read, and owned by other tools: `SSL_CERT_FILE`, `PIXI_CACHE_DIR`, `RATTLER_CACHE_DIR`,
`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY`, `NO_COLOR`, `CLICOLOR_FORCE`, `RUST_LOG`.

## `pixi:*` names in a document

Property names in CycloneDX and comment / annotation names in SPDX. What is frozen is the name and
what it holds; whether a given run emits a particular one depends on the flags. `output-format.md`
says which flag produces which.

| | | |
|---|---|---|
| `pixi:build` | `pixi:build-number` | `pixi:cargo-source` |
| `pixi:channel` | `pixi:channel-url` | `pixi:declared-in` |
| `pixi:direct` | `pixi:direct-url` | `pixi:editable` |
| `pixi:embedded-sbom` | `pixi:environment` | `pixi:excluded` |
| `pixi:extracted-package-dir` | `pixi:file-name` | `pixi:identifier-hash` |
| `pixi:incomplete` | `pixi:incomplete-detail` | `pixi:index-url` |
| `pixi:installer` | `pixi:kev` | `pixi:kev-cve` |
| `pixi:kev-date-added` | `pixi:kev-due-date` | `pixi:kev-ransomware` |
| `pixi:kind` | `pixi:license-exempt` | `pixi:license-family` |
| `pixi:license-file` | `pixi:license-files-source` | `pixi:license-raw` |
| `pixi:license-source` | `pixi:lockfile` | `pixi:marker` |
| `pixi:noarch` | `pixi:platform` | `pixi:prefix` |
| `pixi:purl` | `pixi:pypi-mapping` | `pixi:requires-python` |
| `pixi:scorecard` | `pixi:scorecard-date` | `pixi:size` |
| `pixi:source` | `pixi:source-branch` | `pixi:source-document` |
| `pixi:source-git` | `pixi:source-path` | `pixi:source-rev` |
| `pixi:source-subdirectory` | `pixi:source-tag` | `pixi:source-url` |
| `pixi:stale-cache` | `pixi:subdir` | `pixi:vex-for` |
| `pixi:yanked` | `pixi:yanked-reason` |  |

`pixi:scorecard-check-<name>` is a family rather than one name: the suffix is the OpenSSF check,
so the set grows when OpenSSF adds a check. The prefix is frozen; the suffixes are theirs.

## Report JSON

`--report <kind> --report-format json` writes an object with one key named after the report —
`packages`, `licenses`, `vulnerabilities`, `diff`, `outdated`, `python`, `phantom`, `scorecard` —
holding an array of rows. Row field names are frozen; **row order is not**, except where the
report documents an order (worst-first for vulnerabilities).

CSV columns and their order are frozen. The Markdown and table renderings are not — see below.

## The GitHub Action

Inputs and outputs of `action.yml`. An input maps to the flag of the same name; `extra-args`
passes anything through.

**Inputs:** `all-environments`, `all-platforms`, `allow-license`, `artifact-name`, `attest`,
`attest-subject`, `config`, `deny-license`, `diff-against`, `embedded-sboms`, `environment`,
`extra-args`, `fail-on-diff`, `fail-on-kev`, `fail-on-policy`, `fail-on-scorecard`,
`fail-on-severity`, `fail-on-vulnerabilities`, `fail-on-yanked`, `fetch-licenses`, `format`,
`ignore-license`, `ignore-vuln`, `kev`, `license-texts`, `lockfile`, `output`, `platform`,
`primary-purl`, `pypi-mapping`, `require-license`, `sarif-category`, `scan`, `scorecard`,
`scorecard-min`, `spec-version`, `upload-artifact`, `upload-sarif`, `version`, `vex`, `vex-open`,
`vulnerabilities`.

**Outputs:** `attestation-url`, `diff-changed`, `document`, `output`, `policy-violated`, `sarif`,
`version`, `vulnerabilities-found`.

## Document formats

CycloneDX 1.6 and 1.7, SPDX 2.3 and 3.0.1 stay writable, and `--spec-version` keeps accepting
`1.6`, `1.7`, `2.3` and `3.0`. Which is the default for each `--format` is frozen too: CycloneDX
1.6 and SPDX 2.3.

`--from-sbom` keeps reading CycloneDX 1.4–1.7 and SPDX 2.x / 3.0 JSON.

Lockfile format versions 1 through 7 stay readable. A newer one is refused by name rather than
half-read, and that refusal is exit code 1.

## Not covered

These change without a major version, and nothing should be parsed out of them:

- **Log lines.** Every `INFO` / `WARN` / `DEBUG` line, its wording, its fields and whether it
  appears at all. `--log-format json` gives stable *shape* — a JSON object per line — but the
  messages and fields inside it are not a contract. Gate on exit codes, not on log text.
- **Table and Markdown report layout.** Column widths, ordering of unordered reports, box drawing,
  colour, the tree glyphs. Use `--report-format json` or `csv` if something reads it.
- **Recommendation and diagnostic wording.** `recommendation` text in a document, the phrasing of a
  miette diagnostic, the help text of a flag.
- **Progress output.** Bars, spinners, what they count.
- **`--timings` output.** The phases, their names, the table.
- **`--doctor` output.** What it checks and how it says so; only the exit code is frozen.
- **`--explain` output.** A human-facing explanation, free to improve.
- **The published Rust library.** Every module is `#[doc(hidden)]` and none of it is an API; see
  the crate documentation. The command line is the interface.
- **Element ids and ordering inside a document.** `bom-ref`, `SPDXID` and JSON-LD `spdxId` values
  are derived and may change shape; so may the order of `components` / `packages` / `@graph`
  entries. Match on `purl`, `name` and `version`.
- **Cache layout.** Directory names and file formats under the cache directory.

## Changing something that is frozen

A rename keeps the old spelling as a permanent alias, the way `--root-name` and `--outdated-min`
did. That is additive and ships in a minor release. Removing a spelling, changing what a flag
means, or changing an exit code waits for a major version, and gets a deprecation warning in a
release before it.
