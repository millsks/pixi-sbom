# Command-line reference

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

## Options

| Option | Default | Effect |
|---|---|---|
| `--lockfile <PATH>` | upward search from cwd | Lockfile to read. The file must exist; there is no fallback search when this is given. |
| `--prefix <DIR>` | | Describe an installed environment instead of a lockfile (see below). Cannot be combined with `--lockfile`, `--environment` or the `--all-*` flags. |
| `--name <NAME>`, `--root-version <VERSION>` | directory name, none | With `--prefix`: what the described application is called. |
| `--config <PATH>` | see below | Configuration file to read before the command line. |
| `--no-config` | off | Ignore any configuration file. |
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
| `--exclude <GLOB>` | | Repeatable. Leave packages whose name matches the shell-style pattern (`*`, `?`; case-insensitive, `-` and `_` alike) out of the document, together with whatever only they needed (see below). |
| `--include <GLOB>` | | Repeatable. Keep only packages whose name matches one of the patterns. |
| `--exclude-kind <conda\|conda-source\|pypi\|embedded\|external>` | | Repeatable. Leave every package of that kind out. |
| `--keep-orphans` | off | With the filters above: keep the packages that only excluded packages needed. |
| `--fetch-licenses` | off | Fetch the license of every package, conda and PyPI alike, where the lockfile has none, plus the names of the license files it ships and its summary and project URLs. Conda details come from the local package cache pixi filled at install time, or from the archive on the channel via HTTP range requests (a few KB per package, cached); PyPI details from the wheel's `dist-info` the same way, then the index JSON API for what is still missing. Failures are logged and the run continues. |
| `--license-texts` | off | With `--fetch-licenses`, also embed the full text of every license file. |
| `--embedded-sboms` | off | Add the components declared by SBOMs embedded in wheels (PEP 770, e.g. the Rust crates maturin compiled in) as dependencies of the wheel. Reads each wheel's `dist-info` like `--fetch-licenses`. With `--prefix`, also reads the `cargo auditable` crate list out of the environment's binaries. |
| `--allow-license <LICENSE>` | | Repeatable. Only these SPDX licenses are acceptable; a package whose license expression cannot be satisfied with them alone is a violation. |
| `--deny-license <LICENSE>` | | Repeatable. These SPDX licenses are unacceptable; a package whose expression cannot be satisfied without them is a violation. |
| `--require-license` | off | Every package must declare a license that is an SPDX expression. |
| `--ignore-license <PACKAGE[:WHY]>` | | Repeatable. The policy does not apply to packages matching this name or pattern; they are listed as exempt in the report and carry `pixi:license-exempt` in the document. |
| `--scorecard` | off | With `--fetch-licenses`: ask the OpenSSF Scorecard service how each package's repository is maintained and record the score in the document. |
| `--scorecard-min <N>` | `5` | With `--scorecard`: the score a package or a check has to reach to be left alone. |
| `--fail-on-scorecard <N>` | | With `--scorecard`: exit **9** when a scored package is below this. Unscored packages never fail. |
| `--fail-on-yanked` | off | With `--fetch-licenses`: exit **7** after writing the document when any PyPI package is a yanked release (PEP 592). |
| `--vulnerabilities <osv>` | off | Look up known vulnerabilities of every package with a purl OSV can answer and record them in the document (see below). |
| `--kev` | off | With `--vulnerabilities`: mark findings whose CVE alias is in CISA's Known Exploited Vulnerabilities catalog (downloaded once a day). They are rated `critical`, sorted first, and carry the catalog's dates and required action. |
| `--fail-on-kev` | off | With `--kev`: exit **4** after writing the document when any open finding is known exploited, regardless of severity. |
| `--fail-on-severity <low\|medium\|high\|critical>` | | With `--vulnerabilities`: exit **4** after writing the document when any open finding is at or above the level. Findings of unknown severity never trip it. |
| `--ignore-vuln <ID[:STATE][:TEXT]>` | | Repeatable, with `--vulnerabilities`. Accept a finding by advisory id or alias (GHSA, CVE, ...): it stays in the document with a CycloneDX `analysis` block (`state` defaults to `not_affected`; `TEXT` is the justification), is excluded from `--fail-on-severity` and listed separately in the report. |
| `--vex <PATH>` | | With `--vulnerabilities`: also write a standalone CycloneDX VEX there, linked back to the SBOM. |
| `--vex-open <in-triage\|exploitable>` | `in-triage` | The analysis state the VEX gives findings nobody assessed with `--ignore-vuln`. |
| `--version-details` (`--build-info`) | | Print the version with the target, the features compiled in, the caches, pixi's version and the network settings: the block to paste into a bug report. |
| `--timings` | off | Print where the run spent its time, phase by phase, separating waiting on the network from working. |
| `--doctor` | off | Probe every upstream the other flags bring in, print the configuration and the caches, and exit 1 if anything is unreachable. Needs no lockfile. |
| `--refresh [<CACHE>...]` | off | Ignore cached answers this run and ask again; with no value every cache, else the named ones (`mapping`, `osv`, `kev`, `wheels`, `pypi`, `outdated`, `scorecard`). What is fetched is still cached. |
| `--no-cache` | off | Neither read nor write any cache. |
| `--report <packages\|licenses\|vulnerabilities\|diff\|outdated\|python\|phantom\|scorecard>` | | Print a report to the terminal instead of writing a document (see below). Cannot be combined with `--output`; `vulnerabilities` needs `--vulnerabilities`, `diff` needs `--against`. |
| `--tree` | off | With `--report packages`: draw the dependency graph from the root downward instead of a flat list. |
| `--depth <N>` | unlimited | With `--tree`: how deep to go (`0` shows what the root depends on and nothing below). |
| `--group-by license` | | With `--report licenses`: one section per license instead of one row per package. |
| `--outdated-only <patch\|minor\|major>` | | With `--report outdated`: list only packages at least that far behind. |
| `--source <DIR>` | the lockfile's directory | With `--report phantom`: where the workspace's Python sources are (repeatable). |
| `--assume-used <GLOB>` | | With `--report phantom`: packages matching this are never reported as unused or undeclared (repeatable). |
| `--fail-on-phantom` | off | With `--report phantom`: exit **8** when the workspace imports a package it never declared. |
| `--from-sbom <FILE>` | | Read an existing document (CycloneDX 1.4–1.7, SPDX 2.x or SPDX 3.0 JSON) instead of a lockfile and run the reports, the license policy and the vulnerability gate on it. |
| `--scan <DIR>` | | Describe every pixi workspace under the directory: one document per `pixi.lock` found. Cannot be combined with `--lockfile`, `--prefix`, `--against` or `--output -`. |
| `--scan-depth <N>` | unlimited | With `--scan`: how far below the directory to walk (`0` is the directory itself). |
| `--against <PATH>` | | With `--report diff`: what to compare with — a document (CycloneDX 1.4–1.7, SPDX 2.x or SPDX 3.0 JSON), a `pixi.lock`, or the directory of an installed environment. |
| `--fail-on-diff [<SECTION>...]` | off | With `--report diff`: exit **6** when the named sections (`added`, `removed`, `version`, `license`, `build`, `pip`) are not empty. The bare flag means any change. |
| `--explain <PACKAGE>` | | Repeatable. Print every fact the tool has about the packages matching this name or shell-style pattern (as in `--exclude`) and where each fact came from, including the sources that came back empty (see below). Prints instead of writing, so it cannot be combined with `--output` or `--report`. |
| `--report-format <table\|markdown\|csv\|json\|sarif>` | `table` | How to render the report or `--explain`; `sarif` (2.1.0, for GitHub code scanning) applies to `--report vulnerabilities` only. |
| `--color <auto\|always\|never>` | `auto` | Colour the `table` report. `auto` colours only when the output is a terminal, honouring `NO_COLOR`, `CLICOLOR_FORCE` and `TERM=dumb`. |
| `--pypi-licenses` | | Deprecated alias for `--fetch-licenses` (hidden from `--help`; removed in a future release). |
| `-v`, `-vv` | info | Raise the log level to debug / trace. Logs go to stderr; the SBOM never goes to stdout. |
| `-q`, `-qq`, `-qqq` | info | Lower it to warnings only / errors only / silent. Error diagnostics are printed regardless. |
| `--ca-bundle <FILE>` | the OS trust store | Verify TLS against the certificates in this PEM file instead of the operating system's store: a TLS-intercepting appliance's CA, or a private one. The order is `--ca-bundle`, `PIXI_SBOM_CA_BUNDLE`, `SSL_CERT_FILE`, then the platform verifier — see [which certificates TLS is verified against](#which-certificates-tls-is-verified-against). |
| `--log-format <text\|json>` | `text` | How the log on stderr is rendered. `json` writes one JSON object per event, with the timestamp back and every field its own key. Also `PIXI_SBOM_LOG_FORMAT`. |
| `-h, --help`, `-V, --version` | | Usual meanings. |

## What the log says, and how to narrow it

The log goes to stderr, always; the document and the reports go to stdout, so `pixi sbom > sbom.json` is safe at
any verbosity.

| Level | Flag | What it says |
|---|---|---|
| ERROR | `-qq` | Only what stopped the run. The miette diagnostic is printed regardless of the level. |
| WARN | `-q` | What was skipped and why: a license that could not be read, a request not made because the run is offline, a cache served past its lifetime. |
| INFO | default | One line per step, with its counts: the environment selected, how many licenses were filled, how many packages were queried and how many findings came back, what was written where, and what each cache served. |
| DEBUG | `-v` | Every request with its URL, status, size and elapsed time; every cache hit with its age; the packages each step skipped and why; the effective arguments and the configuration file that produced them. |
| TRACE | `-vv` | Everything above plus the tool's internal bookkeeping. |

`-v` and `-vv` turn the **progress bars off**: the bars and the per-request lines are both drawn on stderr and
would tear each other apart. That surprises people who expect both — at DEBUG the log *is* the progress report.
`--log-format json` turns them off for the same reason.

### Narrowing to one part of the tool with `RUST_LOG`

`RUST_LOG` overrides `-v` / `-q` entirely and takes per-module directives, which is the difference between
reading a few lines and reading a few thousand:

```sh
RUST_LOG=pixi_sbom::http=debug,pixi_sbom=info pixi sbom --vulnerabilities osv
```

That says: debug for the requests, info for everything else. The trailing `pixi_sbom=info` matters — a bare
`RUST_LOG=pixi_sbom::http=debug` silences every other module, including the summary lines.

| Target | What it logs |
|---|---|
| `pixi_sbom` | The per-step summary lines: the counts each phase ended with |
| `pixi_sbom::http` | Every request: method, URL, status, bytes, milliseconds, the whole error chain on failure, and the network configuration at startup |
| `pixi_sbom::cache` | What each cache served: hits, fetches, and the age of the oldest answer |
| `pixi_sbom::osv` | Vulnerability queries and advisory records, including the ones recorded by id alone |
| `pixi_sbom::mapping` | The conda-forge → PyPI name mapping: download, cache age, stale fallback |
| `pixi_sbom::kev` | The CISA KEV catalog download and its cache |
| `pixi_sbom::pypi` | PyPI release metadata lookups (`--fetch-licenses`) |
| `pixi_sbom::wheel` | Wheel `dist-info` reads for licenses and embedded SBOMs |
| `pixi_sbom::pkgcache` | Licenses read from pixi's extracted package cache |
| `pixi_sbom::condaarchive` | Licenses read from channel archives when the package cache has none |
| `pixi_sbom::scorecard` | OpenSSF Scorecard lookups |
| `pixi_sbom::outdated` | `--report outdated` index queries |
| `pixi_sbom::auditable` | Rust crate lists read out of `cargo auditable` binaries |
| `pixi_sbom::phantom`, `::imports` | The import scan behind `--report phantom` |
| `pixi_sbom::lock`, `::prefix`, `::manifest`, `::discover`, `::config` | Which input and which settings the run chose |

### Three recipes

**Nothing came back from the vulnerability lookup.**

```sh
RUST_LOG=pixi_sbom::osv=debug,pixi_sbom::http=debug,pixi_sbom=info pixi sbom --vulnerabilities osv
```

```console
 INFO pixi_sbom::http: network configuration offline=false proxy="none" tls_roots="the platform verifier (the operating system trust store)" timeout_s=120 services=1
DEBUG pixi_sbom::http: upstream service="OSV" url=https://api.osv.dev source="default"
 INFO pixi_sbom: looked up vulnerabilities on OSV queried=0 without_identity=2 findings=0 failed=0 unanswered=0
```

Read the counts on the last line. `queried=0` with `without_identity` equal to the package count means nothing was
ever asked: no package carries a purl OSV answers to, which is every conda-only environment without
`--pypi-mapping prefix`. `unanswered` greater than zero means the questions could not be asked — offline with a
cold cache. `failed` counts advisories that were found but could not be fetched, and those are in the document by
id alone. Only `queried > 0, unanswered = 0, findings = 0` is good news, and the document records the difference
(see [output-format.md](output-format.md#incomplete-enrichment)).

**A license is missing on one package.**

```sh
RUST_LOG=pixi_sbom::wheel=debug,pixi_sbom::pkgcache=debug,pixi_sbom::condaarchive=debug,pixi_sbom::pypi=debug,pixi_sbom=info \
  pixi sbom --fetch-licenses
```

```console
 WARN pixi_sbom::wheel: cannot read license details from the wheel package=six location=https://files.pythonhosted.org/packages/.../six-1.17.0-py2.py3-none-any.whl err=io: offline: PIXI_SBOM_OFFLINE is set, no network requests are made
 INFO pixi_sbom: read PyPI license details from wheels fetched=0 failed=1 skipped=0
 INFO pixi_sbom: read conda license details from the package cache pkgs=/home/u/.cache/rattler/cache/pkgs found=0 licenses_filled=0 files=0
 WARN pixi_sbom::condaarchive: cannot read license details from the archive package=bzip2 location=https://conda.anaconda.org/conda-forge/linux-64/bzip2-1.0.8-hda65f42_10.conda cause="io: offline: PIXI_SBOM_OFFLINE is set, no network requests are made"
```

Each source says which package it could not read and why. `found=0` from the package cache with a `pkgs=` path
that is not where pixi actually keeps its packages is the common one — `PIXI_CACHE_DIR` points elsewhere, or the
environment was never installed, and everything then falls through to the channel archives. For one package,
`--explain <name>` answers the same question without reading a log at all.

**The run is slow.**

```sh
RUST_LOG=pixi_sbom::http=debug,pixi_sbom=info pixi sbom --fetch-licenses --vulnerabilities osv --timings
```

```console
Phase                Time  Detail
input              0.01 s
pypi mapping       1.21 s
wheels             12.40 s  38 fetched, 4 cached
vulnerabilities    2.10 s  24 queried, 9 findings
write              0.00 s
total              15.72 s  of which 15.6 s waiting on the network
 INFO pixi_sbom::cache: cache cache="osv" from_cache=1 fetched=0 oldest_s=0
```

The last line of the table decides what to do: time spent waiting on an upstream is a network problem, and the
`http` debug lines then say which host and how long each request took. Time spent anywhere else is the tool's.
The cache tally underneath says how much of the run was answered from disk — a first run and a warm run are not
comparable, and `--refresh` makes the comparison fair.

## Describing an installed environment

Not every environment has a lockfile: `pixi global` environments, plain conda / mamba / micromamba environments,
environments inside containers. `--prefix <DIR>` describes one of those from what it keeps on disk:

```sh
pixi sbom --prefix ~/.pixi/envs/pixi-sbom
pixi sbom --prefix /opt/conda/envs/app --name app --root-version 1.4.0 --fetch-licenses
```

Conda packages come from `conda-meta/<name>-<version>-<build>.json`, which carries the same facts as a lock record
(name, version, build, channel, subdir, hashes, license, dependencies); pip-installed packages come from the
`site-packages/*.dist-info` directories (`METADATA` for name, version, license, summary and requirements;
`direct_url.json` for VCS installs), skipping the ones whose `INSTALLER` is `conda`, since their conda package is
already listed. The dependency graph is resolved as for a lockfile. The environment is named after the directory,
the platform is the one the records name (`--platform` overrides it), and the document records `pixi:prefix`
instead of `pixi:lockfile`. `--fetch-licenses` reads the license files from the directory each record says the
package was extracted to (`extracted_package_dir`, the package cache), so it needs no network on the machine
that installed the environment. The default output is `sbom.cdx.json` in the working directory, and the
configuration file is looked up there too.

With `--embedded-sboms` the binaries themselves are read too: conda-forge builds its Rust packages with
`cargo auditable`, which embeds the resolved crate graph in the program's `.dep-v0` section, and that is the only
record of what went into `ripgrep` or `fd` — the lockfile knows the conda package and nothing below it. Every
program and shared library the environment installed (`bin/`, `sbin/`, `libexec/`, `Scripts/`, and `.so` / `.dylib`
/ `.dll` / `.pyd` files) is checked by its first four bytes and read only when it is an object file. The crates
become components with `pkg:cargo` purls under the package that ships the binary, so `--vulnerabilities osv`
covers them through RUSTSEC; crates that only built the program are left out.

## Configuration file

The settings that make CI invocations long can live with the project. Before the command line is applied,
`pixi sbom` reads `[tool.pixi-sbom]` from the `pyproject.toml` next to the lockfile when that table exists, else a
`pixi-sbom.toml` next to the lockfile; `--config <PATH>` names another file (either layout), `--no-config` reads
none. Keys mirror the long flags:

```toml
# pixi-sbom.toml
format = "cyclonedx"
spec-version = "1.6"
pypi-mapping = "prefix"          # or pypi-mapping-file = "mirrors/mapping.json" (relative to this file)
primary-purl = "pypi"
fetch-licenses = true
license-texts = false
embedded-sboms = true
exclude = ["pre-commit*", "compilers"]
exclude-kind = ["conda-source"]
keep-orphans = false
allow-license = []                # or deny-license = ["GPL-3.0-only", "AGPL-3.0-only"]
require-license = true
ignore-license = ["internal-*:approved by legal, 2026-01"]
vulnerabilities = "osv"
kev = true
fail-on-severity = "high"
fail-on-kev = true
ignore-vuln = ["GHSA-2xpw-w6gg-jr37:streaming API is not used"]
```

The command line wins wherever it says something, list flags included: `--deny-license MIT` replaces the file's
`deny-license` list rather than extending it. Selection (`--environment`, `--platform`, the `--all-*` flags),
`--output` and `--report` are per invocation and have no file keys. An unknown key, a misspelt value or invalid
TOML is an error (`pixi_sbom::config::parse`), never a silent default, and the relationships between settings
(`fail-on-kev` needs `kev`, `license-texts` needs `fetch-licenses`, ...) are checked after the file applies.

## Leaving packages out

A shipped SBOM often should not list build-only tooling, and a license policy may reasonably exempt it.
`--exclude`, `--include` and `--exclude-kind` drop packages before anything is fetched or checked, so nothing is
looked up for them and the policy, the vulnerability gate and the reports all see the filtered set:

```sh
# The toolchain is not part of the product
pixi sbom --exclude 'pre-commit*' --exclude compilers --exclude rust

# Only the wheels
pixi sbom --exclude-kind conda --exclude-kind conda-source
```

Dropping a package also drops what only it needed: the graph is re-closed from the remaining roots (the packages
nothing depends on), and everything no longer reachable goes too (`orphans` in the log). `--keep-orphans` turns
that off. Either way the root records what was left out, matched packages and orphans alike, in a
`pixi:excluded` property (CycloneDX metadata) or comment (SPDX root package), so a reader can tell the document
is deliberately partial. Excluding every root (for example `--exclude-kind pypi` on a PyPI-only project) empties
the document unless orphans are kept.

## Enforcing a license policy

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

One deliberately accepted package should not force the policy off, so `--ignore-license` exempts it by name or by
a shell-style pattern, as `--ignore-vuln` does for a finding:

```sh
pixi sbom --deny-license GPL-3.0-only \
  --ignore-license "ld_impl_*:build-time only, not shipped" \
  --ignore-license internal-tool
```

An exempt package that would have failed is reported as exempt rather than as a violation: the run exits 0, the
log and the licenses report list it with its justification (`Exempt from the policy (2): ...`), and the component
carries `pixi:license-exempt` with the text (`true` when no justification was given) so the decision is in the
document rather than only in the command line. A package nobody exempted still fails, and an exemption that never
matches anything says nothing.

## Yanked releases

A yanked release (PEP 592) is one the index still serves but has withdrawn: it is broken or unsafe, and a
resolver will not choose it again. A lockfile records nothing about this, so an environment pinned to a yanked
release looks perfectly healthy. With `--fetch-licenses` the index is asked about every PyPI package (not only the
ones still missing a license), and a yanked one gets `pixi:yanked=true` plus `pixi:yanked-reason` in the document,
a `Yanked` column in the packages report, and a line in the log (`yanked=1`). The responses are the same cached
ones the license lookup uses, so this costs one cached request per package and nothing at all on a second run.

`--fail-on-yanked` turns it into a gate: the document is still written, the releases and their reasons are listed
on stderr, and the run exits with code **7**.

```sh
pixi sbom --fetch-licenses --fail-on-yanked
```

Conda packages are not covered: a channel withdraws a build by removing it from `repodata.json`, which would mean
downloading the channel index to detect. That is tracked separately.

## Looking up vulnerabilities

`--vulnerabilities osv` asks the [Open Source Vulnerabilities](https://osv.dev) database about every package with a
purl it indexes (PyPI, crates.io, npm, Go, ...; conda has no ecosystem there) and records the findings in the
CycloneDX `vulnerabilities[]` array: id, aliases (CVE, PYSEC, ...), severity and CVSS ratings, CWEs, summary,
references, the fixed version to upgrade to, and which components are affected. SPDX documents have no place for
them, so `--format spdx` writes the document and warns.

```sh
# Conda-installed Python packages are matched through their PyPI purl, so add the mapping
pixi sbom --pypi-mapping prefix --vulnerabilities osv

# Or as a table, worst first, with a summary by severity
pixi sbom --pypi-mapping prefix --vulnerabilities osv --report vulnerabilities
```

One `querybatch` request per thousand purls yields the advisory ids, then each record is fetched (ten at a time).
Query results are cached for an hour under the pixi-sbom cache directory and records until OSV changes them, so
repeated runs are cheap; with `PIXI_SBOM_OFFLINE=1` the cache is used as is and purls without a cached answer are
treated as clean with a warning. A failed batch query is an error (exit 1) rather than a document that silently
claims there are no vulnerabilities; a record that cannot be fetched is kept by id with nothing known about it.
Records that describe the same vulnerability (a GHSA and a PYSEC entry sharing a CVE) are merged into one finding,
so the list matches what `grype` reports for the same document. The log line says how many purls were asked about
and how many packages had no queryable identity (`without_identity`), which is the size of the conda-only blind
spot.

Severity is the advisory database's own word (`database_specific.severity`) when it has one, else the CVSS v3
base score computed from the vector; CVSS v4 vectors are recorded but not scored. The rating with the worst
severity orders the list.

### Known exploited vulnerabilities (CISA KEV)

`--kev` downloads [CISA's Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
(about a megabyte, cached for a day under the pixi-sbom cache directory; `PIXI_SBOM_KEV_URL` names a mirror and
`PIXI_SBOM_OFFLINE=1` uses the cached copy) and looks every finding's CVE aliases up in it. A hit is a must-fix
regardless of its CVSS score: the finding gets a `critical` rating from `CISA KEV`, moves to the top of the list,
and records the CVE, the date it was added, the BOD 22-01 due date and whether ransomware campaigns are known to
use it (CycloneDX `pixi:kev*` properties; the `KEV` column and a *Known exploited* list in the report). When the
advisory names no fixed version, the catalog's required action becomes the recommendation.

```sh
pixi sbom --pypi-mapping prefix --vulnerabilities osv --kev --report vulnerabilities
pixi sbom --pypi-mapping prefix --vulnerabilities osv --kev --fail-on-kev
```

Python library CVEs are rarely in the catalog, so an empty *Known exploited* list is the normal outcome; the
value is in the run that is not.

### Gating on vulnerabilities

`--fail-on-severity` turns the lookup into a CI gate, shaped like the license policy: the document (or report) is
still produced, the open findings at or above the level are listed on stderr, and the run exits with code **4**.
`--fail-on-kev` does the same for known-exploited findings, independently of severity; the two combine.
`--ignore-vuln` accepts findings you have assessed, VEX style: the finding stays in the document with an
`analysis` block, drops out of the gate, and the report lists it under *Ignored* with its justification.

```sh
# Anything high or critical fails the job
pixi sbom --pypi-mapping prefix --vulnerabilities osv --fail-on-severity high

# ... except the ones assessed as not affecting this deployment
pixi sbom --pypi-mapping prefix --vulnerabilities osv --fail-on-severity high \
  --ignore-vuln "GHSA-2xpw-w6gg-jr37:streaming API is not used" \
  --ignore-vuln "CVE-2023-43804:false_positive:only reachable through a removed code path" \
  --ignore-vuln GHSA-qccp-gfcp-xxvc:in_triage
```

An entry is `ID`, `ID:TEXT` or `ID:STATE:TEXT`. `ID` matches the record id or any alias, case-insensitively.
`STATE` is one of the CycloneDX impact-analysis states (`not_affected`, `false_positive`, `in_triage`,
`resolved`, `resolved_with_pedigree`, `exploitable`); a second segment that is not a state is taken as the
text, so `ID:see ticket: ABC-12` keeps the whole text. An id that matches nothing is logged at debug level and
otherwise ignored, so a list of accepted findings can be kept across upgrades. Findings of unknown severity
(records without a rating) never trip the gate; the report shows them so they can be assessed. When both the
license policy and the vulnerability gate fail, both lists are printed and the exit code is 3.

### A VEX of its own

Consumers increasingly want the assessments as a separate document they can update without re-issuing the SBOM.
`--vex <PATH>` writes one beside the document:

```sh
pixi sbom --pypi-mapping prefix --vulnerabilities osv \
  --ignore-vuln "GHSA-2xpw-w6gg-jr37:streaming API is not used" \
  --output sbom.cdx.json --vex vex.cdx.json
```

It is a CycloneDX BOM with no components: only `vulnerabilities[]`, each one carrying an `analysis` — the state
`--ignore-vuln` gave it, or `in_triage` for the findings nobody has assessed (`--vex-open exploitable` says so
instead). Every `affects[].ref` is a BOM-Link into the SBOM this run wrote
(`urn:cdx:<serial number>/1#<bom-ref>`), the VEX has a serial number of its own derived from the SBOM's, and
`pixi:vex-for` names the document it belongs to. That is the shape Dependency-Track and other VEX consumers
expect, and it validates against the CycloneDX schema like everything else this tool writes.

`--vex` needs `--vulnerabilities` and one document to point at, so it does not combine with `--report`,
`--all-environments`, `--all-platforms` or `--scan`.

## How far behind the environment is

`--report outdated` asks each package's index what the newest release is, how many releases sit between it and
the pinned one, and when each was published:

```sh
pixi sbom --report outdated
pixi sbom --report outdated --outdated-only major --report-format markdown
```

| Column | Meaning |
|---|---|
| `Version`, `Age` | What is pinned, and how many days ago it was published |
| `Latest`, `Released` | The newest release that is neither a prerelease nor yanked, and its date |
| `Behind` | How many such releases were published after the pinned one |
| `Step` | `patch`, `minor` or `major`, by the leading numeric segments; `current` when nothing is newer |

Rows are ordered furthest behind first, then oldest. PyPI packages are read from the project document
(`/pypi/<name>/json`); conda packages from anaconda.org's package API
(`https://api.anaconda.org/package/<channel>/<name>`, `PIXI_SBOM_ANACONDA_URL` for a mirror), which covers
conda-forge and the other channels hosted there. A channel hosted elsewhere would mean downloading its
`repodata.json`, which is hundreds of megabytes, so those packages, along with source packages and anything the
index cannot answer for, are listed under *No index to ask* rather than guessed at. Both documents are cached for
a day, so a second run is free.

## What Python the environment allows

`--report python` answers "why can we not move to the next Python yet?" from facts the document already has: the
`Requires-Python` of every wheel (from the lockfile or its `dist-info`) and the environment's own `python`
package. No network, no index.

```sh
pixi sbom --report python
```

Each row gives the package, its version, the specifier as written, whether the current interpreter satisfies it,
and the highest Python minor version it still allows; the lowest ceiling comes first. The summary names the
interpreter, the highest Python the environment could move to without dropping a package, which packages impose
that ceiling, which packages the current interpreter does *not* satisfy, and how many say nothing at all.

Bounds are read at `MAJOR.MINOR` granularity, which is the level upgrades happen at: `<3.13` becomes a ceiling of
3.12, `<=3.11` of 3.11, `==3.10` of 3.10, and `!=3.9.*` an exclusion. A bound on the major version alone (`<4`)
is not a ceiling, since it says nothing about how far up the 3.x series you may go. Most real environments have
no ceiling at all, which is itself the answer.

## How well each dependency is looked after

Vulnerabilities and licenses answer two supply-chain questions. "Is this dependency maintained, reviewed, signed,
pinned?" is the third, and a lockfile says nothing about it. `--scorecard` asks the
[OpenSSF Scorecard](https://securityscorecards.dev/) service, which scores a repository out of ten from fourteen
checks:

```sh
pixi sbom --fetch-licenses --scorecard --report scorecard
pixi sbom --fetch-licenses --scorecard --fail-on-scorecard 4 --output sbom.cdx.json
```

It needs `--fetch-licenses`, which is what collects each package's repository URL, and it only asks about
repositories the service covers (github.com and gitlab.com). Answers are cached for a week under the pixi-sbom
cache directory — a repository is rescored weekly at most — so a second run costs nothing, and
`PIXI_SBOM_SCORECARD_URL` points the lookup elsewhere.

Each scored package carries `pixi:scorecard` (the aggregate), `pixi:scorecard-date`, and one
`pixi:scorecard-check-<name>` property per check below `--scorecard-min` — a check that passed is not recorded,
and neither is one the service could not run. `--report scorecard` lists the packages worst first with their
weakest checks, a table of how many fall in each band, and the ones below the threshold.

`--fail-on-scorecard <N>` exits **9** when a scored package is below `N`. A package the service has never scored,
or one with no repository to ask about, is reported as unknown and never fails the gate: the answer is missing,
not bad.

## What is imported but never declared

A *phantom dependency* is a package the code imports although nothing declares it: it is in the environment only
because something else pulled it in, and the day that upstream drops it the import breaks. `--report phantom`
names them, together with the two inverses that make environments grow without limit.

```sh
pixi sbom --report phantom
```

| Finding | Meaning | What to do |
|---|---|---|
| `phantom` | Imported by the workspace, declared nowhere, present transitively | Declare it before the transitive path disappears |
| `undeclared` | In the environment, declared nowhere, and nothing in the environment depends on it | A leftover pin or a manual install; remove it or declare it |
| `unused` | Declared, and none of the modules it provides is imported | Dead weight — unless it is a plugin or a command (see below) |

Nothing is executed and nothing is downloaded. The declared set comes from the manifest (the same reading that
marks [`pixi:direct`](output-format.md#pixi-properties)), the installed set from the lockfile or the prefix, and
the imports from the workspace's own `.py` files: every `import x[.y]` and `from x[.y] import ...`, read line by
line, skipping comments, docstrings and relative imports. `--source <DIR>` (repeatable) points at the sources when
they are not in the directory holding the lockfile; `.pixi/`, `site-packages/`, `build/`, `dist/`, `node_modules/`,
`__pycache__/`, `target/` and hidden directories are never scanned, and a top-level package or module of the
workspace itself is never a finding. Standard-library imports are excluded from a bundled table.

Which package provides which module is the one fact a lockfile does not contain. When the environment is
installed — `--prefix`, or pixi's own `.pixi/envs/<environment>` next to the lockfile — it is read from each
distribution's `dist-info` (`top_level.txt`, else the top of every path in `RECORD`), which is exact. Without one,
a wheel is assumed to provide the module its name spells (`charset-normalizer` → `charset_normalizer`) and conda
packages are left out of the mapping entirely, since most of them ship no Python module at all and guessing would
make every compiler look unused. The summary says which of the two answered.

False positives are inevitable for packages nothing imports by name: pytest plugins, stub packages, tools invoked
as commands, imports that only happen under `TYPE_CHECKING`. `--assume-used <GLOB>` (repeatable, or `assume-used`
in the configuration file) keeps them out of the `unused` and `undeclared` lists; `pytest-*`, `types-*` and
`*-stubs` are the usual ones, and are never applied silently. `--fail-on-phantom` exits **8** when the workspace
imports something it never declared, and ignores the other two findings.

Every finding is measured against what the manifest declares, so a workspace with no manifest — `--prefix`, or a
lockfile on its own — produces no findings at all, and the report says so.

## Where every fact came from

"Why does this package have no license?", "why is its purl a conda one?", "why is this version here?" are
questions about provenance, and a document answers none of them: it records what is known, not how it was looked
for. `--explain <PACKAGE>` answers them. It takes a name or a shell-style pattern (the same matching as
`--exclude`: `*` and `?`, case-insensitive, `-` and `_` alike), is repeatable, and prints one row per fact — what
the tool has, and the source that supplied it:

```console
$ pixi sbom --fetch-licenses --explain six
Package     Fact             Value                                Source
------------------------------------------------------------------------------------------------------------
six 1.17.0  identity         pkg:pypi/six@1.17.0                  lockfile pixi.lock
six 1.17.0  declared         default                              the workspace manifest
six 1.17.0  obtained from    pypi.org (https://pypi.org/simple)   lockfile pixi.lock
six 1.17.0  license          MIT                                  the PyPI index metadata (also the lockfile
                                                                  entry: the entry declares none; the wheel's
                                                                  dist-info: nothing cached for this package,
                                                                  and PIXI_SBOM_OFFLINE forbade a request)
six 1.17.0  requires python  >=2.7, !=3.0.*                       lockfile pixi.lock
six 1.17.0  vulnerabilities  -                                    OSV: not queried, --vulnerabilities was not
                                                                  given
six 1.17.0  needed by        -                                    lockfile pixi.lock: nothing else in this
                                                                  environment depends on it
```

The second half of each row is the point. Where a fact is empty the `Source` column names every source that
could have supplied it and says what each one did — not present, not read because the flag that reads it was not
given, nothing cached and offline forbade a request, or not applicable (the package cache holds conda packages,
so it is never asked about a wheel). Where a fact *is* known, the source that answered comes first and the others
follow in parentheses, so "the wheel said MIT and the lockfile said nothing" is one line rather than a guess.
Nothing here is inferred: the answers are read off the model and the `pixi:*` properties the enrichment steps
already record, and a source whose outcome cannot be known is not claimed.

Every fact is covered — identity, kind, version, what declared it, channel or index, location, checksums,
license and license files, other purls, `Requires-Python`, embedded SBOMs, yanked status, scorecard, findings,
both directions of the dependency graph, and every remaining `pixi:*` property — so a run with more flags has
more to say: `--fetch-licenses` turns the license row from "not read" into the wheel or the index,
`--vulnerabilities osv` turns the findings row into advisory ids, and `--pypi-mapping prefix` fills the other
purls.

```sh
pixi sbom --explain six --explain 'libz*'
pixi sbom --fetch-licenses --vulnerabilities osv --explain requests
pixi sbom --explain six --report-format json | jq '.explain[] | select(.value == null)'
```

`--explain` prints and writes nothing, exactly as `--report` does, so it cannot be combined with `--output`,
`--spec-version`, `--vex` or `--report` itself. It obeys `--report-format`: `markdown` and `csv` keep one row per
fact (the CSV adds the package version, kind and the consulted sources as their own columns), and `json` gives an
`explain` array of `{package, version, kind, fact, value, source, considered}` objects plus a summary of what was
asked and how much of it came back empty. A pattern that matches nothing is not an error — the report says so
rather than printing an empty table.

## Looking instead of writing

`--report` prints a report to the terminal and writes nothing:

```sh
# The inventory: name, version, kind, what declared it, source, license, purl
pixi sbom --report packages

# The license view, with a per-license summary, unlicensed and non-SPDX packages called out
# (each non-SPDX license names the token the parser rejected, e.g. "unknown term: 'PSF'")
pixi sbom --fetch-licenses --report licenses

# The findings of --vulnerabilities, one row per finding and affected package, worst first
pixi sbom --pypi-mapping prefix --vulnerabilities osv --report vulnerabilities

# What changed since the last release's document: added, removed, version and license changes
pixi sbom --report diff --against release/sbom.cdx.json --report-format markdown

# For a PR comment, a spreadsheet, or a script
pixi sbom --report licenses --report-format markdown
pixi sbom --report licenses --report-format csv > licenses.csv
pixi sbom --report packages --report-format json | jq '.packages[] | select(.license == null)'
```

Reports respect every selection and enrichment flag, so they show exactly what a document would contain; with
`--all-environments` / `--all-platforms` there is one section (or JSON array element) per document. `--report`
cannot be combined with `--output`.

`--report packages --tree` draws the graph the document carries instead of a flat list: the packages the root
depends on, then everything under them, with the license in the last column. A package is expanded once, at its
first occurrence; every later occurrence is marked `(*)` and not walked again, which keeps the output finite when
the graph has a cycle and short when a package is needed by half the environment. `--depth <N>` stops the walk
(`--depth 0` is the direct dependencies alone). The `json` and `csv` forms keep one row per occurrence, with
`depth`, `parent` and `repeat` on each.

`--report licenses --group-by license` turns the license view around: one section per license expression, most
common first, listing the packages under it, so "what is under GPL-3.0-only" is one glance instead of a scan down
a column. Packages that declare no license get their own last section. The rows themselves do not change, so
`json` and `csv` carry the same fields in that order.

```sh
pixi sbom --report packages --tree --depth 2
pixi sbom --report licenses --group-by license --report-format markdown
```

The `table` format fits the terminal width (`COLUMNS`, default 120, minimum 40) by wrapping cells onto further
lines, so nothing is ever cut: a narrow terminal costs height instead of content. Columns whose values are short
(versions, severities, identifiers) keep their full width while there is room, so the prose columns absorb the
squeeze and an advisory id is never broken in half. Markdown, CSV, JSON and SARIF are never wrapped or truncated.

While `--fetch-licenses`, `--vulnerabilities` and `--embedded-sboms` are fetching, a progress bar on stderr counts
the archives, wheels, package-cache reads, PyPI lookups and advisory records as they finish, naming the package or
advisory in flight. Bars are drawn only for an interactive run: never when stderr is not a terminal (a pipe, a
file, a CI log), never with `-v` or `-q` (the log lines would overwrite them or you asked for silence), and never
when `TERM=dumb`, `CI` or `PIXI_SBOM_NO_PROGRESS` is set. Log lines and diagnostics hide every live bar while they
print, so the two never overwrite each other.

Colour is applied to the `table` format only, since the others are data someone pastes or parses elsewhere.
`--color auto` (the default) colours when the output is a terminal and the environment allows it: a non-empty
`NO_COLOR` turns it off, `CLICOLOR_FORCE` turns it on even through a pipe, and `TERM=dumb` turns it off.
Severities are red through blue by level, `open` findings are yellow and `ignored` ones dim, KEV markers red,
diff rows green (added), red (removed), cyan (version) and magenta (license), licenses that are not SPDX
expressions yellow, and `-` placeholders dim.

The scorecard report has one row per package (package, version, score, when it was scored, and the checks below
the threshold worst first; the csv and json forms add the repository), the scored ones worst first and the
unscored ones last, followed by how many fall in each band and which are below the threshold.

The phantom report has one row per finding (what it is, the package, its kind and version, the modules it
provides, and the workspace files that import them — at most five, then a count of the rest), followed by the
three counts and how much source was read.

The python report has one row per PyPI package (package, version, `Requires-Python`, whether the interpreter
satisfies it, ceiling) and a summary naming the interpreter, the ceiling and the packages holding it.

The packages report carries a `Yanked` column (`yes: <reason>` for a withdrawn release, `-` otherwise) once
`--fetch-licenses` has asked the index; the CSV and JSON forms carry `yanked` and `yanked_reason` fields.

Its `Declared` column names the manifest features whose dependency tables asked for the package — `default`,
`default,docs` — and `-` for everything that came along as somebody else's dependency; the summary under the table
counts them and lists the names the manifest declares that this environment has no package for (a dependency of
another platform is the usual reason). Both are absent when there is no manifest to read, as with `--prefix`.

The vulnerabilities report has one row per finding and affected package (package, version, severity, the highest
CVSS score, KEV, id, aliases, fixed version, status, summary; the CSV and JSON forms add the purl, the OSV URL, the
`--ignore-vuln` justification and the KEV due date), open findings worst first and ignored ones last, followed by
a count of open findings and affected packages, a table of open findings per severity, the known-exploited
findings, the ignored findings with their justification, and the packages that have no purl the database could
answer. `--report-format sarif` renders it as a SARIF 2.1.0 log instead: one run per document, one rule per
advisory (with `security-severity` for GitHub code scanning: the CVSS score, or 10 for known-exploited findings),
one result per finding and affected package located at the lockfile, and accepted findings as suppressions.

The diff report compares the environment this run describes with another one. `--against` takes a document (any of
the formats pixi-sbom writes, from this tool or another), a `pixi.lock`, or the directory of an installed
environment; the last two are read for the same environment and platform as the run. Packages are matched by purl type and normalized name, so a version
bump is one `version` row (before and after) rather than a removal plus an addition; the sections are `added`,
`removed`, `version` and `license` (same package and version, different declared license), and a summary line
counts each plus the unchanged packages. Filters, mapping and license fetching apply to the new side as usual.
A document that is none of the three families is an error (`pixi_sbom::diff::parse`). `--against` does not combine
with `--all-environments` / `--all-platforms`.

`--fail-on-diff` turns the comparison into a gate: the run exits **6**, after printing the report, when the
sections it names are not empty. The bare flag means any change at all; naming sections (`--fail-on-diff version
license`, repeatable) gates on those alone, so a pull request can be allowed to add packages but not to change a
version behind your back. The sections that fired are listed on stderr with their counts.

```sh
# Fail the build when anything at all changed since the released document
pixi sbom --report diff --against release/sbom.cdx.json --fail-on-diff

# Only care that nothing was removed or relicensed
pixi sbom --report diff --against release/sbom.cdx.json --fail-on-diff removed license
```

### Does this container still match the lockfile?

`--prefix <DIR> --against pixi.lock` compares what is installed with what was locked, which is the check a
container image, a long-lived development environment or an incident response actually wants:

```sh
pixi sbom --prefix /opt/conda/envs/app --against pixi.lock --report diff --fail-on-diff
```

The installed environment is the new side and the lockfile the old one, so a package the image is missing is
`removed` and one it has that the lock does not is `added` — with two sections of their own for the ways an image
drifts without a version changing:

| Section | Meaning |
|---|---|
| `pip` | Installed by `pip` into the environment and absent from the lockfile: the classic way a conda environment stops matching its lock |
| `build` | Same package and version, different conda build string: a rebuild against different dependencies, which comparing versions alone misses |

With `--prefix` the document is named after the environment's directory, which says nothing about the lockfile, so
`--environment` (default `default`) names the side to compare with. The comparison also works the other way round —
a lockfile run with `--against <prefix directory>` — and between two lockfiles, where `--against pixi.lock` on the
workspace's own lockfile is the "nothing has changed" baseline.

## Working from an existing SBOM

`--from-sbom <FILE>` reads a document instead of a lockfile, so everything the tool does to a pixi environment can
be done to an SBOM somebody else wrote — including one from a project that does not use pixi at all:

```sh
pixi sbom --from-sbom sbom.cdx.json --vulnerabilities osv --report vulnerabilities
pixi sbom --from-sbom sbom.spdx.json --deny-license GPL-3.0-only --output -
pixi sbom --from-sbom sbom.cdx.json --format spdx --output sbom.spdx.json   # convert
```

The reader is the one behind `--against`, so CycloneDX 1.4–1.7, SPDX 2.x and SPDX 3.0.1 are all accepted. From
CycloneDX and SPDX 2.x it takes the packages, versions, purls, licenses, hashes, descriptions, download locations,
the dependency graph and the `pixi:*` properties a document this tool wrote carries — so a document of ours
round-trips unchanged, declared dependencies and all. SPDX 3.0.1 is read as packages, versions, purls and
licenses; its graph, hashes and properties do not come back.

The described application's name and version come from the document's own root component unless `--name` and
`--root-version` say otherwise, and the environment and platform from what the document records (`default` and
empty when it records nothing, or whatever `--platform` says). A purl that is neither `pkg:conda` nor `pkg:pypi`,
and a package with no purl at all, is recorded as the `external` kind: the document is the only thing that knows
what it is.

What is written carries `pixi:source-document` — the source's serial number or namespace — in place of
`pixi:lockfile`, so the derivation is traceable. Enrichment that needs a lockfile or a local package cache
(`--pypi-mapping`, the package-cache license reads) has nothing to work with and finds nothing; everything keyed on
purls works unchanged. `--all-environments` and `--all-platforms` do not apply, since a document is one
environment.

## A monorepo: every workspace in one run

A pixi workspace has exactly one lockfile next to its manifest, so several lockfiles in a tree mean several
workspaces. `--scan <DIR>` describes them all in one run, in sorted order, instead of a shell loop that everyone
writes slightly differently:

```sh
# One document per workspace, mirroring the tree under sboms/
pixi sbom --scan . --output sboms

# With everything else the tool does, across all of them at once
pixi sbom --scan . --report licenses --deny-license GPL-3.0-only
pixi sbom --scan . --pypi-mapping prefix --vulnerabilities osv --fail-on-severity high
```

The walk never enters hidden directories (`.pixi/`, `.git/`, `.venv/`), `node_modules`, `target`, `build`, `dist`,
`venv` or `__pycache__`, and does not follow symlinked directories, so an installed environment's copy of a
lockfile is never mistaken for a workspace. `--scan-depth <N>` caps the recursion. Finding nothing is an error
(`pixi_sbom::discover::none_found`) naming the directory, so a mistyped path cannot quietly produce no documents.

With `--output <DIR>` each document lands at `<DIR>/<the workspace's path in the tree>/<the usual file name>`, so
two workspaces never collide; without it each lands next to its own lockfile. `--all-environments` and
`--all-platforms` combine with it and keep their file naming inside each workspace's directory. Every document is
byte-identical to what `--lockfile <that file>` would have written: the workspace name still comes from that
workspace's manifest, `pixi:lockfile` stays relative to its own root, and the document identity is unchanged.

Reports, the license policy and the vulnerability gate cover the whole run: one report with a section per
workspace (the `workspace` column names it), and one exit code for all of them. The configuration file is read
once, from the scanned directory rather than from each workspace, so one setting applies to the whole tree.

## One document per environment and platform

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

## Which input and which settings a run chose

Four decisions are made before any work starts, and `-v` names all four:

```console
$ pixi sbom --format cyclonedx -v
DEBUG pixi_sbom::config: configuration file path=/w/pixi-sbom.toml kind="pixi-sbom.toml" applied="exclude, fetch-licenses" overridden_on_the_command_line="format"
DEBUG pixi_sbom: input input="/w/pixi.lock" how="found by searching upward from the working directory" from=/w
DEBUG pixi_sbom: workspace manifest path=/w/pixi.toml
```

- **the input**, and how it was reached: `--lockfile`, the upward search, `--prefix`, `--from-sbom` or `--scan`;
- **the manifest** beside it, or that there is none — which is what turns the root component's dependencies back
  into the graph-root heuristic;
- **the configuration file**, its kind, the settings it supplied that were applied, and the ones the command line
  overrode. "The flag has no effect" and "it described the wrong environment" both start here;
- with `--scan`, that the configuration was read from the scanned directory and each workspace's own file was
  deliberately skipped.

`--no-config` says so rather than saying nothing, and so does a directory with no configuration file in it.
## Reporting a problem

`pixi sbom --version-details` (or `--build-info`) prints the block a bug report needs, and nothing else:

```console
$ pixi sbom --version-details
pixi-sbom 0.9.0 (aarch64 macos)
features: rustls, gzip, platform-verifier, socks-proxy: no, win-system-proxy: no
caches:   /home/u/.cache/rattler/pixi-sbom (exists)
pixi:     pixi 0.81.0
offline:  false   proxy: HTTPS_PROXY=http://user:***@proxy.corp:8080   no-proxy: none
TLS:      the platform verifier (the operating system trust store)
```

The `features` line is the one that is invisible from the outside and settles several questions: a build without
`socks-proxy` cannot use a `socks5://` proxy however correctly it is configured, and one without
`win-system-proxy` ignores a proxy set only in the Windows settings. Proxy passwords are replaced, so the block is
safe to paste; internal host names are not, so read it before you do.

The repository's bug report form asks for this block, the command, and the same command with `-vv`.

## Where the time went

`--timings` prints a table at the end of the run:

```
Phase                   Time  Detail
input                 0.04 s  240 packages
pypi mapping          1.21 s
wheels (dist-info)   12.40 s  38 fetched, 4 cached
conda archives       31.90 s
pypi metadata         2.10 s  36 found, 0 failed
vulnerabilities       2.10 s  24 queried, 9 findings
write                 0.08 s
total                49.90 s  of which 49.6 s waiting on the network
```

The last line is the one that decides what to do about a slow run: time spent waiting on an upstream is a network
problem, and time spent anywhere else is the tool's. A phase appears only when it ran, so the table doubles as a
record of what the flags actually did.

## Which certificates TLS is verified against

Every HTTPS request — the PyPI index, OSV, the KEV catalog, the Scorecard API, each wheel and conda archive — is
verified against the **operating system's trust store** by default, through the platform verifier. No root store
is compiled into the binary, so nothing goes stale between releases, and a CA installed system-wide (as a
TLS-intercepting appliance's usually is) works with no configuration at all.

Where the CA is not installed system-wide — a container, a CI image, a machine where only Python was ever
configured — name a PEM bundle instead. The anchors are resolved once, before the first request, and the first
of these that is set wins:

| Order | Source | |
|---|---|---|
| 1 | `--ca-bundle <FILE>` | The flag, as always, beats the environment |
| 2 | `PIXI_SBOM_CA_BUNDLE` | For a CI job that cannot change the command line |
| 3 | `SSL_CERT_FILE` | What the rest of the Python and conda world already sets in such an image |
| 4 | the platform verifier | The default: the operating system's own trust store |

```sh
pixi sbom --ca-bundle /etc/ssl/certs/corp-ca.pem --vulnerabilities osv
```

`--doctor` and `--version-details` print which source is in play, as the `TLS roots` line. A bundle that is
missing or holds no certificate is reported before the first request, naming the file and the flag or variable
that gave it, rather than arriving later as a handshake failure. The file must be PEM; convert a DER file first
(`openssl x509 -inform der -in ca.der -out ca.pem`).

Proxies come from `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` in either case, including `socks5://`
and `socks5h://`; on Windows a proxy set only in the system settings is used as well. See
[troubleshooting](troubleshooting.md) for what `--doctor` prints when one of these is the problem.

## A log a machine can read

`--log-format json` (or `PIXI_SBOM_LOG_FORMAT=json`) writes the log as one JSON object per line
instead of prose:

```console
$ pixi sbom --vulnerabilities osv --log-format json -v
{"timestamp":"2026-09-25T13:41:02.104323Z","level":"INFO","fields":{"message":"selected lock environment","environment":"default","platform":"linux-64","packages":25},"target":"pixi_sbom::lock"}
{"timestamp":"2026-09-25T13:41:02.271884Z","level":"WARN","fields":{"message":"request failed","service":"OSV","url":"https://api.osv.dev/v1/querybatch","cause":"io: invalid peer certificate: UnknownIssuer"},"target":"pixi_sbom::http"}
```

Everything the human log carries is there, as a field rather than as prose: the service, the URL, the status, the
elapsed time, the package, the cache age, the whole error chain. That is what makes "alert when the mapping
download fails" or "chart how long the OSV lookups take" a `jq` filter rather than a regex over sentences.

The timestamp, which the text renderer drops deliberately (a person watching a terminal knows what time it is),
comes back for `json`. Colour is off and the progress bars are off, since nothing reading this is a terminal.

This is the *log* on stderr and is unrelated to `--report-format json`, which is the *report* on stdout. The
natural shape in CI uses both: `--report-format json --output report.json --log-format json`, the report to a file
and the log to the collector.

The format has to be chosen before anything can be logged, which is before the configuration file is read, so
`--log-format` and `PIXI_SBOM_LOG_FORMAT` are the only ways to set it.

## --doctor: is it the network?

`pixi sbom --doctor` answers "which service could not be reached, and why" without a lockfile, a workspace or
`curl`. Give it the flags of the run you are diagnosing and it probes exactly those upstreams:

```console
$ pixi sbom --doctor --fetch-licenses --vulnerabilities osv
Configuration
  offline    false
  proxy      HTTPS_PROXY=http://user:***@proxy.corp:8080
  no-proxy   NO_PROXY=.corp
  TLS roots  the platform verifier (the operating system trust store)
  timeout    120s
  cache      /home/u/.cache/rattler/pixi-sbom (exists)

Upstreams
  PyPI index                 ok 200, 245 ms
                             https://pypi.org/pypi (default)
  OSV                        failed: io: invalid peer certificate: UnknownIssuer
                             https://api.osv.dev (default)

Caches
  osv                        170 entries, newest 23h old
  pypi                       24 entries, newest 44m old

1 of 2 upstream(s) could not be reached: OSV.
```

Each row carries the address actually used, where it came from, and the outcome with the **whole** error chain.
A status of 400 or more is reported as `reachable` rather than as success or failure, because the probe asks a
base address and that is often not a document — the host answered, which is what was in question. The cache
section is there so "it works because it is cached" is visible: an upstream that fails while its cache is warm
explains a run that succeeded yesterday and fails today.

The exit code is 0 when everything asked answered and 1 when anything did not, so it works as a CI smoke test on
a locked-down runner. With `PIXI_SBOM_OFFLINE=1` every probe is reported as skipped and the command still exits 0.
It cannot be combined with `--output`, `--report` or `--explain`.

## What a run will talk to

Before the first request, a run that uses the network says how it is set up and which upstreams the flags brought
in — the one place two machines usually differ:

```console
$ pixi sbom --fetch-licenses --vulnerabilities osv --pypi-mapping prefix -v
INFO  pixi_sbom::http: network configuration offline=false proxy="HTTPS_PROXY=http://user:***@proxy.corp:8080" tls_roots="the platform verifier (the operating system trust store)" timeout_s=120 services=4
DEBUG pixi_sbom::http: upstream service="PyPI index" url=https://pypi.org/pypi source="default"
DEBUG pixi_sbom::http: upstream service="conda-forge PyPI mapping" url=https://conda-mapping.prefix.dev/... source="default"
DEBUG pixi_sbom::http: upstream service="OSV" url=https://osv.internal source="PIXI_SBOM_OSV_URL"
DEBUG pixi_sbom::http: cache directory path=~/Library/Caches/rattler/cache/pixi-sbom exists=true
```

The summary line is at the default level; the per-service detail needs `-v`. Each upstream says **where its
address came from** — a default, or the variable that changed it — so a mirror or a typo in
`PIXI_SBOM_OSV_URL` is visible rather than inferred. The proxy is whichever of `ALL_PROXY`, `HTTPS_PROXY` and
`HTTP_PROXY` ureq will use, named and with its password replaced; `NO_PROXY` is printed too when set. A run that
touches no upstream prints none of this.

## The caches, and getting out of them

Seven caches back the network features, with lifetimes from an hour to a week:

| Cache | Holds | Lifetime |
|---|---|---|
| `mapping` | the conda-forge name mapping | a day |
| `osv` | query results and advisory records | an hour (records until the advisory changes) |
| `kev` | the CISA catalog | a day |
| `wheels` | `dist-info` read out of wheels | until the wheel changes, which it never does |
| `pypi` | release metadata | as above |
| `outdated` | project documents | a day |
| `scorecard` | OpenSSF scores | a week |

They are what makes a second run fast and an offline run possible, and they are also why "it works on my machine"
is often "my cache is warm". Each run says what they served:

```
INFO pixi_sbom::cache: cache cache="osv" from_cache=24 fetched=6 oldest_s=2460
```

`--refresh` ignores what is on disk and asks again — `--refresh` for all of them, `--refresh osv --refresh pypi`
for those two — while still writing back what it fetches. `--no-cache` neither reads nor writes, which is the one
to reach for when reproducing a problem: it proves the answer came from the network this minute. The two cannot be
combined.

## When something comes back empty

An empty table has two meanings and they are not the same: nothing was found, or nothing could be asked. The
reports say which.

`--report vulnerabilities` over an environment whose packages carry no purl the database answers to — a
conda-only environment without `--pypi-mapping prefix`, which is the usual case — ends with:

```
Nothing could be queried: no package carries a purl the database answers to. Add --pypi-mapping prefix
(or --pypi-mapping-file) so conda packages can be matched.
```

The JSON form carries the same fact as `summary.queryable`, so a pipeline can tell a clean environment from an
unasked one. The outdated and scorecard reports already separate "answered" from "no index to ask" and
"unknown" in the same way.

A cache that was served **past its lifetime** because the fetch failed is also called out once per service, with
how old the data is, so a document built on week-old advisories does not read like one built this morning.



Every request the tool makes is logged at debug, with what it asked for and how it ended:

```console
$ pixi sbom --fetch-licenses --vulnerabilities osv -v
DEBUG pixi_sbom::http: requesting method="GET" url="https://pypi.org/pypi/six/1.17.0/json" detail="" proxy="none"
DEBUG pixi_sbom::http: answered method="GET" url="https://pypi.org/pypi/six/1.17.0/json" status=200 bytes=14204 ms=180
DEBUG pixi_sbom::http: request failed method="GET" url="https://api.osv.dev/v1/querybatch" ms=32 cause="io: invalid peer certificate: UnknownIssuer"
```

The `cause` field is the whole error chain, not only its outermost message: a TLS failure says
`invalid peer certificate`, a proxy failure says so, a refused connection says `Connection refused`. The warnings
that survive at the default level carry the same field, so one pasted line identifies the problem. `proxy` names
the environment variable in effect (`HTTPS_PROXY=http://proxy.corp:8080`) with any password replaced, or `none`.

With `PIXI_SBOM_OFFLINE=1`, each request that was *not* made is logged instead, which is how to tell "there was
nothing to find" from "nothing was asked".

When the same command answers on one network and comes back empty on another, the page to read is
[troubleshooting](troubleshooting.md): the proxy, the private CA and the blocked host, each with what `--doctor`
prints for it.

To narrow the log to the part of the tool you are chasing — the requests, one enrichment step, the caches — see
[what the log says](#what-the-log-says-and-how-to-narrow-it) and its three worked recipes.

## Environment variables

| Variable | Effect |
|---|---|
| `COLUMNS` | Terminal width for `--report-format table` (default 120). |
| `PIXI_CACHE_DIR` / `RATTLER_CACHE_DIR` | Where pixi keeps its package cache; `--fetch-licenses` reads extracted conda packages from its `pkgs/` directory. Default: the platform cache directory's `rattler/cache` (`~/.cache/rattler/cache`, `~/Library/Caches/rattler/cache`, `%LOCALAPPDATA%\rattler\cache`). |
| `PIXI_SBOM_OFFLINE` | Set to `1` to forbid every network request: the mapping, wheel, archive, OSV and KEV caches are used when present and everything else is skipped with a warning. The run still succeeds. |
| `PIXI_SBOM_OSV_URL` | Base of the OSV API queried by `--vulnerabilities osv` (default `https://api.osv.dev`). |
| `PIXI_SBOM_NO_PROGRESS` | Set to `1` to turn the progress bars off even on a terminal. |
| `PIXI_SBOM_ANACONDA_URL` | Base of the anaconda.org API used by `--report outdated` for conda packages (default `https://api.anaconda.org`). |
| `PIXI_SBOM_SCORECARD_URL` | Base of the OpenSSF Scorecard API used by `--scorecard` (default `https://api.securityscorecards.dev`). |
| `PIXI_SBOM_KEV_URL` | Where `--kev` downloads CISA's Known Exploited Vulnerabilities catalog (default `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`). |
| `PIXI_SBOM_PYPI_URL` | Base of the PyPI JSON API queried by `--fetch-licenses` (default `https://pypi.org/pypi`); point it at a mirror such as devpi or Artifactory. |
| `PIXI_SBOM_CACHE_DIR` | Where downloaded data (the PyPI mapping, PyPI metadata, extracted conda `info` directories, wheel `dist-info` files) is cached. Default: `pixi-sbom` inside the pixi cache directory (`PIXI_CACHE_DIR` / `RATTLER_CACHE_DIR`, else `~/.cache/rattler/cache`, `~/Library/Caches/rattler/cache`, `%LOCALAPPDATA%\rattler\cache`), so `pixi clean cache` removes it too. |
| `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` / `NO_PROXY` | Honored for every download, either case, including `socks5://` and `socks5h://` addresses. On Windows a proxy configured only in the system settings is used as well. |
| `PIXI_SBOM_CA_BUNDLE` | A PEM bundle to verify TLS against instead of the operating system's trust store, the same as `--ca-bundle`. |
| `SSL_CERT_FILE` | The same, used when neither `--ca-bundle` nor `PIXI_SBOM_CA_BUNDLE` is given — the variable the rest of the Python and conda world already sets in an image with a private CA. |
| `SOURCE_DATE_EPOCH` | Pins the document timestamp (seconds since the Unix epoch). With it set, repeated runs over the same lockfile are byte-identical, which lets CI diff SBOMs between commits. See [output-format.md](output-format.md#reproducibility). |
| `PIXI_SBOM_LOG_FORMAT` | `text` (the default) or `json`, the same as `--log-format`, for a CI job that cannot change the command line. A value that is neither is named in the log and the run continues as text. |
| `RUST_LOG` | Log filter, overrides `-v`/`-q`, and takes per-module directives — see [what the log says](#what-the-log-says-and-how-to-narrow-it). |

## Examples

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

## Exit codes and errors

| Exit code | Meaning |
|---|---|
| 0 | Document(s) written. |
| 1 | A runtime error; a diagnostic is printed to stderr. |
| 3 | The license policy was violated; the documents were written and the violations listed on stderr. |
| 4 | The vulnerability gate (`--fail-on-severity` / `--fail-on-kev`) failed; the documents were written and the findings listed on stderr. |
| 6 | `--fail-on-diff` found a change it was asked to gate on; the report was printed and the sections listed on stderr. |
| 7 | `--fail-on-yanked` found a yanked release; the documents were written and the releases listed on stderr. |
| 8 | `--fail-on-phantom` found an import the manifest never declared; the report was printed and the packages listed on stderr. |
| 9 | `--fail-on-scorecard` found a scored repository below the threshold; the document was written and the packages listed on stderr. |

Several gates can fail in one run. Each prints its own list, and the run then says which of them fired and which
one chose the exit code, because in CI the code is the headline and the log is long:

```
2 gates failed: license policy (4), vulnerabilities (2).
Exiting 3 (license policy); the others would have been 4.
```

The precedence is the order of the table above: the license policy first, then vulnerabilities, yanked releases,
phantom imports, the comparison, and scorecards last.
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
