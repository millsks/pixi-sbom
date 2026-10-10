# Output format reference

Both formats are produced from the same intermediate model (see [architecture.md](architecture.md)), so they carry
the same information; only the spelling differs. Output is pretty-printed JSON with keys in the order the
specifications list them, followed by a trailing newline.

## Document header

| | CycloneDX 1.6 / 1.7 | SPDX 2.3 |
|---|---|---|
| Identity | `bomFormat: CycloneDX`, `specVersion: 1.6` or `1.7` (`--spec-version`), matching `$schema` | `spdxVersion: SPDX-2.3`, `dataLicense: CC0-1.0`, `SPDXID: SPDXRef-DOCUMENT` (for `--spec-version 3.0` see [SPDX 3.0.1](#spdx-301)) |
| Unique id | `serialNumber: urn:uuid:<v5>` | `documentNamespace: https://spdx.org/spdxdocs/pixi-sbom/<name>/<uuid>` |
| Timestamp (UTC, seconds) | `metadata.timestamp` | `creationInfo.created` |
| Generator | `metadata.tools.components[]`: `pixi-sbom` with version and repository link | `creationInfo.creators[]`: `Tool: pixi-sbom-<version>` |
| Author | `metadata.authors[]` (`name`, `email`) from the manifest's `authors` | `creationInfo.creators[]`: `Person: <name> (<email>)` |
| Generation context | `metadata.lifecycles[]`: the phase the input describes (see [Lifecycle phase](#lifecycle-phase)) | `creationInfo.comment` naming the input and the same phase |
| Data origin (1.7 only) | `citations[]`: one entry attributing `/metadata/component`, `/components` and `/dependencies` to the pixi-sbom tool component, with a note naming the lockfile, environment and platform | (none) |
| Document name | (none; the root component carries it) | `name: <workspace>-<environment>-<platform>` |
| What was described | `metadata.properties[]`: `pixi:environment`, `pixi:platform`, `pixi:lockfile` | root package `sourceInfo` |

`pixi:lockfile` is the lockfile's name relative to the workspace root (normally `pixi.lock`), never the absolute path
it was read from, so a document does not reveal or depend on the layout of the machine that generated it.

### Lifecycle phase

What moment in a project's life the document describes depends on what it was made from:

| Input | CycloneDX `metadata.lifecycles[].phase` | SPDX 3 `software_sbomType` | SPDX 2.3 `creationInfo.comment` |
|---|---|---|---|
| A lockfile (`pixi.lock`, `pylock.toml`) | `pre-build`: resolved, nothing built | `build` | "Generated from the lockfile … before any build; lifecycle phase: pre-build" |
| `--prefix` | `operations`: what is installed | `deployed` | "Generated from the installed environment …; lifecycle phase: operations" |
| `--from-sbom` | the source document's phases | the same, mapped | "Generated from the document …", with its phases |
| `--from-sbom`, source names none | none (`lifecycles` is left out) | none | no phase |

A source document's phases are read from its `metadata.lifecycles` (CycloneDX), its `software_sbomType` (SPDX 3),
or the creator comment of an SPDX 2.3 document pixi-sbom wrote. SPDX 3 has one `build` type for CycloneDX's
`pre-build`, `build` and `post-build`, so a lockfile's document read back from SPDX 3 is `build`; `decommission`
has no SPDX 3 counterpart and is left out there. Before 1.7.0 every document claimed `pre-build`, which was wrong for
`--prefix` and `--from-sbom`.

### Reproducibility

Documents are deterministic. The identifier is a UUIDv5 derived from the lockfile text, the environment, the
platform, the format, and the pixi-sbom version, so the same input always yields the same `serialNumber` /
`documentNamespace`, and any change to the lockfile yields a new one. The timestamp is the only value that varies
between runs; set [`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/specs/source-date-epoch/) (seconds since the
Unix epoch) to pin it, and two runs produce byte-identical files. An unparsable `SOURCE_DATE_EPOCH` is ignored with a
warning.

## The root component

The workspace itself is the subject of the document.

| | CycloneDX | SPDX |
|---|---|---|
| Element | `metadata.component` (`type: application`, `bom-ref: root`) | `packages[0]` with `SPDXID: SPDXRef-Package-root`, `primaryPackagePurpose: APPLICATION` |
| Name / version | `name`, `version` from the manifest | `name`, `versionInfo` |
| License | `licenses[]` (same rules as packages, see below) | `licenseDeclared` |
| Homepage / repository | `externalReferences[]` of type `website` / `vcs` | `homepage` / `downloadLocation` |
| Link to document | implicit | relationship `SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-root` |

Name, version, authors, license, homepage and repository come from `pixi.toml` (`[workspace]`, or the legacy
`[project]` table) or from `pyproject.toml` (`[tool.pixi.workspace]`, with the PEP 621 `[project]` table filling in
whatever is missing: `authors` entries as `{ name, email }`, `license` as an expression string or `{ text = ... }`,
`[project.urls]` keys `Homepage` and `Repository` / `Source`). With no manifest, the name is the lockfile's directory
and everything else is absent.

## Packages

Every package locked for the selected environment and platform becomes one entry, sorted by kind (conda binary,
conda source, PyPI), then name, then version.

| Lockfile data | CycloneDX `components[]` | SPDX `packages[]` |
|---|---|---|
| Kind | `type: library`; property `pixi:kind` = `conda`, `conda-source`, `pypi` or `embedded` | `primaryPackagePurpose: LIBRARY`; kind is part of the `SPDXID` |
| Identifier | `bom-ref` = purl | `SPDXID: SPDXRef-Package-<kind>-<name>-<version>` (sanitized, de-duplicated with a numeric suffix) |
| Name, version | `name`, `version` | `name`, `versionInfo` |
| Package URL | `purl` | `externalRefs[]` with `referenceCategory: PACKAGE-MANAGER`, `referenceType: purl` |
| Supplier | `supplier` (`name`, `url[]`): the conda channel (e.g. `conda-forge`) or the PyPI index host (e.g. `pypi.org`); absent for source packages | `supplier`: `Organization: <name> (<url>)` |
| Extra purls (see below) | property `pixi:purl` per purl | additional `externalRefs[]` entries |
| Download location | `externalReferences[]` of type `distribution`, or `vcs` for `git+` locations; none when nothing records one (`poetry.lock` names files, not URLs) | `downloadLocation` (URL or `git+<url>@<rev>`); `NOASSERTION` plus `sourceInfo` for local paths; `NOASSERTION` alone when nothing records one |
| SHA-256, MD5 | `hashes[]` (`SHA-256`, `MD5`) | `checksums[]` (`SHA256`, `MD5`) |
| License | `licenses[]` (see below) | `licenseDeclared` (see below); `licenseConcluded` and `copyrightText` are `NOASSERTION` |
| License file names, summary, URLs (`--fetch-licenses`) | `pixi:license-file` properties, `description`, `externalReferences[]` | `licenseComments`, `summary`, `homepage` |
| License texts (`--license-texts`) | `licenses[].license.text` | `hasExtractedLicensingInfos` for `LicenseRef-` licenses |
| Everything else | `properties[]` with `pixi:` names | `comment`: one `key=value` per line |
| `filesAnalyzed` | | always `false` (no archive is opened) |

Version is omitted only for pixi-build source packages whose metadata has not been evaluated yet (a "partial" lock
entry).

### `pixi:*` properties

| Property | Set for | Value |
|---|---|---|
| `pixi:kind` | all | `conda`, `conda-source`, `pypi`, `embedded`, `external` |
| `pixi:channel` | conda binary | Channel name, e.g. `conda-forge` (last path segment of the channel URL) |
| `pixi:channel-url` | conda binary | Full channel base URL |
| `pixi:subdir` | conda | `linux-64`, `noarch`, ... |
| `pixi:build` | conda | Build string |
| `pixi:build-number` | conda | Build number |
| `pixi:file-name` | conda binary; PyPI (`poetry.lock`, `pdm.lock`) | Archive file name; for a Poetry package, the wheel or sdist this platform would install, since Poetry records no download URL |
| `pixi:size` | conda | Archive size in bytes |
| `pixi:license-family` | conda | Channel-declared license family |
| `pixi:noarch` | conda | `true` when the package is noarch |
| `pixi:purl` | conda | Additional purls the channel declares (typically the PyPI purl of a Python package) |
| `pixi:identifier-hash` | conda source | pixi-build identifier hash from the lock entry |
| `pixi:source-git`, `pixi:source-rev`, `pixi:source-tag` / `pixi:source-branch`, `pixi:source-subdirectory` | conda source (git) | The pinned build source |
| `pixi:source-url`, `pixi:source-subdirectory` | conda source (archive) | The pinned build source; its SHA-256 goes into the hashes |
| `pixi:source-path` | conda source (path) | Local path |
| `pixi:direct` | any | `true` when the workspace manifest declares this package itself, rather than it coming along as somebody else's dependency. For a lockfile other than `pixi.lock`, the manifest is the `pyproject.toml` or `environment.yml` beside it (see [What a project without pixi declared](cli.md#what-a-project-without-pixi-declared)) With `--prefix`, set on what the user asked for by name (`REQUESTED`, `conda-meta/history`), with `pixi:declared-in = requested` |
| `pixi:declared-in` | any | The features whose dependency tables declare it, comma separated (`default`, `default,docs`) |
| `pixi:license-exempt` | any | Why the license policy does not apply (`--ignore-license`); `true` when no justification was given |
| `pixi:scorecard`, `pixi:scorecard-date` | any | With `--scorecard`: the OpenSSF Scorecard aggregate out of ten and when the repository was scored |
| `pixi:scorecard-check-<name>` | any | One per check below `--scorecard-min`, e.g. `pixi:scorecard-check-Signed-Releases=0.0` |
| `pixi:cargo-source` | embedded (cargo) | Where a crate read from a `cargo auditable` binary came from: `crates.io`, `git`, `local`, ... |
| `pixi:index-url` | PyPI | Index the wheel was resolved from |
| `pixi:repository-source` | PyPI (`--fetch-licenses`) | Where the package's repository URL came from: `wheel` (its `dist-info`), `pypi` (the JSON API's `project_urls`, for a package whose lockfile names no wheel) or `document` (the VCS reference of a `--from-sbom` document) |
| `pixi:resolution-markers` | PyPI (`uv.lock`) | For a package uv locked at more than one version, the environments this one is for, joined with ` \|\| ` |
| `pixi:marker` | PyPI (`pylock.toml`) | The environment marker the lockfile put on the package, e.g. `sys_platform == 'win32'`; the package is in the document because the marker is true for its platform |
| `pixi:direct-url` | PyPI (`pylock.toml`, `uv.lock`, `--prefix`) | Where a package installed from outside an index came from: the repository URL of a VCS source, the path of a local directory (relative to the lockfile), or the URL of an archive |
| `pixi:source-rev` | PyPI (`pylock.toml`, `uv.lock`, `--prefix`) | The exact commit of a VCS source |
| `pixi:editable` | PyPI (`pylock.toml`, `uv.lock`) | `true` for a local directory installed in editable mode |
| `pixi:requires-python` | PyPI | `Requires-Python` of the distribution |
| `pixi:python-extras` | PyPI (`pixi.lock`, `uv.lock`, `poetry.lock`, `pdm.lock`; `--prefix` with `--infer-extras`) | The extras the package was installed with, comma separated, e.g. `socks,security`: what the manifest and the other packages asked of it |
| `pixi:python-extras-inferred` | PyPI (`--prefix --infer-extras`) | `true` when `pixi:python-extras` was inferred from what is installed rather than read from the input |
| `pixi:python-extras-evidence` | PyPI (`--prefix --infer-extras`) | What an inference rests on: each extra and the installed packages it requires, e.g. `socks: pysocks` |
| `pixi:via-extra` | PyPI (`pixi.lock`, `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml`) | The extras the package is in the document for, as `package[extra]`, comma separated, e.g. `requests[socks]`. Set only when nothing else needs the package; what such a package depends on carries the same label |
| `pixi:source` | PyPI | `true` for sdists / source trees |

In SPDX these appear in the package `comment` because SPDX 2.3 has no free-form property field.

### Package URLs

| Kind | Shape |
|---|---|
| conda binary | `pkg:conda/<name>@<version>?build=<build>&channel=<channel>&subdir=<subdir>&type=<conda\|tar.bz2>` |
| conda source | `pkg:conda/<name>@<version>?build=<build>&subdir=<subdir>` (no channel; qualifiers present only when known) |
| PyPI | `pkg:pypi/<normalized-name>@<version>` with PEP 503 normalization (lower-case, runs of `-_.` collapsed to `-`) |
| PyPI, from a GitHub checkout | `pkg:github/<owner>/<repo>@<commit>` |
| PyPI, from another VCS checkout | `pkg:pypi/<normalized-name>@<version>?vcs_url=<vcs>+<repository>@<commit>` |
| PyPI, from an archive URL | `pkg:generic/<name>@<version>?download_url=<url>` |
| PyPI, from a local directory or archive (editable or not) | `pkg:generic/<name>@<version>` |
| First-party workspace member (`uv.lock`) | `pkg:generic/<name>@<version>`: no registry has released it |

A package installed from somewhere other than an index does not get a plain `pkg:pypi` purl, since that would claim
a PyPI release which may not exist or may hold other code, and a scanner would match the wrong advisories. Where it
came from stays in `pixi:direct-url`, `pixi:source-rev` and `pixi:editable`, from every lockfile reader and from
`--prefix` (PEP 610 `direct_url.json`). Nor are they looked up on PyPI by name for a license, a yanked status or the outdated report, since the name may belong to an unrelated project. `--vulnerabilities osv` asks about none of these purls: OSV has no ecosystem
for `generic` or `github`, and a `vcs_url` checkout is not the release of its version. In `pixi.lock` a git or local
source is recognised; a URL without an index is left as it is, since older lockfiles record index wheels that way.

Purls double as the CycloneDX `bom-ref`, which is why they must be unique within a document; within one environment
and platform they always are. The `bom-ref` / `SPDXID` is always derived from the conda purl, even when
`--primary-purl pypi` (below) makes a PyPI purl the component's `purl`.

### PyPI identities for conda packages

Vulnerability databases (OSV, GHSA) and the scanners built on them have no conda ecosystem: a `pkg:conda/numpy@...`
purl matches nothing, so a conda-only Python environment scans as clean whatever it contains. Three sources supply a
`pkg:pypi/...` purl for a conda package, and a fourth for an installed environment:

| Source | When | Recorded as |
|---|---|---|
| Lockfile `purls:` | pixi writes them for environments that have `pypi-dependencies`; an empty list means "not on PyPI" | `pixi:purl` property / extra `externalRefs` entry |
| `--pypi-mapping prefix` | the [conda-forge mapping](https://conda-mapping.prefix.dev/compressed-v0/compressed_mapping.json) pixi itself uses, downloaded and cached for a day | as above, plus `pixi:pypi-mapping=prefix` |
| `--pypi-mapping-file <PATH>` | an offline copy of that mapping (`{"<conda name>": "<pypi name>" \| ["..."] \| null}`) | as above, plus `pixi:pypi-mapping=file` |
| The installed `dist-info` (`--prefix` only) | the conda record's `files` list the `site-packages/<name>-<version>.dist-info/METADATA` the package installed; its `Name` and `Version` are the PyPI project's. Read from disk, no network, no flag | as above, plus `pixi:pypi-mapping=dist-info` and `pixi:pypi-dist-info` (the directory, relative to the prefix) |

What a package installed outranks a name mapping: one with an identity from its `dist-info` is left alone by
`--pypi-mapping`, which still answers for the packages that installed none. The mapping is applied only to
conda-forge binary packages whose lock entry has no `purls:` at all; the lockfile's own
answer, including an explicit empty list, is authoritative. The PyPI purl carries the conda package's version.

pixi writes lockfile purls as bare names — `pkg:pypi/click?source=compressed-mapping`, with no version, because the
mapping behind them is name to name. A purl with no version is a name, not an identity: no database can be asked
about it. Where the lock entry states a bare purl, its version is filled in from that same entry
(`pkg:pypi/click@8.5.0?source=compressed-mapping`). A purl that already carries a version is left alone, and
`purls: []` keeps meaning "not on PyPI".

`--primary-purl pypi` then makes that PyPI purl the component's `purl` (first `externalRefs` entry in SPDX) and moves
the conda purl to `pixi:purl`, because scanners only read the primary identity. With it, `grype` / `trivy` /
`osv-scanner` report advisories for conda-installed Python packages. Without it, a run that leaves PyPI identities
where scanners cannot see them warns once on stderr; [Scanning with Grype](ci-recipes.md#scanning-with-grype) has the
recommended commands and the configuration key.

### CRAN identities for R packages

An `r-*` conda package is usually a [CRAN](https://cran.r-project.org/) package, and OSV indexes CRAN advisories.
Each one that is on CRAN gets a `pkg:cran` purl beside its `pkg:conda` one, by default and offline, the way a conda
Python package gets its PyPI purl: in `pixi:purl` (CycloneDX) or an extra `externalRefs` entry (SPDX). The conda purl
stays primary. `--vulnerabilities osv` and osv-scanner match it; Grype has no CRAN advisories.

CRAN names are case-sensitive and may contain dots, and conda spells versions with `_` where CRAN has `-`, so the
name and version come from the best source on hand, recorded in `pixi:cran-source`:

| `pixi:cran-source` | Where from |
|---|---|
| `description` | The package's own `DESCRIPTION` file, in the installed environment (`--prefix`) or in the extracted package in the pixi package cache. Its `Repository: CRAN` line also decides whether the package is on CRAN: a Bioconductor, GitHub or base-R package gets no CRAN purl. |
| `table` | `data/cran.toml`, generated from CRAN's package list and archive: `r-rcpp` is `Rcpp` |
| `rule` | `r-<name>` is `<name>`, and conda's `1.0.13_1` is CRAN's `1.0.13-1` |

`r-base` and the other `r-*` packages that were never on CRAN, current or archived, get none.

### CPEs for native conda packages

A native library from a conda channel (openssl, libtiff, sqlite, python itself) has no PyPI identity, and its
`pkg:conda` purl is in no advisory database. Scanners that match through NVD, such as Grype, match those by CPE
instead. A channel's conda package whose name is in pixi-sbom's curated table (`data/cpe.toml`) gets one:

| Format | Where |
|---|---|
| CycloneDX 1.6 / 1.7 | `component.cpe` |
| SPDX 2.3 | an `externalRefs` entry: `referenceCategory: SECURITY`, `referenceType: cpe23Type` |
| SPDX 3.0.1 | an `externalIdentifier` with `externalIdentifierType: cpe23` |

The value is a CPE 2.3 formatted string, `cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*`, with the table's
vendor and product as NVD spells them and the conda package's own version (characters a formatted string cannot
carry unquoted are quoted with a backslash).

**A package that is not in the table gets no CPE. pixi-sbom never guesses one from a name**: name guessing is where
scanners' false positives on conda packages come from. Nothing is looked up at run time; the table is identity data,
like the PyPI mapping. PyPI packages, and conda packages with a PyPI identity, are matched by their purl and get no
CPE. `--explain <package>` shows the table entry a CPE came from, or that there is none, and `--report quality`
counts native conda packages that have neither a CPE nor a purl a scanner matches.

A CPE match is only as precise as the version: NVD cannot know that a conda-forge build carries a backported fix, so
a finding on an older version may already be fixed in that build.

### Licenses

Package license strings are whatever the channel or index declared; conda-forge is mostly SPDX-clean but not
entirely, and PyPI wheels in a pixi lockfile carry no license at all unless `--fetch-licenses` looks them up (below).
The rules:

1. A valid SPDX expression is kept verbatim. Deprecated identifiers such as `GPL-3.0` or `LGPL-2.1` count as valid
   because conda-forge still uses them widely.
2. Common non-conforming spellings are parsed leniently and rewritten: `MIT/Apache-2.0` becomes `MIT OR Apache-2.0`,
   `mit` becomes `MIT`, `MIT License` becomes `MIT` (a trailing `license` is dropped when what is left is an SPDX
   identifier on its own). Operator precedence follows the SPDX rules (`AND` binds tighter than `OR`) and parentheses
   are emitted only where needed. **A license is never given a version or variant the package did not state**: a
   bare family name, `LGPL`, `GPL`, `AGPL` or `BSD` (also `GNU GPL`, `BSD License`, or inside a larger expression),
   names no version or clause count, so it is kept as free text rather than guessed as `LGPL-2.0-only` or
   `BSD-2-Clause`. A spelling that does state one is normalized: `GPLv3` is `GPL-3.0-only`, `GPLv2+` is
   `GPL-2.0-or-later`.
3. Anything else is treated as free text and preserved:
   - CycloneDX: `licenses[].license.name` instead of `licenses[].expression`.
   - SPDX: `licenseDeclared` becomes `LicenseRef-pixi-<sanitized text>` and a matching entry is added to
     `hasExtractedLicensingInfos` with the original text, so nothing is lost.
4. No license → no `licenses` entry (CycloneDX) / `NOASSERTION` (SPDX).

conda-forge spells a few toolchain licenses with a clause that is not an SPDX exception, e.g.
`LGPL-2.0-or-later WITH exceptions` (kernel-headers, sysroot, the glibc family). Such a clause is rewritten to
`WITH AdditionRef-exceptions`, which SPDX allows for a reference to an exception text, so the expression remains
evaluable by consumers and by the license policy; the original spelling is kept in a `pixi:license-raw` property. A
genuine SPDX exception (`WITH Classpath-exception-2.0`) is never rewritten.

#### License details with `--fetch-licenses`

`--fetch-licenses` works for every package kind. For conda packages it reads the extracted package in the local
package cache (`<pixi cache>/pkgs/<name>-<version>-<build>/info/`): `about.json` supplies the license expression when
the lockfile has none (recorded as `pixi:license-source=package-cache`), the license family, the summary and the
project URLs, and `info/licenses/` supplies the names of the license files (`pixi:license-files-source=package-cache`).
Packages that are not in the local cache are read from the archive on the channel without downloading it: a `.conda`
file is a zip whose `info-*.tar.zst` member holds the same files, so one or two HTTP range requests (the archive's
tail, then the member when it is not already in the tail) fetch a few kilobytes per package. The extracted files are
cached under the pixi-sbom cache directory by the archive's SHA-256, so repeated runs are offline. Provenance is
recorded as `conda-archive`. Legacy `.tar.bz2` archives have no central directory, so one whose lockfile `size` is
at most 2 MiB is downloaded whole and read the same way; larger ones (or ones without a recorded size) are skipped,
with the size in the debug log. A package whose archive cannot be reached keeps the lockfile's license and the run
continues. For PyPI packages it asks the index as
described next, and reads each wheel's `dist-info` the same way (the `METADATA` member and the license files, by
HTTP range, cached by SHA-256): the PEP 639 `License-Expression` or the older `License` header fills a missing
license (`pixi:license-source=wheel`), `Summary` and the project URLs fill the description and references, and the
`License-File` names (PEP 639 `licenses/` directory, or files next to `METADATA` in older wheels) become the license
files. Sdists are skipped.

By default only the license *type* is recorded: the expression as always, plus the file names as `pixi:license-file`
properties (CycloneDX) / `licenseComments` (SPDX). `--license-texts` additionally embeds the file contents:

| Declared license | CycloneDX `licenses[]` | SPDX 2.3 |
|---|---|---|
| single SPDX identifier, e.g. `Zlib` | `{ license: { id, text, acknowledgement: declared } }` for the first file, then `{ license: { name: <file>, text } }` per additional file | `licenseDeclared: Zlib`; `licenseComments: License files: ...` (the spec has no per-package text for known identifiers) |
| compound expression, e.g. `MIT OR Apache-2.0` | `{ expression }` only, since CycloneDX cannot put texts next to an expression; file names as `pixi:license-file` properties | as above |
| free text, e.g. `Proprietary` | `{ license: { name, text, acknowledgement: declared } }` plus named entries for further files | `LicenseRef-pixi-<name>-<hash>` whose `hasExtractedLicensingInfos` entry carries the file text |
| none, but files exist | one `{ license: { name: <file>, text } }` per file | `NOASSERTION`; `licenseComments` lists the files |

Texts can add a few megabytes to a large environment, which is why they are opt-in. Summary and URLs from
`about.json` become the component `description` and `externalReferences` of type `website` / `vcs` /
`documentation` (SPDX: `summary`, `homepage`).

#### PyPI license lookup

With `--fetch-licenses`, PyPI packages that still have no license after their wheel was read (sdists, unreachable
wheels, wheels that declare only classifiers) are looked up on the index JSON API (`https://pypi.org/pypi/<name>/<version>/json`, or `PIXI_SBOM_PYPI_URL`, ten at a time)
for every PyPI package that has no license and takes, in order: the PEP 639 `license_expression`; the classic
`license` field when it is a short single line (it sometimes holds a whole license text, which is ignored); and the
`License ::` trove classifiers, mapped to SPDX identifiers for the common unambiguous ones (`MIT License` → `MIT`,
`Apache Software License` → `Apache-2.0`, `BSD License` → `BSD-3-Clause`, ...) and joined with `OR` when several are
listed. The result goes through the same normalization as conda licenses and the package gets
`pixi:license-source=pypi`. Responses are cached under the cache directory (a release's metadata never changes). A
lookup that fails is logged and the package is left without a license; once the index looks unreachable the remaining
lookups are skipped.

### Embedded SBOMs (PEP 770)

Wheels may ship their own SBOM fragments under `*.dist-info/sboms/` (PEP 770): maturin records the Rust crates it
compiled into a wheel as a CycloneDX document, and some projects add hand-written SPDX fragments for vendored
libraries. With `--embedded-sboms` those files are read out of each wheel the same way its license details are
(by HTTP range, cached), parsed as CycloneDX 1.4 – 1.7 or SPDX 2.x JSON, and their components become packages of
kind `embedded`:

| Fragment data | Package |
|---|---|
| name, version, purl (`pkg:cargo/...`, `pkg:generic/...`) | `name`, `version`, `purl` (a component without a purl gets `<wheel purl>#<name>@<version>`) |
| license (`expression`, `license.id` / `name`; SPDX `licenseDeclared` else `licenseConcluded`) | `license`, normalized like every other |
| SHA-256, distribution / VCS reference, description | `hashes`, `externalReferences`, `description` |
| `dependencies` / `DEPENDS_ON` | edges between the embedded packages |
| the fragment root's direct dependencies (`metadata.component` + `dependencies`, or `DESCRIBES`), else its undepended components | edges from the **wheel** to them |

Every embedded package carries `pixi:kind=embedded` and `pixi:embedded-sbom=<wheel>/<file>` (several, `;`
separated, when more than one fragment declares the same purl; fragments merge into one package per purl).
Embedded packages take part in `--report`, `--fetch-licenses` (their declared licenses) and the license policy.
SPDX 3 fragments are not read yet. Conda packages have no equivalent convention.

### Rust crates inside a binary (`cargo auditable`)

conda-forge builds its Rust packages with `cargo auditable`, which embeds the resolved crate graph in the
binary's own `.dep-v0` section. With `--prefix` and `--embedded-sboms` those crates are read out of the binaries
the environment installed (ELF, Mach-O and PE alike) and attached like any other embedded component:
`pixi:kind=embedded`, a `pkg:cargo/<name>@<version>` purl, `pixi:embedded-sbom=cargo-auditable:<file>` naming the
binary, `pixi:cargo-source` (`crates.io`, `git`, `local`, ...), and an edge from the conda package to the crate
its program was built from. Crates that only built the program (`kind: build`) are not in it and are left out.
Because the purls are `pkg:cargo`, `--vulnerabilities osv` covers them through RUSTSEC.

### Go modules inside a binary

Every Go binary built with module support carries its build information: the Go version and each module compiled
in, what `go version -m` prints. conda-forge builds its Go packages (`gh`, `go-yq`, `terraform`) from source, so
with `--prefix` and `--embedded-sboms` those modules are read out of the binaries the environment installed and
attached like any other embedded component: `pixi:kind=embedded`, a `pkg:golang/<module>@<version>` purl (after any
`=>` replacement), and `pixi:embedded-sbom=go-buildinfo:<file>`. The Go standard library is a component too,
`stdlib` at version `go1.27.1` with the purl `pkg:golang/stdlib@1.27.1`, as Syft records it, so advisories against
the Go runtime match. Go records which modules are in the binary, not which needs which, so they hang off the
binary's main module when it has a released version, and off the conda package when it is a source build
(`(devel)`). OSV and Grype both index Go advisories. Binaries built before Go 1.18, whose build information is in an
older layout, are passed over.

### Vendored Python distributions

Some packages ship other Python distributions inside themselves, each with its own `dist-info`: setuptools vendors
packaging, wheel and a dozen more under `setuptools/_vendor/`, and bleach vendors html5lib. A vendored copy can lag
the installed one (packaging 26.0 vendored beside 26.3 installed), and an advisory against it is a finding in the
environment. With `--prefix` and `--embedded-sboms`, every `<package>/_vendor/*.dist-info` and
`<package>/vendor/*.dist-info` in site-packages is attached like any other embedded component: `pixi:kind=embedded`,
the `pkg:pypi/<name>@<version>` its `METADATA` names, `pixi:embedded-sbom=vendored:<package>/_vendor` (several,
separated by `;`, when more than one package vendors the same release), and an edge from the package that owns the
directory, found from its conda record's files or its pip `RECORD`.

Its id (`bom-ref`) ends in `#vendored`, so it stays apart from an installed distribution of the same name and version:
they are different copies of the code. `--report diff` leaves vendored copies out: they are not installs.

### Installed environments

With `--prefix` the document describes an installed environment instead of a lockfile: the metadata property is
`pixi:prefix` (the environment directory's name) rather than `pixi:lockfile`, the SPDX root package's source info
says `prefix <name>`, and pip-installed packages carry `pixi:installer` and have no hashes (a direct VCS install is
located by `<vcs>+<url>`, with `pixi:direct-url` and `pixi:source-rev`). Conda packages carry
`pixi:extracted-package-dir`: the name of the directory in the package cache the record says the archive was unpacked
to. **Nothing in the document says where on the machine the environment or the package cache is**: the same
environment at two paths, or on two machines, gives the same document apart from its timestamp and serial number. A
pip package's local `dist-info` directory is not a download location and is not recorded as one. A local `pixi:direct-url` (an editable checkout, a wheel installed from a file) is written relative to the project, as the lockfile writes it (`./libs/utils`); the project is the workspace of a pixi environment, else the directory holding the environment. One outside it is left out. The Python a venv or a plain installation was made with is the document's `pixi:python-version` (a
CycloneDX metadata property, a line of the SPDX root package's comment). A plain installation, such as a container's
`/usr/local`, also lists its interpreter as a component, since most advisories against it name the interpreter:
`python` at that version, `pkg:generic/python@<version>`, with `pixi:interpreter=true`, and CPython's CPE when the
full `X.Y.Z` is known (a CPE for a bare `X.Y` would match releases that already have the fix). A venv's interpreter
lives outside it, and a conda environment lists its `python` package, so neither gets one.

With `--verify-files`, each conda package whose record lists file hashes carries `pixi:verified-files`, the number of
its files checked, and where they apply `pixi:modified-files` and `pixi:missing-files` (comma-separated paths relative
to the environment) and `pixi:regenerated-bytecode` (how many `.pyc` files Python has rewritten, which is not a
failure). See [Has anything changed since installation](cli.md#has-anything-changed-since-installation).

### Documents derived from documents

With `--from-sbom` the document describes what another document described: the metadata property is
`pixi:source-document` — the source's CycloneDX serial number or SPDX document namespace — rather than
`pixi:lockfile`, and the SPDX root package's source info says `document <identity>`. Everything the source records
is carried over, including the `pixi:*` properties, so a document this tool wrote round-trips unchanged; a package
whose purl is neither `pkg:conda` nor `pkg:pypi`, or which has no purl, gets `pixi:kind=external`. Another tool's
facts are read in their standard places: the supplier from CycloneDX `supplier`, `manufacturer`, `authors` or
`author`, or SPDX `supplier` or `originator` (the name, without `Person:` / `Organization:` or an email); and the CPE
from CycloneDX `cpe` or an SPDX `cpe23Type` / `cpe22Type` reference, written back to the output's CPE field.

Merged (`--from-sbom` more than once, or `--scan --merge`), the metadata property lists every input, and each
package carries `pixi:source-document` naming the inputs it came from. Each input's root is a component of its own
(`pkg:generic/<name>@<version>`). A package whose inputs disagree about its license, or about the hash of a purl that names one file, carries
`pixi:merge-conflict`, `license: <kept> (<input>) vs <other> (<input>)`, with several separated by `; `.

### Yanked releases

With `--fetch-licenses`, a PyPI package whose release the index has yanked (PEP 592) carries `pixi:yanked=true`
and, when the index gives one, `pixi:yanked-reason` (CycloneDX properties; SPDX package comment lines, as for
every other `pixi:*` fact).

### Excluded packages

With `--exclude` / `--include` / `--exclude-kind` the document lists only what survived the filter, and the root
says so: a `pixi:excluded` metadata property (CycloneDX) or a `pixi:excluded=...` comment on the root package
(SPDX 2.3 and 3.0.1) naming every package left out, whether it matched a pattern or was only needed by one that
did.

### Incomplete enrichment

A document built where the lookups failed otherwise looks exactly like one built where everything answered:
licenses are simply absent, `vulnerabilities[]` is simply empty. The warnings go to stderr, which does not survive
the upload, so what a run could not finish is recorded in the document as well.

| Property | Example value |
|---|---|
| `pixi:incomplete` | `osv, pypi-releases` — the enrichment steps that did not complete |
| `pixi:incomplete-detail` | `osv: 14 of 14 purls unasked (offline, nothing cached); pypi-releases: 12 of 38 index lookups failed`, separated by `; ` |
| `pixi:stale-cache` | `kev: 9 days old` — data served past its lifetime because the fetch failed |

The steps are named after what they do: `wheel-licenses`, `conda-archives`, `pypi-releases`, `osv`, `scorecard`,
`license-texts`.
OSV records three things separately, because an empty `vulnerabilities[]` has three causes and only one of them is
good news: no package carried a purl the database answers to, the purls could not be asked about (offline with a
cold cache), or an advisory record could not be fetched and is recorded by id alone.

In a run that writes several documents the lookups happen once for all of them, so the counts in
`pixi:incomplete-detail` are the run's rather than that one document's, and the line says so:
`conda-archives: 2 of 2 archive reads failed (looked up once for every document in the run)`.

All three are absent when everything answered, so a complete document is unchanged and existing documents compare
as they always did. In SPDX the same lines go in the root package's `comment`, one per line, beside
`pixi:excluded`. Two documents that differ only because one run could not reach the network now say so.

## Dependency graph

Each conda package's `depends` (matchspecs) and each PyPI package's `requires_dist` (PEP 508) are resolved by
normalized package name against the packages present in the same environment and platform. The solver has already
chosen one package per name, so name matching is exact and version constraints do not need re-evaluating. PyPI
requirements may resolve to conda packages (pixi satisfies PyPI requirements from conda when it can). Virtual packages
(`__glibc`, `__osx`, ...) and requirements not present in the environment (unused extras, other-platform markers) are
dropped. Self-references are removed. Every PyPI package additionally depends on the environment's conda `python`
package: wheels never declare the interpreter, but cannot run without it, and the edge keeps PyPI packages attached
to the graph instead of floating as extra roots.

| | CycloneDX | SPDX |
|---|---|---|
| Package → package | `dependencies[]`: `{ ref, dependsOn[] }` for every component | `DEPENDS_ON` relationship per edge |
| Root → packages | `dependencies[0]` (`ref: root`) lists what the workspace declared, plus the packages nothing else depends on; beside a lockfile that is not `pixi.lock`, with a manifest that declares something, only what it declared; for an installed environment that recorded it, what was requested by name | `SPDXRef-Package-root DEPENDS_ON ...` for the same set |

The declared half comes from the manifest next to the lockfile: the dependency tables of the environment's features
(see [`pixi:direct`](#pixi-properties)), so a declared dependency that something else also needs — `python` is
the usual example — is on the root where it belongs. The other half is the graph-root heuristic: packages nothing
else depends on. Without a readable manifest (`--prefix`, a lockfile on its own) the heuristic is the whole answer,
and nothing is marked direct.

### Runtime, development and optional

When the input tells what the project needs to run apart from what it needs for development or an extra, each
format says so in its own field. Everything reachable from the default dependencies is required, shared packages
included. What only a dependency group reaches is for development, and what only one of the project's extras
reaches is optional; a package both reach counts as optional.

| | CycloneDX | SPDX 2.3 | SPDX 3.0.1 |
|---|---|---|---|
| Required | `scope: required` | `DEPENDS_ON` | `dependsOn` |
| Development | `scope: optional` | `<package> DEV_DEPENDENCY_OF <dependent>` | `LifecycleScopedRelationship`, `dependsOn`, `scope: development` |
| Optional | `scope: optional` | `<package> OPTIONAL_DEPENDENCY_OF <dependent>` | `dependsOn` (3.0.1 has no optional scope) |

The SPDX edges change only where the graph crosses from what is required into a group or extra, usually at the
root: `pytest DEV_DEPENDENCY_OF my-app`. Inside a group the edges stay `DEPENDS_ON` (`pytest` depends on `pluggy`).
`pixi:declared-in` still names the group or extra.

The scopes come from the manifest beside a lockfile other than `pixi.lock`, when it declares dependency groups or
extras (see [What a project without pixi declared](cli.md#what-a-project-without-pixi-declared)), and from the
categories of a `conda-lock.yml` when there are others than `main` (`dev` is development, any other optional). A
`pixi.lock` environment is already one selection of features, so its documents carry no scope, and neither does an
input with nothing to tell apart.

## Vulnerabilities

With `--vulnerabilities osv` the CycloneDX document carries a `vulnerabilities[]` array (1.6 and 1.7 alike) and an
SPDX 3.0.1 document carries the same findings through its [security profile](#spdx-301-security-profile). **SPDX 2.3
has nowhere to put them** and says so on stderr, pointing at `--spec-version 3.0`.

One CycloneDX entry per finding, after records describing the same vulnerability have been merged:

| Field | Content |
|---|---|
| `bom-ref` | `vuln-<id>` |
| `id`, `source` | The OSV record id (`GHSA-...`, `PYSEC-...`, `RUSTSEC-...`) and `{ name: OSV, url: https://osv.dev/vulnerability/<id> }` |
| `references[]` | Every alias with where it is published: `CVE-*` → NVD, `GHSA-*` → GitHub Advisory Database, others → OSV |
| `ratings[]` | The database's qualitative severity (`method: other`, source e.g. `GitHub Advisory Database`) and every CVSS vector the record carries (`method: CVSSv31` / `CVSSv3` / `CVSSv4`, with the v3 base score computed from the vector) |
| `cwes[]` | CWE numbers from the record |
| `description`, `detail` | The record's `summary` and `details` |
| `recommendation` | `Upgrade <package> to <version>` for each affected package with a fixed version, the smallest fix above the installed version |
| `advisories[]` | The record's reference URLs |
| `published`, `updated` | The record's timestamps |
| `affects[]` | `{ ref }` for every affected component (`bom-ref` = the package's purl); a conda package matched through its PyPI purl is listed under its own `bom-ref` |
| `analysis` | Only for findings accepted with `--ignore-vuln`: `{ state, justification, response, detail }`, the CycloneDX impact-analysis (VEX) block. `justification` only when one was given after `not_affected`, `response` only when one was given. `firstIssued` / `lastUpdated` are never written (see [the vulnerability gate](cli.md#looking-up-vulnerabilities)). |
| `properties[]` | With `--kev`, for known-exploited findings: `pixi:kev=true`, `pixi:kev-cve`, `pixi:kev-date-added`, `pixi:kev-due-date`, `pixi:kev-ransomware`; the rating from `CISA KEV` is `critical` and, without a fixed version, `recommendation` carries the catalog's required action |
| `properties[]` | With `--vex-in`, for a finding a statement applied to: `pixi:vex-source`, the file the statement came from (the `analysis` is the statement's) |
| `properties[]` | With `--epss`, for findings FIRST has scored: `pixi:epss` (the probability, 0 to 1), `pixi:epss-percentile` (0 to 1), `pixi:epss-cve` (the alias the score is for, the highest when there are several) and `pixi:epss-date` |

Entries are ordered by the worst rating, then id.

### The VEX document

`--vex <PATH>` writes the assessments as a document of their own: a CycloneDX BOM with no components, the same
`vulnerabilities[]` entries, and two differences from the ones inside the SBOM.

| Field | Content |
|---|---|
| `serialNumber` | Its own, derived from the SBOM's, so the two are never confused |
| `metadata.properties[]` | `pixi:vex-for` = the SBOM's serial number, besides the usual `pixi:environment` / `pixi:platform` |
| `analysis` | On **every** finding: the `--ignore-vuln` state where one was given, else `in_triage` (or what `--vex-open` says) |
| `affects[].ref` | A BOM-Link into the SBOM — `urn:cdx:<the SBOM's serial number without the urn:uuid: prefix>/1#<bom-ref>` — rather than a local reference |


### SPDX 3.0.1 security profile

SPDX 3 is a graph, so a finding is an element with assessments attached rather than a row in an array. A document
that carries any finding adds `security` to its `profileConformance`; one that carries none does not claim the
profile.

| Element | Content |
|---|---|
| `security_Vulnerability` | One per finding. `name` is the advisory id, `summary` / `description` the record's text, and `externalIdentifier[]` holds the id and every alias — `CVE-*` as type `cve`, the rest as `securityOther`, so a reader searching for a CVE finds it whether or not we keyed the record under it. `security_publishedTime` / `security_modifiedTime` when the record has them. |
| `Relationship` `hasAssociatedVulnerability` | One per affected package, from the package to the vulnerability: the direction a reader follows from a component. |
| `security_CvssV2/V3/V4VulnAssessmentRelationship` | One per CVSS rating, from the vulnerability `hasAssessmentFor` the affected packages, with `security_score`, `security_severity` and `security_vectorString`. The schema requires all three together, so a rating missing any of them is left out rather than half-recorded — as is a rating whose method is not CVSS, since SPDX has no class for it. |
| `security_ExploitCatalogVulnAssessmentRelationship` | With `--kev`, for a finding in CISA's catalog: `security_catalogType: kev`, `security_exploited: true`, and the catalog URL as `security_locator`. The added and due dates go in `comment`. |
| `security_EpssVulnAssessmentRelationship` | With `--epss`, for a finding FIRST has scored: `security_probability` and `security_percentile` (both 0 to 1), the score's date as `security_publishedTime`, and the CVE in `comment`. |
| `security_VexNotAffectedVulnAssessmentRelationship` | For a finding accepted with `--ignore-vuln` in the `not_affected` state, carrying your text as `security_impactStatement` and, where it has an SPDX equivalent, your justification as `security_justificationType`. The other states CycloneDX accepts have no SPDX class and stay CycloneDX-only, as do responses. |

**Timestamps are rewritten.** SPDX 3 pins these fields to exactly `YYYY-MM-DDThh:mm:ssZ` — no fractional seconds, no
numeric offset — while OSV records carry nanoseconds (`2026-07-08T06:00:54.217433740Z`). Values are converted to UTC
second precision, and one that cannot be parsed is omitted rather than guessed at.

`security_justificationType` is set only from a justification given on `--ignore-vuln`, never guessed from the
text, and only where one of SPDX's five values means the same thing:

| `--ignore-vuln` justification | `security_justificationType` |
|---|---|
| `code_not_present` | `vulnerableCodeNotPresent` |
| `code_not_reachable` | `vulnerableCodeNotInExecutePath` |
| `protected_by_mitigating_control` | `inlineMitigationsAlreadyExist` |
| `protected_at_runtime`, `protected_at_perimeter` | `vulnerableCodeCannotBeControlledByAdversary` |
| the others | not set; the text stays in `security_impactStatement` |

## SPDX 3.0.1

`--format spdx --spec-version 3.0` writes the SPDX 3.0.1 JSON-LD serialization: a `@context` of
`https://spdx.org/rdf/3.0.1/spdx-context.jsonld` and a `@graph` of typed elements, each with an IRI `spdxId` under
`https://spdx.org/spdxdocs/pixi-sbom/<name>/<uuid>#...` and a reference to one shared `CreationInfo` blank node.

| Element | Content |
|---|---|
| `CreationInfo` | `specVersion: 3.0.1`, `created`, `createdBy` (a `SoftwareAgent` for pixi-sbom plus a `Person` per manifest author), `createdUsing` (the `Tool`), a comment naming the lockfile, environment and platform |
| `SpdxDocument` | `rootElement` = the `software_Sbom`; `dataLicense` = a `CC0-1.0` license element; profile conformance `core`, `software`, `simpleLicensing` |
| `software_Sbom` | `software_sbomType` for the input's phase (see [Lifecycle phase](#lifecycle-phase)), `rootElement` = the workspace package, `element` = every package, relationship and license element |
| `software_Package` (workspace) | `software_primaryPurpose: application`, name, version, homepage, repository as download location, `software_sourceInfo` |
| `software_Package` (each locked package) | `software_primaryPurpose: library`, name, version, `software_packageUrl`, `software_downloadLocation` (or `software_sourceInfo` for local paths), `software_homePage`, `summary`, `suppliedBy` (an `Organization` per channel or index), `verifiedUsing` (`Hash` sha256 / md5), `externalIdentifier` (extra purls, repository URL), and the `pixi:*` properties as `comment` lines |
| `simplelicensing_LicenseExpression` / `simplelicensing_SimpleLicensingText` | one element per distinct license expression, or per free-text license (carrying the license file text when fetched); packages point at them with `hasDeclaredLicense` relationships |
| `Relationship` | `dependsOn` from each package to its dependencies and from the workspace package to the top level; `hasDeclaredLicense` from packages to license elements |

The document is validated against the official 3.0.1 JSON schema in the tests and parses with the reference
`spdx-python-model` deserializer. SPDX 2.3 remains the default because most consumers still read only 2.x.

## Validation

`tests/schemas/` holds the official JSON schemas (`bom-1.6.schema.json` and the `spdx.schema.json` /
`jsf-0.82.schema.json` it references, plus SPDX's `spdx-2.3.schema.json`). The end-to-end tests validate every
generated document against them, and the unit tests validate a hand-built model that exercises the edge cases (source
packages, missing versions, non-SPDX licenses). Both documents also round-trip through `syft convert`.
