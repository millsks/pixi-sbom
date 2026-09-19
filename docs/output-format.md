# Output format reference

Both formats are produced from the same intermediate model (see [architecture.md](architecture.md)), so they carry
the same information; only the spelling differs. Output is pretty-printed JSON with keys in the order the
specifications list them, followed by a trailing newline.

## Document header

| | CycloneDX 1.6 | SPDX 2.3 |
|---|---|---|
| Identity | `bomFormat: CycloneDX`, `specVersion: 1.6`, `$schema` | `spdxVersion: SPDX-2.3`, `dataLicense: CC0-1.0`, `SPDXID: SPDXRef-DOCUMENT` |
| Unique id | `serialNumber: urn:uuid:<v5>` | `documentNamespace: https://spdx.org/spdxdocs/pixi-sbom/<name>/<uuid>` |
| Timestamp (UTC, seconds) | `metadata.timestamp` | `creationInfo.created` |
| Generator | `metadata.tools.components[]`: `pixi-sbom` with version and repository link | `creationInfo.creators[]`: `Tool: pixi-sbom-<version>` |
| Author | `metadata.authors[]` (`name`, `email`) from the manifest's `authors` | `creationInfo.creators[]`: `Person: <name> (<email>)` |
| Generation context | `metadata.lifecycles[]`: `phase: pre-build` (derived from resolved inputs, before any build) | `creationInfo.comment` saying the same |
| Document name | (none; the root component carries it) | `name: <workspace>-<environment>-<platform>` |
| What was described | `metadata.properties[]`: `pixi:environment`, `pixi:platform`, `pixi:lockfile` | root package `sourceInfo` |

`pixi:lockfile` is the lockfile's name relative to the workspace root (normally `pixi.lock`), never the absolute path
it was read from, so a document does not reveal or depend on the layout of the machine that generated it.

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
| Kind | `type: library`; property `pixi:kind` = `conda`, `conda-source` or `pypi` | `primaryPackagePurpose: LIBRARY`; kind is part of the `SPDXID` |
| Identifier | `bom-ref` = purl | `SPDXID: SPDXRef-Package-<kind>-<name>-<version>` (sanitized, de-duplicated with a numeric suffix) |
| Name, version | `name`, `version` | `name`, `versionInfo` |
| Package URL | `purl` | `externalRefs[]` with `referenceCategory: PACKAGE-MANAGER`, `referenceType: purl` |
| Supplier | `supplier` (`name`, `url[]`): the conda channel (e.g. `conda-forge`) or the PyPI index host (e.g. `pypi.org`); absent for source packages | `supplier`: `Organization: <name> (<url>)` |
| Extra purls (see below) | property `pixi:purl` per purl | additional `externalRefs[]` entries |
| Download location | `externalReferences[]` of type `distribution`, or `vcs` for `git+` locations | `downloadLocation` (URL or `git+<url>@<rev>`); `NOASSERTION` plus `sourceInfo` for local paths |
| SHA-256, MD5 | `hashes[]` (`SHA-256`, `MD5`) | `checksums[]` (`SHA256`, `MD5`) |
| License | `licenses[]` (see below) | `licenseDeclared` (see below); `licenseConcluded` and `copyrightText` are `NOASSERTION` |
| Everything else | `properties[]` with `pixi:` names | `comment`: one `key=value` per line |
| `filesAnalyzed` | | always `false` (no archive is opened) |

Version is omitted only for pixi-build source packages whose metadata has not been evaluated yet (a "partial" lock
entry).

### `pixi:*` properties

| Property | Set for | Value |
|---|---|---|
| `pixi:kind` | all | `conda`, `conda-source`, `pypi` |
| `pixi:channel` | conda binary | Channel name, e.g. `conda-forge` (last path segment of the channel URL) |
| `pixi:channel-url` | conda binary | Full channel base URL |
| `pixi:subdir` | conda | `linux-64`, `noarch`, ... |
| `pixi:build` | conda | Build string |
| `pixi:build-number` | conda | Build number |
| `pixi:file-name` | conda binary | Archive file name |
| `pixi:size` | conda | Archive size in bytes |
| `pixi:license-family` | conda | Channel-declared license family |
| `pixi:noarch` | conda | `true` when the package is noarch |
| `pixi:purl` | conda | Additional purls the channel declares (typically the PyPI purl of a Python package) |
| `pixi:identifier-hash` | conda source | pixi-build identifier hash from the lock entry |
| `pixi:source-git`, `pixi:source-rev`, `pixi:source-tag` / `pixi:source-branch`, `pixi:source-subdirectory` | conda source (git) | The pinned build source |
| `pixi:source-url`, `pixi:source-subdirectory` | conda source (archive) | The pinned build source; its SHA-256 goes into the hashes |
| `pixi:source-path` | conda source (path) | Local path |
| `pixi:index-url` | PyPI | Index the wheel was resolved from |
| `pixi:requires-python` | PyPI | `Requires-Python` of the distribution |
| `pixi:source` | PyPI | `true` for sdists / source trees |

In SPDX these appear in the package `comment` because SPDX 2.3 has no free-form property field.

### Package URLs

| Kind | Shape |
|---|---|
| conda binary | `pkg:conda/<name>@<version>?build=<build>&channel=<channel>&subdir=<subdir>&type=<conda\|tar.bz2>` |
| conda source | `pkg:conda/<name>@<version>?build=<build>&subdir=<subdir>` (no channel; qualifiers present only when known) |
| PyPI | `pkg:pypi/<normalized-name>@<version>` with PEP 503 normalization (lower-case, runs of `-_.` collapsed to `-`) |

Purls double as the CycloneDX `bom-ref`, which is why they must be unique within a document; within one environment
and platform they always are.

### Licenses

Package license strings are whatever the channel or index declared; conda-forge is mostly SPDX-clean but not
entirely, and PyPI wheels in a pixi lockfile carry no license at all. The rules:

1. A valid SPDX expression is kept verbatim. Deprecated identifiers such as `GPL-3.0` or `LGPL-2.1` count as valid
   because conda-forge still uses them widely.
2. Common non-conforming spellings are parsed leniently and rewritten: `MIT/Apache-2.0` becomes `MIT OR Apache-2.0`,
   `mit` becomes `MIT`. Operator precedence follows the SPDX rules (`AND` binds tighter than `OR`) and parentheses are
   emitted only where needed.
3. Anything else is treated as free text and preserved:
   - CycloneDX: `licenses[].license.name` instead of `licenses[].expression`.
   - SPDX: `licenseDeclared` becomes `LicenseRef-pixi-<sanitized text>` and a matching entry is added to
     `hasExtractedLicensingInfos` with the original text, so nothing is lost.
4. No license → no `licenses` entry (CycloneDX) / `NOASSERTION` (SPDX).

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
| Root → packages | `dependencies[0]` (`ref: root`) lists the packages that nothing else depends on | `SPDXRef-Package-root DEPENDS_ON ...` for the same set |

The root's edges are a graph-root heuristic, not the manifest's declared dependencies: the lockfile does not record
what was requested directly, so a declared dependency that is also depended on by something else (`python` is the
usual example) is reachable transitively rather than listed on the root.

## Validation

`tests/schemas/` holds the official JSON schemas (`bom-1.6.schema.json` and the `spdx.schema.json` /
`jsf-0.82.schema.json` it references, plus SPDX's `spdx-2.3.schema.json`). The end-to-end tests validate every
generated document against them, and the unit tests validate a hand-built model that exercises the edge cases (source
packages, missing versions, non-SPDX licenses). Both documents also round-trip through `syft convert`.
