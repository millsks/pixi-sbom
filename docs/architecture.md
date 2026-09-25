# Architecture

`pixi-sbom` is a single Rust binary (~3k lines including tests) organized as a short pipeline. Each stage has one
job and one module, and the stages meet at a format-agnostic model so that lockfile interpretation happens exactly
once no matter how many output formats exist.

```
 pixi.lock ──▶ lock.rs ──▶ model::Sbom ──▶ format/cyclonedx.rs ──▶ sbom.cdx.json
                 ▲             ▲       ├──▶ format/spdx.rs      ──▶ sbom.spdx.json (2.3)
                 │             │       └──▶ format/spdx3.rs     ──▶ sbom.spdx.json (3.0.1)
   purl.rs ──────┘             │
   manifest.rs ────────────────┘   (workspace metadata)
   prefix.rs ───── --prefix: conda-meta records + site-packages dist-info into the same model
   config.rs ───── pixi-sbom.toml / [tool.pixi-sbom]: fills what the command line did not say
   filter.rs ───── --include/--exclude/--exclude-kind: drops packages and re-closes the graph first
   mapping.rs ──── enriches model::Sbom with PyPI purls (optional, via http.rs)
   pypi.rs ─────── fills PyPI licenses from the index (optional, via http.rs)
   pkgcache.rs ─── conda license files and metadata from the package cache (optional, offline)
   condaarchive.rs ─ the same from the channel archive by HTTP range (optional, via zipread.rs)
   wheel.rs ─────── PyPI license details from the wheel's dist-info (optional, via zipread.rs)
   embedded.rs ──── PEP 770 embedded SBOMs from the same wheels (optional)
   report.rs ───── --report: renders the model as a terminal table instead of a document
   style.rs ────── --color: when to colour, and which style each kind of cell gets
   progress.rs ─── progress bars for the fetches, hidden while a log line prints
   diff.rs ─────── --report diff --against: reads a previous document (any family) and compares
   policy.rs ───── --allow/--deny/--require-license: violations -> exit 3 after writing
   osv.rs ──────── --vulnerabilities osv: findings from the OSV API into model::Sbom (via http.rs, cvss.rs)
   kev.rs ──────── --kev: CISA's Known Exploited Vulnerabilities catalog onto the findings (via http.rs)
   vulnpolicy.rs ─ --fail-on-severity / --fail-on-kev / --ignore-vuln: analysis blocks and exit 4 after writing
   license.rs ◀── used by both writers
   discover.rs ── finds the lockfile, decides output paths
   cli.rs ──────── clap definitions
   main.rs ─────── wires it together, logging, error reporting
```

## Modules

| Module | Owns | Depends on |
|---|---|---|
| `cli.rs` | The `Args` struct (clap derive) and the `Format` enum with its file-name helpers. Nothing else knows about clap. | clap |
| `discover.rs` | Locating `pixi.lock` (explicit path or upward search) and resolving output paths for single- and all-environment runs. Pure path logic; the only I/O is `is_file()`. | — |
| `manifest.rs` | Reading workspace name/version from `pixi.toml` or `pyproject.toml` into `model::Root`. Never fails: problems are logged and the directory name is used. | toml, serde |
| `lock.rs` | Parsing the lockfile with `rattler_lock`, selecting an environment and platform, converting each locked package into `model::Package`, and resolving the dependency graph. All lockfile-shape knowledge lives here. | rattler_lock, rattler_conda_types, purl.rs |
| `prefix.rs` | `--prefix`: reads `conda-meta/*.json` into conda packages (purl, channel, hashes, license, `pixi:extracted-package-dir`) and `site-packages/*.dist-info` into PyPI packages (`METADATA` through `wheel::info_from_metadata`, `direct_url.json`, `INSTALLER` to skip conda-installed ones), then links dependencies with `lock::link_dependencies`. | serde_json, lock.rs, wheel.rs, purl.rs |
| `purl.rs` | Building `pkg:conda` and `pkg:pypi` purls, PEP 503 name normalization, channel-name and archive-type helpers. | packageurl |
| `mapping.rs` | PyPI identity enrichment: loading the conda-forge conda-to-PyPI mapping (offline file, or downloaded and cached), adding `pkg:pypi` purls to conda-forge packages the lockfile says nothing about, and optionally swapping the primary purl. Also owns the cache directory rule. | serde_json, purl.rs, http.rs |
| `zipread.rs` | Reads single members out of zip archives (`.conda`, wheels) by range: the central directory from the tail, then the member. Works over HTTP ranges, `file://` URLs and paths. Hand-rolled: EOCD, zip64, stored and deflated members. | flate2, http.rs |
| `embedded.rs` | `--embedded-sboms`: parses the PEP 770 fragments `wheel.rs` cached (CycloneDX 1.4 – 1.7, SPDX 2.x), adds their components as `embedded` packages, merges duplicates by purl, and wires the graph under the wheel. | serde_json, wheel.rs |
| `wheel.rs` | The same for PyPI wheels: `METADATA` (PEP 639 `License-Expression`, `License`, `License-File`, `Summary`, `Project-URL`) and the license files, through `zipread`, cached under `wheel-info/<sha256>/`. | zipread.rs, parallel.rs |
| `parallel.rs` | A bounded scoped-thread pool for the fetchers; no async runtime. | — |
| `condaarchive.rs` | The network fallback for conda license details: pulls the `info-*.tar.zst` member through `zipread`, decompresses it and writes `about.json`, `index.json` and `licenses/` into the pixi-sbom cache in the rattler layout, on a small thread pool. | zstd, tar, zipread.rs, pkgcache.rs |
| `pkgcache.rs` | Conda license details from the local rattler package cache: `about.json` and `info/licenses/` of extracted packages, and the cache directory rule (`PIXI_CACHE_DIR`, `RATTLER_CACHE_DIR`, platform default). Offline. | serde_json |
| `config.rs` | The configuration file: finds `[tool.pixi-sbom]` in `pyproject.toml` or `pixi-sbom.toml` next to the lockfile (or `--config`), parses it with unknown keys rejected, and fills every `Args` field the command line did not set (`ArgMatches::value_source` tells a default from an explicit value); the relationships clap cannot check across both sources live in `main::validate`. | toml, clap |
| `filter.rs` | `--include` / `--exclude` / `--exclude-kind`: a small glob matcher over package names, removal before any enrichment, and graph re-closure from the original roots (orphans go unless `--keep-orphans`); records the omission in `Sbom::excluded` for the writers. | model.rs |
| `pypi.rs` | License lookup for PyPI packages from the index JSON API (part of `--fetch-licenses`): field precedence, classifier-to-SPDX table, per-release cache, ten lookups at a time on the shared pool, and the "stop when the network is down" rule (a shared flag, so the jobs already in flight finish and the rest fall through to their cache). | serde_json, http.rs, parallel.rs |
| `http.rs` | The one `ureq` agent (system certificate store, proxies from the environment) and the connectivity-error test. | ureq |
| `model.rs` | `Sbom`, `Root`, `Package`, `PackageKind`: plain data with no serde and no knowledge of any SBOM spec. | — |
| `license.rs` | Turning a declared license string into either an SPDX expression or free text. | spdx |
| `format/mod.rs` | `WriteContext` (timestamp, UUID, tool version), `write()` / `to_value()` entry points, the shared graph-root helper, and the hand-built sample model used by writer tests. | serde_json, chrono, uuid |
| `format/cyclonedx.rs` | Serde structs mirroring the parts of CycloneDX 1.6 / 1.7 that are used, the version table (`$schema`, `specVersion`, 1.7 citations), and the `Sbom` → `Bom` mapping. | serde |
| `format/spdx3.rs` | SPDX 3.0.1 JSON-LD: one node struct for every element class, a builder that mints IRIs and deduplicates license and supplier elements, and the `dependsOn` / `hasDeclaredLicense` relationship graph. Shares id sanitizing with the 2.3 writer. | serde |
| `format/spdx.rs` | Same for SPDX 2.3, including `SPDXRef` id assignment and `LicenseRef` extraction. | serde |
| `osv.rs` | `--vulnerabilities osv`: collects every queryable purl (conda purls excluded), asks OSV's `querybatch` in thousands, fetches each record in parallel, caches queries (one hour) and records (until `modified` moves), merges GHSA / PYSEC twins by alias, picks the fixed version above the installed one, and fills `Sbom::vulnerabilities`. A failed query is fatal; a failed record is not. | serde_json, http.rs, cvss.rs, parallel.rs |
| `kev.rs` | `--kev`: downloads CISA's KEV catalog (cached a day, stale copy on failure), looks each finding's CVE aliases up, and marks hits critical with the catalog's dates and required action. | serde_json, http.rs |
| `vulnpolicy.rs` | `--fail-on-severity` / `--fail-on-kev` / `--ignore-vuln`: parses ignore entries (`ID[:STATE][:TEXT]`), marks matching findings (by id or alias) with an `Analysis`, and lists the open findings at or above the threshold or known exploited; exit code 4 is applied in `main`. | model.rs |
| `cvss.rs` | CVSS v3.0 / v3.1 base scores from vector strings, for advisories that carry a vector but no qualitative severity. | |
| `progress.rs` | Whether progress bars are drawn (terminal, not `-v`/`-q`, not `TERM=dumb`/`CI`/`PIXI_SBOM_NO_PROGRESS`) and the bar itself; one global `MultiProgress` so the tracing writer can suspend every live bar while a log line prints. | indicatif |
| `style.rs` | `--color` resolution (`NO_COLOR`, `CLICOLOR_FORCE`, `TERM=dumb`, terminal detection) and the palette: comfy-table cell styling for tables (so widths are measured on unstyled text) and `anstyle` for the plain lines around them. | anstyle, comfy-table, clap |
| `diff.rs` | `--report diff --against`: reads a previous CycloneDX / SPDX 2.x document through `embedded::parse` or an SPDX 3.0.1 graph directly, reduces both sides to (purl type, normalized name, version, normalized license) and lists added, removed, version- and license-changed packages. | embedded.rs, license.rs |
| `policy.rs` | `--allow-license` / `--deny-license` / `--require-license`: parses licensees, canonicalizes ids (base, `-or-later`, exception) and evaluates each package's expression with the `spdx` crate's `evaluate`, returning violations; exit code 3 is applied in `main`. | spdx, license.rs |
| `report.rs` | `--report`: the `packages` and `licenses` views built from the model, rendered as an aligned table, Markdown, CSV or JSON. Owns no I/O beyond the writer it is handed. | serde_json |
| `main.rs` | Argument parsing, tracing setup, miette report handler, the environment loop, and file output. | miette, tracing |

Errors are `thiserror` enums per module (`DiscoverError`, `LockError`, `PurlError`, `WriteError`) that also derive
`miette::Diagnostic`, giving each variant a stable code (`pixi_sbom::lock::platform`) and, where useful, a `help`
line. `main` returns `miette::Result`, so any of them prints as a formatted report and exits 1. Line wrapping in the
report handler is disabled so lists of environment or platform names stay intact and greppable.

Logging uses `tracing` with a `tracing_subscriber` fmt layer on stderr; ANSI color is enabled only when stderr is a
terminal. `-v`/`-q` set the default level and `RUST_LOG` overrides it. Stdout is never written to, so the command is
safe to use in pipelines.

## The intermediate model

`model::Sbom` holds the root (workspace), the environment and platform names, the lockfile name, and a sorted list of
`Package`s. A `Package` carries an `id` (currently the purl, unique within the document), name, optional version,
kind, purl, extra purls, download location, optional SHA-256/MD5, optional raw license string, a `BTreeMap` of
`pixi:*` properties, and the sorted list of ids it depends on.

Two consequences of this design are worth knowing:

- Everything a writer might want is computed in `lock.rs` and stored as plain strings. Writers never touch
  `rattler_lock` types, which keeps them small and lets them be tested against a hand-built model with no lockfile.
- Sorting happens once, in `lock.rs`, by `(kind, name, version)`. Writers preserve order, so output is byte-for-byte
  reproducible apart from the timestamp and UUID.

## How a run proceeds

1. `main` parses arguments and initializes logging and error reporting.
2. `discover::resolve_lockfile` finds the lockfile. `lock::load` parses it once.
3. `manifest::root_for_lockfile` reads the workspace name/version from the manifest next to the lockfile.
4. The list of `(environment, output path)` targets is built: a single pair, or one per environment with
   `--all-environments` (`default` first, then alphabetical).
5. For each target, `lock::sbom_from_lock` selects the environment and platform (host platform via
   `rattler_conda_types::Platform::current()` when `-p` is absent), converts every locked package, resolves
   dependencies, and sorts.
6. `format::write` serializes with a fresh `WriteContext` and `main::write_output` writes the file, creating parent
   directories as needed.

## Design decisions

These were settled at the start of the project and are recorded here so they are not relitigated by accident.

**Rust, matching the other pixi extensions.** `pixi-diff`, `pixi-pack` and friends are Rust binaries built with a
`pixi.toml` that pulls the toolchain from conda-forge. Following that pattern makes the project familiar to the pixi
community, produces a dependency-free binary, and allows reuse of pixi's own crates.

**`rattler_lock` for parsing.** It is the crate pixi itself uses to read and write `pixi.lock`, so lockfile-version
changes are handled upstream and the parse is authoritative. The alternative, hand-rolled YAML parsing, would have
been smaller but would drift from pixi. Only `rattler_lock` and `rattler_conda_types` are used; the heavier pixi
workspace crates (`pixi_manifest` etc.) are deliberately not depended on, since they are git dependencies that need
`[patch]` overrides and would bring in most of pixi.

**Own serde models for both formats.** The `cyclonedx-bom` crate stops at CycloneDX 1.5 and there is no maintained
SPDX 2.3 writer crate. Writing the small subset of each schema that is actually used (about 150 lines per format)
gives current spec versions, keeps the dependency tree small, and makes the two writers symmetrical. Correctness is
guarded by validating output against the vendored official JSON schemas in tests rather than by a library.

**One document per environment and platform.** A lockfile is many things at once; an SBOM describes one deliverable.
Merging would force consumers to filter by property, and most tooling does not. `--all-environments` is a loop over
the same single-document path, not a different document shape.

**Workspace metadata from the manifest via `toml`.** Only name and version are needed. A 60-line reader covering
`pixi.toml` and `pyproject.toml` is enough; failures degrade to the directory name rather than blocking output.

**Intermediate model instead of writing directly from lock types.** Adds one small module but means every lockfile
rule (source packages, partial metadata, purl construction, dependency resolution) is implemented and tested once,
and a third format could be added without touching `lock.rs`.

**Graph roots for the root component's dependencies.** The lockfile does not record which packages the manifest
requested, so "direct" versus "transitive" cannot be derived from it. Packages that nothing else depends on are
used as the root's dependencies; this is documented as a heuristic in [output-format.md](output-format.md). Reading
the manifest's feature/dependency tables to recover the true direct set was considered and set aside as not needed.

**pixi as the only task runner.** Cargo is never invoked directly in docs, hooks, or CI; every command goes through
a `pixi run` task so the toolchain is the pinned one from `pixi.lock`. See [development.md](development.md).

## Adding a format

1. Add a variant to `cli::Format` and its extension in `Format::extension`.
2. Create `src/format/<name>.rs` with serde structs and a `document(&Sbom, &WriteContext)` function; use
   `format::top_level_ids` for the root's edges and `license::normalize` for licenses.
3. Add the match arm in `format::to_value`.
4. Vendor the format's JSON schema under `tests/schemas/`, add a snapshot test plus a schema-validation test against
   `format::testing::sample_sbom()`, and an end-to-end case in `tests/cli.rs`.
5. Document the field mapping in [output-format.md](output-format.md).
