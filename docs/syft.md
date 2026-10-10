# pixi-sbom and syft

[syft](https://github.com/anchore/syft) is the SBOM generator most people already know, and the one most often put in
front of [Grype](https://github.com/anchore/grype). This page compares the two on the job they share, describing a
Python or conda project or environment, and says what syft does that pixi-sbom does not try to.

Every number here comes from a command shown beside it, run on the repository's examples with the pixi-sbom that
became 1.10.0, syft 1.54.1 and Grype 0.120.1 on 10 October 2026, against a Grype database built on 9 October 2026.
The pixi-sbom column of the first table is checked by the test suite on every change; the rest is rerun for each
release. Advisory counts
change as advisories are published, so a rerun gives different counts; the comparison between the two tools is what
holds.

## Reading a lockfile

| Lockfile | syft packages | pixi-sbom packages | with a hash (pixi-sbom) |
|---|---|---|---|
| `examples/projects/pixi/04-data-analysis/pixi.lock` | 0 | 193 | 193 |
| `examples/projects/conda-lock/04-data-analysis/conda-lock.yml` | 0 | 195 | 195 |
| `examples/projects/uv/02-flask/uv.lock` | 29, none with a hash | 25 | 25 |

```sh
syft scan dir:examples/projects/pixi/04-data-analysis -o syft-json | jq '.artifacts | length'
pixi sbom --lockfile examples/projects/pixi/04-data-analysis/pixi.lock -p linux-64 --output - | jq '.components | length'
```

syft has no reader for `pixi.lock` or `conda-lock.yml`, so a conda or pixi project before installation is invisible
to it. For `uv.lock` it lists every package whatever its environment markers say (colorama, a Windows-only
dependency, appears in a Linux SBOM) plus the project itself, and records no hashes; pixi-sbom evaluates the markers
for the platform asked for (`-p linux-64` gives 25) and records the hash the lockfile pins for each.

## In front of Grype

The question that matters: given the same installed environment, does Grype find as much from pixi-sbom's SBOM as
from syft's? The repository answers it for five environments on every pull request that touches identity code, and
weekly:

```sh
pixi run grype-compare
```

It installs each environment, describes it with `syft scan dir:<env>` and with
`pixi sbom --prefix <env> --primary-purl pypi --embedded-sboms` (offline), scans both with the same Grype and
database, and fails on any conda, Python or npm finding syft's SBOM produces that pixi-sbom's does not:

| Environment | Findings both produce | syft only | pixi-sbom only |
|---|---|---|---|
| A web stack (`pixi/01-django`) | 86 | 0 | 8 |
| A scientific stack (`pixi/04-data-analysis`) | 30 | 0 | 1 |
| Rust tools (`pixi/10-dev-tooling`) | 9 | 0 | 1 |
| A pip venv (`requirements/02-flask`) | 45 | 0 | 0 |
| nodejs and an npm tool (`tests/grype/node-tools`) | 28 | 0 | 1 |

For the environment that installs JavaScript, syft is run with `--select-catalogers +javascript-package-cataloger`:
on a directory it otherwise reads only JavaScript lockfiles, not installed packages, and lists none of the 178 npm
releases there. With it, it lists the same 178 as pixi-sbom, and Grype finds the same 12 npm advisories in both.

The findings only pixi-sbom's SBOM produces are native conda libraries (krb5, libpq, openjpeg, libxml2, zlib) that
syft lists without an identity Grype can match, and pixi-sbom identifies with a CPE from its
[curated table](output-format.md#cpes-for-native-conda-packages).

`--primary-purl pypi` matters here: Grype reads only a package's primary identity, and pixi-sbom's default primary
identity for a conda-installed Python package is its `pkg:conda` purl, with the PyPI one beside it. With it, Grype
matches those packages by their PyPI identity, as it does from syft's SBOM.

## What pixi-sbom records that syft does not

- **The dependency graph a lockfile pins**, with development and optional groups marked, and for an installed conda
  environment the conda dependencies as well as the Python ones.
- **Licenses normalized to SPDX expressions**, with where each came from, and never a version a package did not state.
- **Supplier and download location** for every package from a lockfile.
- **Provenance and gaps**: which sources were asked, and which answered nothing.
- **Vulnerabilities, KEV, EPSS, VEX and license gates** in the same run, with exit codes a pipeline can act on.

## What syft does that pixi-sbom does not

pixi-sbom describes Python and conda projects and environments. syft catalogs much more, and remains the tool for it:

- **Container images**, read from a registry or a tarball, layer by layer.
- **Operating system packages**: dpkg, rpm, apk.
- **Other ecosystems**: npm, Java, Rust crates and Go modules outside a conda environment, and many more. Inside
  one, `--prefix` lists its installed npm packages, and `--prefix --embedded-sboms` reads a binary's Rust crates and
  Go modules, as syft does.
- **Every installed file** with its digests. pixi-sbom records packages, not files; for a conda environment
  `--verify-files` instead checks every file against the hash conda recorded at installation, which syft does not do.

For a container that runs a Python or conda application, the two fit together: syft for the image's operating
system, pixi-sbom for the environment, merged with `pixi sbom --from-sbom image.cdx.json --from-sbom app.cdx.json`.

## Formats syft writes and pixi-sbom does not

pixi-sbom writes CycloneDX JSON (1.6, 1.7), SPDX JSON (2.3, 3.0.1) and GitHub's dependency submission format
(`--format github`, see [GitHub's dependency graph](formats.md#githubs-dependency-graph)). For another format,
`syft convert` reads pixi-sbom's CycloneDX:

```sh
syft convert sbom.cdx.json -o spdx-tag-value=sbom.spdx
syft convert sbom.cdx.json -o cyclonedx-xml=sbom.cdx.xml
```
