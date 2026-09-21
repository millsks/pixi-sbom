# pixi-sbom

A [pixi](https://pixi.sh) extension that writes a Software Bill of Materials from `pixi.lock`: every conda and PyPI
package of one environment on one platform, with purls, licenses and the dependency graph, as
[CycloneDX](https://cyclonedx.org) 1.6 / 1.7 or [SPDX](https://spdx.dev) 2.3 / 3.0.1 JSON that validates against the
official schemas. It reads the lockfile only, so it needs neither an installed environment nor pixi itself.

```sh
pixi global install pixi-sbom

pixi sbom                                   # sbom.cdx.json next to pixi.lock
pixi sbom --output - | grype                # straight into a scanner
pixi sbom --fetch-licenses --deny-license GPL-3.0-only --require-license   # a license gate, exit 3 on violation
```

## Where to go

<div class="grid cards" markdown>

-   **[Installation](installation.md)**

    pixi global, a release binary, or a build from source; how pixi finds the extension.

-   **[Command-line reference](cli.md)**

    Every option, the license policy, terminal reports, batch mode, environment variables, exit codes and error
    codes.

-   **[GitHub Action](github-action.md)**

    `uses: millsks/pixi-sbom@v0.5.1`: inputs, outputs, the policy gate, a worked example.

-   **[CI recipes](ci-recipes.md)**

    Scanning with grype, license tables in PR comments, diffing SBOMs between commits, air-gapped runners.

-   **[Which format to pick](formats.md)**

    CycloneDX 1.6 / 1.7 against SPDX 2.3 / 3.0.1, by consumer.

-   **[Output format reference](output-format.md)**

    Field by field: purls, licenses, the dependency graph, reproducibility.

</div>

## Why a lockfile-based SBOM

Pixi environments mix conda and PyPI packages, and scanners have no conda vulnerability data: a conda-only Python
environment scans as clean no matter what it contains. `pixi sbom` gives conda-forge Python packages their PyPI
identity from the same mapping pixi uses, fetches licenses for every package kind from the package cache, the channel
archive or the wheel, and produces byte-identical documents under `SOURCE_DATE_EPOCH` so CI can diff them.

Contributors: the [architecture](architecture.md) and [development](development.md) pages describe the pipeline, the
modules and the change harness. Releases are listed in the [changelog](changelog.md).
