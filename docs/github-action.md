# GitHub Action

Listed on the [GitHub Marketplace](https://github.com/marketplace/actions/pixi-sbom); the source is `action.yml` at
the root of the [repository](https://github.com/millsks/pixi-sbom).

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

## Without the action

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

## A worked example

This repository dogfoods its own action in `.github/workflows/ci.yml`: every environment of its lockfile is
described with licenses fetched, PyPI identities from the conda-forge mapping and embedded SBOMs attached, a deny
list that is known to trip (`Python-2.0`) proves the `policy-violated` output with `fail-on-policy: "false"`, and a
second step with a satisfiable policy proves exit 0:

```yaml
- uses: millsks/pixi-sbom@v0.5.1
  id: sbom
  with:
    all-environments: "true"
    fetch-licenses: "true"
    pypi-mapping: prefix
    embedded-sboms: "true"
    deny-license: "Python-2.0"
    require-license: "true"
    fail-on-policy: "false"
- run: test "${{ steps.sbom.outputs.policy-violated }}" = "true"
```

Every input maps to a [command-line option](cli.md#options) of the same name; the action adds nothing the binary
cannot do.
