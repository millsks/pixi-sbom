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
| `vulnerabilities`, `kev` | | `osv` looks findings up and records them; `kev: "true"` marks the known-exploited ones |
| `fail-on-severity`, `fail-on-kev` | | The vulnerability gate (exit code 4) |
| `ignore-vuln` | | Accepted findings, one per line: `ID`, `ID:justification` or `ID:state:justification` |
| `fail-on-vulnerabilities` | `true` | Fail the step when the gate trips; with `false` it becomes a warning and the `vulnerabilities-found` output is `true` |
| `upload-sarif`, `sarif-category` | `false`, `pixi-sbom` | Write the findings as SARIF and upload them to GitHub code scanning (see below) |
| `extra-args` | | Any other CLI arguments |
| `upload-artifact`, `artifact-name` | `true`, `sboms` | Artifact upload |

Outputs: `version`, `output`, `policy-violated`, `vulnerabilities-found`, `sarif`. The action runs on Linux (x64, arm64), macOS (Intel, Apple
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

## Vulnerabilities in the Security tab

With `vulnerabilities: osv` the document carries the findings; `upload-sarif: "true"` additionally renders them as
SARIF (`--report vulnerabilities --report-format sarif`, one result per finding and affected package, located at
the lockfile, `security-severity` from the CVSS score or 10 for known-exploited findings, accepted findings as
suppressions) and uploads the file with `github/codeql-action/upload-sarif`, so they appear under *Security →
Code scanning* with the `sarif-category` you choose. The job needs `security-events: write`:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: millsks/pixi-sbom@v0.6.0
    with:
      pypi-mapping: prefix
      vulnerabilities: osv
      kev: "true"
      fail-on-severity: high
      fail-on-kev: "true"
      ignore-vuln: |
        GHSA-2xpw-w6gg-jr37:streaming API is not used
        CVE-2023-43804:false_positive:only reachable through a removed code path
      upload-sarif: "true"
```

Each document is a SARIF run with its own automation id, so code scanning files the alerts under
`pixi-sbom/<environment>` (or `pixi-sbom/<environment>/<platform>` in batch mode) rather than under
`sarif-category`. The SARIF report reuses the lookup's cache, so the second run costs no network requests. Outside the action, the
same file comes from `pixi sbom --vulnerabilities osv --report vulnerabilities --report-format sarif > findings.sarif`.

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
