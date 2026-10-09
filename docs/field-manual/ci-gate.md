# Gate a repository in CI

**When:** you want a pull request to fail when the environment it locks has a known-exploited vulnerability,
a high-severity one, or a license your policy forbids, and you want the SBOM written either way.

## On your machine first

Run the gate where you can read it before putting it in CI. From the directory with `pixi.lock`:

```sh
pixi sbom -p linux-64 --pypi-mapping prefix --vulnerabilities osv --kev --fail-on-kev --fail-on-severity high --output sbom.cdx.json   # needs the network
```

- **Exit 0:** nothing at or above `high`, nothing known exploited. `sbom.cdx.json` has the findings anyway.
- **Exit 4:** the gate tripped. stderr lists each finding with its severity and the affected package, and the
  document is still written, so the pipeline can publish it either way.

`--pypi-mapping prefix` gives conda packages their PyPI identity, without which advisories filed against the
PyPI name (most of them) are never matched to the conda package. See
[PyPI identities for conda packages](../output-format.md#pypi-identities-for-conda-packages).

## Accept what you have assessed

A finding that does not affect you stays in the document, recorded as assessed, and leaves the gate:

```sh
pixi sbom -p linux-64 --pypi-mapping prefix --vulnerabilities osv --kev --fail-on-kev --fail-on-severity high --ignore-vuln "CVE-2023-43804:not_affected:code_not_reachable:only used for internal requests" --output sbom.cdx.json   # needs the network
```

Keep the list in the configuration file rather than the command line once it grows
([Configuration file](../cli.md#configuration-file)): `ignore-vuln = [...]` under `[tool.pixi-sbom]`.

## Rank what is left

Severity alone does not say what to fix first. KEV says what is exploited now; EPSS scores the rest by how
likely exploitation is in the next 30 days, and can gate too:

```sh
pixi sbom -p linux-64 --pypi-mapping prefix --vulnerabilities osv --kev --epss --report vulnerabilities   # needs the network
pixi sbom -p linux-64 --pypi-mapping prefix --vulnerabilities osv --epss --fail-on-epss 0.1 --output sbom.cdx.json   # needs the network
```

## Add a license policy

```sh
pixi sbom -p linux-64 --fetch-licenses --deny-license GPL-3.0-only --deny-license AGPL-3.0-only --require-license --output sbom.cdx.json   # needs the network
```

Exit 3 lists every violation. `--require-license` matters: a deny list only matches SPDX identifiers, and a
package that declares its license as free text (`GNU GPL 3`) passes a deny list unless a non-SPDX license is
itself a violation. See [Enforcing a license policy](../cli.md#enforcing-a-license-policy).

## In GitHub Actions

The action runs the same gates; each input is the flag of the same name.

```yaml
permissions:
  contents: read
  security-events: write   # for upload-sarif
steps:
  - uses: actions/checkout@v4
  - uses: millsks/pixi-sbom@v1
    with:
      platform: linux-64
      pypi-mapping: prefix
      vulnerabilities: osv
      kev: "true"
      fail-on-kev: "true"
      fail-on-severity: high
      upload-sarif: "true"          # findings in the Security tab
      extra-args: --epss
```

`upload-sarif` puts the findings in the repository's *Security → Code scanning* page as well as failing the step.
See [The GitHub Action](../github-action.md).

## If it fails for the wrong reason

- **Exit 1, a network error:** the gate never ran. `pixi sbom --doctor --vulnerabilities osv --kev` says which
  upstream is unreachable; [A restricted network](restricted-network.md) is the next step.
- **No findings at all on a project you know is affected:** the packages probably have no identity the database
  answers to. The vulnerabilities report lists them under *No queryable identity*; add `--pypi-mapping prefix`.
