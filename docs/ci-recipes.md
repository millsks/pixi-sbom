# CI recipes

## Consuming the output with other tools

The documents validate against the official JSON schemas and load in the usual tooling. Examples:

```sh
# Convert between formats or inspect
syft convert sbom.cdx.json -o spdx-json
cyclonedx-cli validate --input-file sbom.cdx.json --input-format json

# Vulnerability scan
grype sbom:sbom.cdx.json
```

Conda packages are identified by `pkg:conda/...` purls with `channel`, `subdir`, `build` and `type` qualifiers; PyPI
packages by `pkg:pypi/...`.

Scanners have no conda vulnerability data, so by default a conda-only Python environment scans as clean no matter
what it contains. To get real results, give conda-forge Python packages their PyPI identity and make it the primary
purl:

```sh
pixi sbom --pypi-mapping prefix --primary-purl pypi --output - | grype
```

`--pypi-mapping prefix` consults the same conda-forge mapping pixi uses (downloaded once a day into a cache);
`--pypi-mapping-file` takes an offline copy. On a typical conda-forge Python environment this gives roughly 60% of the
components a `pkg:pypi` purl. See [output-format.md](output-format.md#pypi-identities-for-conda-packages) for exactly
what is recorded.

## Failing the build on license policy

Any of `--allow-license`, `--deny-license` and `--require-license` turns the run into a gate: the document is still
written, the violations are listed, and the exit code is 3. In the [action](github-action.md) that fails the step
unless `fail-on-policy` is `false`; anywhere else, let the non-zero exit propagate:

```sh
pixi sbom --fetch-licenses --deny-license GPL-3.0-only --deny-license AGPL-3.0-only --require-license
```

See [the policy semantics](cli.md#enforcing-a-license-policy) for how expressions such as `MIT OR GPL-3.0-only` are
evaluated.

## A license table in a pull request comment

`--report licenses --report-format markdown` prints a per-license summary with unlicensed and non-SPDX packages
called out, ready to paste:

```yaml
- name: License report
  run: pixi sbom --fetch-licenses --report licenses --report-format markdown > report.md
- uses: marocchino/sticky-pull-request-comment@v2
  with:
    path: report.md
```

`--report-format csv` and `json` feed spreadsheets and scripts the same way; see
[looking instead of writing](cli.md#looking-instead-of-writing).

## Diffing SBOMs between commits

With `SOURCE_DATE_EPOCH` set, two runs over the same lockfile are byte-identical (the serial number is derived from
the lockfile contents and the timestamp is pinned), so a plain `diff` shows exactly which packages changed:

```sh
SOURCE_DATE_EPOCH=0 pixi sbom --output sbom.cdx.json
git diff --no-index -- sbom-previous.cdx.json sbom.cdx.json
```

See [reproducibility](output-format.md#reproducibility) for what the guarantee covers.

## Air-gapped runners

`PIXI_SBOM_OFFLINE=1` forbids every network request; the PyPI mapping, wheel and archive caches are used when present
and everything else is skipped with a warning, and the run still succeeds. Pair it with `--pypi-mapping-file` pointing
at a saved copy of the conda-forge mapping and a warm `PIXI_SBOM_CACHE_DIR` from an online run. The
[environment variables](cli.md#environment-variables) page lists every knob, including the PyPI mirror URL.
