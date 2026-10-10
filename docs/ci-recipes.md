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

## Scanning with Grype

Grype, like Trivy and osv-scanner, matches a package by its primary purl or its CPE and reads nothing else. No
advisory database indexes `pkg:conda` purls, so with the default `--primary-purl conda` a conda-installed Django,
NumPy or Pillow is invisible to the scanner and a vulnerable environment can scan clean. Make the PyPI identity the
primary purl whenever the document is going to a scanner:

```sh
# A pixi project, from its lockfile
pixi sbom --pypi-mapping prefix --primary-purl pypi --output - | grype

# An installed environment (a conda or pixi env, a venv, a container's /usr/local), offline
pixi sbom --prefix .pixi/envs/default --primary-purl pypi --embedded-sboms --output - | grype
```

On the installed `pixi/01-django` example, Grype finds none of django's 27 vulnerabilities with the default and all
27 with `--primary-purl pypi`. The whole environment gives 94 findings, against 86 from syft's document for the same
directory; [pixi-sbom and syft](syft.md#in-front-of-grype) has the comparison.

What each part does:

- `--primary-purl pypi` makes a conda package's PyPI purl its `purl` (the first `externalRefs` entry in SPDX) and keeps
  the conda purl as `pixi:purl`. The `bom-ref` and the dependency graph do not change.
- `--pypi-mapping prefix` finds the PyPI name of each conda-forge package from the mapping pixi itself uses
  (downloaded once a day into a cache); `--pypi-mapping-file` takes an offline copy. `--prefix` needs neither: it
  reads each package's PyPI identity from the `.dist-info` it installed.
- `--embedded-sboms` adds what is compiled or vendored into packages (Rust crates in wheels, setuptools' vendored
  copies), so Grype checks those too.
- Native conda packages (openssl, libtiff, python) get a CPE from the curated table with no flag at all; Grype matches
  them through NVD.

Set it once rather than on every command line, in the project's `.pixi/pixi-sbom-config.toml`, in
`[tool.pixi-sbom]` in `pyproject.toml`, or for every project in `~/.pixi/pixi-sbom-config.toml`:

```toml
primary-purl = "pypi"
pypi-mapping = "prefix"
```

In the [GitHub Action](github-action.md) the inputs are `primary-purl: pypi` and `pypi-mapping: prefix`.

Until it is set, a run that writes a CycloneDX or SPDX document with conda packages with a PyPI identity scanners cannot see says so once on
stderr, with how many. Setting `primary-purl` either way, `conda` included, is a decision and silences it. The
**PyPI identity** row of [`--report quality`](cli.md#how-complete-the-document-is) gives the same count, unscored.

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

## What changed in the environment

`--report diff --against <previous>` answers the pull-request question directly: which packages were added,
removed or bumped since the document on `main`, as a Markdown table ready for a comment.

```yaml
- uses: actions/download-artifact@v4   # the sboms artifact the main branch uploaded
  with: { name: sboms, path: previous }
- name: Environment changes
  run: pixi sbom --report diff --against previous/sbom-default.cdx.json --report-format markdown > diff.md
- uses: marocchino/sticky-pull-request-comment@v2
  with: { path: diff.md }
```

To gate on it instead of only reporting it, add `--fail-on-diff` (exit code 6), or let the action do both — it puts
the comparison in the job summary:

```yaml
- uses: actions/download-artifact@v4   # the sboms artifact the main branch uploaded
  with: { name: sboms, path: previous }
- uses: millsks/pixi-sbom@v1
  with:
    diff-against: previous/sbom-default.cdx.json
    fail-on-diff: removed version    # adding a package is fine; losing or bumping one is not
```

## Does the image still match the lockfile?

The check for a container built earlier, or one whose base image was rebuilt: compare what is installed with what
was locked. `pip` installs into the conda environment and packages rebuilt at the same version are sections of
their own, so they are not lost among ordinary additions.

```yaml
- name: Drift check
  run: |
    pixi sbom --prefix /opt/conda/envs/app --against pixi.lock       --report diff --report-format markdown --fail-on-diff >> "$GITHUB_STEP_SUMMARY"
```

```sh
# Locally, against a running container
docker run --rm -v "$PWD:/w" -w /w myimage   pixi-sbom --prefix /opt/conda/envs/app --against pixi.lock --report diff --fail-on-diff pip build
```

## Diffing SBOMs between commits

With `SOURCE_DATE_EPOCH` set, two runs over the same lockfile are byte-identical (the serial number is derived from
the lockfile contents and the timestamp is pinned), so a plain `diff` shows exactly which packages changed:

```sh
SOURCE_DATE_EPOCH=0 pixi sbom --output sbom.cdx.json
git diff --no-index -- sbom-previous.cdx.json sbom.cdx.json
```

See [reproducibility](output-format.md#reproducibility) for what the guarantee covers.

## pre-commit

Two hooks, from the mirror repository [`millsks/pixi-sbom-pre-commit`](https://github.com/millsks/pixi-sbom-pre-commit):
each of its tags installs the pixi-sbom wheel of the same version from PyPI, so nothing is compiled.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/millsks/pixi-sbom-pre-commit
    rev: v1.7.0
    hooks:
      # Write sbom.cdx.json next to the lockfile whenever a lockfile changes.
      - id: pixi-sbom
      # The license gate with your policy; writes no file.
      - id: pixi-sbom-policy
        args: [--deny-license, GPL-3.0-only, --deny-license, AGPL-3.0-only]
```

Both run when `pixi.lock`, `uv.lock`, `pylock.toml` (or `pylock.<name>.toml`), `poetry.lock`, `pdm.lock` or
`conda-lock.yml` changes, from the repository root, where the [usual search](cli.md#which-lockfile-is-found) finds
the lockfile; `args:` adds any other flag (`--scan .` for a monorepo, `--format spdx`). `pixi-sbom-policy` runs
`--fetch-licenses --require-license --report licenses`, so it needs the network to fetch licenses.

pre-commit fails a hook that modifies a tracked file, and an SBOM is deterministic except for its timestamp: a rerun
that would change nothing but the timestamp leaves the file alone, so the hook passes until the SBOM really changes.
Commit the SBOM the first time it is written; after that a lockfile change that changes the SBOM fails the hook once,
with the new SBOM ready to stage.

## Air-gapped runners

`PIXI_SBOM_OFFLINE=1` forbids every network request; the PyPI mapping, wheel and archive caches are used when present
and everything else is skipped with a warning, and the run still succeeds. Pair it with `--pypi-mapping-file` pointing
at a saved copy of the conda-forge mapping and a warm `PIXI_SBOM_CACHE_DIR` from an online run. The
[environment variables](cli.md#environment-variables) page lists every knob, including the PyPI mirror URL.
