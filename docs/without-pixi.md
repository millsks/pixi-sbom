# Using pixi-sbom without pixi

pixi-sbom is a pixi extension, but nothing in it needs pixi. It is one self-contained binary that reads a lockfile
(or an installed environment) and writes CycloneDX or SPDX, and it reads the lockfiles of uv, Poetry, PDM,
conda-lock and pip's PEP 751 `pylock.toml` as well as `pixi.lock`. A uv or Poetry project uses it as it is.

## Installing it

```sh
uvx pixi-sbom --lockfile uv.lock      # run it from PyPI without installing anything
uv tool install pixi-sbom             # or keep it on PATH
pip install pixi-sbom                 # or into any Python environment
```

The PyPI wheels hold the same binary as the release archives (there is no Python code, so any Python works), for
Linux (glibc and musl) x86_64 and aarch64, macOS x86_64 and arm64, and Windows x86_64, from 1.7.0 on. `cargo
binstall pixi-sbom`, the release archives and conda-forge are the other ways; see [Installation](installation.md).
Installed this way, the command is `pixi-sbom` rather than `pixi sbom`.

## What it reads

Without `--lockfile`, it looks for a lockfile in the working directory and upward, and picks the first in a fixed
order when a directory has several (see [Which lockfile is found](cli.md#which-lockfile-is-found)).

```sh
pixi-sbom --lockfile uv.lock
pixi-sbom --lockfile pylock.toml --platform linux-64
pixi-sbom --lockfile poetry.lock --format spdx
pixi-sbom --lockfile pdm.lock --report packages
pixi-sbom --lockfile conda-lock.yml --all-platforms
pixi-sbom --lockfile explicit-linux-64.txt
pixi-sbom --prefix .venv
pixi-sbom --prefix .venv --against uv.lock --report diff
```

| Input | What it records | What the document gets from it |
|---|---|---|
| `uv.lock` | every package for every platform, the dependency graph, extras and groups, workspace members | the packages for one platform (`--platform`, default the host), the graph, `pixi:python-extras` / `pixi:via-extra`, a `scope` per group ([Reading uv.lock](cli.md#reading-uvlock)) |
| `pylock.toml` | the packages for the environments it was locked for, each with a marker; from `uv export`, no graph | the packages whose marker holds on the platform; no edges unless the file records dependencies ([Reading pylock.toml](cli.md#reading-pylocktoml)) |
| `poetry.lock` | the packages, the graph, groups and extras; file names and hashes, not URLs | the packages for the platform and the graph; no download URL, so nothing that needs the wheel ([Reading poetry.lock](cli.md#reading-poetrylock)) |
| `pdm.lock` | the packages, the graph, groups; file names and hashes | as for Poetry ([Reading pdm.lock](cli.md#reading-pdmlock)) |
| `conda-lock.yml` | conda and pip packages for several platforms, with the graph and categories | conda and PyPI packages for one platform (or `--all-platforms`), `scope` from categories ([Reading conda-lock.yml](cli.md#reading-conda-lockyml)) |
| explicit spec (`conda list --explicit --md5`) | exact conda package URLs and hashes for one platform | the conda packages, without a graph ([Reading an explicit spec file](cli.md#reading-an-explicit-spec-file)) |
| `--prefix` on a venv or a Python installation | what is installed: each `dist-info`, `REQUESTED`, `direct_url.json` | the installed packages, what was asked for by name as direct, the interpreter version ([Describing an installed environment](cli.md#describing-an-installed-environment)) |

The `pyproject.toml` or `environment.yml` beside the lockfile says what the project declared, which marks those
packages as direct and makes the root depend on them alone ([What a project without pixi
declared](cli.md#what-a-project-without-pixi-declared)).

## It never resolves

pixi-sbom describes what a lockfile or an environment pins; it never decides what a range would resolve to. A
resolver's answer depends on the day, the index and the platform, and an SBOM that changes with those is not a record
of anything. So these are not inputs, and each has a tool that turns it into one:

| Not an input | Why | Run instead |
|---|---|---|
| `requirements.txt` with ranges (`django>=4`) | it names ranges, not versions | `uv pip compile requirements.txt -o pylock.toml`, or `pip lock -r requirements.txt -o pylock.toml` |
| `pyproject.toml` alone | the same: declarations, not a lock | `uv lock`, `poetry lock`, `pdm lock`, or `uv export --format pylock.toml` |
| `environment.yml` alone | conda specs, not builds | `conda-lock -f environment.yml`, or `conda list --explicit --md5 > explicit.txt` in the environment |

A manifest beside a lockfile is still read, for what it declares; only resolving is ruled out.

## In CI and before a commit

The GitHub Action downloads its own binary, so the runner needs neither pixi nor Rust; `lockfile`, `prefix` and
`scan` take every kind above ([GitHub Action](github-action.md#without-pixi-uv-poetry-pdm-pylock-and-venvs)). The
pre-commit hooks install the PyPI wheel and run whenever any of these lockfiles changes ([pre-commit](ci-recipes.md#pre-commit)).
`--prefix .venv --against uv.lock` is a drift check for a venv against its lock
([Does this venv still match its lock?](cli.md#does-this-venv-still-match-its-lock)).

## What works with which input

Every report, `--explain` and every gate, run on every input kind against a local upstream that answers for any
package (`tests/matrix.rs`, which keeps this table and the test in step). A cell is the exit code and the row count;
for licenses and scorecard, how many rows the enrichment reached. Exit codes: 0 ok, 3 license policy, 4 vulnerability
gate, 7 yanked, 9 scorecard gate; that the gates fire is the point, since the upstream gives every PyPI package a
critical, KEV-listed advisory, an MIT license and a 4.2 scorecard, and yanks `six`.

| input | packages | licenses | vulnerabilities | diff | outdated | python | phantom | scorecard | explain | license gate | severity gate | KEV gate | yanked gate | scorecard gate |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| pixi.lock | 0: 30 rows | 0: 30 rows, 30 with license | 0: 6 rows | 0: 30 unchanged | 0: 30 rows | 0: 6 rows | 0: 2 rows | 0: 30 rows, 6 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| uv.lock | 0: 27 rows | 0: 27 rows, 27 with license | 0: 25 rows | 0: 27 unchanged | 0: 27 rows | 0: 27 rows | 0: 12 rows | 0: 27 rows, 25 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| pylock.toml | 0: 27 rows | 0: 27 rows, 26 with license | 0: 25 rows | 0: 27 unchanged | 0: 26 rows | 0: 27 rows | 0: 27 rows | 0: 27 rows, 25 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| poetry.lock | 0: 27 rows | 0: 27 rows, 27 with license | 0: 25 rows | 0: 27 unchanged | 0: 27 rows | 0: 27 rows | 0: 12 rows | 0: 27 rows, 0 with score | 0 | 3 | 4 | 4 | 7 | 0 |
| pdm.lock | 0: 27 rows | 0: 27 rows, 27 with license | 0: 25 rows | 0: 27 unchanged | 0: 27 rows | 0: 27 rows | 0: 12 rows | 0: 27 rows, 0 with score | 0 | 3 | 4 | 4 | 7 | 0 |
| conda-lock.yml | 0: 66 rows | 0: 66 rows, 1 with license | 0: 1 rows | 0: 66 unchanged | 0: 66 rows | 0: 1 rows | 0: 1 rows | 0: 66 rows, 1 with score | 0 | 3 | 4 | 4 | 0 | 9 |
| explicit spec | 0: 65 rows | 0: 65 rows, 0 with license | 0: 0 rows | 0: 65 unchanged | 0: 65 rows | 0: 0 rows | 0: 58 rows | 0: 65 rows, 0 with score | 0 | 0 | 0 | 0 | 0 | 0 |
| --prefix (conda) | 0: 4 rows | 0: 4 rows, 4 with license | 0: 1 rows | 0: 4 unchanged | 0: 4 rows | 0: 1 rows | 0: 0 rows | 0: 4 rows, 0 with score | 0 | 3 | 4 | 4 | 7 | 0 |
| --prefix (venv) | 0: 6 rows | 0: 6 rows, 6 with license | 0: 6 rows | 0: 6 unchanged | 0: 6 rows | 0: 6 rows | 0: 2 rows | 0: 6 rows, 0 with score | 0 | 3 | 4 | 4 | 0 | 0 |
| --from-sbom | 0: 30 rows | 0: 30 rows, 30 with license | 0: 6 rows | 0: 30 unchanged | 0: 30 rows | 0: 6 rows | 0: 2 rows | 0: 30 rows, 6 with score | 0 | 3 | 4 | 4 | 7 | 9 |

Where a cell is smaller than its neighbours, the input does not record what the column needs:

- **vulnerabilities** on conda packages: OSV has no conda ecosystem, so only the PyPI packages of a `conda-lock.yml`
  or a conda prefix are looked up.
- **python** and **phantom** on inputs without a graph (an explicit spec, a `pylock.toml` from `uv export`): no
  package pins an interpreter, and every transitive package looks like a root, so it counts as undeclared.
- **licenses** on `conda-lock.yml` and explicit specs: neither records a conda package's license; `--fetch-licenses`
  reads it from the conda archives, which the test leaves unreachable on purpose.
- **scorecard** on `poetry.lock` and `pdm.lock`: they record file names, not URLs, so no wheel is read and no
  repository is known.
