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

## Getting a lockfile

pixi-sbom reads a lock, never a list of requirements (see [It never resolves](#it-never-resolves)), so the first step
is the lock your project's own tool writes. Every command below was run with the tool named, and what it wrote is read
by a test (`tests/fixtures/lockfile-routes`).

| Your setup | Run | pixi-sbom reads |
|---|---|---|
| uv | `uv lock` | `uv.lock` |
| Poetry | `poetry lock` | `poetry.lock` |
| PDM | `pdm lock` | `pdm.lock` |
| pip, with a `requirements.txt` | `pip lock -r requirements.txt -o pylock.toml` (pip 25.1 and later; experimental there) | `pylock.toml` |
| pip-tools, or any fully pinned `requirements.txt` (`name==version` on every line) | nothing: `pixi-sbom --lockfile requirements.txt` reads it directly | the requirements file |
| a `requirements.txt` with ranges | `uv pip compile requirements.txt -o pylock.toml`, or `pip-compile --generate-hashes` | `pylock.toml`, or the pinned file |
| a Pipenv project (dependencies added with `pipenv install`, so they are in `Pipfile.lock`) | `pipenv requirements > requirements.txt`, then `uv pip compile requirements.txt -o pylock.toml` | `pylock.toml` |
| a venv you installed into with `pip install` | nothing: `pixi-sbom --prefix .venv` | the installed environment |
| a conda environment | `conda list --explicit --md5 > explicit.txt` in it, or `conda list -p <env> --explicit --md5` | the explicit spec |
| a mamba / micromamba environment | `micromamba env export -p <env> --explicit --md5 > explicit.txt` | the explicit spec |
| an `environment.yml` | `conda-lock -f environment.yml -p linux-64 -p osx-arm64` (any platforms you need) | `conda-lock.yml` |
| an environment that is already installed | nothing: `pixi-sbom --prefix <env>` reads it as it is | the installed environment |

`uv pip compile -o pylock.toml` writes PEP 751 because of the file name. It resolves, so a fully pinned
`requirements.txt` gives back exactly its pins, and one with ranges gives today's answer for them; that answer is
then the lock. `pip lock` locks for the interpreter that runs it, so its `pylock.toml` carries no markers.

### Tools you need

Only the tool for your route, and note that the routes for a `requirements.txt` with ranges and for Pipenv end in `uv
pip compile`, so they need **uv** as well; a fully pinned one (pip-tools') is read directly. Every tool here is on
conda-forge (`pixi global install <tool>`, or `conda install -c conda-forge <tool>`); the Python ones are also on PyPI
(`uv tool install <tool>`, `pipx install <tool>`). "Tested with" is the version each command above was run with.

| Tool | Needed for | Tested with |
|---|---|---|
| [uv](https://docs.astral.sh/uv/) | `uv lock`; `uv pip compile` in the routes for a `requirements.txt` with ranges and for Pipenv | 0.12.20 |
| [Poetry](https://python-poetry.org/) | `poetry lock` | 2.0.1 |
| [PDM](https://pdm-project.org/) | `pdm lock` | 2.26.9 |
| [pip](https://pip.pypa.io/) | `pip lock`, which needs pip 25.1 or later (`python -m pip install -U pip`) | 26.2.1 |
| [pip-tools](https://pip-tools.readthedocs.io/) | `pip-compile`, if that is how your `requirements.txt` is made | 7.6.1 |
| [Pipenv](https://pipenv.pypa.io/) | `pipenv requirements` | 2026.8.0 |
| [conda](https://docs.conda.io/) | `conda list --explicit --md5` (from [Miniforge](https://conda-forge.org/download/), or any conda install) | 26.9.1 |
| [micromamba](https://mamba.readthedocs.io/) | `micromamba env export --explicit --md5` | 1.5.12 and 2.9.0 |
| [conda-lock](https://conda.github.io/conda-lock/) | `conda-lock -f environment.yml` and `conda-lock render` | 4.0.0 |

### What is not read

Some files a tool writes are not read, and each has its way in:

| Not read | Why | Way in |
|---|---|---|
| Pipenv's `Pipfile.lock` | Pipenv's own format | `pipenv requirements`, then the pip route above, or `--prefix` on the virtualenv Pipenv made. `pipenv requirements` prints `Pipfile.lock`, not what is installed: a package added with `pip install` is not in it, so for those `--prefix` is the route |
| Rye's `requirements.lock` | Rye's own format; Rye's maintainers point its users to uv | `uv lock` in the project, or `--prefix` on its `.venv` |
| `conda env export` | versions without builds or URLs, so not a lock | `conda list --explicit --md5`, or `conda-lock` |
| `pip freeze` | a list of installed versions, no hashes or sources | `--prefix` on the environment it came from, which reads the same packages with more |

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
| a pinned `requirements.txt` (pip-compile, `uv pip compile`) | exact versions, hashes, markers, and pip-compile's `# via` comments | the packages for one platform, edges from `# via`, what `# via -r` names as declared ([Reading a pinned requirements.txt](cli.md#reading-a-pinned-requirementstxt)) |
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
| uv.lock | 0: 27 rows | 0: 27 rows, 25 with license | 0: 25 rows | 0: 27 unchanged | 0: 25 rows | 0: 27 rows | 0: 12 rows | 0: 27 rows, 25 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| pylock.toml | 0: 27 rows | 0: 27 rows, 25 with license | 0: 25 rows | 0: 27 unchanged | 0: 25 rows | 0: 27 rows | 0: 27 rows | 0: 27 rows, 25 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| poetry.lock | 0: 27 rows | 0: 27 rows, 25 with license | 0: 25 rows | 0: 27 unchanged | 0: 25 rows | 0: 27 rows | 0: 12 rows | 0: 27 rows, 25 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| pdm.lock | 0: 27 rows | 0: 27 rows, 25 with license | 0: 25 rows | 0: 27 unchanged | 0: 25 rows | 0: 27 rows | 0: 12 rows | 0: 27 rows, 25 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| requirements.txt (pip-compile) | 0: 9 rows | 0: 9 rows, 9 with license | 0: 9 rows | 0: 9 unchanged | 0: 9 rows | 0: 9 rows | 0: 2 rows | 0: 9 rows, 9 with score | 0 | 3 | 4 | 4 | 0 | 9 |
| conda-lock.yml | 0: 66 rows | 0: 66 rows, 1 with license | 0: 1 rows | 0: 66 unchanged | 0: 66 rows | 0: 1 rows | 0: 1 rows | 0: 66 rows, 1 with score | 0 | 3 | 4 | 4 | 0 | 9 |
| explicit spec | 0: 65 rows | 0: 65 rows, 0 with license | 0: 0 rows | 0: 65 unchanged | 0: 65 rows | 0: 0 rows | 0: 58 rows | 0: 65 rows, 0 with score | 0 | 0 | 0 | 0 | 0 | 0 |
| --prefix (conda) | 0: 4 rows | 0: 4 rows, 4 with license | 0: 1 rows | 0: 4 unchanged | 0: 4 rows | 0: 1 rows | 0: 0 rows | 0: 4 rows, 1 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| --prefix (venv) | 0: 6 rows | 0: 6 rows, 6 with license | 0: 6 rows | 0: 6 unchanged | 0: 6 rows | 0: 6 rows | 0: 2 rows | 0: 6 rows, 6 with score | 0 | 3 | 4 | 4 | 0 | 9 |
| --from-sbom | 0: 30 rows | 0: 30 rows, 30 with license | 0: 6 rows | 0: 30 unchanged | 0: 30 rows | 0: 6 rows | 0: 2 rows | 0: 30 rows, 6 with score | 0 | 3 | 4 | 4 | 7 | 9 |
| --from-sbom (syft CycloneDX) | 0: 15 rows | 0: 15 rows, 9 with license | 0: 9 rows | 0: 10 unchanged | 0: 9 rows | 0: 9 rows | 0: 0 rows | 0: 15 rows, 9 with score | 0 | 3 | 4 | 4 | 0 | 9 |
| --from-sbom (syft SPDX) | 0: 15 rows | 0: 15 rows, 9 with license | 0: 9 rows | 0: 10 unchanged | 0: 9 rows | 0: 9 rows | 0: 0 rows | 0: 15 rows, 9 with score | 0 | 3 | 4 | 4 | 0 | 9 |

Where a cell is smaller than its neighbours, the input does not record what the column needs:

- **vulnerabilities** on conda packages: OSV has no conda ecosystem, so only the PyPI packages of a `conda-lock.yml`
  or a conda prefix are looked up.
- **python** and **phantom** on inputs without a graph (an explicit spec, a `pylock.toml` from `uv export`): no
  package pins an interpreter, and every transitive package looks like a root, so it counts as undeclared.
- **licenses** on `conda-lock.yml` and explicit specs: neither records a conda package's license; `--fetch-licenses`
  reads it from the conda archives, which the test leaves unreachable on purpose.
- **licenses** and **outdated** on the Python lockfiles count 25 of 27: a package installed from a git checkout or a
  local directory is not looked up on PyPI by name, where the name could belong to an unrelated project.
- **`--from-sbom` on syft's documents** (a venv, in CycloneDX and in SPDX): the same answers from both. The 6
  executables syft found have no purl, so the outdated report lists them as not checked, and the diff matches the
  six by their one name.
- **scorecard** takes the repository from the wheel, or from the PyPI JSON API's `project_urls` where no wheel is
  read: `poetry.lock` and `pdm.lock` record file names, not URLs, and an installed `dist-info` may name none.
