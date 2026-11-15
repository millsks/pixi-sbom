# Examples

Small, real projects for every input pixi-sbom reads, so each reader can be built, tested and tried against files
the real tools wrote rather than hand-made approximations.

Every lockfile here was written by the tool that owns its format, from the manifest next to it. pixi-sbom never
resolves anything; it reads what these tools resolved. The one exception is `requirements-unpinned/`, written by
hand on purpose: those files are not locks, and each one shows a way pixi-sbom refuses one.

## Layout

```
examples/
  scenarios.toml          the 19 scenarios every example is generated from
  shared/internal-utils/  a stand-in private package, depended on by local path
  projects/<reader>/<NN-scenario>/
  projects/requirements-unpinned/   hand-written requirements files that must be refused
  projects/container/20-images/     two container images, unpacked and trimmed, and the script that builds them
```

Each example is a self-contained project: the manifest and the lockfile sit side by side under their real names,
so lockfile discovery, `--scan` and the manifest beside a lockfile (#328) all work on it unchanged.

| Reader | Files in each example | Written by |
|---|---|---|
| `pixi` | `pixi.toml`, `pixi.lock` | `pixi lock` (linux-64, osx-arm64) |
| `pylock` | `pyproject.toml`, `pylock.toml` | `uv export --format pylock.toml`; `pip lock` for 03 and 08 |
| `uv` | `pyproject.toml`, `uv.lock` | `uv lock` |
| `poetry` | `pyproject.toml`, `poetry.lock` | `poetry lock` |
| `pdm` | `pyproject.toml`, `pdm.lock` | `pdm lock --group :all` |
| `conda-lock` | `environment.yml`, `conda-lock.yml` | `conda-lock lock` (linux-64, osx-arm64) |
| `conda-explicit` | `environment.yml`, `explicit-linux-64.txt`, `explicit-osx-arm64.txt` | `conda-lock render --kind explicit` |
| `requirements` | `requirements.in`, `requirements-dev.in`, `requirements.txt`, `requirements-dev.txt` | `uv pip compile --generate-hashes` for Python's floor on manylinux x86_64; `pip-compile --generate-hashes` for 02 and 09 |
| `npm` | `package.json`, `package-lock.json` | `npm install --package-lock-only` |
| `yarn` | `package.json`, `yarn.lock` (v1) | `yarn install` (yarn 1.22, through corepack) |
| `yarn-berry` | `package.json`, `yarn.lock` (Berry) | `yarn install --mode=update-lockfile` (yarn 4.9, through corepack) |
| `pnpm` | `package.json`, `pnpm-lock.yaml` | `pnpm install --lockfile-only` (pnpm 9.15, through corepack) |
| `container` | `<app>.Dockerfile`, `build.sh`, the unpacked image under `<app>/` | `build.sh`: `docker build`, `docker export`, trimmed to installed metadata |

The `pixi` examples are the conda environment the conda readers describe, with the packages conda-forge does not
carry (`conda_pip`) as PyPI dependencies, the local package as an editable path, and each dependency group and
extra as a feature with an environment of its own (`pixi sbom --all-environments` writes one document each).

The `requirements` examples are a pip-tools project: `requirements.in` holds the application's requirements and
extras, `requirements-dev.in` adds the dependency groups on top of it (`-r requirements.in`), and each is compiled to
a hashed `.txt` beside it. A local path or a git checkout cannot be pinned to one version, so neither is in them.
A requirements file is never discovered, so it is always passed with `--lockfile`.

## Scenarios

Scenarios 01 to 14 exist for every Python and conda reader; 15 to 17 are conda-only (R, Go and JavaScript packages
installed in a conda environment), so they are in `pixi`, `conda-lock` and `conda-explicit`. 18 is Pillow's wheels
(`pixi`, `uv`, `requirements`), and 19 is a JavaScript frontend, in the four JavaScript readers and in `pixi` as a
workspace with the frontend beside it. Advisory counts are OSV records for the PyPI versions each
`uv.lock` resolved, queried on 2026-10-07; OSV lists GHSA and PYSEC copies of one advisory separately, and
pixi-sbom merges them, so its own count is lower. New advisories are published all the time, so these only grow.

| Scenario | Python | What it shows | Packages | Affected | OSV records | Look for |
|---|---|---|---|---|---|---|
| 01-django | 3.11 | vulnerabilities, outdated, licenses, a local path package, a git dependency, an extra, two groups | 27 | 5 | 106 | Django 3.2.12, Pillow, sqlparse 0.4.2, `internal-utils` from `libs/`, django-debug-toolbar from git |
| 02-flask | 3.11 | vulnerabilities, outdated, an extra, a group | 27 | 8 | 80 | urllib3 1.26.4, Werkzeug 2.0.2, Flask-Cors 3.0.10, Jinja2 3.0.1 |
| 03-fastapi | ≥3.14 | vulnerabilities, extras, a pylock written by `pip lock` | 39 | 4 | 38 | python-multipart 0.0.9, starlette 0.38.6, python-jose 3.3.0 |
| 04-data-analysis | ≥3.14 | outdated scientific stack, a vulnerable notebook | 109 | 2 | 26 | numpy, pandas and SciPy releases behind; notebook 7.2.1, jupyterlab |
| 05-machine-learning | 3.11 | vulnerabilities in a large graph | 84 | 7 | 121 | mlflow 2.9.2, scikit-learn 1.2.1, joblib 1.1.1 |
| 06-deep-learning | ≥3.14 | a large graph, vulnerabilities | 67 | 2 | 49 | transformers 4.46.0, torch 2.9.0 |
| 07-web-scraping | 3.11 | vulnerabilities, a GPL-3.0 package for the license gate | 47 | 5 | 49 | Scrapy, urllib3 1.26.12, `html2text` (GPL-3.0) |
| 08-cli-tool | ≥3.14 | a clean report, a pylock written by `pip lock` | 21 | 0 | 0 | nothing, which is the point |
| 09-async-worker | 3.11 | vulnerabilities, extras (`celery[redis]`) | 38 | 5 | 101 | aiohttp 3.8.4, redis 4.3.4, flower |
| 10-dev-tooling | ≥3.14 | four dependency groups, a GPL-2.0 package | 73 | 1 | 4 | `pylint` (GPL-2.0), black 24.1.0, groups `lint`/`test`/`docs`/`release` |
| 11-streamlit-dashboard | ≥3.14 | vulnerabilities on a modern stack | 42 | 2 | 40 | streamlit 1.36.0, Pillow |
| 12-aws-cloud | ≥3.14 | vulnerabilities, an LGPL-2.1 package, outdated | 24 | 4 | 53 | PyJWT 2.3.0, urllib3 2.0.6, paramiko 3.3.1 (LGPL-2.1), boto3 behind |
| 13-genai-llm | ≥3.14 | vulnerabilities in an LLM stack | 56 | 6 | 71 | transformers 4.46.0, langchain-core, langchain 0.3.0 |
| 14-django-upgraded | ≥3.14 | 01-django after the upgrade: the other side of a diff | 32 | 1 | 10 | Django 4.2 LTS; compare with 01-django |

The conda-only scenarios, and 18, show what an installed environment carries beyond its lockfile, so try them with `--prefix` after
`pixi install`:

| Scenario | What it shows | Look for |
|---|---|---|
| 15-r-analysis | CRAN purls for `r-*` packages, a CRAN advisory through OSV | `pkg:cran/Rcpp`, `pixi:cran-source`, RSEC-2023-8 against commonmark 1.8.0 with `--vulnerabilities osv`; `r-base` has no CRAN purl |
| 16-go-tools | Go modules read out of `go-yq` and `gh` | `pkg:golang` components and `pkg:golang/stdlib` with `--embedded-sboms` |
| 17-node-tools | npm packages installed by `nodejs` and `configurable-http-proxy` | about 220 `pkg:npm` components, scoped (`%40npmcli/...`) and nested |
| 18-image-wheels | native libraries inside Pillow 10.0.0's wheels, with `--embedded-sboms` | `pkg:generic/libwebp@1.3.1` and its CPE under Pillow, CVE-2023-4863 with `--vulnerabilities osv`, each library's file in `evidence.occurrences` |

Any installed example also shows where each component was found (`evidence.occurrences`, #24): the conda-meta record
of each conda package, the dist-info of each pip package, and the binary each Go module (16) or bundled library (18)
was read from.

19-web-frontend is a JavaScript project, read from its lockfile with nothing installed:

| Example | Look for |
|---|---|
| `npm`, `yarn`, `yarn-berry`, `pnpm` `/19-web-frontend` | the same 29 `pkg:npm` releases from four lockfiles; `semver` and what it needs are development (`scope: optional`); advisories for lodash 4.17.15, minimist 1.2.5, axios 0.21.1 and @babel/traverse 7.22.5 with `--vulnerabilities osv` |
| `pixi/19-web-frontend` | a pixi workspace (Python with FastAPI, and nodejs) with the frontend's `package.json` and `package-lock.json` beside `pixi.toml`; the frontend joins the workspace's document unless `--skip-input javascript` leaves it out |

20-images is `02-flask` installed into two container images, unpacked (#31):

| Example | Look for |
|---|---|
| `container/20-images/python-app` | the official `python:3.11-slim` image: `/usr/local` (its own Python installation, pip and setuptools) and `/app/.venv` (`requirements/02-flask` pip-installed), two environments named by their paths in the image; urllib3 1.26.4 and Werkzeug 2.0.2 advisories |
| `container/20-images/pixi-app` | pixi's production layout: `pixi/02-flask` installed in a build stage and only `/app/.pixi/envs/default` copied to a slim image, with no lockfile beside it |

`pixi sbom --scan <one of them> --merge` describes the whole image's Python and conda content in one document. Each
tree keeps only what an installed environment is read from: `conda-meta/` records (without their per-file hashes),
`pyvenv.cfg`, every `*.dist-info`, the interpreter's `patchlevel.h` and small executable, and `etc/os-release`.

## Trying them

The documentation site has a guided tour of these: [Try it on the examples](https://millsks.github.io/pixi-sbom/latest/try-the-examples/),
one feature at a time, every command tested. A few to start with:

```sh
# The SBOM, with known advisories looked up
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock --vulnerabilities osv

# A pixi workspace: one document per environment (default, s3, dev, test)
pixi sbom --lockfile examples/projects/pixi/01-django/pixi.lock --all-environments --output sboms/

# A compiled requirements file, read for the Python and platform it was compiled for
pixi sbom --lockfile examples/projects/requirements/01-django/requirements-dev.txt --report packages

# One report at a time
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock --vulnerabilities osv --report vulnerabilities
pixi sbom --lockfile examples/projects/poetry/04-data-analysis/poetry.lock --report outdated
pixi sbom --lockfile examples/projects/uv/07-web-scraping/uv.lock --fetch-licenses --report licenses
# html2text declares the free text "GNU GPL 3", which no SPDX deny list matches; --require-license
# makes a license that is not an SPDX expression a violation, so this exits 3 naming it
pixi sbom --lockfile examples/projects/uv/07-web-scraping/uv.lock --fetch-licenses \
  --deny-license GPL-3.0-only --deny-license GPL-3.0-or-later --require-license

# Before and after an upgrade
pixi sbom --lockfile examples/projects/uv/14-django-upgraded/uv.lock \
  --report diff --against examples/projects/uv/01-django/uv.lock

# The same scenario through every reader
pixi sbom --scan examples/projects --report packages
```

## Unpinned requirements

A `requirements.txt` is only a lock when every line is one version. These are what a project usually has instead,
and each one must be refused with `pixi_sbom::requirements::not_pinned` (exit code 1), naming the first line that is
not one version, and must write nothing. `tests/cli.rs` checks each.

| Project | What it is | Refused at |
|---|---|---|
| `01-loose-ranges` | what a project starts with: `>=`, `<`, `~=` ranges | line 3, `Django>=4.2,<5` |
| `02-bare-names` | names and nothing else | line 1, `flask` |
| `03-one-loose-line` | `requirements/08-cli-tool`'s compiled, hashed file with one pin hand-edited into a range | line 55, `rich>=14` |
| `04-editable-and-git` | pins, plus a package worked on in the repository (`-e`) and a fork from git | line 6, `-e ./libs/internal-utils` |
| `05-wildcard-pins` | `Django==4.2.*`, which looks pinned and is any 4.2 release | line 2, `Django==4.2.*` |

```sh
pixi sbom --lockfile examples/projects/requirements-unpinned/01-loose-ranges/requirements.txt
#  × line 3 of requirements.txt is not pinned to one version: Django>=4.2,<5
#  help: pixi-sbom reads a lock and never resolves one; make this file a lock with `uv pip compile ...`
```

## Python versions

The examples' floor is Python 3.14. Scenarios that demonstrate old, vulnerable pins declare an older one, because
those releases only published wheels for the Pythons of their day:

- **01, 02, 05, 07, 09** use Python 3.11 for every reader.
- **03, 04, 06, 10, 11, 13** use ≥3.14 for the Python readers and **3.12 for the conda readers**: conda-forge built
  these pins only for Pythons before 3.14.
- A few locks are narrowed only where a tool requires it. Poetry checks that every dependency supports the whole
  `requires-python` range, so its manifests cap an open range at `<4` (and 06 at `<3.15`, for triton). PDM is
  locked for `>=3.14,!=3.14.1,<3.15` in 06, because networkx excludes 3.14.1 and PDM will not lock around it.

## Where the conda examples differ

conda-forge does not publish every version PyPI does, so a few conda pins are the nearest version it has, chosen so
the scenario still shows what it is there to show:

| Scenario | PyPI pin | conda-forge pin |
|---|---|---|
| 01-django | psycopg2-binary 2.9.5, Pillow 9.3.0 | psycopg2 2.9.6, pillow 9.4.0 (still affected by CVE-2023-44271 and CVE-2023-50447) |
| 03-fastapi | fastapi 0.114.0 | fastapi 0.114.1 |
| 06-deep-learning | torch 2.9.0, torchvision 0.24.0 | pytorch 2.9.1, torchvision unpinned |
| 07-web-scraping | Scrapy 2.6.1, urllib3 1.26.12, selenium 4.8.0 | scrapy 2.7.1, urllib3 1.26.13, selenium 4.8.2 (all still affected) |
| 09-async-worker | celery 5.2.3, flower 1.0.0 | celery 5.2.7, flower 1.2.0 |
| 13-genai-llm | openai 1.30.0 | openai 1.30.1 |

Packages without a conda-forge build of the right kind come from a `pip:` section in `conda-lock.yml` (01, 05 and
14), and from `[pypi-dependencies]` in `pixi.toml`. An explicit spec cannot carry pip packages, so the
`conda-explicit` examples are the conda part only.

pixi never lets a PyPI package replace a conda one, so where a PyPI dependency caps a package conda-forge would
otherwise pick newer, the pixi workspace adds the cap as a conda constraint (`pixi_conda`): 05's mlflow 2.9.2 needs
`packaging<24` and `pytz<2024`.

## Regenerating

```sh
pixi run -e examples examples                       # every reader, every scenario
pixi run -e examples examples --reader uv           # one reader
pixi run -e examples examples --scenario 01-django  # one scenario
pixi run -e examples examples-test                  # the generator's own tests
```

The container images are rebuilt by their own script, which needs docker (or podman as `docker`), rsync and jq, and
builds for linux/amd64:

```sh
examples/projects/container/20-images/build.sh             # both images
examples/projects/container/20-images/build.sh pixi-app    # one
```

`scripts/examples.py` writes each manifest from `scenarios.toml` and runs the tool. The tools live in the
dev-only `examples` and `examples-pip` pixi environments and never become dependencies of pixi-sbom. Expect the
lockfiles to change when regenerated: the tools resolve unpinned dependencies to whatever is newest that day.
