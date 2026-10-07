# Examples

Small, real projects for every input pixi-sbom reads besides `pixi.lock`, so each reader can be built,
tested and tried against files the real tools wrote rather than hand-made approximations.

Every lockfile here was written by the tool that owns its format, from the manifest next to it. pixi-sbom never
resolves anything; it reads what these tools resolved.

> These are the inputs for the 1.7.0 readers (#321–#327). Until a reader lands, `pixi sbom` refuses its file with
> a diagnostic; each reader's pull request makes its directory below work end to end.

## Layout

```
examples/
  scenarios.toml          the 14 scenarios every example is generated from
  shared/internal-utils/  a stand-in private package, depended on by local path
  projects/<reader>/<NN-scenario>/
```

Each example is a self-contained project: the manifest and the lockfile sit side by side under their real names,
so lockfile discovery, `--scan` and the manifest beside a lockfile (#328) all work on it unchanged.

| Reader | Files in each example | Written by |
|---|---|---|
| `pylock` | `pyproject.toml`, `pylock.toml` | `uv export --format pylock.toml`; `pip lock` for 03 and 08 |
| `uv` | `pyproject.toml`, `uv.lock` | `uv lock` |
| `poetry` | `pyproject.toml`, `poetry.lock` | `poetry lock` |
| `pdm` | `pyproject.toml`, `pdm.lock` | `pdm lock --group :all` |
| `conda-lock` | `environment.yml`, `conda-lock.yml` | `conda-lock lock` (linux-64, osx-arm64) |
| `conda-explicit` | `environment.yml`, `explicit-linux-64.txt`, `explicit-osx-arm64.txt` | `conda-lock render --kind explicit` |

## Scenarios

The same 14 scenarios exist for every reader. Advisory counts are OSV records for the PyPI versions each
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

## Trying them

Once a reader has landed:

```sh
# The SBOM, with known advisories looked up
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock --vulnerabilities osv

# One report at a time
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock --vulnerabilities osv --report vulnerabilities
pixi sbom --lockfile examples/projects/poetry/04-data-analysis/poetry.lock --report outdated
pixi sbom --lockfile examples/projects/uv/07-web-scraping/uv.lock --fetch-licenses --report licenses
pixi sbom --lockfile examples/projects/uv/07-web-scraping/uv.lock --fetch-licenses \
  --deny-license GPL-3.0-only --deny-license GPL-3.0-or-later   # html2text declares only "GNU GPL 3"

# Before and after an upgrade
pixi sbom --lockfile examples/projects/uv/14-django-upgraded/uv.lock \
  --report diff --against examples/projects/uv/01-django/uv.lock

# The same scenario through every reader
pixi sbom --scan examples/projects --report packages
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
14). An explicit spec cannot carry pip packages, so the `conda-explicit` examples are the conda part only.

## Regenerating

```sh
pixi run -e examples examples                       # every reader, every scenario
pixi run -e examples examples --reader uv           # one reader
pixi run -e examples examples --scenario 01-django  # one scenario
pixi run -e examples examples-test                  # the generator's own tests
```

`scripts/examples.py` writes each manifest from `scenarios.toml` and runs the tool. The tools live in the
dev-only `examples` and `examples-pip` pixi environments and never become dependencies of pixi-sbom. Expect the
lockfiles to change when regenerated: the tools resolve unpinned dependencies to whatever is newest that day.
