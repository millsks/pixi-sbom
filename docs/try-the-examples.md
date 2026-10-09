# Try it on the examples

The repository has more than a hundred real projects to try pixi-sbom on. There are fourteen
scenarios, from a Django app on an old LTS to an LLM stack, each locked by every tool pixi-sbom
reads. Every lockfile was written by the tool that owns its format. Some scenarios have known
vulnerabilities, one has a GPL package, one is an upgrade of another, and a separate set of
`requirements.txt` files is built to be refused.

Nothing needs installing beyond pixi-sbom itself ([Installation](installation.md)). Get the examples
with a clone:

```sh
git clone https://github.com/millsks/pixi-sbom
cd pixi-sbom
```

Every command below runs from there. A test runs each one as written, so they work. The commands marked
`# needs the network` look things up online (OSV, CISA KEV, FIRST EPSS, the package indexes); the
rest work offline.

## What's there

```
examples/projects/<reader>/<NN-scenario>/
examples/projects/requirements-unpinned/<NN-name>/
```

| Reader | What each example has |
|---|---|
| `pixi` | `pixi.toml`, `pixi.lock`, one environment per dependency group and extra |
| `uv` | `pyproject.toml`, `uv.lock` |
| `poetry` | `pyproject.toml`, `poetry.lock` |
| `pdm` | `pyproject.toml`, `pdm.lock` |
| `pylock` | `pyproject.toml`, `pylock.toml` |
| `conda-lock` | `environment.yml`, `conda-lock.yml` |
| `conda-explicit` | `environment.yml`, `explicit-linux-64.txt`, `explicit-osx-arm64.txt` |
| `requirements` | `requirements.in` / `.txt` and `requirements-dev.in` / `.txt`, compiled and hashed |

The scenarios worth knowing first:

| Scenario | Why try it |
|---|---|
| `01-django` | Django 3.2.12 with known advisories, an editable local package, a git dependency, an extra and two groups |
| `02-flask` | a 2021-era stack: urllib3 1.26.4, Werkzeug 2.0.2, several findings |
| `07-web-scraping` | `html2text` is GPL-3.0, for the license gate |
| `08-cli-tool` | nothing wrong with it, which is what a clean report looks like |
| `14-django-upgraded` | `01-django` after the upgrade: the other side of a diff |

`examples/README.md` in the repository lists all fourteen, with what each one shows.

The conda and pixi examples are locked for linux-64 and osx-arm64, so the commands below pass
`-p linux-64` to give the same answer on any machine.

## One document from every kind of lockfile

The same scenario through each reader. The package count differs between conda and PyPI, because a
conda environment carries the interpreter and system libraries too.

```sh
pixi sbom --lockfile examples/projects/pixi/01-django/pixi.lock -p linux-64 --report packages
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock -p linux-64 --report packages
pixi sbom --lockfile examples/projects/poetry/01-django/poetry.lock -p linux-64 --report packages
pixi sbom --lockfile examples/projects/pdm/01-django/pdm.lock -p linux-64 --report packages
pixi sbom --lockfile examples/projects/pylock/01-django/pylock.toml -p linux-64 --report packages
pixi sbom --lockfile examples/projects/conda-lock/01-django/conda-lock.yml -p linux-64 --report packages
pixi sbom --lockfile examples/projects/conda-explicit/01-django/explicit-linux-64.txt --report packages
pixi sbom --lockfile examples/projects/requirements/01-django/requirements-dev.txt --report packages
```

Writing the document rather than a table, in either format:

```sh
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock -p linux-64 --output -
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock -p linux-64 --format spdx --spec-version 3.0 --output -
```

See [Using pixi-sbom without pixi](without-pixi.md) for what each reader takes from its lockfile.

## A requirements file that is not a lock

A `requirements.txt` is only a lock when every line is one version. Each project in
`requirements-unpinned/` fails in a different way, and pixi-sbom refuses each one, naming the first
line that isn't one version:

```sh
pixi sbom --lockfile examples/projects/requirements-unpinned/01-loose-ranges/requirements.txt --output -   # exit 1
pixi sbom --lockfile examples/projects/requirements-unpinned/03-one-loose-line/requirements.txt --output -   # exit 1
pixi sbom --lockfile examples/projects/requirements-unpinned/05-wildcard-pins/requirements.txt --output -   # exit 1
```

The third one is the subtle one: `Django==4.2.*` looks pinned and is any 4.2 release. See
[Reading a pinned requirements.txt](cli.md#reading-a-pinned-requirementstxt).

## Every environment of a pixi workspace

`pixi/01-django` has a default environment and one each for its `s3` extra and its `dev` and `test`
groups. `--all-environments` writes one document each into a directory:

```sh
pixi sbom --lockfile examples/projects/pixi/01-django/pixi.lock -p linux-64 --all-environments --output sboms/
```

See [One document per environment and platform](cli.md#one-document-per-environment-and-platform).

## Where a fact came from

`internal-utils` is a local package installed in editable mode. `--explain` shows what pixi-sbom
knows about it and what it deliberately doesn't ask an index about:

```sh
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock -p linux-64 --explain internal-utils
```

## Before and after an upgrade

`14-django-upgraded` is `01-django` moved to Django 4.2 LTS:

```sh
pixi sbom --lockfile examples/projects/uv/14-django-upgraded/uv.lock -p linux-64 --report diff --against examples/projects/uv/01-django/uv.lock
```

See [Looking instead of writing](cli.md#looking-instead-of-writing).

## Vulnerabilities, and which to fix first

`02-flask` has several findings. CISA KEV marks the ones being exploited now, and FIRST EPSS scores
how likely the rest are to be exploited:

```sh
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock -p linux-64 --vulnerabilities osv --kev --epss --report vulnerabilities   # needs the network
```

The same findings as a CI gate. The document is still written, and the run exits 4:

```sh
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock -p linux-64 --vulnerabilities osv --fail-on-severity high --output -   # needs the network
```

`08-cli-tool` has none, which is the answer a clean project gets:

```sh
pixi sbom --lockfile examples/projects/uv/08-cli-tool/uv.lock -p linux-64 --vulnerabilities osv --report vulnerabilities   # needs the network
```

See [Looking up vulnerabilities](cli.md#looking-up-vulnerabilities).

## A license gate

`07-web-scraping` depends on `html2text`, which is GPL-3.0. Its wheel doesn't say so in a form a policy
can match: it declares the free text `GNU GPL 3`. A deny list matches SPDX ids, so on its own it
passes this project:

```sh
pixi sbom --lockfile examples/projects/uv/07-web-scraping/uv.lock -p linux-64 --fetch-licenses --deny-license GPL-3.0-only --deny-license GPL-3.0-or-later --output -   # needs the network
```

`--require-license` closes that gap: a license that isn't an SPDX expression becomes a violation. The
run names html2text and exits 3:

```sh
pixi sbom --lockfile examples/projects/uv/07-web-scraping/uv.lock -p linux-64 --fetch-licenses --deny-license GPL-3.0-only --deny-license GPL-3.0-or-later --require-license --output -   # needs the network
```

See [Enforcing a license policy](cli.md#enforcing-a-license-policy).

## How far behind

`04-data-analysis` pins a scientific stack well behind its newest releases:

```sh
pixi sbom --lockfile examples/projects/poetry/04-data-analysis/poetry.lock -p linux-64 --report outdated   # needs the network
```

See [How far behind the environment is](cli.md#how-far-behind-the-environment-is).

## Someone else's SBOM

Make two documents, then treat them as if a vendor had sent them: grade one, and merge both into one
document for the product:

```sh
pixi sbom --lockfile examples/projects/uv/01-django/uv.lock -p linux-64 --output app.cdx.json
pixi sbom --lockfile examples/projects/requirements/12-aws-cloud/requirements.txt --format spdx --output vendor.spdx.json
pixi sbom --from-sbom vendor.spdx.json --report quality
pixi sbom --from-sbom app.cdx.json --from-sbom vendor.spdx.json --root-name product --report packages
```

See [How complete the document is](cli.md#how-complete-the-document-is) and
[Merging documents](cli.md#merging-documents).

## The whole tree at once

`--scan` finds every project with a lockfile of a fixed name under a directory: the pixi, uv,
Poetry, PDM, pylock and conda-lock examples, 84 in all. Explicit specs and requirements files have
no fixed name, so a scan doesn't pick them up.

```sh
pixi sbom --scan examples/projects -p linux-64 --report packages
```

See [A monorepo: every workspace in one run](cli.md#a-monorepo-every-workspace-in-one-run).

## What changes from day to day

The lockfiles don't change, so anything read from them doesn't either: the packages, the graph, the
diff and the refusals. Anything looked up online does. New advisories are published every day,
EPSS scores are recomputed daily, and the indexes keep releasing. The vulnerability counts and the
outdated report you see will drift from what anyone saw before you, and that's the tool working.
