# A project without pixi

**When:** the project uses uv, Poetry, PDM, conda-lock, pip or a plain venv, and you want its SBOM without
adopting pixi.

pixi-sbom needs nothing from pixi. Install it from PyPI and point it at the lockfile your tool already writes:

```sh
uvx pixi-sbom --lockfile uv.lock
```

## Which file to give it

| The project has | Give it | Notes |
|---|---|---|
| `uv.lock` | `uv.lock` | found by the upward search |
| `poetry.lock`, `pdm.lock` | that file | found by the upward search |
| `pylock.toml` | that file | `pip lock` and `uv export --format pylock.toml` write one |
| `conda-lock.yml` | that file | one document per platform |
| `requirements.txt` with `==` on every line | that file, with `--lockfile` | pip-compile and `uv pip compile` write one |
| `requirements.txt` with ranges | nothing yet | pin it first: `uv pip compile requirements.txt -o requirements.lock.txt` |
| only `pyproject.toml` or `environment.yml` | nothing yet | lock it with the project's tool; pixi-sbom names the command |
| a virtualenv, no lockfile | `--prefix .venv` | what is installed, not what was asked for |

pixi-sbom never resolves: given a manifest or a list of ranges, it refuses and names the command that makes a
lock. A requirements file with one unpinned line is refused at that line.

## Check it reads what you think

```sh
pixi sbom --lockfile requirements.txt --report packages
```

The summary line counts the packages, and how many the project declared itself. For a uv, Poetry or PDM project,
the declared ones come from `pyproject.toml` beside the lockfile; dependency groups and extras become CycloneDX
`scope` and SPDX dev/optional relationships.

## In CI and before a commit

The action takes the same lockfile (`lockfile: uv.lock`) on a runner with no pixi, and a pre-commit hook keeps an
SBOM next to the lockfile. See [Using pixi-sbom without pixi](../without-pixi.md) for every reader, the tools that
write each lockfile, and what works with which input.
