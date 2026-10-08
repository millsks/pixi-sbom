# Lockfile routes

What each common setup's own tool writes, captured from real runs for #389, one per row of the "Getting a
lockfile" table in `docs/without-pixi.md`. `tests/cli.rs` reads each one.

| File | Written by |
|---|---|
| `pylock.pip-tools.toml` | `pip-compile --generate-hashes requirements.in -o requirements.txt`, then `uv pip compile requirements.txt -o pylock.toml` |
| `pylock.pipenv.toml` | `pipenv install requests==2.32.3`, `pipenv requirements > requirements.txt`, then `uv pip compile requirements.txt -o pylock.toml` |
| `requirements.txt` | `pip-compile --generate-hashes --strip-extras requirements.in -o requirements.txt` (pip-tools 7.6), read directly (#393) |
| `pylock.pip.toml` | `pip lock -r requirements.in -o pylock.toml` (pip 26) |
| `explicit-micromamba.txt` | `micromamba env export -p <env> --explicit --md5` (micromamba 1.5.12; 2.9.0 writes the same packages) |
| `explicit-conda.txt` | `conda list -p <env> --explicit --md5`, on the same environment |
| `conda-lock.yml` | `conda-lock -f environment.yml -p linux-64 -p osx-arm64` (conda-lock 4.0) |
| `conda-linux-64.lock` | `conda-lock render --kind explicit -p linux-64 conda-lock.yml` |

`requirements.in` was `requests>=2.31`; the environments were `python=3.12 requests` from conda-forge.
