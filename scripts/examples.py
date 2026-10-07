"""Regenerate examples/projects: one small project per scenario for every non-pixi reader (#362).

Run it as `pixi run examples` (or `pixi run -e examples python scripts/examples.py --help`). The
scenarios live in examples/scenarios.toml; this writes each reader's manifest from them and then
runs the reader's own tool to lock it, so every lockfile under examples/projects is one that tool
really wrote. pixi-sbom never resolves anything, so neither does this script: the tools do.

The standard library only, like the other scripts here: this is one helper beside a Rust project.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
SCENARIOS = EXAMPLES / "scenarios.toml"
PROJECTS = EXAMPLES / "projects"
LOCAL_LIB = EXAMPLES / "shared" / "internal-utils"

READERS = ("pylock", "uv", "poetry", "pdm", "conda-lock", "conda-explicit")
CONDA_PLATFORMS = ("linux-64", "osx-arm64")
# The examples' Python floor. A scenario that shows old, vulnerable pins may declare an older one
# (`python` / `conda_python`), because those releases only have wheels for the Pythons of their day.
PYTHON = ">=3.14"
CONDA_PYTHON = "3.14"


def toml_string(value: str) -> str:
    """A TOML basic string."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def toml_list(values: list[str], indent: str = "    ") -> str:
    """A multi-line TOML array of strings, or `[]`."""
    if not values:
        return "[]"
    lines = "".join(f"{indent}{toml_string(v)},\n" for v in values)
    return f"[\n{lines}]"


def requires_python(scenario: dict, reader: str) -> str:
    """The `requires-python` a reader's manifest declares. Poetry insists every dependency supports
    the whole range, so a Poetry project caps it the way Poetry projects do (`<4`), or narrower where
    a scenario says so (`poetry_python`)."""
    declared = scenario.get("python", PYTHON)
    if reader != "poetry":
        return declared
    if "poetry_python" in scenario:
        return scenario["poetry_python"]
    return declared if "<" in declared else f"{declared},<4"


def project_table(scenario: dict, reader: str = "uv") -> str:
    """The PEP 621 `[project]` table every Python reader shares."""
    out = [
        "[project]",
        f"name = {toml_string(scenario['id'].split('-', 1)[1] + '-example')}",
        'version = "0.1.0"',
        f"description = {toml_string(scenario['title'])}",
        f"requires-python = {toml_string(requires_python(scenario, reader))}",
        f"dependencies = {toml_list(scenario.get('dependencies', []))}",
    ]
    extras = scenario.get("optional", {})
    if extras:
        out.append("")
        out.append("[project.optional-dependencies]")
        for name, deps in extras.items():
            out.append(f"{name} = {toml_list(deps)}")
    return "\n".join(out) + "\n"


def dependency_groups(groups: dict[str, list[str]]) -> str:
    """PEP 735 `[dependency-groups]`, as uv and PDM read them."""
    if not groups:
        return ""
    lines = ["", "[dependency-groups]"]
    lines += [f"{name} = {toml_list(deps)}" for name, deps in groups.items()]
    return "\n".join(lines) + "\n"


def poetry_groups(groups: dict[str, list[str]]) -> str:
    """Poetry's own `[tool.poetry.group.<name>.dependencies]`, which is how Poetry projects declare
    groups in practice. Each requirement is PEP 508; Poetry takes the version part as a constraint.
    """
    lines: list[str] = []
    for name, deps in groups.items():
        lines += ["", f"[tool.poetry.group.{name}.dependencies]"]
        for dep in deps:
            if " @ git+" in dep:
                name, url = (part.strip() for part in dep.split(" @ git+", 1))
                repo, _, rev = url.rpartition("@")
                lines.append(f"{toml_key(name)} = {{ git = {toml_string(repo)}, rev = {toml_string(rev)} }}")
                continue
            requirement, version = split_requirement(dep)
            lines.append(f"{toml_key(requirement)} = {toml_string(version or '*')}")
    return "\n".join(lines) + "\n" if lines else ""


def split_requirement(dep: str) -> tuple[str, str]:
    """`name[extra]==1.0` into (`name[extra]`, `==1.0`); a bare name has no version part."""
    for i, char in enumerate(dep):
        if char in "<>=!~ ;":
            return dep[:i].strip(), dep[i:].split(";")[0].strip()
    return dep.strip(), ""


def toml_key(name: str) -> str:
    """A TOML key, quoted only when it has to be."""
    bare = all(c.isalnum() or c in "-_" for c in name)
    return name if bare else toml_string(name)


def python_floor(scenario: dict) -> str:
    """The lowest Python the Python readers' manifest allows, as `3.11`: what Poetry has to run on."""
    for clause in scenario.get("python", PYTHON).split(","):
        clause = clause.strip()
        if clause.startswith(">="):
            return ".".join(clause[2:].split(".")[:2])
    raise ValueError(f"{scenario['id']}: no lower bound in {scenario.get('python')!r}")


def local_dependency(reader: str) -> tuple[str, str]:
    """How each reader's manifest declares the shared local package: (dependency line, extra TOML)."""
    rel = "libs/internal-utils"
    if reader in ("uv", "pylock"):
        return "internal-utils", f'\n[tool.uv.sources]\ninternal-utils = {{ path = "{rel}", editable = true }}\n'
    if reader == "pdm":
        return f"internal-utils @ file:///${{PROJECT_ROOT}}/{rel}", ""
    if reader == "poetry":
        # Poetry 2 reads [project.dependencies]; the tool table only says where that name comes from.
        return "internal-utils", f'\n[tool.poetry.dependencies]\ninternal-utils = {{ path = "{rel}", develop = true }}\n'
    raise ValueError(f"{reader} has no local path dependencies")


def pyproject(scenario: dict, reader: str) -> str:
    """The `pyproject.toml` one Python reader's tool locks."""
    scenario = dict(scenario)
    extra = ""
    if scenario.get("local"):
        line, extra = local_dependency(reader)
        if line:
            scenario["dependencies"] = [*scenario.get("dependencies", []), line]
    groups = scenario.get("groups", {})
    body = project_table(scenario, reader)
    body += poetry_groups(groups) if reader == "poetry" else dependency_groups(groups)
    body += extra
    if reader == "poetry":
        body += '\n[tool.poetry]\npackage-mode = false\n'
    return body


def environment_yml(scenario: dict, with_pip: bool) -> str:
    """A conda `environment.yml`: conda-forge only, the scenario's Python, and a pip section when asked."""
    lines = [
        f"name: {scenario['id']}",
        "channels:",
        "  - conda-forge",
        "dependencies:",
        f"  - python={scenario.get('conda_python', CONDA_PYTHON)}",
    ]
    lines += [f"  - {spec}" for spec in scenario.get("conda", [])]
    pip = scenario.get("conda_pip", []) if with_pip else []
    if pip:
        lines += ["  - pip", "  - pip:"]
        lines += [f"      - {spec}" for spec in pip]
    lines += ["platforms:"] + [f"  - {p}" for p in CONDA_PLATFORMS]
    return "\n".join(lines) + "\n"


def tool_env(venv: Path | None = None, base: dict[str, str] | None = None) -> dict[str, str]:
    """The environment a tool runs in. With `venv`, that virtualenv is active, which is how Poetry
    is told which Python the project is locked for."""
    env = {
        **(os.environ if base is None else base),
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PDM_CHECK_UPDATE": "false",
        # Poetry's virtualenv for a scenario lives in Poetry's cache, never in the example itself.
        "POETRY_VIRTUALENVS_IN_PROJECT": "false",
    }
    if venv:
        # Poetry treats pixi's own environment (CONDA_PREFIX) as active unless told otherwise, and
        # remembers per-project virtualenvs in its cache; a private cache path keeps those out.
        env.pop("CONDA_PREFIX", None)
        env["VIRTUAL_ENV"] = str(venv)
        env["POETRY_VIRTUALENVS_PATH"] = str(venv.parent / "poetry-virtualenvs")
        bindir = venv / ("Scripts" if os.name == "nt" else "bin")
        env["PATH"] = f"{bindir}{os.pathsep}{env.get('PATH', '')}"
    return env


def run(command: list[str], cwd: Path, venv: Path | None = None) -> None:
    """Run one tool command, failing loudly with its output."""
    sys.stderr.write(f"  $ {' '.join(command)}\n")
    env = tool_env(venv)
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed in {cwd}:\n{result.stdout}\n{result.stderr}")


def interpreter(version: str) -> str:
    """A CPython of `version` (e.g. "3.11"), found or downloaded by uv. Poetry will not lock a
    project whose requires-python excludes the python it finds, so it is given one that matches the
    scenario rather than the 3.13 the tools themselves run on."""
    run(["uv", "python", "install", "--quiet", version], ROOT)
    found = subprocess.run(["uv", "python", "find", version], capture_output=True, text=True, check=True)
    return found.stdout.strip()


def pip_python() -> Path:
    """The examples-pip environment's interpreter. `pip lock` locks for the Python running it, so it
    is called by path: a nested `pixi run` inherits the outer environment and finds 3.13 without pip."""
    run(["pixi", "install", "--manifest-path", str(ROOT / "pixi.toml"), "-e", "examples-pip"], ROOT)
    env = ROOT / ".pixi" / "envs" / "examples-pip"
    return env / "python.exe" if os.name == "nt" else env / "bin" / "python"


def fresh(directory: Path) -> Path:
    """Empty `directory` (it is generated output) and return it."""
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    return directory


def with_local_lib(directory: Path) -> None:
    shutil.copytree(LOCAL_LIB, directory / "libs" / "internal-utils")


def generate(scenario: dict, reader: str) -> Path:
    """Write and lock one example; returns its directory."""
    target = fresh(PROJECTS / reader / scenario["id"])
    python_reader = reader in ("pylock", "uv", "poetry", "pdm")
    if python_reader and scenario.get("local"):
        with_local_lib(target)

    if reader == "uv":
        (target / "pyproject.toml").write_text(pyproject(scenario, reader))
        run(["uv", "lock", "--quiet"], target)
    elif reader == "pylock":
        (target / "pyproject.toml").write_text(pyproject(scenario, reader))
        if scenario.get("pylock_tool") == "pip":
            if "python" in scenario:
                raise ValueError(f"{scenario['id']}: pip lock locks for Python {CONDA_PYTHON}; use uv export for an older floor")
            # pip locks for the interpreter running it, so it runs on the examples' own Python.
            run([str(pip_python()), "-m", "pip", "lock", "--quiet", "-o", "pylock.toml", "."], target)
            # pip builds the project's own metadata with setuptools to lock it; that is not part of it.
            for leftover in [*target.glob("*.egg-info"), target / "build"]:
                shutil.rmtree(leftover, ignore_errors=True)
        else:
            run(["uv", "lock", "--quiet"], target)
            run(
                ["uv", "export", "--quiet", "--frozen", "--all-groups", "--all-extras",
                 "--format", "pylock.toml", "-o", "pylock.toml"],
                target,
            )
            (target / "uv.lock").unlink()
    elif reader == "poetry":
        (target / "pyproject.toml").write_text(pyproject(scenario, reader))
        # Poetry will not lock a project whose requires-python excludes the Python it sees, and its
        # own `env use` builds the virtualenv on the Python Poetry runs on. So it is handed a
        # throwaway virtualenv built here on the scenario's Python, already active.
        python = interpreter(python_floor(scenario))
        with tempfile.TemporaryDirectory() as scratch:
            venv = Path(scratch) / "venv"
            run([python, "-m", "venv", str(venv)], target)
            run(["poetry", "lock", "--no-interaction"], target, venv=venv)
    elif reader == "pdm":
        (target / "pyproject.toml").write_text(pyproject(scenario, reader))
        # A scenario may narrow the range PDM locks for: PDM refuses a dependency that excludes a
        # single patch release of the declared floor (networkx needs !=3.14.1), where uv forks.
        target_python = ["--python", scenario["pdm_python"]] if "pdm_python" in scenario else []
        run(["pdm", "lock", "--group", ":all", *target_python], target)
        # PDM makes a virtualenv to lock in, and remembers its interpreter; neither belongs in an example.
        shutil.rmtree(target / ".venv", ignore_errors=True)
        (target / ".pdm-python").unlink(missing_ok=True)
    elif reader == "conda-lock":
        (target / "environment.yml").write_text(environment_yml(scenario, with_pip=True))
        run(["conda-lock", "lock", "--micromamba", "--file", "environment.yml", "--lockfile", "conda-lock.yml"], target)
    elif reader == "conda-explicit":
        # An explicit spec cannot carry pip packages, so this environment is the conda part only.
        (target / "environment.yml").write_text(environment_yml(scenario, with_pip=False))
        with tempfile.TemporaryDirectory() as scratch:
            lock = Path(scratch) / "conda-lock.yml"
            run(
                ["conda-lock", "lock", "--micromamba", "--file", str(target / "environment.yml"), "--lockfile", str(lock)],
                target,
            )
            run(
                ["conda-lock", "render", "--kind", "explicit",
                 "--filename-template", "explicit-{platform}.txt", str(lock)],
                target,
            )
    else:
        raise ValueError(f"unknown reader {reader}")
    return target


def load(path: Path = SCENARIOS) -> list[dict]:
    return tomllib.loads(path.read_text())["scenario"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reader", action="append", choices=READERS, help="only these readers (repeatable)")
    parser.add_argument("--scenario", action="append", help="only these scenario ids, e.g. 01-django (repeatable)")
    args = parser.parse_args()

    scenarios = [s for s in load() if not args.scenario or s["id"] in args.scenario]
    readers = args.reader or list(READERS)
    failures = []
    for scenario in scenarios:
        for reader in readers:
            if reader not in scenario.get("readers", READERS):
                continue
            sys.stderr.write(f"{reader}/{scenario['id']}\n")
            try:
                generate(scenario, reader)
            except RuntimeError as err:
                failures.append(str(err))
                sys.stderr.write(f"  FAILED\n{err}\n")
    if failures:
        sys.stderr.write(f"{len(failures)} example(s) failed\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
