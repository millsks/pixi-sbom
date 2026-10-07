"""Tests for the example generator's manifest rendering.

Run with `pixi run -e examples examples-test`. The standard library only, like the generator. What
is tested is what each reader's tool is handed: a manifest the tool misreads produces a lockfile
that looks real and describes the wrong project, which is the one failure nobody would notice.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import examples

SCENARIO = {
    "id": "01-django",
    "title": "Django web application",
    "python": ">=3.11,<3.12",
    "conda_python": "3.11",
    "dependencies": ["Django[argon2]==3.2.12", "sqlparse==0.4.2"],
    "optional": {"s3": ["django-storages[s3]==1.13.2"]},
    "groups": {
        "dev": ["django-debug-toolbar @ git+https://github.com/django-commons/django-debug-toolbar@3.2.4"],
        "test": ["pytest-django==4.5.2"],
    },
    "local": True,
    "conda": ["django=3.2.12", "sqlparse=0.4.2"],
    "conda_pip": ["django-environ==0.9.0"],
}


def parsed(reader: str, scenario: dict = SCENARIO) -> dict:
    return tomllib.loads(examples.pyproject(scenario, reader))


class PyprojectTest(unittest.TestCase):
    def test_every_python_reader_gets_valid_toml_with_the_scenarios_floor(self) -> None:
        for reader in ("pylock", "uv", "poetry", "pdm"):
            project = parsed(reader)["project"]
            self.assertEqual(project["name"], "django-example", reader)
            self.assertEqual(project["requires-python"], ">=3.11,<3.12", reader)
            self.assertIn("Django[argon2]==3.2.12", project["dependencies"], reader)
            self.assertEqual(project["optional-dependencies"], {"s3": ["django-storages[s3]==1.13.2"]}, reader)

    def test_poetry_caps_an_open_ended_range(self) -> None:
        open_ended = {**SCENARIO, "python": ">=3.14"}
        self.assertEqual(parsed("poetry", open_ended)["project"]["requires-python"], ">=3.14,<4")
        self.assertEqual(parsed("uv", open_ended)["project"]["requires-python"], ">=3.14")
        self.assertEqual(parsed("poetry")["project"]["requires-python"], ">=3.11,<3.12", "already capped")
        narrowed = {**open_ended, "poetry_python": ">=3.14,<3.15"}
        self.assertEqual(parsed("poetry", narrowed)["project"]["requires-python"], ">=3.14,<3.15")
        self.assertEqual(parsed("pdm", narrowed)["project"]["requires-python"], ">=3.14")

    def test_the_default_floor_is_3_14(self) -> None:
        plain = {k: v for k, v in SCENARIO.items() if k not in ("python", "conda_python")}
        self.assertEqual(parsed("uv", plain)["project"]["requires-python"], ">=3.14")
        self.assertIn("python=3.14", examples.environment_yml(plain, with_pip=False))

    def test_uv_and_pdm_use_pep_735_groups(self) -> None:
        for reader in ("uv", "pdm"):
            groups = parsed(reader)["dependency-groups"]
            self.assertEqual(groups["test"], ["pytest-django==4.5.2"], reader)
            self.assertTrue(groups["dev"][0].startswith("django-debug-toolbar @ git+"), reader)

    def test_poetry_uses_its_own_group_tables_and_git_sources(self) -> None:
        doc = parsed("poetry")
        self.assertNotIn("dependency-groups", doc)
        groups = doc["tool"]["poetry"]["group"]
        self.assertEqual(groups["test"]["dependencies"], {"pytest-django": "==4.5.2"})
        self.assertEqual(
            groups["dev"]["dependencies"]["django-debug-toolbar"],
            {"git": "https://github.com/django-commons/django-debug-toolbar", "rev": "3.2.4"},
        )
        self.assertFalse(doc["tool"]["poetry"]["package-mode"])

    def test_each_reader_points_at_the_local_package_its_own_way(self) -> None:
        uv = parsed("uv")
        self.assertIn("internal-utils", uv["project"]["dependencies"])
        self.assertEqual(uv["tool"]["uv"]["sources"]["internal-utils"], {"path": "libs/internal-utils", "editable": True})

        poetry = parsed("poetry")
        self.assertIn("internal-utils", poetry["project"]["dependencies"])
        self.assertEqual(
            poetry["tool"]["poetry"]["dependencies"]["internal-utils"],
            {"path": "libs/internal-utils", "develop": True},
        )

        pdm = parsed("pdm")["project"]["dependencies"]
        self.assertIn("internal-utils @ file:///${PROJECT_ROOT}/libs/internal-utils", pdm)

        with self.assertRaises(ValueError):
            examples.local_dependency("conda-lock")

    def test_a_scenario_without_a_local_package_names_none(self) -> None:
        plain = {k: v for k, v in SCENARIO.items() if k != "local"}
        self.assertNotIn("internal-utils", examples.pyproject(plain, "uv"))


class PythonFloorTest(unittest.TestCase):
    def test_poetry_runs_on_the_python_readers_floor_not_the_conda_one(self) -> None:
        self.assertEqual(examples.python_floor(SCENARIO), "3.11")
        self.assertEqual(examples.python_floor({"id": "x", "conda_python": "3.12"}), "3.14")
        self.assertEqual(examples.python_floor({"id": "x", "python": ">=3.14,!=3.14.1,<3.15"}), "3.14")
        with self.assertRaises(ValueError):
            examples.python_floor({"id": "x", "python": "<3.15"})


class RequirementTest(unittest.TestCase):
    def test_split_requirement(self) -> None:
        self.assertEqual(examples.split_requirement("Django[argon2]==3.2.12"), ("Django[argon2]", "==3.2.12"))
        self.assertEqual(examples.split_requirement("ruff>=0.6"), ("ruff", ">=0.6"))
        self.assertEqual(examples.split_requirement("attrs"), ("attrs", ""))
        self.assertEqual(examples.split_requirement('tomli>=2; python_version < "3.11"'), ("tomli", ">=2"))

    def test_toml_key_quotes_only_when_needed(self) -> None:
        self.assertEqual(examples.toml_key("pytest-django"), "pytest-django")
        self.assertEqual(examples.toml_key("uvicorn[standard]"), '"uvicorn[standard]"')


class ToolEnvTest(unittest.TestCase):
    def test_a_venv_is_activated_in_place_of_pixis_environment(self) -> None:
        base = {"PATH": "/usr/bin", "CONDA_PREFIX": "/repo/.pixi/envs/examples"}
        env = examples.tool_env(Path("/tmp/x/venv"), base)
        self.assertNotIn("CONDA_PREFIX", env, "Poetry would take pixi's environment as the active one")
        self.assertEqual(env["VIRTUAL_ENV"], "/tmp/x/venv")
        self.assertTrue(env["PATH"].startswith(str(Path("/tmp/x/venv") / ("Scripts" if examples.os.name == "nt" else "bin"))))
        self.assertEqual(env["POETRY_VIRTUALENVS_PATH"], str(Path("/tmp/x/poetry-virtualenvs")))

    def test_without_a_venv_the_environment_is_left_alone(self) -> None:
        base = {"PATH": "/usr/bin", "CONDA_PREFIX": "/repo/.pixi/envs/examples"}
        env = examples.tool_env(None, base)
        self.assertEqual(env["CONDA_PREFIX"], base["CONDA_PREFIX"])
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertNotIn("VIRTUAL_ENV", env)
        self.assertEqual(env["PDM_CHECK_UPDATE"], "false")


class EnvironmentTest(unittest.TestCase):
    def test_conda_lock_gets_the_pip_section_and_explicit_does_not(self) -> None:
        with_pip = examples.environment_yml(SCENARIO, with_pip=True)
        without = examples.environment_yml(SCENARIO, with_pip=False)
        for text in (with_pip, without):
            self.assertIn("  - python=3.11\n", text)
            self.assertIn("  - django=3.2.12\n", text)
            self.assertIn("  - conda-forge\n", text)
            self.assertIn("platforms:\n  - linux-64\n  - osx-arm64\n", text)
        self.assertIn("      - django-environ==0.9.0\n", with_pip)
        self.assertNotIn("pip", without)


class ScenarioFileTest(unittest.TestCase):
    def test_every_scenario_is_complete_and_uniquely_named(self) -> None:
        scenarios = examples.load()
        ids = [s["id"] for s in scenarios]
        self.assertEqual(len(ids), len(set(ids)))
        for scenario in scenarios:
            for key in ("id", "title", "shows", "dependencies", "conda"):
                self.assertIn(key, scenario, scenario["id"])
            # pip lock locks for the interpreter it runs on, which is the examples' 3.14.
            if scenario.get("pylock_tool") == "pip":
                self.assertNotIn("python", scenario, scenario["id"])
            tomllib.loads(examples.pyproject(scenario, "uv"))
            tomllib.loads(examples.pyproject(scenario, "poetry"))

    def test_pip_lock_refuses_an_older_floor(self) -> None:
        scenario = {**SCENARIO, "id": "99-test", "pylock_tool": "pip", "local": False}
        original = examples.PROJECTS
        examples.PROJECTS = Path(examples.tempfile.mkdtemp())
        try:
            with self.assertRaises(ValueError):
                examples.generate(scenario, "pylock")
        finally:
            examples.shutil.rmtree(examples.PROJECTS)
            examples.PROJECTS = original


if __name__ == "__main__":
    unittest.main()
