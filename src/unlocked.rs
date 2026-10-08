//! Files that declare what a project wants without locking it: `pyproject.toml`, `pixi.toml`,
//! `environment.yml`, `conda env export` output, a `Pipfile`. pixi-sbom never resolves, so it
//! cannot read them as input, but it can say which command turns each one into a lock it reads,
//! for the file given to `--lockfile` and for the manifest the upward search found without a
//! lockfile beside it.

use std::path::{Path, PathBuf};

use miette::Diagnostic;
use thiserror::Error;

/// A file given as `--lockfile` that declares rather than locks.
#[derive(Debug, Error, Diagnostic)]
#[error("{path} is {what}, not a lock: pixi-sbom reads a lockfile and never resolves one")]
#[diagnostic(code(pixi_sbom::input::not_a_lock), help("{next}"))]
pub struct NotALock {
    pub path: String,
    /// What the file is: "a Poetry project's pyproject.toml".
    pub what: String,
    /// The command that makes a lock of it, and what to pass then.
    pub next: String,
}

/// The manifests the upward search looks for when it finds no lockfile, nearest first within a
/// directory.
const MANIFESTS: [&str; 7] = [
    "pixi.toml",
    "pyproject.toml",
    "environment.yml",
    "environment.yaml",
    "Pipfile",
    "Pipfile.lock",
    "setup.py",
];

/// What `path` is and how to lock it, when it is one of the files this module knows.
pub fn diagnose(path: &Path) -> Option<NotALock> {
    let name = path.file_name()?.to_str()?;
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let (what, next) = match name {
        "pixi.toml" => (
            "a pixi workspace manifest".to_string(),
            "run `pixi lock` beside it, then pass pixi.lock (or leave --lockfile out)".to_string(),
        ),
        "pyproject.toml" => pyproject(&text),
        "Pipfile" | "Pipfile.lock" => (
            format!("Pipenv's {name}"),
            "Pipenv's files are not read: run `pipenv requirements > requirements.txt` and `uv pip compile \
             requirements.txt -o pylock.toml`, then pass pylock.toml; or describe the virtualenv itself with \
             `--prefix $(pipenv --venv)`"
                .to_string(),
        ),
        "setup.py" | "setup.cfg" => (
            format!("a setuptools {name}"),
            format!("run `uv pip compile {name} -o pylock.toml`, then pass pylock.toml"),
        ),
        _ if is_conda_env_export(&text) => (
            "`conda env export` output, which pins versions but not builds or URLs".to_string(),
            "run `conda list --explicit --md5 > explicit.txt` in that environment, then pass explicit.txt; or \
             `--prefix` on the environment"
                .to_string(),
        ),
        _ if name.ends_with(".yml") || name.ends_with(".yaml") => {
            if !is_environment_yml(&text) {
                return None;
            }
            (
                "a conda environment.yml".to_string(),
                format!(
                    "run `conda-lock -f {name} -p linux-64` (with every platform you need), then pass \
                     conda-lock.yml; or `conda list --explicit --md5` in the created environment"
                ),
            )
        }
        _ => return None,
    };
    Some(NotALock {
        path: path.display().to_string(),
        what,
        next,
    })
}

/// A `pyproject.toml`: which tool's project it is, by its `[tool.*]` tables.
fn pyproject(text: &str) -> (String, String) {
    let tool = |name: &str| {
        text.lines()
            .any(|line| line.trim_start().starts_with(&format!("[tool.{name}")))
    };
    if tool("pixi") {
        return (
            "a pixi workspace's manifest".to_string(),
            "run `pixi lock` beside it, then pass pixi.lock (or leave --lockfile out)".to_string(),
        );
    }
    for (name, tool_name, lock) in [
        ("poetry", "Poetry", "poetry.lock"),
        ("pdm", "PDM", "pdm.lock"),
        ("uv", "uv", "uv.lock"),
    ] {
        if tool(name) {
            return (
                format!("a {tool_name} project's manifest"),
                format!("run `{name} lock` beside it, then pass {lock} (or leave --lockfile out)"),
            );
        }
    }
    (
        "a Python project's manifest".to_string(),
        "run your project's tool beside it: `uv lock` (uv.lock), `poetry lock` (poetry.lock) or `pdm lock` (pdm.lock); \
         then pass the lockfile, or leave --lockfile out"
            .to_string(),
    )
}

/// `conda env export` writes `name`, `channels`, `dependencies` with `pkg=version=build` pins, and
/// the environment's `prefix:`.
fn is_conda_env_export(text: &str) -> bool {
    is_environment_yml(text) && text.lines().any(|line| line.starts_with("prefix:"))
}

fn is_environment_yml(text: &str) -> bool {
    text.lines().any(|line| line.trim_end() == "dependencies:")
}

/// The nearest manifest at or above `start` that this module can say how to lock, for the upward
/// search that found no lockfile.
pub fn nearest_manifest(start: &Path) -> Option<(PathBuf, NotALock)> {
    start.ancestors().find_map(|dir| {
        MANIFESTS.iter().find_map(|name| {
            let path = dir.join(name);
            if !path.is_file() {
                return None;
            }
            diagnose(&path).map(|found| (path, found))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn each_kind_of_unlocked_file_is_named_with_its_lock_command() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for (name, text, what, command) in [
            ("pixi.toml", "[workspace]\n", "pixi workspace manifest", "pixi lock"),
            (
                "pyproject.toml",
                "[project]\n[tool.poetry]\n",
                "Poetry project",
                "poetry lock",
            ),
            (
                "pyproject.toml",
                "[tool.pdm.dev-dependencies]\n",
                "PDM project",
                "pdm lock",
            ),
            ("pyproject.toml", "[tool.uv]\n", "uv project", "uv lock"),
            (
                "pyproject.toml",
                "[tool.pixi.workspace]\n",
                "pixi workspace's manifest",
                "pixi lock",
            ),
            (
                "pyproject.toml",
                "[project]\nname = \"x\"\n",
                "Python project's manifest",
                "`uv lock` (uv.lock), `poetry lock`",
            ),
            ("Pipfile", "[packages]\n", "Pipenv's Pipfile", "pipenv requirements"),
            (
                "Pipfile.lock",
                "{}",
                "Pipenv's Pipfile.lock",
                "--prefix $(pipenv --venv)",
            ),
            ("setup.py", "", "setuptools setup.py", "uv pip compile setup.py"),
            (
                "environment.yml",
                "name: x\ndependencies:\n  - python=3.12\n",
                "conda environment.yml",
                "conda-lock -f environment.yml",
            ),
            (
                "env.yaml",
                "name: x\nchannels:\n  - conda-forge\ndependencies:\n  - python=3.12.1=h1\nprefix: /opt/conda/envs/x\n",
                "conda env export",
                "conda list --explicit --md5",
            ),
        ] {
            let path = write(d, name, text);
            let found = diagnose(&path).unwrap_or_else(|| panic!("{name}: {text}"));
            assert!(found.what.contains(what), "{name}: {}", found.what);
            assert!(found.next.contains(command), "{name}: {}", found.next);
        }
        assert!(
            diagnose(&write(d, "config.yml", "key: value\n")).is_none(),
            "YAML that is not an environment"
        );
        assert!(diagnose(&write(d, "notes.txt", "hello\n")).is_none());
        let message = diagnose(&write(d, "pixi.toml", "")).unwrap().to_string();
        assert!(message.contains("not a lock"), "{message}");
    }

    #[test]
    fn the_nearest_manifest_is_found_upward() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        assert!(nearest_manifest(&nested).is_none() || !nearest_manifest(&nested).unwrap().0.starts_with(dir.path()));
        write(dir.path(), "pyproject.toml", "[tool.poetry]\n");
        write(&dir.path().join("a"), "environment.yml", "dependencies:\n  - numpy\n");
        let (path, found) = nearest_manifest(&nested).unwrap();
        assert_eq!(path, dir.path().join("a/environment.yml"), "the nearer one");
        assert!(found.next.contains("conda-lock"));
    }
}
