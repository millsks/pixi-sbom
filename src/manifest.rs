//! Reads workspace name/version from the pixi manifest next to the lockfile.

use std::path::Path;

use serde::Deserialize;

use crate::model::Root;

#[derive(Debug, Default, Deserialize)]
struct NameVersion {
    name: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PixiToml {
    workspace: Option<NameVersion>,
    project: Option<NameVersion>,
}

#[derive(Debug, Default, Deserialize)]
struct PyprojectToml {
    project: Option<NameVersion>,
    tool: Option<PyprojectTool>,
}

#[derive(Debug, Default, Deserialize)]
struct PyprojectTool {
    pixi: Option<PixiToml>,
}

/// Determine the workspace root described by a lockfile.
///
/// Looks for `pixi.toml` first, then `pyproject.toml`, in the lockfile's directory.
/// Falls back to the directory name when neither yields a name. Unreadable or
/// malformed manifests are logged and treated as absent; they must not block SBOM generation.
pub fn root_for_lockfile(lockfile: &Path) -> Root {
    let dir = lockfile.parent().unwrap_or(Path::new("."));
    let from_manifest = read_pixi_toml(&dir.join("pixi.toml")).or_else(|| read_pyproject(&dir.join("pyproject.toml")));

    match from_manifest {
        Some(root) => root,
        None => Root {
            name: fallback_name(dir),
            version: None,
        },
    }
}

fn fallback_name(dir: &Path) -> String {
    dir.canonicalize()
        .ok()
        .as_deref()
        .and_then(Path::file_name)
        .or_else(|| dir.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "workspace".to_string())
}

fn read_pixi_toml(path: &Path) -> Option<Root> {
    let manifest: PixiToml = read_toml(path)?;
    root_from_pixi(manifest)
}

fn read_pyproject(path: &Path) -> Option<Root> {
    let manifest: PyprojectToml = read_toml(path)?;
    let pixi_root = manifest.tool.and_then(|tool| tool.pixi).and_then(root_from_pixi);
    let project = manifest.project.unwrap_or_default();
    // A pixi table with a name wins; otherwise fall back to [project], but let a
    // [project] version fill in a pixi table that only has a name.
    match pixi_root {
        Some(mut root) => {
            if root.version.is_none() {
                root.version = project.version;
            }
            Some(root)
        }
        None => project.name.map(|name| Root {
            name,
            version: project.version,
        }),
    }
}

fn root_from_pixi(manifest: PixiToml) -> Option<Root> {
    let table = manifest.workspace.or(manifest.project)?;
    table.name.map(|name| Root {
        name,
        version: table.version,
    })
}

fn read_toml<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "cannot read manifest; using fallback workspace metadata");
            return None;
        }
    };
    match toml::from_str(&text) {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "cannot parse manifest; using fallback workspace metadata");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in files {
            std::fs::write(dir.path().join(name), content).unwrap();
        }
        dir
    }

    #[test]
    fn reads_workspace_table_from_pixi_toml() {
        let dir = workspace(&[("pixi.toml", "[workspace]\nname = \"demo\"\nversion = \"1.0.0\"\n")]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.name, "demo");
        assert_eq!(root.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn reads_legacy_project_table_from_pixi_toml() {
        let dir = workspace(&[("pixi.toml", "[project]\nname = \"legacy\"\n")]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.name, "legacy");
        assert_eq!(root.version, None);
    }

    #[test]
    fn pixi_toml_wins_over_pyproject() {
        let dir = workspace(&[
            ("pixi.toml", "[workspace]\nname = \"from-pixi\"\n"),
            (
                "pyproject.toml",
                "[project]\nname = \"from-pyproject\"\nversion = \"9.9.9\"\n",
            ),
        ]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.name, "from-pixi");
    }

    #[test]
    fn pyproject_pixi_table_name_with_project_version() {
        let dir = workspace(&[(
            "pyproject.toml",
            "[project]\nname = \"pkg\"\nversion = \"2.0.0\"\n[tool.pixi.workspace]\nname = \"ws\"\n",
        )]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.name, "ws");
        assert_eq!(root.version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn pyproject_project_table_alone() {
        let dir = workspace(&[("pyproject.toml", "[project]\nname = \"pkg\"\nversion = \"2.0.0\"\n")]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.name, "pkg");
        assert_eq!(root.version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn falls_back_to_directory_name_without_manifest() {
        let dir = workspace(&[]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        let expected = dir.path().canonicalize().unwrap();
        assert_eq!(root.name, expected.file_name().unwrap().to_string_lossy());
        assert_eq!(root.version, None);
    }

    #[test]
    fn malformed_manifest_falls_back() {
        let dir = workspace(&[("pixi.toml", "this is = not [ toml")]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.version, None);
        assert!(!root.name.is_empty());
    }

    #[test]
    fn manifest_without_name_falls_back() {
        let dir = workspace(&[("pixi.toml", "[workspace]\nchannels = [\"conda-forge\"]\n")]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert!(!root.name.is_empty());
    }
}
