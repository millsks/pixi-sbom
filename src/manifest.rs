//! Reads workspace name/version from the pixi manifest next to the lockfile.

use std::path::Path;

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::model::{Author, Root};

/// The `[workspace]` / `[project]` table of a pixi manifest.
#[derive(Debug, Default, Deserialize)]
struct PixiTable {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    authors: Vec<String>,
    license: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PixiToml {
    workspace: Option<PixiTable>,
    project: Option<PixiTable>,
}

/// The PEP 621 `[project]` table of a pyproject.
#[derive(Debug, Default, Deserialize)]
struct PyprojectProject {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    authors: Vec<PyprojectAuthor>,
    license: Option<PyprojectLicense>,
    #[serde(default)]
    urls: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct PyprojectAuthor {
    name: Option<String>,
    email: Option<String>,
}

/// PEP 639 string form, or the older `{ text = ... }` / `{ file = ... }` table.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PyprojectLicense {
    Expression(String),
    Table { text: Option<String> },
}

#[derive(Debug, Default, Deserialize)]
struct PyprojectToml {
    project: Option<PyprojectProject>,
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
            ..Root::default()
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
    let project = root_from_pyproject(manifest.project.unwrap_or_default());
    // A pixi table with a name wins; otherwise fall back to [project], but let [project]
    // fill in whatever the pixi table leaves empty.
    match pixi_root {
        Some(mut root) => {
            root.version = root.version.or(project.version);
            if root.authors.is_empty() {
                root.authors = project.authors;
            }
            root.license = root.license.or(project.license);
            root.homepage = root.homepage.or(project.homepage);
            root.repository = root.repository.or(project.repository);
            Some(root)
        }
        None => (!project.name.is_empty()).then_some(project),
    }
}

fn root_from_pixi(manifest: PixiToml) -> Option<Root> {
    let table = manifest.workspace.or(manifest.project)?;
    let name = table.name?;
    Some(Root {
        name,
        version: table.version,
        authors: table.authors.iter().filter_map(|a| Author::parse(a)).collect(),
        license: table.license,
        homepage: table.homepage,
        repository: table.repository,
    })
}

/// Map a PEP 621 `[project]` table onto [`Root`]; the name is empty when the table has none.
fn root_from_pyproject(project: PyprojectProject) -> Root {
    let url = |wanted: &[&str]| {
        project
            .urls
            .iter()
            .find(|(key, _)| wanted.iter().any(|w| key.eq_ignore_ascii_case(w)))
            .map(|(_, value)| value.clone())
    };
    Root {
        homepage: url(&["homepage"]),
        repository: url(&["repository", "source", "source code"]),
        name: project.name.unwrap_or_default(),
        version: project.version,
        authors: project
            .authors
            .into_iter()
            .filter_map(|a| match (a.name, a.email) {
                (Some(name), email) => Some(Author { name, email }),
                (None, Some(email)) => Some(Author {
                    name: email.clone(),
                    email: Some(email),
                }),
                (None, None) => None,
            })
            .collect(),
        license: match project.license {
            Some(PyprojectLicense::Expression(text)) => Some(text),
            Some(PyprojectLicense::Table { text }) => text,
            None => None,
        },
    }
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
        assert!(root.authors.is_empty());
        assert_eq!(root.license, None);
    }

    #[test]
    fn reads_authors_license_and_urls_from_pixi_toml() {
        let dir = workspace(&[(
            "pixi.toml",
            concat!(
                "[workspace]\nname = \"demo\"\n",
                "authors = [\"Ada Lovelace <ada@example.org>\", \"Anonymous\", \"\"]\n",
                "license = \"MIT\"\nhomepage = \"https://example.org\"\n",
                "repository = \"https://github.com/example/demo\"\n",
            ),
        )]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.authors.len(), 2);
        assert_eq!(root.authors[0].name, "Ada Lovelace");
        assert_eq!(root.authors[0].email.as_deref(), Some("ada@example.org"));
        assert_eq!(root.authors[1].name, "Anonymous");
        assert_eq!(root.license.as_deref(), Some("MIT"));
        assert_eq!(root.homepage.as_deref(), Some("https://example.org"));
        assert_eq!(root.repository.as_deref(), Some("https://github.com/example/demo"));
    }

    #[test]
    fn reads_pep621_authors_license_and_urls_from_pyproject() {
        let dir = workspace(&[(
            "pyproject.toml",
            concat!(
                "[project]\nname = \"pkg\"\nversion = \"2.0.0\"\n",
                "authors = [{name = \"Ada\", email = \"ada@example.org\"}, {email = \"x@example.org\"}, {}]\n",
                "license = \"Apache-2.0\"\n",
                "[project.urls]\nHomepage = \"https://example.org\"\n\"Source Code\" = \"https://github.com/example/pkg\"\n",
            ),
        )]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.authors.len(), 2);
        assert_eq!(root.authors[0].name, "Ada");
        assert_eq!(root.authors[1].name, "x@example.org");
        assert_eq!(root.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(root.homepage.as_deref(), Some("https://example.org"));
        assert_eq!(root.repository.as_deref(), Some("https://github.com/example/pkg"));
    }

    #[test]
    fn pyproject_license_table_forms() {
        let dir = workspace(&[(
            "pyproject.toml",
            "[project]\nname = \"pkg\"\nlicense = { text = \"BSD\" }\n",
        )]);
        assert_eq!(
            root_for_lockfile(&dir.path().join("pixi.lock")).license.as_deref(),
            Some("BSD")
        );
        let dir = workspace(&[(
            "pyproject.toml",
            "[project]\nname = \"pkg\"\nlicense = { file = \"LICENSE\" }\n",
        )]);
        assert_eq!(root_for_lockfile(&dir.path().join("pixi.lock")).license, None);
    }

    #[test]
    fn pyproject_project_fills_in_what_the_pixi_table_lacks() {
        let dir = workspace(&[(
            "pyproject.toml",
            concat!(
                "[project]\nname = \"pkg\"\nversion = \"2.0.0\"\nlicense = \"MIT\"\n",
                "authors = [{name = \"From Project\"}]\n",
                "[tool.pixi.workspace]\nname = \"ws\"\nauthors = [\"From Pixi\"]\n",
                "homepage = \"https://pixi.example\"\n",
            ),
        )]);
        let root = root_for_lockfile(&dir.path().join("pixi.lock"));
        assert_eq!(root.name, "ws");
        assert_eq!(root.version.as_deref(), Some("2.0.0"));
        assert_eq!(root.authors[0].name, "From Pixi");
        assert_eq!(root.license.as_deref(), Some("MIT"));
        assert_eq!(root.homepage.as_deref(), Some("https://pixi.example"));
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
