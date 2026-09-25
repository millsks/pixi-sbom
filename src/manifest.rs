//! Reads the pixi manifest next to the lockfile: the workspace metadata, and the dependency
//! tables that say which packages the workspace asked for itself.

use std::path::Path;

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::model::{Author, PackageKind, Root, Sbom};
use crate::purl::normalize_pypi_name;

/// The `pixi:*` property marking a package the manifest declares itself, as opposed to one
/// that came along as somebody else's dependency.
pub const DIRECT_PROPERTY: &str = "pixi:direct";
/// The `pixi:*` property listing the features whose tables declare it, comma separated.
pub const DECLARED_IN_PROPERTY: &str = "pixi:declared-in";

/// The feature the top-level dependency tables belong to, and which every environment
/// includes unless it sets `no-default-feature`.
const DEFAULT_FEATURE: &str = "default";

/// One dependency a manifest declares, and the feature that declares it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Declared {
    /// Name as the manifest spells it.
    pub name: String,
    /// Whether it came from a `pypi-dependencies` table rather than a conda one.
    pub pypi: bool,
    /// The feature whose tables declare it; `default` for the top-level ones.
    pub feature: String,
}

/// An entry of the manifest's `[environments]` table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    pub features: Vec<String>,
    /// Whether the environment leaves the default feature out.
    pub no_default_feature: bool,
}

/// What the workspace manifest says: the metadata the document's root component is built
/// from, and the dependencies the workspace declared. Both are empty when there is no
/// readable manifest, which is the `--prefix` and bare-lockfile case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub root: Root,
    /// Every declared dependency, in manifest order per feature.
    pub declared: Vec<Declared>,
    /// The `[environments]` table; an environment missing from it is the default feature alone.
    pub environments: BTreeMap<String, Environment>,
}

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
    #[serde(flatten)]
    deps: DepTables,
    #[serde(default)]
    feature: BTreeMap<String, DepTables>,
    #[serde(default)]
    environments: BTreeMap<String, EnvSpec>,
}

/// The dependency tables of one feature (the top-level ones belong to `default`). Values are
/// left as they are written: only the key names a package.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct DepTables {
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
    #[serde(default)]
    host_dependencies: BTreeMap<String, toml::Value>,
    #[serde(default)]
    build_dependencies: BTreeMap<String, toml::Value>,
    #[serde(default)]
    pypi_dependencies: BTreeMap<String, toml::Value>,
    #[serde(default)]
    target: BTreeMap<String, DepTables>,
}

impl DepTables {
    /// Append everything these tables declare for `feature`.
    fn collect(&self, feature: &str, out: &mut Vec<Declared>) {
        for (table, pypi) in [
            (&self.dependencies, false),
            (&self.host_dependencies, false),
            (&self.build_dependencies, false),
            (&self.pypi_dependencies, true),
        ] {
            out.extend(table.keys().map(|name| Declared {
                name: name.clone(),
                pypi,
                feature: feature.to_string(),
            }));
        }
        // A platform table declares for the same feature; what belongs to another platform
        // simply matches no package in the environment being described.
        for tables in self.target.values() {
            tables.collect(feature, out);
        }
    }
}

/// An `[environments]` entry: a bare feature list, or a table that can drop the default feature.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EnvSpec {
    Features(Vec<String>),
    Table {
        #[serde(default)]
        features: Vec<String>,
        #[serde(default, rename = "no-default-feature")]
        no_default_feature: bool,
    },
}

impl EnvSpec {
    fn environment(&self) -> Environment {
        match self {
            EnvSpec::Features(features) => Environment {
                features: features.clone(),
                no_default_feature: false,
            },
            EnvSpec::Table {
                features,
                no_default_feature,
            } => Environment {
                features: features.clone(),
                no_default_feature: *no_default_feature,
            },
        }
    }
}

/// The PEP 621 `[project]` table of a pyproject.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct PyprojectProject {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    authors: Vec<PyprojectAuthor>,
    license: Option<PyprojectLicense>,
    #[serde(default)]
    urls: BTreeMap<String, String>,
    /// PEP 508 requirement strings; pixi resolves them as the default feature's PyPI
    /// dependencies.
    #[serde(default)]
    dependencies: Vec<String>,
    /// Extras, which pixi turns into features of the same name.
    #[serde(default)]
    optional_dependencies: BTreeMap<String, Vec<String>>,
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

/// Read the manifest describing a lockfile.
///
/// Looks for `pixi.toml` first, then `pyproject.toml`, in the lockfile's directory. The
/// workspace name falls back to the directory name when neither yields one. Unreadable or
/// malformed manifests are logged and treated as absent; they must not block SBOM generation.
pub fn read(lockfile: &Path) -> Manifest {
    let dir = lockfile.parent().unwrap_or(Path::new("."));
    let mut manifest = read_pixi_toml(&dir.join("pixi.toml")).unwrap_or_default();
    // No pixi.toml, or one that does not name the workspace: the pyproject may, and it is
    // then also where the dependencies are.
    if manifest.root.name.is_empty() {
        let pyproject = read_pyproject(&dir.join("pyproject.toml")).unwrap_or_default();
        manifest.root = pyproject.root;
        if manifest.declared.is_empty() {
            manifest.declared = pyproject.declared;
        }
        if manifest.environments.is_empty() {
            manifest.environments = pyproject.environments;
        }
    }
    if manifest.root.name.is_empty() {
        manifest.root.name = fallback_name(dir);
    }
    tracing::debug!(
        declared = manifest.declared.len(),
        environments = manifest.environments.len(),
        "read the workspace manifest"
    );
    manifest
}

impl Manifest {
    /// The features an environment is built from: the ones `[environments]` lists, plus the
    /// default feature unless the environment opted out of it. An environment the manifest
    /// does not mention — it has drifted from the lockfile — is the default feature alone.
    fn features_of(&self, environment: &str) -> BTreeSet<&str> {
        let mut features = BTreeSet::new();
        match self.environments.get(environment) {
            Some(env) => {
                features.extend(env.features.iter().map(String::as_str));
                if !env.no_default_feature {
                    features.insert(DEFAULT_FEATURE);
                }
            }
            None => {
                features.insert(DEFAULT_FEATURE);
            }
        }
        features
    }

    /// Mark the packages of `sbom` that its environment's manifest asked for directly, and
    /// record the declared names the environment has no package for. Does nothing when there
    /// is no manifest, so a bare lockfile keeps the graph-root heuristic it always had.
    pub fn apply(&self, sbom: &mut Sbom) {
        if self.declared.is_empty() {
            return;
        }
        let features = self.features_of(&sbom.environment);
        let mut wanted: BTreeMap<(bool, String), BTreeSet<&str>> = BTreeMap::new();
        for declared in self.declared.iter().filter(|d| features.contains(d.feature.as_str())) {
            wanted
                .entry((declared.pypi, matching_key(&declared.name, declared.pypi)))
                .or_default()
                .insert(&declared.feature);
        }
        let mut matched: BTreeSet<(bool, String)> = BTreeSet::new();
        for package in &mut sbom.packages {
            let pypi = match package.kind {
                PackageKind::Pypi => true,
                PackageKind::CondaBinary | PackageKind::CondaSource => false,
                // Not installed as a package of its own, and not from a manifest at all.
                PackageKind::Embedded | PackageKind::External => continue,
            };
            let key = (pypi, matching_key(&package.name, pypi));
            if let Some(features) = wanted.get(&key) {
                package
                    .properties
                    .insert(DIRECT_PROPERTY.to_string(), "true".to_string());
                package.properties.insert(
                    DECLARED_IN_PROPERTY.to_string(),
                    features.iter().copied().collect::<Vec<_>>().join(","),
                );
                matched.insert(key);
            }
        }
        let missing: Vec<String> = wanted
            .keys()
            .filter(|key| !matched.contains(*key))
            .map(|(_, name)| name.clone())
            .collect();
        if !missing.is_empty() {
            tracing::debug!(
                environment = %sbom.environment,
                platform = %sbom.platform,
                names = %missing.join(", "),
                "declared dependencies this environment has no package for"
            );
        }
        sbom.declared_missing = missing;
    }
}

/// How a declared name is matched to a package: PEP 503 normalization for PyPI names, plain
/// lowercasing for conda ones.
fn matching_key(name: &str, pypi: bool) -> String {
    if pypi {
        normalize_pypi_name(name)
    } else {
        name.to_ascii_lowercase()
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

fn read_pixi_toml(path: &Path) -> Option<Manifest> {
    read_toml(path).map(manifest_from_pixi)
}

fn read_pyproject(path: &Path) -> Option<Manifest> {
    let file: PyprojectToml = read_toml(path)?;
    let project = file.project.unwrap_or_default();
    let mut manifest = file
        .tool
        .and_then(|tool| tool.pixi)
        .map(manifest_from_pixi)
        .unwrap_or_default();
    // PEP 621 requirements are the default feature's PyPI dependencies, and each extra is a
    // feature of the same name.
    for requirement in &project.dependencies {
        manifest
            .declared
            .extend(declared_requirement(requirement, DEFAULT_FEATURE));
    }
    for (extra, requirements) in &project.optional_dependencies {
        for requirement in requirements {
            manifest.declared.extend(declared_requirement(requirement, extra));
        }
    }
    // A pixi table with a name wins; otherwise fall back to [project], but let [project]
    // fill in whatever the pixi table leaves empty.
    let project = root_from_pyproject(project);
    let root = &mut manifest.root;
    if root.name.is_empty() {
        root.name = project.name;
    }
    root.version = root.version.take().or(project.version);
    if root.authors.is_empty() {
        root.authors = project.authors;
    }
    root.license = root.license.take().or(project.license);
    root.homepage = root.homepage.take().or(project.homepage);
    root.repository = root.repository.take().or(project.repository);
    Some(manifest)
}

fn manifest_from_pixi(file: PixiToml) -> Manifest {
    let mut declared = Vec::new();
    file.deps.collect(DEFAULT_FEATURE, &mut declared);
    for (feature, tables) in &file.feature {
        tables.collect(feature, &mut declared);
    }
    Manifest {
        root: root_from_pixi(file.workspace.or(file.project).unwrap_or_default()),
        declared,
        environments: file
            .environments
            .iter()
            .map(|(name, spec)| (name.clone(), spec.environment()))
            .collect(),
    }
}

/// The package a PEP 508 requirement string asks for; `None` when it names nothing.
fn declared_requirement(requirement: &str, feature: &str) -> Option<Declared> {
    let name: String = requirement
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    (!name.is_empty()).then(|| Declared {
        name,
        pypi: true,
        feature: feature.to_string(),
    })
}

/// Map a pixi `[workspace]` / `[project]` table onto [`Root`]; the name is empty when the
/// table has none, which is what makes the caller look further.
fn root_from_pixi(table: PixiTable) -> Root {
    Root {
        name: table.name.unwrap_or_default(),
        version: table.version,
        authors: table.authors.iter().filter_map(|a| Author::parse(a)).collect(),
        license: table.license,
        homepage: table.homepage,
        repository: table.repository,
    }
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
        let root = read(&dir.path().join("pixi.lock")).root;
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
        let root = read(&dir.path().join("pixi.lock")).root;
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
        let root = read(&dir.path().join("pixi.lock")).root;
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
        assert_eq!(read(&dir.path().join("pixi.lock")).root.license.as_deref(), Some("BSD"));
        let dir = workspace(&[(
            "pyproject.toml",
            "[project]\nname = \"pkg\"\nlicense = { file = \"LICENSE\" }\n",
        )]);
        assert_eq!(read(&dir.path().join("pixi.lock")).root.license, None);
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
        let root = read(&dir.path().join("pixi.lock")).root;
        assert_eq!(root.name, "ws");
        assert_eq!(root.version.as_deref(), Some("2.0.0"));
        assert_eq!(root.authors[0].name, "From Pixi");
        assert_eq!(root.license.as_deref(), Some("MIT"));
        assert_eq!(root.homepage.as_deref(), Some("https://pixi.example"));
    }

    #[test]
    fn reads_legacy_project_table_from_pixi_toml() {
        let dir = workspace(&[("pixi.toml", "[project]\nname = \"legacy\"\n")]);
        let root = read(&dir.path().join("pixi.lock")).root;
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
        let root = read(&dir.path().join("pixi.lock")).root;
        assert_eq!(root.name, "from-pixi");
    }

    #[test]
    fn pyproject_pixi_table_name_with_project_version() {
        let dir = workspace(&[(
            "pyproject.toml",
            "[project]\nname = \"pkg\"\nversion = \"2.0.0\"\n[tool.pixi.workspace]\nname = \"ws\"\n",
        )]);
        let root = read(&dir.path().join("pixi.lock")).root;
        assert_eq!(root.name, "ws");
        assert_eq!(root.version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn pyproject_project_table_alone() {
        let dir = workspace(&[("pyproject.toml", "[project]\nname = \"pkg\"\nversion = \"2.0.0\"\n")]);
        let root = read(&dir.path().join("pixi.lock")).root;
        assert_eq!(root.name, "pkg");
        assert_eq!(root.version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn falls_back_to_directory_name_without_manifest() {
        let dir = workspace(&[]);
        let root = read(&dir.path().join("pixi.lock")).root;
        let expected = dir.path().canonicalize().unwrap();
        assert_eq!(root.name, expected.file_name().unwrap().to_string_lossy());
        assert_eq!(root.version, None);
    }

    #[test]
    fn malformed_manifest_falls_back() {
        let dir = workspace(&[("pixi.toml", "this is = not [ toml")]);
        let root = read(&dir.path().join("pixi.lock")).root;
        assert_eq!(root.version, None);
        assert!(!root.name.is_empty());
    }

    /// The declared set as `feature:kind:name`, which reads better in an assertion than the
    /// struct does.
    fn declared(manifest: &Manifest) -> Vec<String> {
        let mut out: Vec<String> = manifest
            .declared
            .iter()
            .map(|d| format!("{}:{}:{}", d.feature, if d.pypi { "pypi" } else { "conda" }, d.name))
            .collect();
        out.sort();
        out
    }

    #[test]
    fn reads_the_dependency_tables_of_every_feature() {
        let dir = workspace(&[(
            "pixi.toml",
            concat!(
                "[workspace]\nname = \"demo\"\n",
                "[dependencies]\npython = \"3.12.*\"\nrust = { version = \"==1.98.1\", channel = \"conda-forge\" }\n",
                "[pypi-dependencies]\nrequests = \">=2\"\nmy_pkg = { path = \".\", editable = true }\n",
                "[build-dependencies]\ncmake = \"*\"\n",
                "[host-dependencies]\nopenssl = \"*\"\n",
                "[target.linux-64.dependencies]\ncompilers = \"*\"\n",
                "[feature.docs.dependencies]\nmkdocs = \"*\"\n",
                "[feature.docs.target.win-64.dependencies]\nwinpty = \"*\"\n",
            ),
        )]);
        let manifest = read(&dir.path().join("pixi.lock"));
        assert_eq!(
            declared(&manifest),
            [
                "default:conda:cmake",
                "default:conda:compilers",
                "default:conda:openssl",
                "default:conda:python",
                "default:conda:rust",
                "default:pypi:my_pkg",
                "default:pypi:requests",
                "docs:conda:mkdocs",
                "docs:conda:winpty",
            ]
        );
    }

    #[test]
    fn environments_include_the_default_feature_unless_they_opt_out() {
        let dir = workspace(&[(
            "pixi.toml",
            concat!(
                "[workspace]\nname = \"demo\"\n",
                "[environments]\ndefault = [\"lint\"]\n",
                "docs = { features = [\"docs\"], no-default-feature = true }\n",
            ),
        )]);
        let manifest = read(&dir.path().join("pixi.lock"));
        assert_eq!(manifest.features_of("default"), ["default", "lint"].into());
        assert_eq!(manifest.features_of("docs"), ["docs"].into());
        // Not in the table: the manifest has drifted from the lockfile, so only the default
        // feature is certain.
        assert_eq!(manifest.features_of("test"), ["default"].into());
    }

    #[test]
    fn declares_pep621_requirements_and_extras_as_pypi_dependencies() {
        let dir = workspace(&[(
            "pyproject.toml",
            concat!(
                "[project]\nname = \"pkg\"\n",
                "dependencies = [\"requests >= 2.0\", \"tomli; python_version < '3.11'\", \"\"]\n",
                "[project.optional-dependencies]\ndocs = [\"mkdocs-material[imaging]>=9\"]\n",
                "[tool.pixi.dependencies]\npython = \"3.12.*\"\n",
            ),
        )]);
        let manifest = read(&dir.path().join("pixi.lock"));
        assert_eq!(
            declared(&manifest),
            [
                "default:conda:python",
                "default:pypi:requests",
                "default:pypi:tomli",
                "docs:pypi:mkdocs-material",
            ]
        );
    }

    #[test]
    fn marks_declared_packages_direct_and_records_what_is_missing() {
        let dir = workspace(&[(
            "pixi.toml",
            concat!(
                "[workspace]\nname = \"demo\"\n",
                "[dependencies]\nzlib = \"*\"\n",
                "[pypi-dependencies]\nSix = \"*\"\n",
                "[feature.docs.dependencies]\nmkdocs = \"*\"\n",
                "[target.win-64.dependencies]\nvs2019_win-64 = \"*\"\n",
            ),
        )]);
        let manifest = read(&dir.path().join("pixi.lock"));
        let mut sbom = crate::format::testing::sample_sbom();
        manifest.apply(&mut sbom);

        let direct: Vec<&str> = sbom
            .packages
            .iter()
            .filter(|p| p.properties.contains_key(DIRECT_PROPERTY))
            .map(|p| p.name.as_str())
            .collect();
        // `Six` matches after PEP 503 normalization; `libzlib` is nobody's declaration.
        assert_eq!(direct, ["zlib", "six"]);
        let zlib = sbom.packages.iter().find(|p| p.name == "zlib").unwrap();
        assert_eq!(
            zlib.properties.get(DECLARED_IN_PROPERTY).map(String::as_str),
            Some("default")
        );
        // The docs feature is not part of this environment, and the Windows table is not part
        // of this platform.
        assert_eq!(sbom.declared_missing, ["vs2019_win-64"]);
    }

    #[test]
    fn a_lockfile_without_a_manifest_marks_nothing() {
        let dir = workspace(&[]);
        let manifest = read(&dir.path().join("pixi.lock"));
        let mut sbom = crate::format::testing::sample_sbom();
        manifest.apply(&mut sbom);
        assert!(
            sbom.packages
                .iter()
                .all(|p| !p.properties.contains_key(DIRECT_PROPERTY))
        );
        assert!(sbom.declared_missing.is_empty());
    }

    #[test]
    fn manifest_without_name_falls_back() {
        let dir = workspace(&[("pixi.toml", "[workspace]\nchannels = [\"conda-forge\"]\n")]);
        let root = read(&dir.path().join("pixi.lock")).root;
        assert!(!root.name.is_empty());
    }
}
