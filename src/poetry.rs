//! `poetry.lock`: the lockfile Poetry writes (lock-version 2.x).
//!
//! Poetry records, on each package, the environments it is needed in (`markers`), so a document
//! for one platform holds the packages whose markers hold there, as for `pylock.toml`. Markers
//! that name an extra (`extra == "s3"`) are evaluated with every extra the lockfile records
//! switched on, since the lockfile describes all of them.
//!
//! The lockfile has no entry for the project itself: what the project asked for is in its
//! `pyproject.toml`, which is where its name and direct dependencies come from. Poetry records
//! the files of a package by name and hash but not where they were downloaded from, so a package
//! from an index records which artifact (`pixi:file-name`) and its hash, but no download location.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use miette::Diagnostic;
use pep508_rs::{ExtraName, MarkerTree};
use serde::Deserialize;
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom, Supplier};
use crate::purl;
use crate::pylock::{self, Artifact, PylockError};

/// PyPI, which is where a package with no `[package.source]` comes from.
const PYPI_INDEX: &str = "https://pypi.org/simple";

/// Python assumed for markers when the lockfile names none.
const FALLBACK_PYTHON: &str = "3.14";

/// Errors from reading a `poetry.lock`.
#[derive(Debug, Error, Diagnostic)]
pub enum PoetryError {
    /// The file could not be read.
    #[error("cannot read {path}")]
    #[diagnostic(code(pixi_sbom::poetry::read))]
    Read {
        /// The lockfile.
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The file is not a valid `poetry.lock`.
    #[error("{path} is not a valid poetry.lock")]
    #[diagnostic(code(pixi_sbom::poetry::parse), help("{message}"))]
    Parse {
        /// The lockfile.
        path: String,
        /// What the TOML parser said.
        message: String,
    },

    /// A lock-version this reader does not understand.
    #[error("poetry.lock lock-version {found} is not supported")]
    #[diagnostic(
        code(pixi_sbom::poetry::version),
        help("pixi-sbom reads lock-version 2.x, which Poetry 1.5 and later write; run `poetry lock` to rewrite it")
    )]
    Version {
        /// The version the file declares.
        found: String,
    },

    /// A package's environment marker could not be parsed.
    #[error("the marker on {package} cannot be parsed: {marker}")]
    #[diagnostic(code(pixi_sbom::poetry::marker), help("{message}"))]
    Marker {
        /// The package carrying it.
        package: String,
        /// The marker as written.
        marker: String,
        /// What the parser said.
        message: String,
    },

    /// The platform or Python markers cannot be evaluated for.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Environment(#[from] PylockError),

    /// A package name the purl spec rejects.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

/// A parsed `poetry.lock`, with the text it was parsed from.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed lockfile.
    pub lock: PoetryLock,
    /// The source text, which identifies the input for reproducible document ids.
    pub contents: String,
}

/// The parts of a `poetry.lock` a document is built from.
#[derive(Debug, Clone, Deserialize)]
pub struct PoetryLock {
    /// The locked packages.
    #[serde(default, rename = "package")]
    pub packages: Vec<PoetryPackage>,
    /// The project's extras and the packages each brings.
    #[serde(default)]
    pub extras: BTreeMap<String, Vec<String>>,
    /// Lock-wide facts.
    pub metadata: Metadata,
}

/// The `[metadata]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Metadata {
    /// `2.1` for current Poetry.
    pub lock_version: String,
    /// The Pythons the lock is for.
    #[serde(default)]
    pub python_versions: Option<String>,
}

/// One `[[package]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct PoetryPackage {
    /// As written by Poetry.
    pub name: String,
    /// The locked version.
    pub version: String,
    /// The environments the package is needed in; absent means all of them.
    #[serde(default)]
    pub markers: Option<String>,
    /// Installed in development (editable) mode, for a directory source.
    #[serde(default)]
    pub develop: bool,
    /// Where it comes from, when that is not PyPI.
    #[serde(default)]
    pub source: Option<Source>,
    /// Its files, by name and hash.
    #[serde(default)]
    pub files: Vec<File>,
    /// What it depends on: a version constraint, or a table with one.
    #[serde(default)]
    pub dependencies: BTreeMap<String, toml::Value>,
    /// Its own extras.
    #[serde(default)]
    pub extras: BTreeMap<String, Vec<String>>,
}

/// A `[package.source]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct Source {
    /// `legacy` (a package index), `git`, `directory`, `file` or `url`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The index, repository, path or URL.
    pub url: String,
    /// The index's name in the project, for a legacy source.
    #[serde(default)]
    pub reference: Option<String>,
    /// The exact commit, for a git source.
    #[serde(default)]
    pub resolved_reference: Option<String>,
}

/// A `files` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct File {
    /// The file name.
    pub file: String,
    /// `sha256:<hex>`.
    #[serde(default)]
    pub hash: Option<String>,
}

impl File {
    fn to_artifact(&self) -> Artifact {
        let mut hashes = BTreeMap::new();
        if let Some((algorithm, digest)) = self.hash.as_deref().and_then(|h| h.split_once(':')) {
            hashes.insert(algorithm.to_string(), digest.to_string());
        }
        Artifact {
            name: Some(self.file.clone()),
            url: None,
            path: None,
            hashes,
        }
    }
}

/// Whether `path` names a Poetry lockfile.
pub fn is_poetry_lock_name(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "poetry.lock")
}

/// Read and parse the lockfile at `path`.
pub fn load(path: &Path) -> Result<Loaded, PoetryError> {
    let contents = std::fs::read_to_string(path).map_err(|source| PoetryError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let lock = parse(&contents, &path.display().to_string())?;
    Ok(Loaded { lock, contents })
}

/// Parse lockfile text; `origin` names it in errors.
pub fn parse(contents: &str, origin: &str) -> Result<PoetryLock, PoetryError> {
    // The version is checked before the rest is trusted to have lock-version 2's shape.
    let version = toml::from_str::<toml::Table>(contents)
        .ok()
        .and_then(|table| table.get("metadata")?.get("lock-version")?.as_str().map(str::to_string));
    if let Some(found) = version.filter(|v| v.split('.').next() != Some("2")) {
        return Err(PoetryError::Version { found });
    }
    toml::from_str(contents).map_err(|err| PoetryError::Parse {
        path: origin.to_string(),
        message: err.message().to_string(),
    })
}

/// Build the document model for `platform` (`None` = the host).
pub fn build_sbom(
    lock: &PoetryLock,
    platform: Option<&str>,
    root: Root,
    lockfile_name: &str,
) -> Result<Sbom, PoetryError> {
    let platform = match platform {
        Some(name) => name.to_string(),
        None => rattler_conda_types::Platform::current()
            .map(|p| p.to_string())
            .ok_or(PylockError::UnknownCurrentPlatform)?,
    };
    let python = lock
        .metadata
        .python_versions
        .as_deref()
        .and_then(pylock::python_floor)
        .unwrap_or_else(|| FALLBACK_PYTHON.to_string());
    let env = pylock::marker_environment(&platform, &python)?;
    // Every extra the lockfile knows of, the project's and each package's, is on: the lockfile
    // describes all of them, and markers such as `extra == "s3"` would otherwise never hold.
    let extras: Vec<ExtraName> = lock
        .extras
        .keys()
        .chain(lock.packages.iter().flat_map(|p| p.extras.keys()))
        .filter_map(|name| ExtraName::from_str(name).ok())
        .collect();

    let mut selected = Vec::new();
    for package in &lock.packages {
        if let Some(marker) = &package.markers {
            let tree = MarkerTree::from_str(marker).map_err(|err| PoetryError::Marker {
                package: package.name.clone(),
                marker: marker.clone(),
                message: err.to_string(),
            })?;
            if !tree.evaluate(&env, &extras) {
                tracing::debug!(package = %package.name, %marker, %platform, "not installed on this platform");
                continue;
            }
        }
        selected.push(package);
    }

    let mut packages = selected
        .iter()
        .map(|package| convert(package, &platform, &python))
        .collect::<Result<Vec<_>, _>>()?;
    let ids: BTreeMap<String, String> = selected
        .iter()
        .zip(&packages)
        .map(|(locked, package)| (purl::normalize_pypi_name(&locked.name), package.id.clone()))
        .collect();
    for (locked, package) in selected.iter().zip(packages.iter_mut()) {
        let mut deps: Vec<String> = locked
            .dependencies
            .keys()
            .filter_map(|name| ids.get(&purl::normalize_pypi_name(name)).cloned())
            .filter(|id| *id != package.id)
            .collect();
        deps.sort();
        deps.dedup();
        package.dependencies = deps;
    }
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    tracing::info!(
        platform = %platform,
        python = %python,
        packages = packages.len(),
        of = lock.packages.len(),
        "read poetry.lock"
    );

    Ok(Sbom {
        root,
        environment: "default".to_string(),
        platform,
        lockfile: lockfile_name.to_string(),
        prefix: None,
        document: None,
        packages,
        vulnerabilities: Vec::new(),
        excluded: Vec::new(),
        declared_missing: Vec::new(),
        incomplete: crate::model::Incomplete::default(),
        lifecycles: vec![crate::model::PHASE_LOCKFILE.into()],
        declared_roots: false,
    })
}

/// One locked package as a model package.
fn convert(locked: &PoetryPackage, platform: &str, python: &str) -> Result<Package, PoetryError> {
    let purl = purl::pypi(&locked.name, &locked.version)?;
    let mut properties = BTreeMap::new();
    if let Some(marker) = &locked.markers {
        properties.insert("pixi:marker".into(), marker.clone());
    }
    let mut supplier = None;
    let mut sha256 = None;
    let mut index = |properties: &mut BTreeMap<String, String>, url: &str| {
        properties.insert("pixi:index-url".into(), url.to_string());
        supplier = Some(Supplier {
            name: pylock::url_host(url).unwrap_or_else(|| url.to_string()),
            url: Some(url.to_string()),
        });
    };
    let location = match &locked.source {
        Some(source) if source.kind == "git" => {
            properties.insert("pixi:direct-url".into(), source.url.clone());
            if let Some(commit) = &source.resolved_reference {
                properties.insert("pixi:source-rev".into(), commit.clone());
            }
            Some(format!("git+{}", source.url))
        }
        Some(source) if matches!(source.kind.as_str(), "directory" | "file") => {
            let reference = crate::lock::local_path_reference(&source.url);
            properties.insert("pixi:direct-url".into(), reference.clone());
            if locked.develop {
                properties.insert("pixi:editable".into(), "true".into());
            }
            Some(reference)
        }
        Some(source) if source.kind == "url" => {
            properties.insert("pixi:direct-url".into(), source.url.clone());
            Some(source.url.clone())
        }
        other => {
            // An index: a `legacy` source names it, and no source at all means PyPI.
            index(&mut properties, other.as_ref().map_or(PYPI_INDEX, |s| s.url.as_str()));
            None
        }
    };
    if location.is_none()
        || locked
            .source
            .as_ref()
            .is_some_and(|s| matches!(s.kind.as_str(), "file" | "url"))
    {
        let files: Vec<Artifact> = locked.files.iter().map(File::to_artifact).collect();
        let (wheels, sdists): (Vec<Artifact>, Vec<Artifact>) = files
            .into_iter()
            .partition(|a| a.name.as_deref().is_some_and(|n| n.ends_with(".whl")));
        if let Some(chosen) = pylock::choose_artifact(&wheels, sdists.first(), platform, python) {
            if let Some(name) = &chosen.name {
                properties.insert("pixi:file-name".into(), name.clone());
            }
            if sdists.first().is_some_and(|s| std::ptr::eq(chosen, s)) {
                properties.insert("pixi:source".into(), "true".into());
            }
            sha256 = chosen.hashes.get("sha256").cloned();
        }
    }

    Ok(Package {
        id: purl.clone(),
        name: locked.name.clone(),
        version: Some(locked.version.clone()),
        kind: PackageKind::Pypi,
        purl,
        supplier,
        extra_purls: Vec::new(),
        purls_from_lock: false,
        location: location.unwrap_or_default(),
        sha256,
        md5: None,
        license: None,
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties,
        dependencies: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
[[package]]
name = "django"
version = "3.2.12"
optional = false
python-versions = ">=3.6"
groups = ["main"]
files = [
    {file = "Django-3.2.12-py3-none-any.whl", hash = "sha256:bb"},
    {file = "Django-3.2.12.tar.gz", hash = "sha256:aa"},
]

[package.dependencies]
argon2-cffi = {version = ">=19.1.0", optional = true, markers = "extra == \"argon2\""}
sqlparse = ">=0.2.2"

[package.extras]
argon2 = ["argon2-cffi (>=19.1.0)"]

[[package]]
name = "sqlparse"
version = "0.4.2"
optional = false
python-versions = ">=3.5"
groups = ["main"]
files = [{file = "sqlparse-0.4.2.tar.gz", hash = "sha256:cc"}]

[[package]]
name = "argon2-cffi"
version = "25.1.0"
optional = false
python-versions = ">=3.8"
groups = ["main"]
files = [{file = "argon2_cffi-25.1.0-py3-none-any.whl", hash = "sha256:dd"}]

[[package]]
name = "colorama"
version = "0.4.6"
optional = false
python-versions = "*"
groups = ["test"]
markers = "sys_platform == \"win32\""
files = [{file = "colorama-0.4.6-py2.py3-none-any.whl", hash = "sha256:ee"}]

[[package]]
name = "django-storages"
version = "1.13.2"
optional = true
python-versions = ">=3.7"
groups = ["main"]
markers = "extra == \"s3\""
files = []

[[package]]
name = "toolbar"
version = "3.2.4"
optional = false
python-versions = "*"
groups = ["dev"]
files = []

[package.source]
type = "git"
url = "https://github.com/django-commons/django-debug-toolbar"
reference = "3.2.4"
resolved_reference = "9ec7210e"

[[package]]
name = "internal-utils"
version = "0.3.0"
optional = false
python-versions = "*"
groups = ["main"]
develop = true
files = []

[package.source]
type = "directory"
url = "libs/internal-utils"

[[package]]
name = "torch"
version = "2.9.0+cpu"
optional = false
python-versions = ">=3.10"
groups = ["main"]
files = [
    {file = "torch-2.9.0+cpu-cp312-cp312-manylinux_2_28_x86_64.whl", hash = "sha256:t1"},
    {file = "torch-2.9.0+cpu-cp312-cp312-win_amd64.whl", hash = "sha256:t2"},
]

[package.source]
type = "legacy"
url = "https://download.pytorch.org/whl/cpu"
reference = "pytorch-cpu"

[extras]
s3 = ["django-storages"]

[metadata]
lock-version = "2.1"
python-versions = ">=3.12,<3.13"
content-hash = "x"
"#;

    fn sbom(platform: &str) -> Sbom {
        build_sbom(
            &parse(LOCK, "poetry.lock").unwrap(),
            Some(platform),
            Root::default(),
            "poetry.lock",
        )
        .unwrap()
    }

    fn package<'a>(sbom: &'a Sbom, name: &str) -> &'a Package {
        sbom.packages
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn package_markers_are_evaluated_for_the_platform_with_every_extra_on() {
        let linux = sbom("linux-64");
        let names: Vec<&str> = linux.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(!names.contains(&"colorama"), "win32 only: {names:?}");
        assert!(names.contains(&"django-storages"), "the s3 extra is described too");
        assert!(sbom("win-64").packages.iter().any(|p| p.name == "colorama"));
        assert_eq!(
            package(&linux, "django").dependencies,
            ["pkg:pypi/argon2-cffi@25.1.0", "pkg:pypi/sqlparse@0.4.2"]
        );
    }

    #[test]
    fn an_index_package_records_its_file_and_hash_but_no_location() {
        let doc = sbom("linux-64");
        let django = package(&doc, "django");
        assert_eq!(django.location, "", "Poetry records no download URL");
        assert_eq!(django.properties["pixi:file-name"], "Django-3.2.12-py3-none-any.whl");
        assert_eq!(django.sha256.as_deref(), Some("bb"));
        assert_eq!(django.properties["pixi:index-url"], PYPI_INDEX);
        let sqlparse = package(&doc, "sqlparse");
        assert_eq!(sqlparse.properties["pixi:source"], "true", "only an sdist");

        let torch_linux = package(&doc, "torch");
        assert_eq!(torch_linux.purl, "pkg:pypi/torch@2.9.0%2Bcpu");
        assert_eq!(torch_linux.supplier.as_ref().unwrap().name, "download.pytorch.org");
        assert_eq!(
            torch_linux.properties["pixi:index-url"],
            "https://download.pytorch.org/whl/cpu"
        );
        assert_eq!(torch_linux.sha256.as_deref(), Some("t1"));
        assert_eq!(package(&sbom("win-64"), "torch").sha256.as_deref(), Some("t2"));
    }

    #[test]
    fn git_and_directory_sources_say_where_they_came_from() {
        let doc = sbom("linux-64");
        let toolbar = package(&doc, "toolbar");
        assert_eq!(
            toolbar.location,
            "git+https://github.com/django-commons/django-debug-toolbar"
        );
        assert_eq!(toolbar.properties["pixi:source-rev"], "9ec7210e");
        let local = package(&doc, "internal-utils");
        assert_eq!(local.location, "libs/internal-utils");
        assert_eq!(local.properties["pixi:editable"], "true");
    }

    #[test]
    fn an_old_lock_version_is_refused_with_the_fix() {
        let old = "[metadata]\nlock-version = \"1.1\"\npython-versions = \"^3.8\"\ncontent-hash = \"x\"\n";
        let err = parse(old, "poetry.lock").unwrap_err();
        assert!(matches!(err, PoetryError::Version { ref found } if found == "1.1"));
        assert!(matches!(
            parse("[metadata]\nnope = 1\n", "x"),
            Err(PoetryError::Parse { .. })
        ));
        assert!(is_poetry_lock_name(Path::new("a/poetry.lock")));
        assert!(!is_poetry_lock_name(Path::new("a/uv.lock")));
        let bad = LOCK.replace("sys_platform == \\\"win32\\\"", "sys_platform ==");
        assert!(matches!(
            build_sbom(&parse(&bad, "x").unwrap(), Some("linux-64"), Root::default(), "x"),
            Err(PoetryError::Marker { .. })
        ));
        assert!(load(Path::new("/does/not/exist/poetry.lock")).is_err());
    }
}
