//! `pdm.lock`: the lockfile PDM writes (lock_version 4.x).
//!
//! PDM records, on each package, the environments it is needed in (`marker`), so a document for
//! one platform holds the packages whose markers hold there. Dependencies are PEP 508
//! requirement strings, whose own markers decide whether the edge applies.
//!
//! An extra is a package entry of its own: `django[argon2]` is a second `django` entry with
//! `extras = ["argon2"]` that depends on `django` and on what the extra brings. Those entries are
//! folded into the package they extend, so the component appears once and the extra's packages
//! hang off it.
//!
//! PDM records a package's files by name and hash but neither their download URL nor which of
//! the project's sources served them, so an index package records which artifact
//! (`pixi:file-name`) and its hash, and no location or supplier.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use miette::Diagnostic;
use pep508_rs::{MarkerTree, Requirement, VerbatimUrl};
use serde::Deserialize;
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom};
use crate::purl;
use crate::pylock::{self, Artifact, PylockError};

/// Python assumed for markers when the lockfile names none.
const FALLBACK_PYTHON: &str = "3.14";

/// Errors from reading a `pdm.lock`.
#[derive(Debug, Error, Diagnostic)]
pub enum PdmError {
    /// The file could not be read.
    #[error("cannot read {path}")]
    #[diagnostic(code(pixi_sbom::pdm::read))]
    Read {
        /// The lockfile.
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The file is not a valid `pdm.lock`.
    #[error("{path} is not a valid pdm.lock")]
    #[diagnostic(code(pixi_sbom::pdm::parse), help("{message}"))]
    Parse {
        /// The lockfile.
        path: String,
        /// What the TOML parser said.
        message: String,
    },

    /// A lock_version this reader does not understand.
    #[error("pdm.lock lock_version {found} is not supported")]
    #[diagnostic(
        code(pixi_sbom::pdm::version),
        help("pixi-sbom reads lock_version 4.x; run `pdm lock` with a current PDM to rewrite it")
    )]
    Version {
        /// The version the file declares.
        found: String,
    },

    /// A package's or a dependency's environment marker could not be parsed.
    #[error("the marker on {package} cannot be parsed: {marker}")]
    #[diagnostic(code(pixi_sbom::pdm::marker), help("{message}"))]
    Marker {
        /// The package carrying it.
        package: String,
        /// The marker or requirement as written.
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

/// A parsed `pdm.lock`, with the text it was parsed from.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed lockfile.
    pub lock: PdmLock,
    /// The source text, which identifies the input for reproducible document ids.
    pub contents: String,
}

/// The parts of a `pdm.lock` a document is built from.
#[derive(Debug, Clone, Deserialize)]
pub struct PdmLock {
    /// Lock-wide facts.
    pub metadata: Metadata,
    /// The locked packages.
    #[serde(default, rename = "package")]
    pub packages: Vec<PdmPackage>,
}

/// The `[metadata]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    /// `4.5.0` for current PDM.
    pub lock_version: String,
    /// The dependency groups the lock covers.
    #[serde(default)]
    pub groups: Vec<String>,
    /// The environments the lock targets.
    #[serde(default)]
    pub targets: Vec<Target>,
}

/// One `[[metadata.targets]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    /// The Pythons this target is for.
    #[serde(default)]
    pub requires_python: Option<String>,
}

/// One `[[package]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct PdmPackage {
    /// As written by PDM.
    pub name: String,
    /// The locked version.
    #[serde(default)]
    pub version: Option<String>,
    /// For an extra's entry, the extras it stands for.
    #[serde(default)]
    pub extras: Vec<String>,
    /// The environments the package is needed in.
    #[serde(default)]
    pub marker: Option<String>,
    /// The package's own `Requires-Python`.
    #[serde(default)]
    pub requires_python: Option<String>,
    /// The groups that need it (kept for the dependency-group work).
    #[serde(default)]
    pub groups: Vec<String>,
    /// PEP 508 requirements on other packages.
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// A git repository.
    #[serde(default)]
    pub git: Option<String>,
    /// The exact commit, for a git source.
    #[serde(default)]
    pub revision: Option<String>,
    /// A local path.
    #[serde(default)]
    pub path: Option<String>,
    /// Installed in editable mode.
    #[serde(default)]
    pub editable: bool,
    /// A direct URL.
    #[serde(default)]
    pub url: Option<String>,
    /// Its files, by name and hash.
    #[serde(default)]
    pub files: Vec<File>,
}

/// A `files` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct File {
    /// The file name.
    #[serde(default)]
    pub file: Option<String>,
    /// Where it was downloaded from, when the lock was made with `static_urls`.
    #[serde(default)]
    pub url: Option<String>,
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
            name: self.file.clone(),
            url: self.url.clone(),
            path: None,
            hashes,
        }
    }
}

/// Whether `path` names a PDM lockfile.
pub fn is_pdm_lock_name(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "pdm.lock")
}

/// Read and parse the lockfile at `path`.
pub fn load(path: &Path) -> Result<Loaded, PdmError> {
    let contents = std::fs::read_to_string(path).map_err(|source| PdmError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let lock = parse(&contents, &path.display().to_string())?;
    Ok(Loaded { lock, contents })
}

/// Parse lockfile text; `origin` names it in errors.
pub fn parse(contents: &str, origin: &str) -> Result<PdmLock, PdmError> {
    let version = toml::from_str::<toml::Table>(contents)
        .ok()
        .and_then(|table| table.get("metadata")?.get("lock_version")?.as_str().map(str::to_string));
    if let Some(found) = version.filter(|v| v.split('.').next() != Some("4")) {
        return Err(PdmError::Version { found });
    }
    toml::from_str(contents).map_err(|err| PdmError::Parse {
        path: origin.to_string(),
        message: err.message().to_string(),
    })
}

/// Build the document model for `platform` (`None` = the host).
pub fn build_sbom(lock: &PdmLock, platform: Option<&str>, root: Root, lockfile_name: &str) -> Result<Sbom, PdmError> {
    let platform = match platform {
        Some(name) => name.to_string(),
        None => rattler_conda_types::Platform::current()
            .map(|p| p.to_string())
            .ok_or(PylockError::UnknownCurrentPlatform)?,
    };
    let python = lock
        .metadata
        .targets
        .iter()
        .find_map(|t| t.requires_python.as_deref().and_then(pylock::python_floor))
        .unwrap_or_else(|| FALLBACK_PYTHON.to_string());
    let env = pylock::marker_environment(&platform, &python)?;
    let parse_marker = |package: &str, marker: &str| {
        MarkerTree::from_str(marker).map_err(|err| PdmError::Marker {
            package: package.to_string(),
            marker: marker.to_string(),
            message: err.to_string(),
        })
    };

    let mut selected = Vec::new();
    for package in &lock.packages {
        if let Some(marker) = &package.marker
            && !parse_marker(&package.name, marker)?.evaluate(&env, &[])
        {
            tracing::debug!(package = %package.name, %marker, %platform, "not installed on this platform");
            continue;
        }
        selected.push(package);
    }

    // One component per package; an extra's entry adds its edges to the package it extends.
    let key = |p: &PdmPackage| (purl::normalize_pypi_name(&p.name), p.version.clone());
    let mut components: BTreeMap<(String, Option<String>), Package> = BTreeMap::new();
    for package in selected.iter().filter(|p| p.extras.is_empty()) {
        components.insert(key(package), convert(package, &platform, &python)?);
    }
    let ids: BTreeMap<String, String> = components
        .iter()
        .map(|((name, _), package)| (name.clone(), package.id.clone()))
        .collect();
    let mut edges: BTreeMap<(String, Option<String>), BTreeSet<String>> = BTreeMap::new();
    for package in &selected {
        let from = key(package);
        for requirement in &package.dependencies {
            let parsed = Requirement::<VerbatimUrl>::from_str(requirement).map_err(|err| PdmError::Marker {
                package: package.name.clone(),
                marker: requirement.clone(),
                message: err.to_string(),
            })?;
            if !parsed.marker.evaluate(&env, &[]) {
                continue;
            }
            if let Some(id) = ids.get(&purl::normalize_pypi_name(parsed.name.as_ref())) {
                edges.entry(from.clone()).or_default().insert(id.clone());
            }
        }
    }
    let mut packages: Vec<Package> = components
        .into_iter()
        .map(|(key, mut package)| {
            package.dependencies = edges
                .remove(&key)
                .unwrap_or_default()
                .into_iter()
                .filter(|id| *id != package.id)
                .collect();
            package
        })
        .collect();
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    tracing::info!(
        platform = %platform,
        python = %python,
        packages = packages.len(),
        of = lock.packages.len(),
        groups = ?lock.metadata.groups,
        "read pdm.lock"
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
fn convert(locked: &PdmPackage, platform: &str, python: &str) -> Result<Package, PdmError> {
    let purl = purl::pypi(&locked.name, locked.version.as_deref().unwrap_or("0"))?;
    let mut properties = BTreeMap::new();
    if let Some(marker) = &locked.marker {
        properties.insert("pixi:marker".into(), marker.clone());
    }
    if let Some(requires_python) = &locked.requires_python {
        properties.insert("pixi:requires-python".into(), requires_python.clone());
    }
    let mut sha256 = None;
    let location = if let Some(git) = &locked.git {
        properties.insert("pixi:direct-url".into(), git.clone());
        if let Some(commit) = &locked.revision {
            properties.insert("pixi:source-rev".into(), commit.clone());
        }
        Some(format!("git+{git}"))
    } else if let Some(path) = &locked.path {
        let reference = crate::lock::local_path_reference(path.trim_start_matches("./"));
        properties.insert("pixi:direct-url".into(), reference.clone());
        if locked.editable {
            properties.insert("pixi:editable".into(), "true".into());
        }
        Some(reference)
    } else if let Some(url) = &locked.url {
        properties.insert("pixi:direct-url".into(), url.clone());
        Some(url.clone())
    } else {
        let files: Vec<Artifact> = locked.files.iter().map(File::to_artifact).collect();
        let (wheels, sdists): (Vec<Artifact>, Vec<Artifact>) = files
            .into_iter()
            .partition(|a| a.name.as_deref().is_some_and(|n| n.ends_with(".whl")));
        let chosen = pylock::choose_artifact(&wheels, sdists.first(), platform, python);
        if let Some(chosen) = chosen {
            if let Some(name) = &chosen.name {
                properties.insert("pixi:file-name".into(), name.clone());
            }
            if sdists.first().is_some_and(|s| std::ptr::eq(chosen, s)) {
                properties.insert("pixi:source".into(), "true".into());
            }
            sha256 = chosen.hashes.get("sha256").cloned();
        }
        // A lock made with the static_urls strategy says where each file came from.
        chosen.and_then(|a| a.url.clone())
    };

    Ok(Package {
        id: purl.clone(),
        name: locked.name.clone(),
        version: locked.version.clone(),
        kind: PackageKind::Pypi,
        purl,
        supplier: None,
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
[metadata]
groups = ["default", "dev", "s3"]
strategy = ["inherit_metadata"]
lock_version = "4.5.0"
content_hash = "sha256:x"

[[metadata.targets]]
requires_python = ">=3.11,<3.12"

[[package]]
name = "django"
version = "3.2.12"
requires_python = ">=3.6"
groups = ["default", "dev"]
dependencies = ["asgiref<4,>=3.3.2", "sqlparse>=0.2.2", "tzdata; sys_platform == \"win32\""]
files = [
    {file = "Django-3.2.12-py3-none-any.whl", hash = "sha256:bb"},
    {file = "Django-3.2.12.tar.gz", hash = "sha256:aa"},
]

[[package]]
name = "django"
version = "3.2.12"
extras = ["argon2"]
requires_python = ">=3.6"
groups = ["default"]
dependencies = ["Django==3.2.12", "argon2-cffi>=19.1.0"]
files = [{file = "Django-3.2.12-py3-none-any.whl", hash = "sha256:bb"}]

[[package]]
name = "argon2-cffi"
version = "25.1.0"
groups = ["default"]
files = [{file = "argon2_cffi-25.1.0-py3-none-any.whl", url = "https://files.pythonhosted.org/a/argon2_cffi-25.1.0-py3-none-any.whl", hash = "sha256:cc"}]

[[package]]
name = "asgiref"
version = "3.8.1"
groups = ["default"]
files = []

[[package]]
name = "sqlparse"
version = "0.4.2"
groups = ["default"]
files = [{file = "sqlparse-0.4.2.tar.gz", hash = "sha256:dd"}]

[[package]]
name = "tzdata"
version = "2026.5"
groups = ["default"]
marker = "sys_platform == \"win32\""
files = []

[[package]]
name = "django-debug-toolbar"
version = "3.2.4"
git = "https://github.com/django-commons/django-debug-toolbar"
ref = "3.2.4"
revision = "9ec7210e"
groups = ["dev"]
dependencies = ["Django>=2.2"]

[[package]]
name = "internal-utils"
version = "0.3.0"
path = "./libs/internal-utils"
editable = true
groups = ["default"]
"#;

    fn sbom(platform: &str) -> Sbom {
        build_sbom(
            &parse(LOCK, "pdm.lock").unwrap(),
            Some(platform),
            Root::default(),
            "pdm.lock",
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
    fn an_extras_entry_is_folded_into_the_package_it_extends() {
        let linux = sbom("linux-64");
        assert_eq!(linux.packages.iter().filter(|p| p.name == "django").count(), 1);
        assert_eq!(
            package(&linux, "django").dependencies,
            [
                "pkg:pypi/argon2-cffi@25.1.0",
                "pkg:pypi/asgiref@3.8.1",
                "pkg:pypi/sqlparse@0.4.2"
            ],
            "the extra's package hangs off django; tzdata's edge is Windows-only"
        );
    }

    #[test]
    fn package_and_requirement_markers_are_evaluated_for_the_platform() {
        assert!(!sbom("linux-64").packages.iter().any(|p| p.name == "tzdata"));
        let windows = sbom("win-64");
        assert!(
            package(&windows, "django")
                .dependencies
                .contains(&"pkg:pypi/tzdata@2026.5".to_string())
        );
        assert_eq!(
            package(&windows, "tzdata").properties["pixi:marker"],
            "sys_platform == \"win32\""
        );
    }

    #[test]
    fn files_give_a_name_and_hash_and_a_url_only_when_the_lock_has_one() {
        let doc = sbom("linux-64");
        let django = package(&doc, "django");
        assert_eq!(django.location, "");
        assert_eq!(django.properties["pixi:file-name"], "Django-3.2.12-py3-none-any.whl");
        assert_eq!(django.sha256.as_deref(), Some("bb"));
        assert!(
            django.supplier.is_none(),
            "the lock does not say which source served it"
        );
        assert!(
            package(&doc, "argon2-cffi")
                .location
                .starts_with("https://files.pythonhosted.org/")
        );
        assert_eq!(package(&doc, "sqlparse").properties["pixi:source"], "true");

        let toolbar = package(&doc, "django-debug-toolbar");
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
    fn what_cannot_be_read_says_so() {
        let old = "[metadata]\nlock_version = \"3.0\"\n";
        assert!(matches!(parse(old, "pdm.lock"), Err(PdmError::Version { ref found }) if found == "3.0"));
        assert!(matches!(
            parse("[metadata]\nnope = 1\n", "x"),
            Err(PdmError::Parse { .. })
        ));
        assert!(is_pdm_lock_name(Path::new("a/pdm.lock")));
        let bad = LOCK.replace("\"asgiref<4,>=3.3.2\"", "\"asgiref <<< 4\"");
        assert!(matches!(
            build_sbom(&parse(&bad, "x").unwrap(), Some("linux-64"), Root::default(), "x"),
            Err(PdmError::Marker { .. })
        ));
        assert!(load(Path::new("/does/not/exist/pdm.lock")).is_err());
    }
}
