//! PEP 751 `pylock.toml`: the standard Python lockfile, written by `uv export --format
//! pylock.toml`, `pip lock` and others.
//!
//! One lockfile describes every environment it was resolved for, with an environment marker on
//! each package that is not needed everywhere. A document is for one platform, so the markers are
//! evaluated for it, the way pip and uv evaluate them, and a package whose marker is false for that
//! platform is not in the document.
//!
//! Neither uv nor pip writes the optional `[[packages.dependencies]]`, so a lockfile from either
//! has no dependency graph to read: its packages are recorded without edges rather than with
//! invented ones. When a writer does include them, they become the graph.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use miette::Diagnostic;
use pep508_rs::{MarkerEnvironment, MarkerEnvironmentBuilder, MarkerTree};
use serde::Deserialize;
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom, Supplier};
use crate::purl;

/// Python assumed for markers when a lockfile does not say (`pip lock` writes no
/// `requires-python`; its lockfile is for the one interpreter it ran on anyway).
const FALLBACK_PYTHON: &str = "3.14";

/// Errors from reading a `pylock.toml`.
#[derive(Debug, Error, Diagnostic)]
pub enum PylockError {
    /// The file could not be read.
    #[error("cannot read {path}")]
    #[diagnostic(code(pixi_sbom::pylock::read))]
    Read {
        /// The lockfile.
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The file is not a valid `pylock.toml`.
    #[error("{path} is not a valid pylock.toml")]
    #[diagnostic(code(pixi_sbom::pylock::parse), help("{message}"))]
    Parse {
        /// The lockfile.
        path: String,
        /// What the TOML parser said.
        message: String,
    },

    /// A lock-version this reader does not understand.
    #[error("pylock.toml lock-version {found} is not supported")]
    #[diagnostic(
        code(pixi_sbom::pylock::version),
        help("this version of pixi-sbom reads lock-version 1.x (PEP 751)")
    )]
    Version {
        /// The version the file declares.
        found: String,
    },

    /// A package's environment marker could not be parsed.
    #[error("the marker on {package} cannot be parsed: {marker}")]
    #[diagnostic(code(pixi_sbom::pylock::marker), help("{message}"))]
    Marker {
        /// The package carrying it.
        package: String,
        /// The marker as written.
        marker: String,
        /// What the parser said.
        message: String,
    },

    /// A platform whose environment markers this reader does not know how to evaluate.
    #[error("cannot evaluate environment markers for platform {platform}")]
    #[diagnostic(code(pixi_sbom::pylock::platform), help("choose one of {known} with --platform"))]
    Platform {
        /// The platform asked for.
        platform: String,
        /// The platforms that are supported.
        known: String,
    },

    /// The host platform could not be determined and none was given.
    #[error("cannot determine the current platform")]
    #[diagnostic(
        code(pixi_sbom::pylock::current_platform),
        help("pass the platform explicitly with --platform")
    )]
    UnknownCurrentPlatform,

    /// A package name the purl spec rejects.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

/// A parsed `pylock.toml`, with the text it was parsed from.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed lockfile.
    pub lock: Pylock,
    /// The source text, which identifies the input for reproducible document ids.
    pub contents: String,
}

/// The parts of a PEP 751 lockfile a document is built from. Keys this reader has no use for
/// (attestations, tool tables, `extras`, `dependency-groups`) are ignored rather than rejected.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Pylock {
    /// `1.0` for PEP 751.
    pub lock_version: String,
    /// The tool that wrote the file.
    #[serde(default)]
    pub created_by: Option<String>,
    /// The Pythons the lock is for.
    #[serde(default)]
    pub requires_python: Option<String>,
    /// The locked packages.
    #[serde(default)]
    pub packages: Vec<LockedPackage>,
}

/// One `[[packages]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LockedPackage {
    /// Normalised or not; it is normalised for the purl.
    pub name: String,
    /// Absent for a directory or VCS source whose version was not recorded.
    #[serde(default)]
    pub version: Option<String>,
    /// The environments the package is installed in; absent means all of them.
    #[serde(default)]
    pub marker: Option<String>,
    /// The package's own `Requires-Python`.
    #[serde(default)]
    pub requires_python: Option<String>,
    /// The index the package came from.
    #[serde(default)]
    pub index: Option<String>,
    /// Other packages this one depends on, when the writer recorded them.
    #[serde(default)]
    pub dependencies: Vec<DependencyRef>,
    /// A version-control source.
    #[serde(default)]
    pub vcs: Option<Vcs>,
    /// A local directory source.
    #[serde(default)]
    pub directory: Option<Directory>,
    /// A single archive (not from an index).
    #[serde(default)]
    pub archive: Option<Artifact>,
    /// The source distribution, for an index package.
    #[serde(default)]
    pub sdist: Option<Artifact>,
    /// The wheels, for an index package.
    #[serde(default)]
    pub wheels: Vec<Artifact>,
}

/// A `dependencies` entry: enough keys to pick out one `[[packages]]` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct DependencyRef {
    /// The package depended on.
    pub name: String,
    /// Its version, when the name alone is ambiguous.
    #[serde(default)]
    pub version: Option<String>,
}

/// A `packages.vcs` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Vcs {
    /// `git`, `hg`, `bzr` or `svn`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The repository.
    #[serde(default)]
    pub url: Option<String>,
    /// A local repository, when there is no URL.
    #[serde(default)]
    pub path: Option<String>,
    /// The exact commit.
    pub commit_id: String,
}

/// A `packages.directory` table.
#[derive(Debug, Clone, Deserialize)]
pub struct Directory {
    /// Relative to the lockfile.
    pub path: String,
    /// Installed in editable mode.
    #[serde(default)]
    pub editable: Option<bool>,
}

/// A wheel, an sdist or an archive.
#[derive(Debug, Clone, Deserialize)]
pub struct Artifact {
    /// The file name; may be omitted when the URL or path ends in it.
    #[serde(default)]
    pub name: Option<String>,
    /// Where it is downloaded from.
    #[serde(default)]
    pub url: Option<String>,
    /// Where it is on disk, for a local file.
    #[serde(default)]
    pub path: Option<String>,
    /// Hashes by algorithm.
    #[serde(default)]
    pub hashes: BTreeMap<String, String>,
}

impl Artifact {
    /// The file name, from `name` or the end of the URL or path.
    fn file_name(&self) -> &str {
        self.name
            .as_deref()
            .or_else(|| self.url.as_deref().and_then(|url| url.rsplit('/').next()))
            .or_else(|| self.path.as_deref().and_then(|path| path.rsplit(['/', '\\']).next()))
            .unwrap_or("")
    }

    /// Where it is, as a URI reference.
    pub(crate) fn location(&self) -> Option<String> {
        self.url
            .clone()
            .or_else(|| self.path.as_deref().map(crate::lock::local_path_reference))
    }
}

/// Whether `path` names a PEP 751 lockfile: `pylock.toml`, or `pylock.<name>.toml` for a named one.
pub fn is_pylock_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "pylock.toml"
        || name
            .strip_prefix("pylock.")
            .and_then(|rest| rest.strip_suffix(".toml"))
            .is_some_and(|middle| !middle.is_empty() && !middle.contains('.'))
}

/// The environment a named lockfile describes: `dev` for `pylock.dev.toml`, `default` otherwise.
pub fn environment_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("pylock."))
        .and_then(|rest| rest.strip_suffix(".toml"))
        .filter(|middle| !middle.is_empty())
        .unwrap_or("default")
        .to_string()
}

/// Read and parse the lockfile at `path`.
pub fn load(path: &Path) -> Result<Loaded, PylockError> {
    let contents = std::fs::read_to_string(path).map_err(|source| PylockError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let lock = parse(&contents, &path.display().to_string())?;
    Ok(Loaded { lock, contents })
}

/// Parse lockfile text; `origin` names it in errors.
pub fn parse(contents: &str, origin: &str) -> Result<Pylock, PylockError> {
    let lock: Pylock = toml::from_str(contents).map_err(|err| PylockError::Parse {
        path: origin.to_string(),
        message: err.message().to_string(),
    })?;
    if lock.lock_version.split('.').next() != Some("1") {
        return Err(PylockError::Version {
            found: lock.lock_version.clone(),
        });
    }
    Ok(lock)
}

/// The marker values one conda platform stands for: `sys_platform`, `platform_system`, `os_name`
/// and `platform_machine`.
fn platform_markers(platform: &str) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    Some(match platform {
        "linux-64" => ("linux", "Linux", "posix", "x86_64"),
        "linux-aarch64" => ("linux", "Linux", "posix", "aarch64"),
        "linux-ppc64le" => ("linux", "Linux", "posix", "ppc64le"),
        "osx-64" => ("darwin", "Darwin", "posix", "x86_64"),
        "osx-arm64" => ("darwin", "Darwin", "posix", "arm64"),
        "win-64" => ("win32", "Windows", "nt", "AMD64"),
        "win-arm64" => ("win32", "Windows", "nt", "ARM64"),
        _ => return None,
    })
}

const KNOWN_PLATFORMS: &str = "linux-64, linux-aarch64, linux-ppc64le, osx-64, osx-arm64, win-64, win-arm64";

/// The lowest Python a `requires-python` allows, as `3.11`: the one the markers are evaluated
/// for, because a lockfile has to work there. `None` when there is no lower bound to read.
pub fn python_floor(requires_python: &str) -> Option<String> {
    requires_python.split(',').find_map(|clause| {
        let clause = clause.trim();
        let version = clause
            .strip_prefix(">=")
            .or_else(|| clause.strip_prefix("~="))
            .or_else(|| clause.strip_prefix("=="))?
            .trim()
            .trim_end_matches(".*");
        let mut parts = version.split('.');
        let (major, minor) = (parts.next()?, parts.next()?);
        (major.parse::<u32>().is_ok() && minor.parse::<u32>().is_ok()).then(|| format!("{major}.{minor}"))
    })
}

/// The marker environment for `platform` and Python `python` (`3.11`).
pub(crate) fn marker_environment(platform: &str, python: &str) -> Result<MarkerEnvironment, PylockError> {
    let (sys_platform, platform_system, os_name, platform_machine) =
        platform_markers(platform).ok_or_else(|| PylockError::Platform {
            platform: platform.to_string(),
            known: KNOWN_PLATFORMS.to_string(),
        })?;
    let full = format!("{python}.0");
    MarkerEnvironment::try_from(MarkerEnvironmentBuilder {
        implementation_name: "cpython",
        implementation_version: &full,
        os_name,
        platform_machine,
        platform_python_implementation: "CPython",
        platform_release: "",
        platform_system,
        platform_version: "",
        python_full_version: &full,
        python_version: python,
        sys_platform,
    })
    .map_err(|err| PylockError::Platform {
        platform: format!("{platform} with Python {python}: {err}"),
        known: KNOWN_PLATFORMS.to_string(),
    })
}

/// Whether a wheel's platform tag is installable on `platform`.
fn wheel_fits(file: &str, platform: &str) -> bool {
    let Some(stem) = file.strip_suffix(".whl") else {
        return false;
    };
    let tag = stem.rsplit('-').next().unwrap_or("");
    if tag == "any" {
        return true;
    }
    tag.split('.').any(|tag| match platform {
        "linux-64" => tag.contains("linux") && tag.ends_with("x86_64"),
        "linux-aarch64" => tag.contains("linux") && tag.ends_with("aarch64"),
        "linux-ppc64le" => tag.contains("linux") && tag.ends_with("ppc64le"),
        "osx-64" => {
            tag.starts_with("macosx")
                && (tag.ends_with("x86_64") || tag.ends_with("universal2") || tag.ends_with("intel"))
        }
        "osx-arm64" => tag.starts_with("macosx") && (tag.ends_with("arm64") || tag.ends_with("universal2")),
        "win-64" => tag == "win_amd64",
        "win-arm64" => tag == "win_arm64",
        _ => false,
    })
}

/// The artifact that stands for a package on `platform`: a universal wheel, else a wheel for the
/// platform (one built for `python` first), else the sdist. A lockfile lists one per platform and
/// Python; the document records the one this platform would install.
pub(crate) fn choose_artifact<'a>(
    wheels: &'a [Artifact],
    sdist: Option<&'a Artifact>,
    platform: &str,
    python: &str,
) -> Option<&'a Artifact> {
    let universal = wheels.iter().find(|w| w.file_name().ends_with("-none-any.whl"));
    let cp = format!("-cp{}-", python.replace('.', ""));
    let fitting: Vec<&Artifact> = wheels.iter().filter(|w| wheel_fits(w.file_name(), platform)).collect();
    universal
        .or_else(|| fitting.iter().find(|w| w.file_name().contains(&cp)).copied())
        .or_else(|| fitting.iter().find(|w| w.file_name().contains("-abi3-")).copied())
        .or_else(|| fitting.first().copied())
        .or(sdist)
        .or_else(|| wheels.first())
}

/// Whether `package` is the project the lockfile was written for: pip records it as a directory
/// package at the lockfile's own location.
fn is_the_project(package: &LockedPackage) -> bool {
    package
        .directory
        .as_ref()
        .is_some_and(|dir| matches!(dir.path.trim_end_matches('/'), "." | "" | "./"))
}

/// Build the document model for `platform` (`None` = the host).
pub fn build_sbom(
    lock: &Pylock,
    environment: &str,
    platform: Option<&str>,
    mut root: Root,
    lockfile_name: &str,
) -> Result<Sbom, PylockError> {
    let platform = match platform {
        Some(name) => name.to_string(),
        None => rattler_conda_types::Platform::current()
            .map(|p| p.to_string())
            .ok_or(PylockError::UnknownCurrentPlatform)?,
    };
    let python = match lock.requires_python.as_deref().and_then(python_floor) {
        Some(python) => python,
        None => {
            tracing::debug!(
                python = FALLBACK_PYTHON,
                "the lockfile names no Python; evaluating its markers for this one"
            );
            FALLBACK_PYTHON.to_string()
        }
    };
    let env = marker_environment(&platform, &python)?;

    let mut selected = Vec::new();
    for package in &lock.packages {
        if let Some(marker) = &package.marker {
            let tree = MarkerTree::from_str(marker).map_err(|err| PylockError::Marker {
                package: package.name.clone(),
                marker: marker.clone(),
                message: err.to_string(),
            })?;
            if !tree.evaluate(&env, &[]) {
                tracing::debug!(package = %package.name, %marker, %platform, "not installed on this platform");
                continue;
            }
        }
        if is_the_project(package) {
            if root.name.is_empty() {
                root.name.clone_from(&package.name);
            }
            if root.version.is_none() {
                root.version.clone_from(&package.version);
            }
            continue;
        }
        selected.push(package);
    }

    let mut packages = selected
        .iter()
        .map(|package| convert(package, &platform, &python))
        .collect::<Result<Vec<_>, _>>()?;
    link(&selected, &mut packages);
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    tracing::info!(
        platform = %platform,
        python = %python,
        packages = packages.len(),
        of = lock.packages.len(),
        writer = lock.created_by.as_deref().unwrap_or("unknown"),
        "read pylock.toml"
    );

    Ok(Sbom {
        root,
        environment: environment.to_string(),
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

/// One `[[packages]]` entry as a model package.
fn convert(package: &LockedPackage, platform: &str, python: &str) -> Result<Package, PylockError> {
    let purl = purl::pypi(&package.name, package.version.as_deref().unwrap_or("0"))?;
    let mut properties = BTreeMap::new();
    if let Some(marker) = &package.marker {
        properties.insert("pixi:marker".into(), marker.clone());
    }
    if let Some(requires_python) = &package.requires_python {
        properties.insert("pixi:requires-python".into(), requires_python.clone());
    }

    let mut supplier = None;
    let mut sha256 = None;
    let location = if let Some(vcs) = &package.vcs {
        let url = vcs
            .url
            .clone()
            .or_else(|| vcs.path.as_deref().map(crate::lock::local_path_reference))
            .unwrap_or_default();
        properties.insert("pixi:direct-url".into(), url.clone());
        properties.insert("pixi:source-rev".into(), vcs.commit_id.clone());
        Some(format!("{}+{url}", vcs.kind))
    } else if let Some(dir) = &package.directory {
        let reference = crate::lock::local_path_reference(&dir.path);
        properties.insert("pixi:direct-url".into(), reference.clone());
        if dir.editable == Some(true) {
            properties.insert("pixi:editable".into(), "true".into());
        }
        Some(reference)
    } else if let Some(archive) = &package.archive {
        let location = archive.location();
        if let Some(location) = &location {
            properties.insert("pixi:direct-url".into(), location.clone());
        }
        sha256 = archive.hashes.get("sha256").cloned();
        location
    } else {
        if let Some(index) = &package.index {
            properties.insert("pixi:index-url".into(), index.clone());
            supplier = Some(Supplier {
                name: url_host(index).unwrap_or_else(|| index.clone()),
                url: Some(index.clone()),
            });
        }
        let artifact = choose_artifact(&package.wheels, package.sdist.as_ref(), platform, python);
        if artifact.is_some_and(|a| package.sdist.as_ref().is_some_and(|s| std::ptr::eq(a, s))) {
            properties.insert("pixi:source".into(), "true".into());
        }
        sha256 = artifact.and_then(|a| a.hashes.get("sha256").cloned());
        artifact.and_then(Artifact::location)
    };

    Ok(Package {
        id: purl.clone(),
        name: package.name.clone(),
        version: package.version.clone(),
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

/// The host of an index URL, as the supplier's name.
pub(crate) fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?;
    (!host.is_empty()).then(|| host.to_string())
}

/// Dependency edges from `[[packages.dependencies]]`, where the writer recorded them. A reference
/// that names a package not in this platform's document (its marker was false) is dropped.
fn link(selected: &[&LockedPackage], packages: &mut [Package]) {
    let by_name: BTreeMap<String, Vec<(Option<&str>, String)>> =
        selected
            .iter()
            .zip(packages.iter())
            .fold(BTreeMap::new(), |mut map, (locked, package)| {
                map.entry(purl::normalize_pypi_name(&locked.name))
                    .or_default()
                    .push((locked.version.as_deref(), package.id.clone()));
                map
            });
    for (locked, package) in selected.iter().zip(packages.iter_mut()) {
        let mut edges: Vec<String> = locked
            .dependencies
            .iter()
            .filter_map(|dep| {
                let candidates = by_name.get(&purl::normalize_pypi_name(&dep.name))?;
                candidates
                    .iter()
                    .find(|(version, _)| dep.version.is_none() || dep.version.as_deref() == *version)
                    .map(|(_, id)| id.clone())
            })
            .filter(|id| *id != package.id)
            .collect();
        edges.sort();
        edges.dedup();
        package.dependencies = edges;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UV: &str = r#"
lock-version = "1.0"
created-by = "uv"
requires-python = "==3.11.*"

[[packages]]
name = "django"
version = "3.2.12"
index = "https://pypi.org/simple"
sdist = { url = "https://files.pythonhosted.org/packages/a/Django-3.2.12.tar.gz", hashes = { sha256 = "aa" } }
wheels = [{ url = "https://files.pythonhosted.org/packages/b/Django-3.2.12-py3-none-any.whl", hashes = { sha256 = "bb" } }]

[[packages]]
name = "colorama"
version = "0.4.6"
marker = "sys_platform == 'win32'"
index = "https://pypi.org/simple"
wheels = [{ url = "https://files.pythonhosted.org/packages/c/colorama-0.4.6-py2.py3-none-any.whl", hashes = { sha256 = "cc" } }]

[[packages]]
name = "psycopg2-binary"
version = "2.9.5"
index = "https://pypi.org/simple"
sdist = { url = "https://files.pythonhosted.org/packages/d/psycopg2-binary-2.9.5.tar.gz", hashes = { sha256 = "dd" } }
wheels = [
    { url = "https://files.pythonhosted.org/packages/e/psycopg2_binary-2.9.5-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", hashes = { sha256 = "e0" } },
    { url = "https://files.pythonhosted.org/packages/e/psycopg2_binary-2.9.5-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", hashes = { sha256 = "e1" } },
    { url = "https://files.pythonhosted.org/packages/e/psycopg2_binary-2.9.5-cp311-cp311-macosx_11_0_arm64.whl", hashes = { sha256 = "e2" } },
    { url = "https://files.pythonhosted.org/packages/e/psycopg2_binary-2.9.5-cp311-cp311-win_amd64.whl", hashes = { sha256 = "e3" } },
]

[[packages]]
name = "django-debug-toolbar"
version = "3.2.4"
vcs = { type = "git", url = "https://github.com/django-commons/django-debug-toolbar", requested-revision = "3.2.4", commit-id = "9ec7210e" }

[[packages]]
name = "internal-utils"
directory = { path = "libs/internal-utils", editable = true }
"#;

    const PIP: &str = r#"
lock-version = "1.0"
created-by = "pip"

[[packages]]
name = "cli-tool-example"
directory = { path = "." }

[[packages]]
name = "click"
version = "8.3.0"
wheels = [{ name = "click-8.3.0-py3-none-any.whl", url = "https://files.pythonhosted.org/packages/x/click-8.3.0-py3-none-any.whl", hashes = { sha256 = "ff" } }]

[[packages]]
name = "rich"
version = "14.0.0"
dependencies = [{ name = "click" }, { name = "markdown-it-py" }]
wheels = [{ name = "rich-14.0.0-py3-none-any.whl", url = "https://files.pythonhosted.org/packages/y/rich-14.0.0-py3-none-any.whl", hashes = { sha256 = "ee" } }]
"#;

    fn sbom(text: &str, platform: &str) -> Sbom {
        let lock = parse(text, "pylock.toml").unwrap();
        build_sbom(&lock, "default", Some(platform), Root::default(), "pylock.toml").unwrap()
    }

    fn package<'a>(sbom: &'a Sbom, name: &str) -> &'a Package {
        sbom.packages
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn file_names() {
        assert!(is_pylock_name(Path::new("pylock.toml")));
        assert!(is_pylock_name(Path::new("dir/pylock.dev.toml")));
        assert!(
            !is_pylock_name(Path::new("pylock.a.b.toml")),
            "PEP 751 names have one part"
        );
        assert!(!is_pylock_name(Path::new("pylock..toml")));
        assert!(!is_pylock_name(Path::new("pixi.lock")));
        assert!(!is_pylock_name(Path::new("poetry.lock")));
        assert_eq!(environment_name(Path::new("pylock.dev.toml")), "dev");
        assert_eq!(environment_name(Path::new("pylock.toml")), "default");
    }

    #[test]
    fn markers_are_evaluated_for_the_platform() {
        assert!(sbom(UV, "win-64").packages.iter().any(|p| p.name == "colorama"));
        let linux = sbom(UV, "linux-64");
        assert!(!linux.packages.iter().any(|p| p.name == "colorama"), "win32 only");
        assert_eq!(linux.platform, "linux-64");
        assert_eq!(
            package(&sbom(UV, "win-64"), "colorama").properties["pixi:marker"],
            "sys_platform == 'win32'"
        );
    }

    #[test]
    fn an_index_package_records_the_artifact_this_platform_installs() {
        let django = package(&sbom(UV, "linux-64"), "django").clone();
        assert_eq!(django.purl, "pkg:pypi/django@3.2.12");
        assert_eq!(django.kind, PackageKind::Pypi);
        assert!(django.location.ends_with("-py3-none-any.whl"), "the universal wheel");
        assert_eq!(django.sha256.as_deref(), Some("bb"));
        assert_eq!(django.properties["pixi:index-url"], "https://pypi.org/simple");
        assert_eq!(django.supplier.as_ref().unwrap().name, "pypi.org");

        let on = |platform| package(&sbom(UV, platform), "psycopg2-binary").sha256.clone();
        assert_eq!(
            on("linux-64").as_deref(),
            Some("e1"),
            "the cp311 manylinux wheel, not cp310"
        );
        assert_eq!(on("osx-arm64").as_deref(), Some("e2"));
        assert_eq!(on("win-64").as_deref(), Some("e3"));
        let aarch64 = package(&sbom(UV, "linux-aarch64"), "psycopg2-binary").clone();
        assert_eq!(aarch64.sha256.as_deref(), Some("dd"), "no wheel fits, so the sdist");
        assert_eq!(aarch64.properties["pixi:source"], "true");
    }

    #[test]
    fn vcs_and_directory_sources_keep_where_they_came_from() {
        let doc = sbom(UV, "linux-64");
        let toolbar = package(&doc, "django-debug-toolbar");
        assert_eq!(
            toolbar.location,
            "git+https://github.com/django-commons/django-debug-toolbar"
        );
        assert_eq!(
            toolbar.properties["pixi:direct-url"],
            "https://github.com/django-commons/django-debug-toolbar"
        );
        assert_eq!(toolbar.properties["pixi:source-rev"], "9ec7210e");

        let local = package(&doc, "internal-utils");
        assert_eq!(local.version, None);
        assert_eq!(local.location, "libs/internal-utils");
        assert_eq!(local.properties["pixi:direct-url"], "libs/internal-utils");
        assert_eq!(local.properties["pixi:editable"], "true");
    }

    #[test]
    fn the_project_itself_is_the_root_not_a_component() {
        let doc = sbom(PIP, "linux-64");
        assert_eq!(doc.root.name, "cli-tool-example");
        assert!(!doc.packages.iter().any(|p| p.name == "cli-tool-example"));
        // A manifest that names the project wins over the lockfile.
        let lock = parse(PIP, "pylock.toml").unwrap();
        let named = Root {
            name: "from-the-manifest".into(),
            ..Root::default()
        };
        let doc = build_sbom(&lock, "default", Some("linux-64"), named, "pylock.toml").unwrap();
        assert_eq!(doc.root.name, "from-the-manifest");
    }

    #[test]
    fn recorded_dependencies_become_edges_and_absent_ones_are_not_invented() {
        let doc = sbom(PIP, "linux-64");
        assert_eq!(
            package(&doc, "rich").dependencies,
            ["pkg:pypi/click@8.3.0"],
            "markdown-it-py is not locked"
        );
        assert!(package(&doc, "click").dependencies.is_empty());
        assert!(
            sbom(UV, "linux-64").packages.iter().all(|p| p.dependencies.is_empty()),
            "uv writes no graph"
        );
    }

    #[test]
    fn markers_use_the_lowest_python_the_lock_allows() {
        assert_eq!(python_floor("==3.11.*").as_deref(), Some("3.11"));
        assert_eq!(python_floor(">=3.14").as_deref(), Some("3.14"));
        assert_eq!(python_floor(">=3.10, <4").as_deref(), Some("3.10"));
        assert_eq!(python_floor("~=3.12.1").as_deref(), Some("3.12"));
        assert_eq!(python_floor("<3.15"), None);

        let text = r#"
lock-version = "1.0"
requires-python = ">=3.11"
[[packages]]
name = "tomli"
version = "2.0.1"
marker = "python_version < '3.11'"
[[packages]]
name = "exceptiongroup"
version = "1.2.0"
marker = "python_full_version < '3.12'"
"#;
        let names: Vec<String> = sbom(text, "linux-64").packages.into_iter().map(|p| p.name).collect();
        assert_eq!(names, ["exceptiongroup"]);
    }

    #[test]
    fn what_cannot_be_read_says_so() {
        assert!(matches!(
            parse("lock-version = \"2.0\"", "x"),
            Err(PylockError::Version { .. })
        ));
        assert!(matches!(parse("packages = 3", "x"), Err(PylockError::Parse { .. })));
        let bad_marker =
            "lock-version = \"1.0\"\n[[packages]]\nname = \"a\"\nversion = \"1\"\nmarker = \"sys_platform ==\"\n";
        let lock = parse(bad_marker, "x").unwrap();
        assert!(matches!(
            build_sbom(&lock, "default", Some("linux-64"), Root::default(), "x"),
            Err(PylockError::Marker { .. })
        ));
        let lock = parse(UV, "x").unwrap();
        assert!(matches!(
            build_sbom(&lock, "default", Some("emscripten-wasm32"), Root::default(), "x"),
            Err(PylockError::Platform { .. })
        ));
        assert!(load(Path::new("/does/not/exist/pylock.toml")).is_err());
    }

    #[test]
    fn urls_name_their_host() {
        assert_eq!(url_host("https://pypi.org/simple").as_deref(), Some("pypi.org"));
        assert_eq!(
            url_host("https://user:pw@mirror.internal:8443/x").as_deref(),
            Some("mirror.internal:8443")
        );
        assert_eq!(url_host("not a url"), None);
    }
}
