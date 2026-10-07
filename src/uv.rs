//! `uv.lock`: the lockfile uv writes for a project or a workspace.
//!
//! Unlike `pylock.toml`, it records the dependency graph, with environment markers on the edges
//! rather than on the packages, and extras requested along an edge (`django[argon2]`). A
//! document is for one platform, so the packages in it are the ones reached from the workspace
//! members along edges whose markers hold there. Every member's extras and dependency groups are
//! followed: the lockfile describes all of them, and which one brought a package in is recorded
//! by the extras and groups work rather than by leaving packages out.
//!
//! Workspace members are first-party. The member at the workspace root is the document's root;
//! the others are components with a `pkg:generic` purl, since a `pkg:pypi` purl would claim a
//! PyPI release that does not exist.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::str::FromStr;

use miette::Diagnostic;
use pep508_rs::MarkerTree;
use serde::Deserialize;
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom, Supplier};
use crate::purl;
use crate::pylock::{self, Artifact, PylockError};

/// The `uv.lock` version this reader understands. uv bumps `revision` for additive changes and
/// `version` for incompatible ones.
const SUPPORTED_VERSION: u32 = 1;

/// Python assumed for markers when the lockfile names none.
const FALLBACK_PYTHON: &str = "3.14";

/// Errors from reading a `uv.lock`.
#[derive(Debug, Error, Diagnostic)]
pub enum UvError {
    /// The file could not be read.
    #[error("cannot read {path}")]
    #[diagnostic(code(pixi_sbom::uv::read))]
    Read {
        /// The lockfile.
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The file is not a valid `uv.lock`.
    #[error("{path} is not a valid uv.lock")]
    #[diagnostic(code(pixi_sbom::uv::parse), help("{message}"))]
    Parse {
        /// The lockfile.
        path: String,
        /// What the TOML parser said.
        message: String,
    },

    /// A lockfile version this reader does not understand.
    #[error("uv.lock version {found} is not supported")]
    #[diagnostic(
        code(pixi_sbom::uv::version),
        help("this version of pixi-sbom reads uv.lock version {SUPPORTED_VERSION}; a newer pixi-sbom may read it")
    )]
    Version {
        /// The version the file declares.
        found: u32,
    },

    /// An edge's environment marker could not be parsed.
    #[error("the marker on {from} -> {to} cannot be parsed: {marker}")]
    #[diagnostic(code(pixi_sbom::uv::marker), help("{message}"))]
    Marker {
        /// The package the edge leaves.
        from: String,
        /// The package it points at.
        to: String,
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

/// A parsed `uv.lock`, with the text it was parsed from.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed lockfile.
    pub lock: UvLock,
    /// The source text, which identifies the input for reproducible document ids.
    pub contents: String,
}

/// The parts of a `uv.lock` a document is built from.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct UvLock {
    /// The lockfile format version.
    pub version: u32,
    /// The Pythons the lock is for.
    #[serde(default)]
    pub requires_python: Option<String>,
    /// The workspace members, for a workspace.
    #[serde(default)]
    pub manifest: Option<UvManifest>,
    /// The locked packages.
    #[serde(default, rename = "package")]
    pub packages: Vec<UvPackage>,
}

/// The `[manifest]` table of a workspace lock.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UvManifest {
    /// The member projects, by name.
    #[serde(default)]
    pub members: Vec<String>,
}

/// One `[[package]]` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct UvPackage {
    /// As written by uv.
    pub name: String,
    /// Absent for a dynamic-version local project.
    #[serde(default)]
    pub version: Option<String>,
    /// Where it comes from: one of `registry`, `git`, `editable`, `virtual`, `path`, `directory`
    /// or `url`, with its location.
    #[serde(default)]
    pub source: BTreeMap<String, String>,
    /// Its dependencies.
    #[serde(default)]
    pub dependencies: Vec<Edge>,
    /// Its extras' dependencies.
    #[serde(default)]
    pub optional_dependencies: BTreeMap<String, Vec<Edge>>,
    /// Its dependency groups (uv's own name for them, from before PEP 735).
    #[serde(default)]
    pub dev_dependencies: BTreeMap<String, Vec<Edge>>,
    /// For a package locked at more than one version, the environments this one is for.
    #[serde(default)]
    pub resolution_markers: Vec<String>,
    /// Its source distribution.
    #[serde(default)]
    pub sdist: Option<UvArtifact>,
    /// Its wheels.
    #[serde(default)]
    pub wheels: Vec<UvArtifact>,
}

/// A dependency edge.
#[derive(Debug, Clone, Deserialize)]
pub struct Edge {
    /// The package depended on.
    pub name: String,
    /// Its version, when the name alone is ambiguous.
    #[serde(default)]
    pub version: Option<String>,
    /// Its source, when name and version are still ambiguous.
    #[serde(default)]
    pub source: Option<BTreeMap<String, String>>,
    /// Extras of the target the edge asks for.
    #[serde(default)]
    pub extra: Vec<String>,
    /// The environments the edge applies in.
    #[serde(default)]
    pub marker: Option<String>,
}

/// A wheel or sdist entry.
#[derive(Debug, Clone, Deserialize)]
pub struct UvArtifact {
    /// Where it is downloaded from.
    #[serde(default)]
    pub url: Option<String>,
    /// Where it is on disk.
    #[serde(default)]
    pub path: Option<String>,
    /// The file name, when neither of the above ends in it.
    #[serde(default)]
    pub filename: Option<String>,
    /// `sha256:<hex>`.
    #[serde(default)]
    pub hash: Option<String>,
}

impl UvArtifact {
    fn to_artifact(&self) -> Artifact {
        let mut hashes = BTreeMap::new();
        if let Some((algorithm, digest)) = self.hash.as_deref().and_then(|h| h.split_once(':')) {
            hashes.insert(algorithm.to_string(), digest.to_string());
        }
        Artifact {
            name: self.filename.clone(),
            url: self.url.clone(),
            path: self.path.clone(),
            hashes,
        }
    }
}

/// Whether `path` names a uv lockfile.
pub fn is_uv_lock_name(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "uv.lock")
}

/// Read and parse the lockfile at `path`.
pub fn load(path: &Path) -> Result<Loaded, UvError> {
    let contents = std::fs::read_to_string(path).map_err(|source| UvError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let lock = parse(&contents, &path.display().to_string())?;
    Ok(Loaded { lock, contents })
}

/// Parse lockfile text; `origin` names it in errors.
pub fn parse(contents: &str, origin: &str) -> Result<UvLock, UvError> {
    let lock: UvLock = toml::from_str(contents).map_err(|err| UvError::Parse {
        path: origin.to_string(),
        message: err.message().to_string(),
    })?;
    if lock.version != SUPPORTED_VERSION {
        return Err(UvError::Version { found: lock.version });
    }
    Ok(lock)
}

/// Whether a package is a member of the workspace the lockfile was written for.
fn is_member(package: &UvPackage, members: &BTreeSet<String>) -> bool {
    package.source.contains_key("virtual")
        || members.contains(&purl::normalize_pypi_name(&package.name))
        || package.source.get("editable").is_some_and(|path| path == ".")
}

/// Whether a package is the project at the workspace root.
fn is_the_project(package: &UvPackage) -> bool {
    ["virtual", "editable", "directory"].iter().any(|kind| {
        package
            .source
            .get(*kind)
            .is_some_and(|path| matches!(path.as_str(), "." | "./"))
    })
}

/// Build the document model for `platform` (`None` = the host).
pub fn build_sbom(lock: &UvLock, platform: Option<&str>, mut root: Root, lockfile_name: &str) -> Result<Sbom, UvError> {
    let platform = match platform {
        Some(name) => name.to_string(),
        None => rattler_conda_types::Platform::current()
            .map(|p| p.to_string())
            .ok_or(PylockError::UnknownCurrentPlatform)?,
    };
    let python = lock
        .requires_python
        .as_deref()
        .and_then(pylock::python_floor)
        .unwrap_or_else(|| FALLBACK_PYTHON.to_string());
    let env = pylock::marker_environment(&platform, &python)?;

    let members: BTreeSet<String> = lock
        .manifest
        .as_ref()
        .map(|m| m.members.iter().map(|n| purl::normalize_pypi_name(n)).collect())
        .unwrap_or_default();
    let by_name: BTreeMap<String, Vec<usize>> =
        lock.packages
            .iter()
            .enumerate()
            .fold(BTreeMap::new(), |mut map, (i, package)| {
                map.entry(purl::normalize_pypi_name(&package.name)).or_default().push(i);
                map
            });
    let resolve = |edge: &Edge| -> Option<usize> {
        let candidates = by_name.get(&purl::normalize_pypi_name(&edge.name))?;
        candidates
            .iter()
            .copied()
            .filter(|&i| edge.version.is_none() || lock.packages[i].version == edge.version)
            .find(|&i| {
                edge.source
                    .as_ref()
                    .is_none_or(|source| *source == lock.packages[i].source)
            })
    };

    // Walk from every member, following the edges whose markers hold here. A package is visited
    // again only when a later edge asks for an extra the earlier ones did not.
    let mut done: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    let mut edges: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    let mut queue: VecDeque<(usize, BTreeSet<String>)> = lock
        .packages
        .iter()
        .enumerate()
        .filter(|(_, p)| is_member(p, &members))
        .map(|(i, p)| (i, p.optional_dependencies.keys().cloned().collect()))
        .collect();
    // What extras did along the way: edges taken only for an extra (`from`'s name and extra),
    // edges taken without one, and the extras each edge asked of its target.
    let mut gated: BTreeMap<(usize, usize), BTreeSet<String>> = BTreeMap::new();
    let mut plain: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut requested: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
    while let Some((i, extras)) = queue.pop_front() {
        let first = !done.contains_key(&i);
        let seen = done.entry(i).or_default();
        let new_extras: Vec<String> = extras.into_iter().filter(|e| !seen.contains(e)).collect();
        if !first && new_extras.is_empty() {
            continue;
        }
        seen.extend(new_extras.iter().cloned());
        let package = &lock.packages[i];
        let mut outgoing: Vec<(&Edge, Option<&str>)> = Vec::new();
        if first {
            outgoing.extend(package.dependencies.iter().map(|e| (e, None)));
            if is_member(package, &members) {
                outgoing.extend(package.dev_dependencies.values().flatten().map(|e| (e, None)));
            }
        }
        for extra in &new_extras {
            outgoing.extend(
                package
                    .optional_dependencies
                    .get(extra)
                    .into_iter()
                    .flatten()
                    .map(|e| (e, Some(extra.as_str()))),
            );
        }
        for (edge, via) in outgoing {
            if let Some(marker) = &edge.marker {
                let tree = MarkerTree::from_str(marker).map_err(|err| UvError::Marker {
                    from: package.name.clone(),
                    to: edge.name.clone(),
                    marker: marker.clone(),
                    message: err.to_string(),
                })?;
                if !tree.evaluate(&env, &[]) {
                    continue;
                }
            }
            let Some(target) = resolve(edge) else {
                tracing::debug!(from = %package.name, to = %edge.name, "an edge names no locked package");
                continue;
            };
            edges.entry(i).or_default().insert(target);
            match via {
                Some(extra) => {
                    gated
                        .entry((i, target))
                        .or_default()
                        .insert(format!("{}[{extra}]", package.name));
                }
                None => {
                    plain.insert((i, target));
                }
            }
            if !edge.extra.is_empty() {
                requested.entry(target).or_default().extend(edge.extra.iter().cloned());
            }
            queue.push_back((target, edge.extra.iter().cloned().collect()));
        }
    }

    let project = lock.packages.iter().position(is_the_project);
    if let Some(project) = project.map(|i| &lock.packages[i]) {
        if root.name.is_empty() {
            root.name.clone_from(&project.name);
        }
        if root.version.is_none() {
            root.version.clone_from(&project.version);
        }
    }
    let direct: BTreeSet<usize> = project.and_then(|i| edges.get(&i)).cloned().unwrap_or_default();

    let reached: Vec<usize> = done.keys().copied().filter(|&i| Some(i) != project).collect();
    let mut ids: BTreeMap<usize, String> = BTreeMap::new();
    let mut packages = Vec::new();
    for &i in &reached {
        let locked = &lock.packages[i];
        let member = is_member(locked, &members);
        let mut package = convert(locked, member, &platform, &python)?;
        if direct.contains(&i) {
            package.properties.insert("pixi:direct".into(), "true".into());
        }
        ids.insert(i, package.id.clone());
        packages.push((i, package));
    }
    for (i, package) in &mut packages {
        let mut deps: Vec<String> = edges
            .get(i)
            .into_iter()
            .flatten()
            .filter_map(|target| ids.get(target).cloned())
            .filter(|id| *id != package.id)
            .collect();
        deps.sort();
        deps.dedup();
        package.dependencies = deps;
    }
    let mut packages: Vec<Package> = packages.into_iter().map(|(_, p)| p).collect();

    // Extras: what each package was asked for, and what is here only because of one. The
    // project's own extras are labelled with its name; its other edges are the roots.
    let mut extras = crate::extras::Extras::default();
    for (target, asked) in &requested {
        if let Some(id) = ids.get(target) {
            extras.request(id, asked.iter().cloned());
        }
    }
    let mut roots: BTreeSet<String> = BTreeSet::new();
    for ((from, to), via) in &gated {
        if plain.contains(&(*from, *to)) {
            continue;
        }
        let Some(to_id) = ids.get(to) else { continue };
        if Some(*from) == project {
            extras
                .project
                .entry(to_id.clone())
                .or_default()
                .extend(via.iter().cloned());
        } else if let Some(from_id) = ids.get(from) {
            for label in via {
                extras
                    .gated
                    .entry((from_id.clone(), to_id.clone()))
                    .or_default()
                    .insert(label.clone());
            }
        }
    }
    for (from, to) in &plain {
        if Some(*from) == project
            && let Some(id) = ids.get(to)
        {
            roots.insert(id.clone());
        }
    }
    for (i, id) in &ids {
        if is_member(&lock.packages[*i], &members) {
            roots.insert(id.clone());
        }
    }
    if project.is_some() {
        extras.roots = Some(roots);
    }
    extras.apply(&mut packages);
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    tracing::info!(
        platform = %platform,
        python = %python,
        packages = packages.len(),
        of = lock.packages.len(),
        "read uv.lock"
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
        scopes: std::collections::BTreeMap::new(),
        interpreter: None,
    })
}

/// One locked package as a model package.
fn convert(locked: &UvPackage, member: bool, platform: &str, python: &str) -> Result<Package, UvError> {
    let version = locked.version.as_deref().unwrap_or("0");
    let (kind, purl) = if member {
        (PackageKind::External, purl::generic(&locked.name, version)?)
    } else {
        (PackageKind::Pypi, purl::pypi(&locked.name, version)?)
    };
    let mut properties = BTreeMap::new();
    if !locked.resolution_markers.is_empty() {
        properties.insert("pixi:resolution-markers".into(), locked.resolution_markers.join(" || "));
    }
    let mut supplier = None;
    let mut sha256 = None;
    let source = &locked.source;
    let location = if let Some(git) = source.get("git") {
        // `https://host/repo?rev=v1#<commit>`: the repository, then the exact commit.
        let (rest, commit) = git.split_once('#').unwrap_or((git.as_str(), ""));
        let repository = rest.split('?').next().unwrap_or(rest).to_string();
        properties.insert("pixi:direct-url".into(), repository.clone());
        if !commit.is_empty() {
            properties.insert("pixi:source-rev".into(), commit.to_string());
        }
        Some(format!("git+{repository}"))
    } else if let Some(path) = source
        .get("editable")
        .or_else(|| source.get("directory"))
        .or_else(|| source.get("virtual"))
    {
        let reference = crate::lock::local_path_reference(path);
        properties.insert("pixi:direct-url".into(), reference.clone());
        if source.contains_key("editable") {
            properties.insert("pixi:editable".into(), "true".into());
        }
        Some(reference)
    } else if let Some(path) = source.get("path") {
        let reference = crate::lock::local_path_reference(path);
        properties.insert("pixi:direct-url".into(), reference.clone());
        sha256 = locked
            .sdist
            .as_ref()
            .map(UvArtifact::to_artifact)
            .and_then(|a| a.hashes.get("sha256").cloned());
        Some(reference)
    } else if let Some(url) = source.get("url") {
        properties.insert("pixi:direct-url".into(), url.clone());
        sha256 = locked
            .sdist
            .as_ref()
            .map(UvArtifact::to_artifact)
            .and_then(|a| a.hashes.get("sha256").cloned());
        Some(url.clone())
    } else {
        if let Some(index) = source.get("registry") {
            properties.insert("pixi:index-url".into(), index.clone());
            supplier = Some(Supplier {
                name: pylock::url_host(index).unwrap_or_else(|| index.clone()),
                url: Some(index.clone()),
            });
        }
        let wheels: Vec<Artifact> = locked.wheels.iter().map(UvArtifact::to_artifact).collect();
        let sdist = locked.sdist.as_ref().map(UvArtifact::to_artifact);
        let chosen = pylock::choose_artifact(&wheels, sdist.as_ref(), platform, python);
        if chosen.is_some_and(|a| sdist.as_ref().is_some_and(|s| std::ptr::eq(a, s))) {
            properties.insert("pixi:source".into(), "true".into());
        }
        sha256 = chosen.and_then(|a| a.hashes.get("sha256").cloned());
        chosen.and_then(Artifact::location)
    };

    let mut package = Package {
        id: purl.clone(),
        name: locked.name.clone(),
        version: locked.version.clone(),
        kind,
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
    };
    purl::identify_pypi_source(&mut package)?;
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
version = 1
revision = 3
requires-python = "==3.11.*"

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "django", extra = ["argon2"] },
    { name = "internal-utils" },
]
[package.optional-dependencies]
s3 = [{ name = "boto3" }]
[package.dev-dependencies]
test = [{ name = "pytest" }]

[[package]]
name = "django"
version = "3.2.12"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "sqlparse" }]
sdist = { url = "https://files.pythonhosted.org/Django-3.2.12.tar.gz", hash = "sha256:aa" }
wheels = [{ url = "https://files.pythonhosted.org/Django-3.2.12-py3-none-any.whl", hash = "sha256:bb" }]
[package.optional-dependencies]
argon2 = [{ name = "argon2-cffi" }]
bcrypt = [{ name = "bcrypt" }]

[[package]]
name = "sqlparse"
version = "0.4.2"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "argon2-cffi"
version = "25.1.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "colorama", marker = "sys_platform == 'win32'" }]

[[package]]
name = "colorama"
version = "0.4.6"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "bcrypt"
version = "4.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "boto3"
version = "1.40.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { git = "https://github.com/pytest-dev/pytest?rev=8.0.0#abc123" }

[[package]]
name = "internal-utils"
version = "0.3.0"
source = { editable = "libs/internal-utils" }

[[package]]
name = "orphan"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
"#;

    fn sbom(text: &str, platform: &str) -> Sbom {
        build_sbom(
            &parse(text, "uv.lock").unwrap(),
            Some(platform),
            Root::default(),
            "uv.lock",
        )
        .unwrap()
    }

    fn names(sbom: &Sbom) -> Vec<&str> {
        sbom.packages.iter().map(|p| p.name.as_str()).collect()
    }

    fn package<'a>(sbom: &'a Sbom, name: &str) -> &'a Package {
        sbom.packages
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn the_graph_is_walked_from_the_project_along_edges_that_hold_here() {
        let linux = sbom(LOCK, "linux-64");
        assert_eq!(linux.root.name, "app");
        assert_eq!(linux.root.version.as_deref(), Some("0.1.0"));
        // django[argon2] brings argon2-cffi, not bcrypt; the project's extras and groups are all
        // followed; nothing reaches orphan; colorama is Windows-only.
        assert_eq!(
            names(&linux),
            ["argon2-cffi", "boto3", "django", "internal-utils", "pytest", "sqlparse"]
        );
        assert!(names(&sbom(LOCK, "win-64")).contains(&"colorama"));
        let django = package(&linux, "django");
        assert_eq!(
            django.dependencies,
            ["pkg:pypi/argon2-cffi@25.1.0", "pkg:pypi/sqlparse@0.4.2"]
        );
        assert_eq!(django.properties["pixi:direct"], "true");
        assert!(!package(&linux, "sqlparse").properties.contains_key("pixi:direct"));
    }

    #[test]
    fn sources_say_where_each_package_came_from() {
        let doc = sbom(LOCK, "linux-64");
        let django = package(&doc, "django");
        assert_eq!(django.purl, "pkg:pypi/django@3.2.12");
        assert!(django.location.ends_with("-py3-none-any.whl"));
        assert_eq!(django.sha256.as_deref(), Some("bb"));
        assert_eq!(django.supplier.as_ref().unwrap().name, "pypi.org");

        let pytest = package(&doc, "pytest");
        assert_eq!(pytest.location, "git+https://github.com/pytest-dev/pytest");
        assert_eq!(pytest.properties["pixi:source-rev"], "abc123");
        assert_eq!(
            pytest.purl, "pkg:github/pytest-dev/pytest@abc123",
            "the commit, not a PyPI release"
        );

        let local = package(&doc, "internal-utils");
        assert_eq!(local.properties["pixi:editable"], "true");
        assert!(local.purl.starts_with("pkg:generic/internal-utils"), "{}", local.purl);
        assert_eq!(local.location, "libs/internal-utils");
    }

    #[test]
    fn workspace_members_are_first_party_not_pypi_releases() {
        let text = r#"
version = 1
revision = 3
requires-python = ">=3.12"
[manifest]
members = ["acme-cli", "acme-platform"]
[[package]]
name = "acme-platform"
version = "2.1.0"
source = { editable = "." }
dependencies = [{ name = "acme-cli" }]
[[package]]
name = "acme-cli"
version = "0.4.0"
source = { editable = "packages/cli" }
dependencies = [{ name = "click" }]
[[package]]
name = "click"
version = "8.1.0"
source = { registry = "https://pypi.org/simple" }
"#;
        let doc = sbom(text, "linux-64");
        assert_eq!(doc.root.name, "acme-platform");
        let cli = package(&doc, "acme-cli");
        assert_eq!(cli.kind, PackageKind::External);
        assert_eq!(cli.purl, "pkg:generic/acme-cli@0.4.0");
        assert_eq!(cli.dependencies, ["pkg:pypi/click@8.1.0"]);
        assert_eq!(package(&doc, "click").kind, PackageKind::Pypi);
    }

    #[test]
    fn a_forked_package_keeps_its_resolution_markers_and_edges_pick_the_right_one() {
        let text = r#"
version = 1
revision = 3
requires-python = ">=3.11"
[[package]]
name = "app"
version = "1"
source = { virtual = "." }
dependencies = [
    { name = "numpy", version = "1.26.4", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version < '3.12'" },
    { name = "numpy", version = "2.1.0", source = { registry = "https://pypi.org/simple" }, marker = "python_full_version >= '3.12'" },
]
[[package]]
name = "numpy"
version = "1.26.4"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version < '3.12'"]
[[package]]
name = "numpy"
version = "2.1.0"
source = { registry = "https://pypi.org/simple" }
resolution-markers = ["python_full_version >= '3.12'"]
"#;
        let doc = sbom(text, "linux-64");
        let numpy = package(&doc, "numpy");
        assert_eq!(numpy.version.as_deref(), Some("1.26.4"), "the lock's floor is 3.11");
        assert_eq!(
            numpy.properties["pixi:resolution-markers"],
            "python_full_version < '3.12'"
        );
        assert_eq!(doc.packages.len(), 1);
    }

    #[test]
    fn what_cannot_be_read_says_so() {
        assert!(is_uv_lock_name(Path::new("dir/uv.lock")));
        assert!(!is_uv_lock_name(Path::new("pixi.lock")));
        assert!(matches!(
            parse("version = 2", "uv.lock"),
            Err(UvError::Version { found: 2 })
        ));
        assert!(matches!(parse("version = 'x'", "uv.lock"), Err(UvError::Parse { .. })));
        let bad = "version = 1\n[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { virtual = \".\" }\ndependencies = [{ name = \"b\", marker = \"os_name ==\" }]\n";
        assert!(matches!(
            build_sbom(&parse(bad, "x").unwrap(), Some("linux-64"), Root::default(), "x"),
            Err(UvError::Marker { .. })
        ));
        assert!(matches!(
            build_sbom(&parse(LOCK, "x").unwrap(), Some("plan9-mips"), Root::default(), "x"),
            Err(UvError::Environment(_))
        ));
        assert!(load(Path::new("/does/not/exist/uv.lock")).is_err());
    }
}
