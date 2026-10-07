//! `conda-lock.yml`: the unified lockfile conda-lock writes (version 1).
//!
//! One file pins an environment for several platforms; every package entry names its platform,
//! so a document for one platform holds that platform's entries. Conda packages are described
//! exactly as the `pixi.lock` reader describes them (purl, channel supplier, archive hashes,
//! file name), because both are read from the same archive URL; a `pixi.lock` and a
//! `conda-lock.yml` of the same environment give the same components. `manager: pip` entries are
//! PyPI packages.
//!
//! Two facts a `pixi.lock` records are not in a `conda-lock.yml` and are left out rather than
//! guessed: the build number and the archive size.

use std::collections::BTreeMap;
use std::path::Path;

use miette::Diagnostic;
use serde::Deserialize;
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom, Supplier};
use crate::purl::{self, CondaPurl};

/// The `conda-lock.yml` format version this reader understands.
const SUPPORTED_VERSION: u32 = 1;

/// Errors from reading a `conda-lock.yml`.
#[derive(Debug, Error, Diagnostic)]
pub enum CondaLockError {
    /// The file could not be read.
    #[error("cannot read {path}")]
    #[diagnostic(code(pixi_sbom::conda_lock::read))]
    Read {
        /// The lockfile.
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// The file is not a valid unified `conda-lock.yml`.
    #[error("{path} is not a valid conda-lock.yml")]
    #[diagnostic(code(pixi_sbom::conda_lock::parse), help("{message}"))]
    Parse {
        /// The lockfile.
        path: String,
        /// What the YAML parser said.
        message: String,
    },

    /// A format version this reader does not understand.
    #[error("conda-lock.yml version {found} is not supported")]
    #[diagnostic(
        code(pixi_sbom::conda_lock::version),
        help("pixi-sbom reads the unified conda-lock.yml, version {SUPPORTED_VERSION}")
    )]
    Version {
        /// The version the file declares.
        found: u32,
    },

    /// The platform asked for is not locked.
    #[error("platform {platform} is not in this conda-lock.yml")]
    #[diagnostic(
        code(pixi_sbom::conda_lock::platform),
        help("it locks {available}; choose one with --platform, or --all-platforms for each")
    )]
    PlatformNotFound {
        /// The platform asked for.
        platform: String,
        /// The platforms the file locks.
        available: String,
    },

    /// The host platform could not be determined and none was given.
    #[error("cannot determine the current platform")]
    #[diagnostic(
        code(pixi_sbom::conda_lock::current_platform),
        help("pass the platform explicitly with --platform")
    )]
    UnknownCurrentPlatform,

    /// A package name the purl spec rejects.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

/// A parsed `conda-lock.yml`, with the text it was parsed from.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed lockfile.
    pub lock: CondaLock,
    /// The source text, which identifies the input for reproducible document ids.
    pub contents: String,
}

/// The parts of a `conda-lock.yml` a document is built from.
#[derive(Debug, Clone, Deserialize)]
pub struct CondaLock {
    /// The format version.
    pub version: u32,
    /// Lock-wide facts.
    pub metadata: Metadata,
    /// Every locked package, for every platform.
    #[serde(default)]
    pub package: Vec<LockedPackage>,
}

/// The `metadata` mapping.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    /// The platforms locked.
    #[serde(default)]
    pub platforms: Vec<String>,
}

/// One `package` entry.
#[derive(Debug, Clone, Deserialize)]
pub struct LockedPackage {
    /// The package name.
    pub name: String,
    /// The locked version.
    pub version: String,
    /// `conda` or `pip`.
    pub manager: String,
    /// The platform this entry is for.
    pub platform: String,
    /// Its dependencies, by name, with their constraints.
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    /// The archive or wheel it was locked to.
    pub url: String,
    /// Its hashes, by algorithm.
    #[serde(default)]
    pub hash: BTreeMap<String, String>,
    /// `main`, `dev`, ... (kept for the dependency-group work).
    #[serde(default)]
    pub category: Option<String>,
}

/// Whether `path` names a unified conda-lock file.
pub fn is_conda_lock_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "conda-lock.yml" || name == "conda-lock.yaml")
}

/// Read and parse the lockfile at `path`.
pub fn load(path: &Path) -> Result<Loaded, CondaLockError> {
    let contents = std::fs::read_to_string(path).map_err(|source| CondaLockError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let lock = parse(&contents, &path.display().to_string())?;
    Ok(Loaded { lock, contents })
}

/// Parse lockfile text; `origin` names it in errors.
pub fn parse(contents: &str, origin: &str) -> Result<CondaLock, CondaLockError> {
    let version = serde_yaml::from_str::<serde_yaml::Value>(contents)
        .ok()
        .and_then(|value| value.get("version")?.as_u64());
    if let Some(found) = version.filter(|v| *v != u64::from(SUPPORTED_VERSION)) {
        return Err(CondaLockError::Version {
            found: u32::try_from(found).unwrap_or(u32::MAX),
        });
    }
    serde_yaml::from_str(contents).map_err(|err| CondaLockError::Parse {
        path: origin.to_string(),
        message: err.to_string(),
    })
}

/// The platforms the lockfile locks, for `--all-platforms`.
pub fn platform_names(lock: &CondaLock) -> Vec<String> {
    lock.metadata.platforms.clone()
}

/// Build the document model for `platform` (`None` = the host).
pub fn build_sbom(
    lock: &CondaLock,
    platform: Option<&str>,
    root: Root,
    lockfile_name: &str,
) -> Result<Sbom, CondaLockError> {
    let platform = match platform {
        Some(name) => name.to_string(),
        None => rattler_conda_types::Platform::current()
            .map(|p| p.to_string())
            .ok_or(CondaLockError::UnknownCurrentPlatform)?,
    };
    if !lock.metadata.platforms.contains(&platform) {
        return Err(CondaLockError::PlatformNotFound {
            platform,
            available: lock.metadata.platforms.join(", "),
        });
    }
    let entries: Vec<&LockedPackage> = lock.package.iter().filter(|p| p.platform == platform).collect();
    let mut packages = entries.iter().map(|p| convert(p)).collect::<Result<Vec<_>, _>>()?;

    // Edges by name: a conda dependency names a conda package; a pip package's dependency names
    // a pip package, or the conda package that provides it.
    let conda_ids: BTreeMap<String, String> = entries
        .iter()
        .zip(&packages)
        .filter(|(e, _)| e.manager == "conda")
        .map(|(e, p)| (e.name.clone(), p.id.clone()))
        .collect();
    let pip_ids: BTreeMap<String, String> = entries
        .iter()
        .zip(&packages)
        .filter(|(e, _)| e.manager == "pip")
        .map(|(e, p)| (purl::normalize_pypi_name(&e.name), p.id.clone()))
        .collect();
    for (entry, package) in entries.iter().zip(packages.iter_mut()) {
        let mut deps: Vec<String> = entry
            .dependencies
            .keys()
            .filter(|name| !name.starts_with("__"))
            .filter_map(|name| match entry.manager.as_str() {
                "pip" => pip_ids
                    .get(&purl::normalize_pypi_name(name))
                    .or_else(|| conda_ids.get(name))
                    .cloned(),
                _ => conda_ids.get(name).cloned(),
            })
            .filter(|id| *id != package.id)
            .collect();
        deps.sort();
        deps.dedup();
        package.dependencies = deps;
    }
    // Categories other than `main` say what each package is for; all `main` says nothing.
    let categories: Vec<Option<&str>> = entries.iter().map(|e| e.category.as_deref()).collect();
    let scopes = if categories.iter().flatten().any(|c| *c != "main") {
        entries
            .iter()
            .zip(&packages)
            .filter_map(|(entry, package)| {
                let category = entry.category.as_deref()?;
                Some((package.id.clone(), crate::scope::Scope::from_category(category)))
            })
            .collect()
    } else {
        std::collections::BTreeMap::new()
    };
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    tracing::info!(platform = %platform, packages = packages.len(), "read conda-lock.yml");

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
        scopes,
    })
}

/// One entry as a model package.
fn convert(entry: &LockedPackage) -> Result<Package, CondaLockError> {
    if entry.manager == "pip" {
        return pip(entry);
    }
    Ok(conda_package(
        &entry.url,
        Some(&entry.name),
        Some(&entry.version),
        entry.hash.get("sha256").cloned(),
        entry.hash.get("md5").cloned(),
    )?)
}

/// A conda package from its archive URL, as the `pixi.lock` reader describes it:
/// `https://conda.anaconda.org/conda-forge/linux-64/python-3.11.9-h..._0_cpython.conda` gives the
/// channel, the subdir and the file name, and from the file name the build. `name` and `version`
/// are read from the file name (`<name>-<version>-<build>`) when the caller has none, as for an
/// explicit spec file, whose lines are bare URLs.
pub(crate) fn conda_package(
    url: &str,
    name: Option<&str>,
    version: Option<&str>,
    sha256: Option<String>,
    md5: Option<String>,
) -> Result<Package, purl::PurlError> {
    let (base, file_name) = url.rsplit_once('/').unwrap_or(("", url));
    let (channel_url, subdir) = base.rsplit_once('/').unwrap_or(("", base));
    let channel_url = format!("{channel_url}/");
    let channel = purl::channel_name_from_url(&channel_url).map(str::to_string);
    let archive_type = purl::archive_type_from_file_name(file_name);
    let stem = file_name
        .strip_suffix(".conda")
        .or_else(|| file_name.strip_suffix(".tar.bz2"))
        .unwrap_or(file_name);
    // Split from the right: a conda name may contain dashes, a version and a build may not.
    let mut parts = stem.rsplitn(3, '-');
    let (parsed_build, parsed_version, parsed_name) = (parts.next(), parts.next(), parts.next());
    let name = name.or(parsed_name).unwrap_or(stem).to_string();
    let version = version.or(parsed_version).map(str::to_string);
    let build = match &version {
        Some(version) => stem.strip_prefix(&format!("{name}-{version}-")).map(str::to_string),
        None => parsed_build.map(str::to_string),
    };

    let mut properties = BTreeMap::new();
    properties.insert("pixi:channel-url".into(), channel_url.clone());
    properties.insert("pixi:file-name".into(), file_name.to_string());
    if let Some(channel) = &channel {
        properties.insert("pixi:channel".into(), channel.clone());
    }
    properties.insert("pixi:subdir".into(), subdir.to_string());
    if let Some(build) = &build {
        properties.insert("pixi:build".into(), build.clone());
    }
    if subdir == "noarch" {
        properties.insert("pixi:noarch".into(), "true".into());
    }

    let purl = purl::conda(CondaPurl {
        name: &name,
        version: version.as_deref(),
        build: build.as_deref(),
        channel: channel.as_deref(),
        subdir: Some(subdir),
        archive_type,
    })?;
    Ok(Package {
        id: purl.clone(),
        name,
        version,
        kind: PackageKind::CondaBinary,
        purl,
        supplier: channel.map(|name| Supplier {
            name,
            url: Some(channel_url),
        }),
        extra_purls: Vec::new(),
        purls_from_lock: false,
        location: url.to_string(),
        sha256,
        md5,
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

/// A `manager: pip` entry, as a PyPI package.
fn pip(entry: &LockedPackage) -> Result<Package, CondaLockError> {
    let purl = purl::pypi(&entry.name, &entry.version)?;
    Ok(Package {
        id: purl.clone(),
        name: entry.name.clone(),
        version: Some(entry.version.clone()),
        kind: PackageKind::Pypi,
        purl,
        supplier: crate::pylock::url_host(&entry.url).map(|host| Supplier { name: host, url: None }),
        extra_purls: Vec::new(),
        purls_from_lock: false,
        location: entry.url.clone(),
        sha256: entry.hash.get("sha256").cloned(),
        md5: entry.hash.get("md5").cloned(),
        license: None,
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties: BTreeMap::new(),
        dependencies: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
version: 1
metadata:
  content_hash:
    linux-64: x
    osx-arm64: y
  channels:
  - url: conda-forge
    used_env_vars: []
  platforms:
  - linux-64
  - osx-arm64
  sources:
  - environment.yml
package:
- name: python
  version: 3.12.14
  manager: conda
  platform: linux-64
  dependencies:
    __glibc: '>=2.17,<3.0.a0'
    libzlib: '>=1.3.1,<2.0a0'
  url: https://conda.anaconda.org/conda-forge/linux-64/python-3.12.14-h5f976f7_3_cpython.conda
  hash:
    md5: m1
    sha256: s1
  category: main
  optional: false
- name: libzlib
  version: 1.3.1
  manager: conda
  platform: linux-64
  dependencies: {}
  url: https://conda.anaconda.org/conda-forge/linux-64/libzlib-1.3.1-hb9d3cd8_2.conda
  hash:
    md5: m2
    sha256: s2
  category: main
  optional: false
- name: django
  version: 3.2.12
  manager: conda
  platform: linux-64
  dependencies:
    python: '>=3.6'
  url: https://conda.anaconda.org/conda-forge/noarch/django-3.2.12-pyhd8ed1ab_0.tar.bz2
  hash:
    md5: m3
    sha256: s3
  category: main
  optional: false
- name: django-environ
  version: 0.9.0
  manager: pip
  platform: linux-64
  dependencies:
    django: '>=1.11'
  url: https://files.pythonhosted.org/packages/x/django_environ-0.9.0-py2.py3-none-any.whl
  hash:
    sha256: s4
  category: main
  optional: false
- name: python
  version: 3.12.14
  manager: conda
  platform: osx-arm64
  dependencies: {}
  url: https://conda.anaconda.org/conda-forge/osx-arm64/python-3.12.14-h1234_3_cpython.conda
  hash:
    md5: m5
    sha256: s5
  category: main
  optional: false
"#;

    fn sbom(platform: &str) -> Sbom {
        build_sbom(
            &parse(LOCK, "conda-lock.yml").unwrap(),
            Some(platform),
            Root::default(),
            "conda-lock.yml",
        )
        .unwrap()
    }

    #[test]
    fn categories_other_than_main_set_each_packages_scope() {
        use crate::scope::Scope;
        assert!(sbom("linux-64").scopes.is_empty(), "all main: nothing to tell apart");
        let text = LOCK.replacen("category: main", "category: dev", 1);
        let doc = build_sbom(
            &parse(&text, "conda-lock.yml").unwrap(),
            Some("linux-64"),
            Root::default(),
            "conda-lock.yml",
        )
        .unwrap();
        let scopes: Vec<Scope> = doc
            .packages
            .iter()
            .filter_map(|p| doc.scopes.get(&p.id).copied())
            .collect();
        assert!(scopes.contains(&Scope::Development));
        assert!(scopes.contains(&Scope::Required));
    }

    fn package<'a>(sbom: &'a Sbom, name: &str) -> &'a Package {
        sbom.packages
            .iter()
            .find(|p| p.name == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[test]
    fn a_conda_entry_is_described_as_the_pixi_lock_reader_describes_it() {
        let doc = sbom("linux-64");
        let python = package(&doc, "python");
        // The same purl the pixi.lock reader gives this exact archive (see tests/fixtures/with-pypi).
        assert_eq!(
            python.purl,
            "pkg:conda/python@3.12.14?build=h5f976f7_3_cpython&channel=conda-forge&subdir=linux-64&type=conda"
        );
        assert_eq!(python.kind, PackageKind::CondaBinary);
        assert_eq!(python.supplier.as_ref().unwrap().name, "conda-forge");
        assert_eq!(
            python.supplier.as_ref().unwrap().url.as_deref(),
            Some("https://conda.anaconda.org/conda-forge/")
        );
        assert_eq!(
            python.properties["pixi:channel-url"],
            "https://conda.anaconda.org/conda-forge/"
        );
        assert_eq!(python.properties["pixi:build"], "h5f976f7_3_cpython");
        assert_eq!(
            python.properties["pixi:file-name"],
            "python-3.12.14-h5f976f7_3_cpython.conda"
        );
        assert_eq!(
            (python.sha256.as_deref(), python.md5.as_deref()),
            (Some("s1"), Some("m1"))
        );
        assert!(
            !python.properties.contains_key("pixi:build-number"),
            "not in a conda-lock.yml"
        );
        assert_eq!(
            python.dependencies,
            ["pkg:conda/libzlib@1.3.1?build=hb9d3cd8_2&channel=conda-forge&subdir=linux-64&type=conda"],
            "__glibc is virtual"
        );

        let django = package(&doc, "django");
        assert!(django.purl.ends_with("subdir=noarch&type=tar.bz2"), "{}", django.purl);
        assert_eq!(django.properties["pixi:noarch"], "true");
    }

    #[test]
    fn pip_entries_are_pypi_packages_linked_to_the_conda_packages_they_need() {
        let doc = sbom("linux-64");
        let environ = package(&doc, "django-environ");
        assert_eq!(environ.kind, PackageKind::Pypi);
        assert_eq!(environ.purl, "pkg:pypi/django-environ@0.9.0");
        assert_eq!(environ.supplier.as_ref().unwrap().name, "files.pythonhosted.org");
        assert_eq!(environ.dependencies.len(), 1);
        assert!(environ.dependencies[0].starts_with("pkg:conda/django@3.2.12"));
    }

    #[test]
    fn each_platform_gets_its_own_entries() {
        assert_eq!(sbom("linux-64").packages.len(), 4);
        let mac = sbom("osx-arm64");
        assert_eq!(mac.packages.len(), 1);
        assert!(package(&mac, "python").purl.contains("subdir=osx-arm64"));
        assert_eq!(platform_names(&parse(LOCK, "x").unwrap()), ["linux-64", "osx-arm64"]);
        assert!(matches!(
            build_sbom(&parse(LOCK, "x").unwrap(), Some("win-64"), Root::default(), "x"),
            Err(CondaLockError::PlatformNotFound { .. })
        ));
    }

    #[test]
    fn what_cannot_be_read_says_so() {
        assert!(matches!(
            parse("version: 2\nmetadata: {}\n", "x"),
            Err(CondaLockError::Version { found: 2 })
        ));
        assert!(matches!(parse("version: 1\n", "x"), Err(CondaLockError::Parse { .. })));
        assert!(is_conda_lock_name(Path::new("a/conda-lock.yml")));
        assert!(is_conda_lock_name(Path::new("a/conda-lock.yaml")));
        assert!(!is_conda_lock_name(Path::new("a/environment.yml")));
        assert!(load(Path::new("/does/not/exist/conda-lock.yml")).is_err());
    }
}
