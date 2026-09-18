//! Converts one environment/platform of a `pixi.lock` into the [`Sbom`] model.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use miette::Diagnostic;
use rattler_conda_types::{PackageName, PackageRecord};
use rattler_lock::{CondaPackageData, LockFile, LockedPackage, PackageHashes, PypiPackageData, UrlOrPath};
use thiserror::Error;

use crate::model::{Package, PackageKind, Root, Sbom};
use crate::purl::{self, CondaPurl};

/// Errors raised while reading the lockfile or selecting what to describe.
#[derive(Debug, Error, Diagnostic)]
pub enum LockError {
    /// The lockfile could not be parsed.
    #[error("cannot read lockfile {path}")]
    #[diagnostic(code(pixi_sbom::lock::parse))]
    Parse {
        /// Lockfile path.
        path: String,
        #[source]
        source: Box<rattler_lock::ParseCondaLockError>,
    },

    /// The requested environment is not in the lockfile.
    #[error("environment '{name}' not found in lockfile; available: {}", available.join(", "))]
    #[diagnostic(
        code(pixi_sbom::lock::environment),
        help("pass one of the available names with --environment")
    )]
    EnvironmentNotFound {
        /// Requested environment.
        name: String,
        /// Environments the lockfile defines.
        available: Vec<String>,
    },

    /// The requested platform is not locked for the environment.
    #[error("platform '{platform}' is not locked for environment '{environment}'; available: {}", available.join(", "))]
    #[diagnostic(
        code(pixi_sbom::lock::platform),
        help("pass one of the available platforms with --platform")
    )]
    PlatformNotFound {
        /// Requested platform.
        platform: String,
        /// Environment that was searched.
        environment: String,
        /// Platforms locked for that environment.
        available: Vec<String>,
    },

    /// The host platform could not be determined and none was given.
    #[error("cannot determine the current platform")]
    #[diagnostic(
        code(pixi_sbom::lock::current_platform),
        help("pass the platform explicitly with --platform")
    )]
    UnknownCurrentPlatform,

    /// A package name the purl spec rejects.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

/// What to extract from the lockfile.
#[derive(Debug, Clone)]
pub struct Selection<'a> {
    /// Lock environment name.
    pub environment: &'a str,
    /// Platform name; `None` means the host platform.
    pub platform: Option<&'a str>,
}

/// Parse `path` and build the SBOM model for the selected environment/platform.
pub fn build_sbom(path: &Path, selection: Selection<'_>, root: Root) -> Result<Sbom, LockError> {
    let lock = LockFile::from_path(path).map_err(|source| LockError::Parse {
        path: path.display().to_string(),
        source: Box::new(source),
    })?;
    sbom_from_lock(&lock, selection, root, &path.display().to_string())
}

/// Build the SBOM model from an already parsed lockfile.
pub fn sbom_from_lock(
    lock: &LockFile,
    selection: Selection<'_>,
    root: Root,
    lockfile_display: &str,
) -> Result<Sbom, LockError> {
    let environment = lock
        .environment(selection.environment)
        .ok_or_else(|| LockError::EnvironmentNotFound {
            name: selection.environment.to_string(),
            available: lock.environments().map(|(name, _)| name.to_string()).collect(),
        })?;

    let platform_name = match selection.platform {
        Some(name) => name.to_string(),
        None => current_platform_name()?,
    };
    let platform = environment
        .platforms()
        .find(|platform| platform.name().as_str() == platform_name)
        .ok_or_else(|| LockError::PlatformNotFound {
            platform: platform_name.clone(),
            environment: selection.environment.to_string(),
            available: environment.platforms().map(|p| p.name().to_string()).collect(),
        })?;

    let locked: Vec<&LockedPackage> = environment
        .packages(platform)
        .map(Iterator::collect)
        .unwrap_or_default();
    tracing::info!(
        environment = selection.environment,
        platform = %platform_name,
        packages = locked.len(),
        "selected lock environment"
    );

    let mut packages = locked
        .iter()
        .map(|package| convert_package(package))
        .collect::<Result<Vec<_>, _>>()?;
    resolve_dependencies(&locked, &mut packages);
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    Ok(Sbom {
        root,
        environment: selection.environment.to_string(),
        platform: platform_name,
        lockfile: lockfile_display.to_string(),
        packages,
    })
}

fn current_platform_name() -> Result<String, LockError> {
    rattler_conda_types::Platform::current()
        .map(|platform| platform.to_string())
        .ok_or(LockError::UnknownCurrentPlatform)
}

fn convert_package(package: &LockedPackage) -> Result<Package, LockError> {
    match package {
        LockedPackage::Conda(conda) => convert_conda(conda),
        LockedPackage::Pypi(pypi) => convert_pypi(pypi),
    }
}

fn convert_conda(conda: &CondaPackageData) -> Result<Package, LockError> {
    let name = conda.name().as_source().to_string();
    let location = location_string(conda.location());
    let record = conda.record();
    let version = record.map(|record| record.version.as_str().into_owned());
    let mut properties = BTreeMap::new();

    let (kind, channel, subdir, archive_type, build) = match conda {
        CondaPackageData::Binary(binary) => {
            let channel_url = binary.channel.as_ref().map(|c| c.url().to_string());
            let channel = channel_url
                .as_deref()
                .and_then(purl::channel_name_from_url)
                .map(str::to_string);
            if let Some(url) = &channel_url {
                properties.insert("pixi:channel-url".into(), url.clone());
            }
            let file_name = binary.file_name.to_string();
            let archive_type = purl::archive_type_from_file_name(&file_name).map(str::to_string);
            properties.insert("pixi:file-name".into(), file_name);
            (
                PackageKind::CondaBinary,
                channel,
                Some(binary.package_record.subdir.clone()),
                archive_type,
                Some(binary.package_record.build.clone()),
            )
        }
        CondaPackageData::Source(source) => {
            if let Some(hash) = &source.identifier_hash {
                properties.insert("pixi:identifier-hash".into(), hash.clone());
            }
            (
                PackageKind::CondaSource,
                None,
                record.map(|r| r.subdir.clone()),
                None,
                record.map(|r| r.build.clone()).filter(|b| !b.is_empty()),
            )
        }
    };

    if let Some(channel) = &channel {
        properties.insert("pixi:channel".into(), channel.clone());
    }
    if let Some(subdir) = &subdir {
        properties.insert("pixi:subdir".into(), subdir.clone());
    }
    if let Some(build) = &build {
        properties.insert("pixi:build".into(), build.clone());
    }
    if let Some(record) = record {
        add_record_properties(record, &mut properties);
    }

    let purl = purl::conda(CondaPurl {
        name: &name,
        version: version.as_deref().unwrap_or("0"),
        build: build.as_deref(),
        channel: channel.as_deref(),
        subdir: subdir.as_deref(),
        archive_type: archive_type.as_deref(),
    })?;
    let extra_purls = record
        .and_then(|record| record.purls.as_ref())
        .map(|purls| purls.iter().map(ToString::to_string).collect())
        .unwrap_or_default();

    Ok(Package {
        id: purl.clone(),
        name,
        version,
        kind,
        purl,
        extra_purls,
        location,
        sha256: record.and_then(|r| r.sha256.as_ref()).map(hex),
        md5: record.and_then(|r| r.md5.as_ref()).map(hex),
        license: record.and_then(|r| r.license.clone()),
        properties,
        dependencies: Vec::new(),
    })
}

fn add_record_properties(record: &PackageRecord, properties: &mut BTreeMap<String, String>) {
    properties.insert("pixi:build-number".into(), record.build_number.to_string());
    if let Some(family) = &record.license_family {
        properties.insert("pixi:license-family".into(), family.clone());
    }
    if let Some(size) = record.size {
        properties.insert("pixi:size".into(), size.to_string());
    }
    if !record.noarch.is_none() {
        properties.insert("pixi:noarch".into(), "true".into());
    }
}

fn convert_pypi(pypi: &PypiPackageData) -> Result<Package, LockError> {
    let name = pypi.name().to_string();
    let version = pypi.version().map(ToString::to_string);
    let purl = purl::pypi(&name, version.as_deref().unwrap_or("0"))?;
    let mut properties = BTreeMap::new();
    let hashes = pypi.as_wheel().and_then(|wheel| wheel.hash.as_ref());
    if let Some(index) = pypi.as_wheel().and_then(|wheel| wheel.index_url.as_ref()) {
        properties.insert("pixi:index-url".into(), index.to_string());
    }
    if let Some(requires_python) = pypi.requires_python() {
        properties.insert("pixi:requires-python".into(), requires_python.to_string());
    }
    if pypi.as_source().is_some() {
        properties.insert("pixi:source".into(), "true".into());
    }

    Ok(Package {
        id: purl.clone(),
        name,
        version,
        kind: PackageKind::Pypi,
        purl,
        extra_purls: Vec::new(),
        location: location_string(pypi.location().inner()),
        sha256: hashes.and_then(PackageHashes::sha256).map(hex),
        md5: hashes.and_then(PackageHashes::md5).map(hex),
        license: None,
        properties,
        dependencies: Vec::new(),
    })
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn location_string(location: &UrlOrPath) -> String {
    match location {
        UrlOrPath::Url(url) => url.to_string(),
        UrlOrPath::Path(path) => path.to_string(),
    }
}

/// Fill in `dependencies` on every package by resolving declared requirements
/// against the packages that are actually present in the environment. The solver
/// already picked one package per name, so resolution is by normalized name.
fn resolve_dependencies(locked: &[&LockedPackage], packages: &mut [Package]) {
    let conda_ids: HashMap<String, &str> = packages
        .iter()
        .filter(|p| p.kind != PackageKind::Pypi)
        .map(|p| {
            (
                PackageName::new_unchecked(p.name.to_lowercase())
                    .as_normalized()
                    .to_string(),
                p.id.as_str(),
            )
        })
        .collect();
    let pypi_ids: HashMap<String, &str> = packages
        .iter()
        .filter(|p| p.kind == PackageKind::Pypi)
        .map(|p| (purl::normalize_pypi_name(&p.name), p.id.as_str()))
        .collect();

    let resolved: Vec<Vec<String>> = locked
        .iter()
        .map(|package| match package {
            LockedPackage::Conda(conda) => conda
                .depends()
                .iter()
                .map(|spec| PackageName::normalized_name_from_matchspec_str(spec).into_owned())
                .filter(|dep| !dep.starts_with("__"))
                .filter_map(|dep| conda_ids.get(&dep).map(|id| (*id).to_string()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            LockedPackage::Pypi(pypi) => pypi
                .requires_dist()
                .iter()
                .map(|req| purl::normalize_pypi_name(req.name.as_ref()))
                .filter_map(|dep| {
                    pypi_ids
                        .get(&dep)
                        .or_else(|| conda_ids.get(&dep))
                        .map(|id| (*id).to_string())
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        })
        .collect();

    for (package, deps) in packages.iter_mut().zip(resolved) {
        package.dependencies = deps.into_iter().filter(|dep| dep != &package.id).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
            .join("pixi.lock")
    }

    fn root() -> Root {
        Root {
            name: "test".into(),
            version: Some("0.0.1".into()),
        }
    }

    fn select<'a>(environment: &'a str, platform: &'a str) -> Selection<'a> {
        Selection {
            environment,
            platform: Some(platform),
        }
    }

    #[test]
    fn conda_only_lock_yields_binary_packages_with_purls() {
        let sbom = build_sbom(&fixture("conda-only"), select("default", "linux-64"), root()).unwrap();

        assert_eq!(sbom.environment, "default");
        assert_eq!(sbom.platform, "linux-64");
        let names: Vec<_> = sbom.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["libzlib", "zlib"]);

        let zlib = &sbom.packages[1];
        assert_eq!(zlib.kind, PackageKind::CondaBinary);
        assert_eq!(zlib.version.as_deref(), Some("1.3.2"));
        assert_eq!(
            zlib.purl,
            "pkg:conda/zlib@1.3.2?build=h25fd6f3_3&channel=conda-forge&subdir=linux-64&type=conda"
        );
        assert!(zlib.location.ends_with("zlib-1.3.2-h25fd6f3_3.conda"));
        assert_eq!(zlib.sha256.as_deref().map(str::len), Some(64));
        assert_eq!(zlib.md5.as_deref().map(str::len), Some(32));
        assert_eq!(zlib.license.as_deref(), Some("Zlib"));
        assert_eq!(zlib.properties["pixi:channel"], "conda-forge");
        assert_eq!(zlib.properties["pixi:subdir"], "linux-64");
        assert_eq!(zlib.properties["pixi:build"], "h25fd6f3_3");
        assert_eq!(
            zlib.properties["pixi:channel-url"],
            "https://conda.anaconda.org/conda-forge/"
        );
        assert!(zlib.properties.contains_key("pixi:size"));
    }

    #[test]
    fn conda_dependencies_resolve_to_ids_and_skip_virtual_packages() {
        let sbom = build_sbom(&fixture("conda-only"), select("default", "linux-64"), root()).unwrap();

        let libzlib = &sbom.packages[0];
        let zlib = &sbom.packages[1];
        // libzlib depends only on __glibc (virtual) which must be dropped.
        assert!(libzlib.dependencies.is_empty());
        assert_eq!(zlib.dependencies, vec![libzlib.id.clone()]);
    }

    #[test]
    fn other_platform_is_selectable() {
        let sbom = build_sbom(&fixture("conda-only"), select("default", "osx-arm64"), root()).unwrap();

        assert_eq!(sbom.platform, "osx-arm64");
        assert!(sbom.packages.iter().all(|p| p.properties["pixi:subdir"] == "osx-arm64"));
    }

    #[test]
    fn pypi_packages_are_converted_and_link_to_conda_and_pypi_deps() {
        let sbom = build_sbom(&fixture("with-pypi"), select("web", "linux-64"), root()).unwrap();

        let pypi: Vec<_> = sbom.packages.iter().filter(|p| p.kind == PackageKind::Pypi).collect();
        let names: Vec<_> = pypi.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"requests"), "{names:?}");
        assert!(names.contains(&"six"), "{names:?}");

        let requests = pypi.iter().find(|p| p.name == "requests").unwrap();
        assert!(requests.purl.starts_with("pkg:pypi/requests@2."));
        assert_eq!(requests.sha256.as_deref().map(str::len), Some(64));
        assert!(requests.location.contains("files.pythonhosted.org"));
        assert!(requests.properties.contains_key("pixi:requires-python"));
        let dep_names: Vec<_> = requests
            .dependencies
            .iter()
            .map(|id| sbom.packages.iter().find(|p| &p.id == id).unwrap().name.as_str())
            .collect();
        for expected in ["charset-normalizer", "idna", "urllib3", "certifi"] {
            assert!(dep_names.contains(&expected), "{expected} missing from {dep_names:?}");
        }
    }

    #[test]
    fn noarch_python_packages_carry_noarch_property_and_python_dependency() {
        let sbom = build_sbom(&fixture("with-pypi"), select("default", "linux-64"), root()).unwrap();

        let python = sbom.packages.iter().find(|p| p.name == "python").unwrap();
        assert_eq!(python.kind, PackageKind::CondaBinary);
        assert!(python.dependencies.len() > 3, "python has many runtime deps");
        let noarch: Vec<_> = sbom
            .packages
            .iter()
            .filter(|p| p.properties.contains_key("pixi:noarch"))
            .collect();
        assert!(!noarch.is_empty());
        assert!(noarch.iter().all(|p| p.properties["pixi:subdir"] == "noarch"));
    }

    #[test]
    fn default_environment_excludes_feature_only_packages() {
        let default = build_sbom(&fixture("with-pypi"), select("default", "linux-64"), root()).unwrap();
        let web = build_sbom(&fixture("with-pypi"), select("web", "linux-64"), root()).unwrap();

        assert!(default.packages.iter().all(|p| p.name != "requests"));
        assert!(web.packages.len() > default.packages.len());
    }

    #[test]
    fn packages_are_sorted_deterministically() {
        let sbom = build_sbom(&fixture("with-pypi"), select("web", "linux-64"), root()).unwrap();

        let keys: Vec<_> = sbom.packages.iter().map(Package::sort_key).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        let ids: BTreeSet<_> = sbom.packages.iter().map(|p| &p.id).collect();
        assert_eq!(ids.len(), sbom.packages.len(), "ids are unique");
    }

    #[test]
    fn unknown_environment_lists_available() {
        let err = build_sbom(&fixture("with-pypi"), select("nope", "linux-64"), root()).unwrap_err();

        let text = err.to_string();
        assert!(text.contains("'nope'"));
        assert!(text.contains("default"));
        assert!(text.contains("web"));
    }

    #[test]
    fn unknown_platform_lists_available() {
        let err = build_sbom(&fixture("conda-only"), select("default", "win-64"), root()).unwrap_err();

        let text = err.to_string();
        assert!(text.contains("'win-64'"));
        assert!(text.contains("linux-64"));
        assert!(text.contains("osx-arm64"));
    }

    #[test]
    fn unparsable_lockfile_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pixi.lock");
        std::fs::write(&path, "version: 7\nthis: [is not a lockfile\n").unwrap();

        let err = build_sbom(&path, select("default", "linux-64"), root()).unwrap_err();
        assert!(matches!(err, LockError::Parse { .. }));
    }

    #[test]
    fn host_platform_is_used_when_none_given() {
        let host = rattler_conda_types::Platform::current().unwrap().to_string();
        let selection = Selection {
            environment: "default",
            platform: None,
        };
        let result = build_sbom(&fixture("conda-only"), selection, root());
        match result {
            Ok(sbom) => assert_eq!(sbom.platform, host),
            Err(LockError::PlatformNotFound { platform, .. }) => assert_eq!(platform, host),
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
