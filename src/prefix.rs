//! `--prefix <DIR>`: describe an installed environment that has no lockfile: a `pixi global`
//! environment, a conda / mamba / micromamba environment, an environment inside a container.
//! Conda packages come from `conda-meta/<name>-<version>-<build>.json` (the same fields as a
//! lock record), pip-installed packages from `site-packages/*.dist-info` (`METADATA`, and
//! `INSTALLER` to leave the ones conda put there to their conda package).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::lock::{DeclaredDeps, link_dependencies};
use crate::model::{Package, PackageKind, Root, Sbom, Supplier};
use crate::purl::{self, CondaPurl};
use crate::wheel;

/// Why a prefix could not be read.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum PrefixError {
    #[error("{path} is not a conda environment: it has no conda-meta directory")]
    #[diagnostic(
        code(pixi_sbom::prefix::not_an_environment),
        help("--prefix takes an environment directory such as ~/.pixi/envs/<name> or a conda env")
    )]
    NotAnEnvironment { path: PathBuf },
    #[error("cannot read {path}: {source}")]
    #[diagnostic(code(pixi_sbom::prefix::read))]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse the conda-meta record {path}: {source}")]
    #[diagnostic(code(pixi_sbom::prefix::record))]
    Record {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

/// The fields of a `conda-meta` record this tool reads.
#[derive(Debug, Deserialize)]
struct Record {
    name: String,
    version: String,
    build: String,
    #[serde(default)]
    build_number: Option<u64>,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    subdir: Option<String>,
    #[serde(default, rename = "fn")]
    file_name: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    md5: Option<String>,
    #[serde(default)]
    license: Option<String>,
    #[serde(default)]
    license_family: Option<String>,
    #[serde(default)]
    depends: Vec<String>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    noarch: Option<serde_json::Value>,
    #[serde(default)]
    extracted_package_dir: Option<String>,
}

/// Property naming the directory the package was extracted from, for `--fetch-licenses`.
pub const EXTRACTED_DIR_PROPERTY: &str = "pixi:extracted-package-dir";

/// The environment's name: the directory's file name.
pub fn environment_name(prefix: &Path) -> String {
    prefix
        .canonicalize()
        .ok()
        .as_deref()
        .and_then(Path::file_name)
        .or_else(|| prefix.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "prefix".into())
}

/// Read the environment at `prefix` into a model. `platform` overrides the one the records
/// name.
pub fn build_sbom(prefix: &Path, root: Root, platform: Option<&str>) -> Result<Sbom, PrefixError> {
    let meta = prefix.join("conda-meta");
    if !meta.is_dir() {
        return Err(PrefixError::NotAnEnvironment {
            path: prefix.to_path_buf(),
        });
    }
    let mut packages = Vec::new();
    let mut declared = Vec::new();
    let mut subdirs: BTreeMap<String, usize> = BTreeMap::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&meta)
        .map_err(|source| PrefixError::Read {
            path: meta.clone(),
            source,
        })?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    entries.sort();
    for path in entries {
        let text = std::fs::read_to_string(&path).map_err(|source| PrefixError::Read {
            path: path.clone(),
            source,
        })?;
        let record: Record = serde_json::from_str(&text).map_err(|source| PrefixError::Record {
            path: path.clone(),
            source,
        })?;
        if let Some(subdir) = record.subdir.as_deref().filter(|s| *s != "noarch") {
            *subdirs.entry(subdir.to_string()).or_default() += 1;
        }
        packages.push(conda_package(&record)?);
        declared.push(DeclaredDeps::Conda(record.depends));
    }

    for dist_info in dist_infos(prefix) {
        let Some((package, requires)) = pypi_package(&dist_info)? else {
            continue;
        };
        packages.push(package);
        declared.push(DeclaredDeps::Pypi(requires));
    }

    link_dependencies(&mut packages, &declared);
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    let platform = platform
        .map(str::to_string)
        .or_else(|| {
            subdirs
                .into_iter()
                .max_by_key(|(_, count)| *count)
                .map(|(subdir, _)| subdir)
        })
        .or_else(|| rattler_conda_types::Platform::current().map(|p| p.to_string()))
        .unwrap_or_else(|| "unknown".into());
    Ok(Sbom {
        root,
        environment: environment_name(prefix),
        platform,
        lockfile: String::new(),
        prefix: Some(environment_name(prefix)),
        packages,
        vulnerabilities: Vec::new(),
        excluded: Vec::new(),
    })
}

fn conda_package(record: &Record) -> Result<Package, PrefixError> {
    let mut properties = BTreeMap::new();
    let channel_url = record.channel.clone();
    let channel = channel_url
        .as_deref()
        .and_then(purl::channel_name_from_url)
        .map(str::to_string)
        // A bare channel name (`conda-forge`) is what older records carry.
        .or_else(|| channel_url.clone().filter(|c| !c.contains("://")));
    if let Some(url) = channel_url.as_deref().filter(|c| c.contains("://")) {
        properties.insert("pixi:channel-url".into(), url.to_string());
    }
    if let Some(channel) = &channel {
        properties.insert("pixi:channel".into(), channel.clone());
    }
    if let Some(subdir) = &record.subdir {
        properties.insert("pixi:subdir".into(), subdir.clone());
    }
    properties.insert("pixi:build".into(), record.build.clone());
    if let Some(number) = record.build_number {
        properties.insert("pixi:build-number".into(), number.to_string());
    }
    if let Some(family) = &record.license_family {
        properties.insert("pixi:license-family".into(), family.clone());
    }
    if let Some(size) = record.size {
        properties.insert("pixi:size".into(), size.to_string());
    }
    if record
        .noarch
        .as_ref()
        .is_some_and(|n| !n.is_null() && n.as_bool() != Some(false))
    {
        properties.insert("pixi:noarch".into(), "true".into());
    }
    let file_name = record
        .file_name
        .clone()
        .or_else(|| {
            record
                .url
                .as_deref()
                .and_then(|u| u.rsplit('/').next())
                .map(str::to_string)
        })
        .unwrap_or_else(|| format!("{}-{}-{}.conda", record.name, record.version, record.build));
    let archive_type = purl::archive_type_from_file_name(&file_name).map(str::to_string);
    properties.insert("pixi:file-name".into(), file_name.clone());
    if let Some(dir) = &record.extracted_package_dir {
        properties.insert(EXTRACTED_DIR_PROPERTY.into(), dir.clone());
    }
    let purl = purl::conda(CondaPurl {
        name: &record.name,
        version: Some(&record.version),
        build: Some(&record.build),
        channel: channel.as_deref(),
        subdir: record.subdir.as_deref(),
        archive_type: archive_type.as_deref(),
    })?;
    let location = record
        .url
        .clone()
        .unwrap_or_else(|| match (&channel_url, &record.subdir) {
            (Some(channel), Some(subdir)) if channel.contains("://") => {
                format!("{}/{subdir}/{file_name}", channel.trim_end_matches('/'))
            }
            _ => file_name.clone(),
        });
    Ok(Package {
        id: purl.clone(),
        name: record.name.clone(),
        version: Some(record.version.clone()),
        kind: PackageKind::CondaBinary,
        purl,
        supplier: channel.as_ref().map(|name| Supplier {
            name: name.clone(),
            url: channel_url.clone().filter(|c| c.contains("://")),
        }),
        extra_purls: Vec::new(),
        purls_from_lock: false,
        location,
        sha256: record.sha256.clone(),
        md5: record.md5.clone(),
        license: record.license.clone().filter(|l| !l.trim().is_empty()),
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

/// Every `*.dist-info` directory under the environment's site-packages, whichever layout the
/// platform uses.
fn dist_infos(prefix: &Path) -> Vec<PathBuf> {
    let mut roots = vec![prefix.join("Lib").join("site-packages")];
    if let Ok(lib) = std::fs::read_dir(prefix.join("lib")) {
        for entry in lib.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("python") {
                roots.push(entry.path().join("site-packages"));
            }
        }
    }
    let mut found = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.extension().is_some_and(|e| e == "dist-info") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// A pip-installed package from its `dist-info`; `None` when conda installed it (its conda
/// package is already listed) or the metadata is unusable.
fn pypi_package(dist_info: &Path) -> Result<Option<(Package, Vec<String>)>, PrefixError> {
    let installer = std::fs::read_to_string(dist_info.join("INSTALLER")).unwrap_or_default();
    if installer.trim().eq_ignore_ascii_case("conda") {
        return Ok(None);
    }
    let metadata = match std::fs::read_to_string(dist_info.join("METADATA")) {
        Ok(text) => text,
        Err(err) => {
            tracing::warn!(path = %dist_info.display(), %err, "dist-info without a readable METADATA; skipped");
            return Ok(None);
        }
    };
    let headers = wheel::parse_headers(&metadata);
    let first = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.first())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let (Some(name), Some(version)) = (first("name"), first("version")) else {
        tracing::warn!(path = %dist_info.display(), "dist-info METADATA without Name and Version; skipped");
        return Ok(None);
    };
    let purl = purl::pypi(&name, &version)?;
    let info = wheel::info_from_metadata(&metadata);
    let mut properties = BTreeMap::new();
    if let Some(python) = first("requires-python") {
        properties.insert("pixi:requires-python".into(), python);
    }
    if !installer.trim().is_empty() {
        properties.insert("pixi:installer".into(), installer.trim().to_string());
    }
    let mut location = format!(
        "file://{}",
        dist_info
            .display()
            .to_string()
            .replace('\\', "/")
            .trim_start_matches('/')
    );
    if !location.starts_with("file:///") {
        location = location.replacen("file://", "file:///", 1);
    }
    // PEP 610: where pip got it from, when it was a direct URL or VCS install.
    if let Ok(text) = std::fs::read_to_string(dist_info.join("direct_url.json"))
        && let Ok(direct) = serde_json::from_str::<serde_json::Value>(&text)
        && let Some(url) = direct.get("url").and_then(|u| u.as_str())
    {
        properties.insert("pixi:direct-url".into(), url.to_string());
        if let Some(vcs) = direct.get("vcs_info") {
            if let Some(commit) = vcs.get("commit_id").and_then(|c| c.as_str()) {
                properties.insert("pixi:source-rev".into(), commit.to_string());
            }
            location = format!("{}+{url}", vcs.get("vcs").and_then(|v| v.as_str()).unwrap_or("git"));
        }
    }
    let requires = headers
        .get("requires-dist")
        .into_iter()
        .flatten()
        .filter_map(|req| requirement_name(req))
        .collect();
    let license = info.license_expression.or(info.license);
    Ok(Some((
        Package {
            id: purl.clone(),
            name,
            version: Some(version),
            kind: PackageKind::Pypi,
            purl,
            supplier: None,
            extra_purls: Vec::new(),
            purls_from_lock: false,
            location,
            sha256: None,
            md5: None,
            license,
            license_files: Vec::new(),
            description: info.summary,
            homepage: info.homepage,
            repository: info.repository,
            documentation: info.documentation,
            yanked: None,
            properties,
            dependencies: Vec::new(),
        },
        requires,
    )))
}

/// The project name at the front of a PEP 508 requirement string.
fn requirement_name(requirement: &str) -> Option<String> {
    let name: String = requirement
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prefix")
    }

    #[test]
    fn reads_conda_meta_and_dist_info_and_links_them() {
        let sbom = build_sbom(&fixture(), Root::default(), None).unwrap();
        assert_eq!(sbom.environment, "prefix");
        assert_eq!(sbom.prefix.as_deref(), Some("prefix"));
        assert_eq!(sbom.platform, "linux-64", "the records' subdir, noarch ignored");
        assert_eq!(sbom.lockfile, "");
        let names: Vec<&str> = sbom.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["libzlib", "python", "tzdata", "six"],
            "conda first, then pypi; ruamel's dist-info skipped"
        );

        let python = sbom.packages.iter().find(|p| p.name == "python").unwrap();
        assert_eq!(python.kind, PackageKind::CondaBinary);
        assert_eq!(
            python.purl,
            "pkg:conda/python@3.12.14?build=h5f976f7_3_cpython&channel=conda-forge&subdir=linux-64&type=conda"
        );
        assert_eq!(python.supplier.as_ref().unwrap().name, "conda-forge");
        assert_eq!(python.license.as_deref(), Some("Python-2.0"));
        assert_eq!(python.properties["pixi:build-number"], "3");
        assert_eq!(
            python.properties["pixi:file-name"],
            "python-3.12.14-h5f976f7_3_cpython.conda"
        );
        assert_eq!(
            python.properties[EXTRACTED_DIR_PROPERTY],
            "/opt/pkgs/python-3.12.14-h5f976f7_3_cpython"
        );
        assert!(
            python
                .location
                .starts_with("https://conda.anaconda.org/conda-forge/linux-64/")
        );
        assert_eq!(
            python.dependencies,
            [
                "pkg:conda/libzlib@1.3.2?build=h25fd6f3_3&channel=conda-forge&subdir=linux-64&type=conda",
                "pkg:conda/tzdata@2026b?build=h78e105d_0&channel=conda-forge&subdir=noarch&type=conda"
            ]
        );
        let tzdata = sbom.packages.iter().find(|p| p.name == "tzdata").unwrap();
        assert_eq!(tzdata.properties["pixi:noarch"], "true");

        let six = sbom.packages.iter().find(|p| p.name == "six").unwrap();
        assert_eq!(six.kind, PackageKind::Pypi);
        assert_eq!(six.purl, "pkg:pypi/six@1.17.0");
        assert_eq!(six.license.as_deref(), Some("MIT"));
        assert_eq!(
            six.description.as_deref(),
            Some("Python 2 and 3 compatibility utilities")
        );
        assert_eq!(six.properties["pixi:installer"], "pip");
        assert!(six.location.starts_with("file:///"), "{}", six.location);
        assert!(six.location.ends_with("six-1.17.0.dist-info"));
        assert_eq!(
            six.dependencies,
            std::slice::from_ref(&python.id),
            "wheels hang off python"
        );
    }

    #[test]
    fn platform_override_and_errors() {
        let sbom = build_sbom(&fixture(), Root::default(), Some("osx-arm64")).unwrap();
        assert_eq!(sbom.platform, "osx-arm64");
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            build_sbom(dir.path(), Root::default(), None).unwrap_err(),
            PrefixError::NotAnEnvironment { .. }
        ));
        std::fs::create_dir_all(dir.path().join("conda-meta")).unwrap();
        std::fs::write(dir.path().join("conda-meta/bad-1.0-0.json"), "{").unwrap();
        assert!(matches!(
            build_sbom(dir.path(), Root::default(), None).unwrap_err(),
            PrefixError::Record { .. }
        ));
    }

    #[test]
    fn requirement_names() {
        assert_eq!(requirement_name("requests>=2,<3").as_deref(), Some("requests"));
        assert_eq!(
            requirement_name("charset_normalizer ; extra == 'x'").as_deref(),
            Some("charset_normalizer")
        );
        assert_eq!(
            requirement_name("ruamel.yaml[jinja2] (>=0.17)").as_deref(),
            Some("ruamel.yaml")
        );
        assert_eq!(requirement_name("  "), None);
    }
}
