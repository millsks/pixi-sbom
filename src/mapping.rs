//! PyPI identity enrichment for conda packages.
//!
//! Vulnerability databases (OSV, GHSA) and scanners (grype, trivy, osv-scanner) have no conda
//! ecosystem, so a `pkg:conda/...` purl alone matches nothing. conda-forge publishes a
//! conda-name to PyPI-name mapping (parselmouth), the same one pixi uses to satisfy PyPI
//! requirements from conda packages. This module applies that mapping to packages whose lock
//! entry has no `purls:` (pixi only records purls for environments with `pypi-dependencies`)
//! and, on request, makes the PyPI purl the primary one so scanners can act on it.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use miette::Diagnostic;
use serde::Deserialize;
use thiserror::Error;

use crate::model::{PackageKind, Sbom};
use crate::purl;

/// Where the compressed conda-forge mapping is published.
pub const PREFIX_MAPPING_URL: &str = "https://conda-mapping.prefix.dev/compressed-v0/compressed_mapping.json";

/// How long a downloaded mapping is reused before it is fetched again.
pub const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Environment variable that overrides the cache directory.
pub const CACHE_DIR_ENV: &str = "PIXI_SBOM_CACHE_DIR";

/// Property recorded on every package whose PyPI purl came from a mapping.
pub const MAPPING_PROPERTY: &str = "pixi:pypi-mapping";

/// Largest mapping document accepted from the network, in bytes.
const MAX_MAPPING_BYTES: u64 = 64 * 1024 * 1024;

/// Errors raised while obtaining a mapping.
#[derive(Debug, Error, Diagnostic)]
pub enum MappingError {
    /// The mapping file could not be read.
    #[error("cannot read PyPI mapping file {path}")]
    #[diagnostic(code(pixi_sbom::mapping::read))]
    Read {
        /// File that was requested.
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The mapping is not the expected JSON shape.
    #[error("PyPI mapping from {origin} is not a JSON object of conda name to PyPI name")]
    #[diagnostic(
        code(pixi_sbom::mapping::parse),
        help("the format is {{\"<conda name>\": \"<pypi name>\" | [\"<pypi name>\", ...] | null, ...}}")
    )]
    Parse {
        /// File path or URL.
        origin: String,
        #[source]
        source: serde_json::Error,
    },

    /// The mapping could not be downloaded and no cached copy exists.
    #[error("cannot download the conda-forge PyPI mapping from {url}")]
    #[diagnostic(
        code(pixi_sbom::mapping::fetch),
        help("check network access and proxies, or pass an offline copy with --pypi-mapping-file")
    )]
    Fetch {
        /// URL that was requested.
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
}

/// A PyPI name, a list of names, or `null` for "known not to be on PyPI".
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
enum PypiNames {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl PypiNames {
    fn names(&self) -> &[String] {
        match self {
            PypiNames::None => &[],
            PypiNames::One(name) => std::slice::from_ref(name),
            PypiNames::Many(names) => names,
        }
    }
}

/// conda package name to PyPI names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PypiMapping {
    entries: HashMap<String, PypiNames>,
    /// Label recorded in the [`MAPPING_PROPERTY`] property: `prefix` or `file`.
    label: &'static str,
}

impl PypiMapping {
    /// Parse the JSON document published by parselmouth / prefix.dev.
    fn from_json(json: &str, origin: &str, label: &'static str) -> Result<Self, MappingError> {
        let raw: HashMap<String, Option<PypiNames>> =
            serde_json::from_str(json).map_err(|source| MappingError::Parse {
                origin: origin.to_string(),
                source,
            })?;
        let entries = raw
            .into_iter()
            .map(|(name, names)| (name.to_lowercase(), names.unwrap_or_default()))
            .collect();
        Ok(Self { entries, label })
    }

    /// Load a mapping from a local JSON file.
    pub fn from_file(path: &Path) -> Result<Self, MappingError> {
        let json = std::fs::read_to_string(path).map_err(|source| MappingError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&json, &path.display().to_string(), "file")
    }

    /// Download the conda-forge mapping, reusing a cached copy younger than
    /// [`CACHE_MAX_AGE`]. A stale copy is used with a warning when the download fails.
    pub fn fetch(cache_dir: &Path) -> Result<Self, MappingError> {
        Self::fetch_with(cache_dir, CACHE_MAX_AGE, SystemTime::now(), download)
    }

    fn fetch_with(
        cache_dir: &Path,
        max_age: Duration,
        now: SystemTime,
        download: impl FnOnce(&str) -> Result<String, Box<ureq::Error>>,
    ) -> Result<Self, MappingError> {
        let cache_file = cache_dir.join("conda-forge-pypi-mapping.json");
        let cached = std::fs::read_to_string(&cache_file).ok();
        let age = std::fs::metadata(&cache_file)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok());

        if let (Some(json), Some(age)) = (&cached, age)
            && age <= max_age
        {
            tracing::debug!(path = %cache_file.display(), age_secs = age.as_secs(), "using cached PyPI mapping");
            return Self::from_json(json, &cache_file.display().to_string(), "prefix");
        }

        tracing::info!(url = PREFIX_MAPPING_URL, "downloading the conda-forge PyPI mapping");
        match download(PREFIX_MAPPING_URL) {
            Ok(json) => {
                let mapping = Self::from_json(&json, PREFIX_MAPPING_URL, "prefix")?;
                if let Err(err) = std::fs::create_dir_all(cache_dir).and_then(|()| std::fs::write(&cache_file, &json)) {
                    tracing::warn!(path = %cache_file.display(), %err, "cannot cache the PyPI mapping");
                }
                Ok(mapping)
            }
            Err(source) => match cached {
                Some(json) => {
                    tracing::warn!(%source, "download failed; using the stale cached PyPI mapping");
                    Self::from_json(&json, &cache_file.display().to_string(), "prefix")
                }
                None => Err(MappingError::Fetch {
                    url: PREFIX_MAPPING_URL.to_string(),
                    source,
                }),
            },
        }
    }

    /// PyPI names for a conda package, if the mapping knows it.
    pub fn lookup(&self, conda_name: &str) -> Option<&[String]> {
        self.entries.get(&conda_name.to_lowercase()).map(PypiNames::names)
    }

    /// Number of conda names in the mapping.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn download(url: &str) -> Result<String, Box<ureq::Error>> {
    crate::http::get_text(url, MAX_MAPPING_BYTES)
}

/// Directory for cached downloads: `PIXI_SBOM_CACHE_DIR`, else `pixi-sbom` under
/// `PIXI_CACHE_DIR`, else the platform cache directory.
pub fn cache_dir() -> PathBuf {
    cache_dir_from(|name| std::env::var_os(name).map(PathBuf::from))
}

fn cache_dir_from(env: impl Fn(&str) -> Option<PathBuf>) -> PathBuf {
    if let Some(dir) = env(CACHE_DIR_ENV) {
        return dir;
    }
    if let Some(dir) = env("PIXI_CACHE_DIR") {
        return dir.join("pixi-sbom");
    }
    let base = if cfg!(windows) {
        env("LOCALAPPDATA").map(|d| d.join("cache"))
    } else if cfg!(target_os = "macos") {
        env("HOME").map(|d| d.join("Library").join("Caches"))
    } else {
        env("XDG_CACHE_HOME").or_else(|| env("HOME").map(|d| d.join(".cache")))
    };
    base.unwrap_or_else(std::env::temp_dir).join("pixi-sbom")
}

/// Add a `pkg:pypi` purl to every conda-forge package the mapping knows and whose lockfile
/// entry does not already state its purls. Returns how many packages were enriched.
pub fn enrich(sbom: &mut Sbom, mapping: &PypiMapping) -> usize {
    let mut enriched = 0;
    for package in &mut sbom.packages {
        if package.kind != PackageKind::CondaBinary || package.purls_from_lock || !is_conda_forge(package) {
            continue;
        }
        let Some(names) = mapping.lookup(&package.name) else {
            continue;
        };
        let Some(version) = package.version.as_deref() else {
            continue;
        };
        let purls: BTreeSet<String> = names
            .iter()
            .filter_map(|name| match purl::pypi(name, version) {
                Ok(purl) => Some(purl),
                Err(err) => {
                    tracing::warn!(package = %package.name, pypi = %name, %err, "skipping unusable mapped name");
                    None
                }
            })
            .collect();
        if purls.is_empty() {
            continue;
        }
        for purl in purls {
            if !package.extra_purls.contains(&purl) {
                package.extra_purls.push(purl);
            }
        }
        package
            .properties
            .insert(MAPPING_PROPERTY.to_string(), mapping.label.to_string());
        enriched += 1;
    }
    enriched
}

/// Make the PyPI purl the primary `purl` of every conda package that has one, moving the
/// conda purl to the extra purls. The package id (`bom-ref` / `SPDXID`) is unchanged.
/// Returns how many packages were switched.
pub fn prefer_pypi_purl(sbom: &mut Sbom) -> usize {
    let mut switched = 0;
    for package in &mut sbom.packages {
        if package.kind == PackageKind::Pypi {
            continue;
        }
        let Some(index) = package.extra_purls.iter().position(|p| p.starts_with("pkg:pypi/")) else {
            continue;
        };
        let pypi = package.extra_purls.remove(index);
        let conda = std::mem::replace(&mut package.purl, pypi);
        package.extra_purls.insert(0, conda);
        switched += 1;
    }
    switched
}

fn is_conda_forge(package: &crate::model::Package) -> bool {
    package
        .properties
        .get("pixi:channel-url")
        .is_some_and(|url| url.trim_end_matches('/').ends_with("/conda-forge"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use crate::lock::{Selection, build_sbom};
    use crate::model::Root;

    fn fixture_mapping() -> PypiMapping {
        PypiMapping::from_file(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pypi-mapping.json")).unwrap()
    }

    fn conda_python_sbom() -> Sbom {
        build_sbom(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/conda-python/pixi.lock"),
            Selection {
                environment: "default",
                platform: Some("linux-64"),
            },
            Root::default(),
        )
        .unwrap()
    }

    #[test]
    fn parses_string_list_and_null_values() {
        let mapping = fixture_mapping();
        assert_eq!(mapping.len(), 7);
        assert_eq!(mapping.lookup("numpy"), Some(&["numpy".to_string()][..]));
        assert_eq!(mapping.lookup("PyTorch"), Some(&["torch".to_string()][..]));
        assert_eq!(
            mapping.lookup("typing_extensions"),
            Some(&["typing-extensions".to_string()][..])
        );
        assert_eq!(mapping.lookup("python"), Some(&[][..]));
        assert_eq!(mapping.lookup("not-there"), None);
    }

    #[test]
    fn malformed_and_missing_files_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "[1, 2]").unwrap();
        assert!(matches!(
            PypiMapping::from_file(&bad).unwrap_err(),
            MappingError::Parse { .. }
        ));
        assert!(matches!(
            PypiMapping::from_file(&dir.path().join("missing.json")).unwrap_err(),
            MappingError::Read { .. }
        ));
    }

    #[test]
    fn enrich_adds_pypi_purls_only_where_appropriate() {
        let mut sbom = conda_python_sbom();
        let count = enrich(&mut sbom, &fixture_mapping());
        assert_eq!(count, 3, "numpy, pytorch, typing_extensions");
        let find = |name: &str| sbom.packages.iter().find(|p| p.name == name).unwrap();

        assert_eq!(find("numpy").extra_purls, vec!["pkg:pypi/numpy@2.3.1"]);
        assert_eq!(find("numpy").properties[MAPPING_PROPERTY], "file");
        assert_eq!(find("pytorch").extra_purls, vec!["pkg:pypi/torch@2.7.1"]);
        assert_eq!(
            find("typing_extensions").extra_purls,
            vec!["pkg:pypi/typing-extensions@4.14.1"]
        );
        // null mapping: known not to be on PyPI
        assert!(find("python").extra_purls.is_empty());
        assert!(!find("python").properties.contains_key(MAPPING_PROPERTY));
        // the lockfile already states `purls: []`
        assert!(find("requests").extra_purls.is_empty());
        // not a conda-forge package, even though the mapping has an entry
        assert!(find("samtools").extra_purls.is_empty());
        assert!(find("libzlib").extra_purls.is_empty());
    }

    #[test]
    fn enrich_is_idempotent_and_skips_pypi_and_source_packages() {
        let mut sbom = sample_sbom();
        let mapping = PypiMapping::from_json(
            r#"{"libzlib": "zlib-py", "zlib": "zlib", "mylib": "mylib", "six": "six"}"#,
            "test",
            "file",
        )
        .unwrap();
        // libzlib has a channel url in the sample? It has pixi:channel only; add the url.
        sbom.packages[0].properties.insert(
            "pixi:channel-url".into(),
            "https://conda.anaconda.org/conda-forge".into(),
        );
        assert_eq!(enrich(&mut sbom, &mapping), 1);
        assert_eq!(enrich(&mut sbom, &mapping), 1, "re-running adds nothing new");
        assert_eq!(sbom.packages[0].extra_purls, vec!["pkg:pypi/zlib-py@1.3.1"]);
        assert_eq!(
            sbom.packages[1].extra_purls,
            vec!["pkg:pypi/zlib@1.3.1"],
            "lock purls untouched"
        );
        assert!(sbom.packages[2].extra_purls.is_empty(), "source package skipped");
        assert!(sbom.packages[3].extra_purls.is_empty(), "pypi package skipped");
    }

    #[test]
    fn prefer_pypi_purl_swaps_primary_and_keeps_id() {
        let mut sbom = conda_python_sbom();
        enrich(&mut sbom, &fixture_mapping());
        assert_eq!(prefer_pypi_purl(&mut sbom), 3);
        let numpy = sbom.packages.iter().find(|p| p.name == "numpy").unwrap();
        assert_eq!(numpy.purl, "pkg:pypi/numpy@2.3.1");
        assert!(numpy.extra_purls[0].starts_with("pkg:conda/numpy@2.3.1"));
        assert!(numpy.id.starts_with("pkg:conda/numpy@2.3.1"), "id unchanged");
        let python = sbom.packages.iter().find(|p| p.name == "python").unwrap();
        assert!(python.purl.starts_with("pkg:conda/"));

        let mut sample = sample_sbom();
        assert_eq!(
            prefer_pypi_purl(&mut sample),
            1,
            "zlib has a lock purl; six is already pypi"
        );
        assert_eq!(sample.packages[1].purl, "pkg:pypi/zlib@1.3.1");
        assert_eq!(sample.packages[3].purl, "pkg:pypi/six@1.17.0");
    }

    #[test]
    fn fetch_uses_fresh_cache_without_downloading() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("conda-forge-pypi-mapping.json"),
            r#"{"numpy": "numpy"}"#,
        )
        .unwrap();
        let mapping = PypiMapping::fetch_with(dir.path(), CACHE_MAX_AGE, SystemTime::now(), |_| {
            panic!("must not download")
        })
        .unwrap();
        assert_eq!(mapping.lookup("numpy"), Some(&["numpy".to_string()][..]));
        assert_eq!(mapping.label, "prefix");
    }

    #[test]
    fn fetch_downloads_when_cache_is_stale_and_writes_it() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("nested").join("cache");
        let mapping = PypiMapping::fetch_with(&cache, CACHE_MAX_AGE, SystemTime::now(), |url| {
            assert_eq!(url, PREFIX_MAPPING_URL);
            Ok(r#"{"pytorch": "torch"}"#.to_string())
        })
        .unwrap();
        assert_eq!(mapping.lookup("pytorch"), Some(&["torch".to_string()][..]));
        assert_eq!(
            std::fs::read_to_string(cache.join("conda-forge-pypi-mapping.json")).unwrap(),
            r#"{"pytorch": "torch"}"#
        );

        // Now the cache is fresh; pretend it is two days old and it must be refetched.
        let later = SystemTime::now() + CACHE_MAX_AGE * 2;
        let mapping =
            PypiMapping::fetch_with(&cache, CACHE_MAX_AGE, later, |_| Ok(r#"{"x": "y"}"#.to_string())).unwrap();
        assert_eq!(mapping.lookup("x"), Some(&["y".to_string()][..]));
    }

    #[test]
    fn fetch_failure_falls_back_to_stale_cache_or_errors() {
        let dir = tempfile::tempdir().unwrap();
        let failing = |_: &str| Err(Box::new(ureq::Error::Io(std::io::Error::other("offline"))));

        let err = PypiMapping::fetch_with(dir.path(), CACHE_MAX_AGE, SystemTime::now(), failing).unwrap_err();
        assert!(matches!(err, MappingError::Fetch { .. }));

        std::fs::write(
            dir.path().join("conda-forge-pypi-mapping.json"),
            r#"{"numpy": "numpy"}"#,
        )
        .unwrap();
        let later = SystemTime::now() + CACHE_MAX_AGE * 2;
        let mapping = PypiMapping::fetch_with(dir.path(), CACHE_MAX_AGE, later, failing).unwrap();
        assert_eq!(mapping.lookup("numpy"), Some(&["numpy".to_string()][..]));
    }

    #[test]
    fn downloaded_garbage_is_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            PypiMapping::fetch_with(dir.path(), CACHE_MAX_AGE, SystemTime::now(), |_| Ok("nope".into())).unwrap_err();
        assert!(matches!(err, MappingError::Parse { .. }));
        assert!(!dir.path().join("conda-forge-pypi-mapping.json").exists());
    }

    #[test]
    fn cache_dir_precedence() {
        let with = |vars: &[(&str, &str)]| {
            let vars: Vec<(String, PathBuf)> = vars.iter().map(|(k, v)| (k.to_string(), PathBuf::from(v))).collect();
            cache_dir_from(move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
        };
        assert_eq!(
            with(&[("PIXI_SBOM_CACHE_DIR", "/explicit"), ("PIXI_CACHE_DIR", "/pixi")]),
            Path::new("/explicit")
        );
        assert_eq!(with(&[("PIXI_CACHE_DIR", "/pixi")]), Path::new("/pixi/pixi-sbom"));
        let platform = with(&[
            ("HOME", "/home/u"),
            ("XDG_CACHE_HOME", "/xdg"),
            ("LOCALAPPDATA", "/lad"),
        ]);
        assert!(platform.ends_with("pixi-sbom"), "{platform:?}");
        assert!(with(&[]).ends_with("pixi-sbom"));
    }
}
