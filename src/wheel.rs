//! License details for PyPI wheels, read from the wheel's `dist-info` without downloading it.
//!
//! A wheel is a zip whose `<name>-<version>.dist-info/` directory sits at the end. `METADATA`
//! carries the PEP 639 `License-Expression`, the older `License` field, the `License-File`
//! names and the project's summary and URLs; the license files themselves live under
//! `dist-info/licenses/` (PEP 639) or next to `METADATA` (older wheels). Everything is read
//! through [`crate::zipread`] with HTTP range requests and cached under
//! `<cache>/wheel-info/<sha256>/` so repeated runs are offline. Sdists are skipped.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use crate::model::{LicenseFile, PackageKind, Sbom};
use crate::zipread;

/// Property value recorded on packages whose details came from the wheel.
pub const LICENSE_SOURCE: &str = "wheel";

/// Fetches in flight at once.
const CONCURRENCY: usize = 10;

/// Largest license file read, in bytes.
const MAX_LICENSE_FILE_BYTES: u64 = 1024 * 1024;

/// Largest embedded SBOM file read, in bytes (maturin's Rust inventories run to a few hundred KB).
const MAX_SBOM_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// The `License` header sometimes holds an entire license text; longer values are not a name.
const MAX_LICENSE_FIELD_LEN: usize = 200;

/// What one wheel contributes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WheelInfo {
    /// PEP 639 `License-Expression`.
    pub license_expression: Option<String>,
    /// The older free-form `License` header, when it is a short single line.
    pub license: Option<String>,
    /// `Summary`.
    pub summary: Option<String>,
    /// `Home-page`, or the `Homepage` project URL.
    pub homepage: Option<String>,
    /// The `Source` / `Repository` project URL.
    pub repository: Option<String>,
    /// The `Documentation` project URL.
    pub documentation: Option<String>,
    /// License files, sorted by name; texts only on request.
    pub license_files: Vec<LicenseFile>,
}

/// Counts from one enrichment pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Wheels whose details were obtained (from the wheel or the cache).
    pub fetched: usize,
    /// Wheels that could not be read.
    pub failed: usize,
    /// Sdists and other non-wheel distributions, skipped.
    pub skipped: usize,
}

struct Job {
    index: usize,
    location: String,
    key: String,
}

/// Fill in details for every PyPI wheel in the SBOM. Texts are read only with `texts`.
pub fn enrich(sbom: &mut Sbom, cache_dir: &Path, texts: bool) -> Outcome {
    let mut outcome = Outcome::default();
    let mut jobs = Vec::new();
    for (index, package) in sbom.packages.iter().enumerate() {
        if package.kind != PackageKind::Pypi {
            continue;
        }
        if !package.location.ends_with(".whl") {
            tracing::debug!(package = %package.name, "not a wheel; license details skipped");
            outcome.skipped += 1;
            continue;
        }
        let key = cache_key(package);
        jobs.push(Job {
            index,
            location: package.location.clone(),
            key,
        });
    }
    let results = crate::parallel::map(&jobs, CONCURRENCY, |job| {
        info_for(&job.location, &job.key, cache_dir, texts)
    });
    for (job, result) in jobs.iter().zip(results) {
        match result {
            Ok(info) => {
                apply(&mut sbom.packages[job.index], info);
                outcome.fetched += 1;
            }
            Err(err) => {
                tracing::warn!(package = %sbom.packages[job.index].name, location = %job.location, %err, "cannot read license details from the wheel");
                outcome.failed += 1;
            }
        }
    }
    outcome
}

/// Merge `info` into `package`: fill what is missing, never override what is already known.
fn apply(package: &mut crate::model::Package, info: WheelInfo) {
    if package.license.is_none()
        && let Some(license) = info.license_expression.or(info.license)
    {
        package.license = Some(license);
        package
            .properties
            .insert("pixi:license-source".into(), LICENSE_SOURCE.into());
    }
    package.description = package.description.take().or(info.summary);
    package.homepage = package.homepage.take().or(info.homepage);
    package.repository = package.repository.take().or(info.repository);
    package.documentation = package.documentation.take().or(info.documentation);
    if package.license_files.is_empty() && !info.license_files.is_empty() {
        package.license_files = info.license_files;
        package
            .properties
            .insert("pixi:license-files-source".into(), LICENSE_SOURCE.into());
    }
}

/// The wheel's details: from the cache when present, otherwise read from the wheel and cached.
fn info_for(location: &str, key: &str, cache_dir: &Path, texts: bool) -> io::Result<WheelInfo> {
    let dir = cache_dir.join("wheel-info").join(key);
    if let Some(info) = read_cached(&dir, texts) {
        return Ok(info);
    }
    extract(location, &dir)?;
    read_cached(&dir, texts).ok_or_else(|| io::Error::other("wheel has no METADATA"))
}

/// Read `METADATA` and the license files out of the wheel at `location` into `dir`.
pub fn extract(location: &str, dir: &Path) -> io::Result<()> {
    let source = zipread::open(location)?;
    let entries = zipread::central_directory(source.as_ref())?;
    let metadata_entry = entries
        .iter()
        .find(|e| e.name.ends_with(".dist-info/METADATA") && e.name.matches('/').count() == 1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no dist-info/METADATA member; not a wheel"))?;
    let dist_info = metadata_entry.name.trim_end_matches("METADATA").to_string();
    let metadata = zipread::read_entry(source.as_ref(), metadata_entry)?;
    let headers = parse_headers(&String::from_utf8_lossy(&metadata));

    let staging = dir.with_extension("partial");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(staging.join("licenses"))?;
    std::fs::create_dir_all(staging.join("sboms"))?;
    std::fs::write(staging.join("METADATA"), &metadata)?;

    // PEP 639 puts license files under licenses/; older wheels list them next to METADATA.
    let declared: Vec<&str> = headers
        .get("license-file")
        .map(Vec::as_slice)
        .unwrap_or(&[])
        .iter()
        .map(String::as_str)
        .collect();
    for entry in &entries {
        let Some(rest) = entry.name.strip_prefix(&dist_info) else {
            continue;
        };
        // PEP 770 embedded SBOMs live under sboms/ and are kept for `--embedded-sboms`.
        let (folder, relative) = if let Some(under) = rest.strip_prefix("sboms/") {
            ("sboms", Some(under.to_string()))
        } else if let Some(under) = rest.strip_prefix("licenses/") {
            ("licenses", Some(under.to_string()))
        } else if declared.iter().any(|d| d.trim_start_matches("./") == rest) {
            ("licenses", Some(rest.to_string()))
        } else {
            ("licenses", None)
        };
        let Some(relative) = relative.filter(|r| !r.is_empty() && !r.ends_with('/') && !r.contains("..")) else {
            continue;
        };
        let limit = if folder == "sboms" {
            MAX_SBOM_FILE_BYTES
        } else {
            MAX_LICENSE_FILE_BYTES
        };
        if entry.uncompressed_size > limit {
            tracing::debug!(member = %entry.name, "skipping oversized {folder} member");
            continue;
        }
        let bytes = zipread::read_entry(source.as_ref(), entry)?;
        let target = staging.join(folder).join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(target, bytes)?;
    }
    let _ = std::fs::remove_dir_all(dir);
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::rename(&staging, dir)?;
    Ok(())
}

/// The embedded SBOM files cached for a wheel (`sboms/` under its cache directory), as
/// (file name, contents), sorted by name. Empty when the wheel has not been read or ships none.
pub fn cached_sboms(cache_dir: &Path, key: &str) -> Vec<(String, String)> {
    let dir = cache_dir.join("wheel-info").join(key).join("sboms");
    let mut out: Vec<(String, String)> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_file())
        .filter_map(|e| {
            let text = std::fs::read_to_string(e.path()).ok()?;
            Some((e.file_name().to_string_lossy().into_owned(), text))
        })
        .collect();
    out.sort();
    out
}

/// The cache key for a package: its sha256, else a name derived from its location.
pub fn cache_key(package: &crate::model::Package) -> String {
    package
        .sha256
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, package.location.as_bytes()).to_string())
}
fn read_cached(dir: &Path, texts: bool) -> Option<WheelInfo> {
    let metadata = std::fs::read_to_string(dir.join("METADATA")).ok()?;
    let mut info = info_from_metadata(&metadata);
    let mut files = Vec::new();
    collect_files(&dir.join("licenses"), Path::new(""), texts, &mut files);
    files.sort_by(|a, b| a.name.cmp(&b.name));
    info.license_files = files;
    Some(info)
}

fn collect_files(dir: &Path, prefix: &Path, texts: bool, out: &mut Vec<LicenseFile>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let relative = prefix.join(entry.file_name());
        if path.is_dir() {
            collect_files(&path, &relative, texts, out);
            continue;
        }
        let name = relative.to_string_lossy().replace('\\', "/");
        let text = texts
            .then(|| {
                std::fs::read(&path)
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .ok()
            })
            .flatten();
        if texts && text.is_none() {
            continue;
        }
        out.push(LicenseFile { name, text });
    }
}

/// Parse the RFC 822-style headers at the top of `METADATA` (up to the first blank line),
/// lower-casing names and keeping repeated headers in order.
pub fn parse_headers(metadata: &str) -> BTreeMap<String, Vec<String>> {
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut last: Option<String> = None;
    for line in metadata.lines() {
        if line.is_empty() {
            break;
        }
        if line.starts_with([' ', '\t'])
            && let Some(name) = &last
            && let Some(values) = headers.get_mut(name)
            && let Some(value) = values.last_mut()
        {
            // Continuation line.
            value.push('\n');
            value.push_str(line.trim());
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        headers.entry(name.clone()).or_default().push(value.trim().to_string());
        last = Some(name);
    }
    headers
}

/// The license and project facts in `METADATA`.
pub fn info_from_metadata(metadata: &str) -> WheelInfo {
    let headers = parse_headers(metadata);
    let first = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.first())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    let short = |value: Option<String>| value.filter(|v| v.len() <= MAX_LICENSE_FIELD_LEN && !v.contains('\n'));
    let project_url = |wanted: &[&str]| {
        headers.get("project-url").into_iter().flatten().find_map(|entry| {
            let (label, url) = entry.split_once(',')?;
            wanted
                .iter()
                .any(|w| label.trim().eq_ignore_ascii_case(w))
                .then(|| url.trim().to_string())
        })
    };
    WheelInfo {
        license_expression: short(first("license-expression")),
        license: short(first("license")),
        summary: first("summary"),
        homepage: first("home-page").or_else(|| project_url(&["homepage", "home"])),
        repository: project_url(&["source", "source code", "repository", "code"]),
        documentation: project_url(&["documentation", "docs"]),
        license_files: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    fn wheel() -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/archives/six-1.17.0-py2.py3-none-any.whl")
            .display()
            .to_string()
    }

    #[test]
    fn parses_headers_with_repeats_and_continuations() {
        let headers = parse_headers(
            "Metadata-Version: 2.4\nName: x\nLicense-File: LICENSE\nLicense-File: NOTICE\nDescription: first\n  second\nProject-URL: Source, https://s\n\nBody: not a header\n",
        );
        assert_eq!(headers["license-file"], ["LICENSE", "NOTICE"]);
        assert_eq!(headers["description"], ["first\nsecond"]);
        assert!(!headers.contains_key("body"));
    }

    #[test]
    fn info_prefers_the_expression_and_reads_project_urls() {
        let info = info_from_metadata(
            "License-Expression: MIT\nLicense: MIT License\nSummary: Sum\nProject-URL: Homepage, https://h\nProject-URL: Source Code, https://r\nProject-URL: Documentation, https://d\n\n",
        );
        assert_eq!(info.license_expression.as_deref(), Some("MIT"));
        assert_eq!(info.license.as_deref(), Some("MIT License"));
        assert_eq!(info.summary.as_deref(), Some("Sum"));
        assert_eq!(info.homepage.as_deref(), Some("https://h"));
        assert_eq!(info.repository.as_deref(), Some("https://r"));
        assert_eq!(info.documentation.as_deref(), Some("https://d"));

        let old = info_from_metadata("License: BSD\nHome-page: https://old\n\n");
        assert_eq!(old.license_expression, None);
        assert_eq!(old.license.as_deref(), Some("BSD"));
        assert_eq!(old.homepage.as_deref(), Some("https://old"));

        let text = format!("License: {}\n\n", "x".repeat(300));
        assert_eq!(
            info_from_metadata(&text).license,
            None,
            "whole license texts are not names"
        );
    }

    #[test]
    fn extracts_metadata_and_declared_license_file_from_an_old_style_wheel() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("six");
        extract(&wheel(), &target).unwrap();
        assert!(target.join("METADATA").exists());
        assert!(target.join("licenses/LICENSE").exists());
        let info = read_cached(&target, true).unwrap();
        assert_eq!(info.license.as_deref(), Some("MIT"));
        assert_eq!(info.license_expression, None);
        assert_eq!(info.summary.as_deref(), Some("Python 2 and 3 compatibility utilities"));
        assert_eq!(info.license_files.len(), 1);
        assert_eq!(info.license_files[0].name, "LICENSE");
        assert!(
            info.license_files[0]
                .text
                .as_deref()
                .unwrap()
                .contains("Benjamin Peterson")
        );
        let names_only = read_cached(&target, false).unwrap();
        assert_eq!(names_only.license_files[0].text, None);
        assert!(!target.with_extension("partial").exists());
    }

    #[test]
    fn non_wheels_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let conda = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/archives/zlib-1.3.2-h25fd6f3_3.conda")
            .display()
            .to_string();
        let err = extract(&conda, &dir.path().join("x")).unwrap_err();
        assert!(err.to_string().contains("not a wheel"));
        assert!(extract("/missing/x.whl", &dir.path().join("y")).is_err());
    }

    #[test]
    fn enrich_fills_wheels_skips_sdists_and_uses_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        // six: the real wheel; add an sdist and a conda package that must be ignored.
        sbom.packages[3].location = wheel();
        sbom.packages[3].sha256 = Some("a".repeat(64));
        let mut sdist = sbom.packages[3].clone();
        sdist.id = "pkg:pypi/other@1.0".into();
        sdist.name = "other".into();
        sdist.location = "https://files.pythonhosted.org/packages/other-1.0.tar.gz".into();
        sbom.packages.push(sdist);

        let outcome = enrich(&mut sbom, dir.path(), false);
        assert_eq!(
            outcome,
            Outcome {
                fetched: 1,
                failed: 0,
                skipped: 1
            }
        );
        let six = &sbom.packages[3];
        assert_eq!(six.license.as_deref(), Some("MIT"));
        assert_eq!(six.properties["pixi:license-source"], LICENSE_SOURCE);
        assert_eq!(six.license_files[0].name, "LICENSE");
        assert_eq!(six.license_files[0].text, None);
        assert_eq!(six.properties["pixi:license-files-source"], LICENSE_SOURCE);
        assert_eq!(
            six.description.as_deref(),
            Some("Python 2 and 3 compatibility utilities")
        );
        assert!(
            dir.path()
                .join("wheel-info")
                .join("a".repeat(64))
                .join("METADATA")
                .exists()
        );

        // Cached: the wheel can disappear; texts come from the cache.
        let mut again = sample_sbom();
        again.packages[3].location = "/gone/six.whl".into();
        again.packages[3].sha256 = Some("a".repeat(64));
        assert_eq!(enrich(&mut again, dir.path(), true).fetched, 1);
        assert!(again.packages[3].license_files[0].text.is_some());

        // Unreachable and uncached: a failure, not a crash; lock license untouched.
        let mut missing = sample_sbom();
        missing.packages[3].location = "/gone/other.whl".into();
        missing.packages[3].sha256 = None;
        missing.packages[3].license = Some("Apache-2.0".into());
        assert_eq!(enrich(&mut missing, dir.path(), false).failed, 1);
        assert_eq!(missing.packages[3].license.as_deref(), Some("Apache-2.0"));
    }
}
