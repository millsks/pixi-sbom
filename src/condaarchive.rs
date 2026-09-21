//! License details for conda packages that are not in the local package cache, read from
//! the archive on the channel without downloading it.
//!
//! A `.conda` file is a zip whose `info-<name>.tar.zst` member (a few kilobytes) holds
//! `about.json`, `index.json` and `licenses/`. The member is located through the zip
//! central directory and fetched with HTTP range requests, decompressed, and the relevant
//! files are written to `<cache>/conda-info/<sha256>/info/` in the same layout the rattler
//! package cache uses, so [`crate::pkgcache::read_extracted`] reads both and repeated runs
//! are offline. Legacy `.tar.bz2` archives have no central directory, so they are downloaded
//! whole when the lockfile says they are small ([`MAX_LEGACY_ARCHIVE_BYTES`]) and skipped
//! otherwise.

use std::collections::HashSet;
use std::io::{self, Read};
use std::path::Path;

use crate::model::{PackageKind, Sbom};
use crate::pkgcache::{self, CondaInfo};
use crate::zipread;

/// Property value recorded on packages whose details came from the channel archive.
pub const LICENSE_SOURCE: &str = "conda-archive";

/// Decompressed size cap for the info member; real ones are kilobytes.
const MAX_INFO_BYTES: u64 = 256 * 1024 * 1024;

/// Largest `.tar.bz2` archive downloaded whole for its `info/` directory.
pub const MAX_LEGACY_ARCHIVE_BYTES: u64 = 2 * 1024 * 1024;

/// Fetches in flight at once.
const CONCURRENCY: usize = 10;

/// Counts from one enrichment pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Packages whose details were obtained (from the archive or the sbom cache).
    pub fetched: usize,
    /// Packages whose archive could not be read.
    pub failed: usize,
    /// Legacy `.tar.bz2` packages too large (or of unknown size) to download whole, skipped.
    pub skipped: usize,
}

/// A conda binary package to look up.
#[derive(Debug, Clone)]
struct Job {
    index: usize,
    location: String,
    key: String,
}

/// Fill in details for every conda binary package in `indexes` (the ones the local package
/// cache did not have). Texts are read only with `texts`.
pub fn enrich(sbom: &mut Sbom, indexes: &[usize], cache_dir: &Path, texts: bool) -> Outcome {
    let mut outcome = Outcome::default();
    let mut jobs = Vec::new();
    for &index in indexes {
        let package = &sbom.packages[index];
        if package.kind != PackageKind::CondaBinary {
            continue;
        }
        if is_legacy(&package.location) {
            let size = package.properties.get("pixi:size").and_then(|s| s.parse::<u64>().ok());
            match size {
                Some(size) if size <= MAX_LEGACY_ARCHIVE_BYTES => {}
                Some(size) => {
                    tracing::debug!(
                        package = %package.name,
                        size,
                        limit = MAX_LEGACY_ARCHIVE_BYTES,
                        "legacy .tar.bz2 archive is too large to download whole; license details skipped"
                    );
                    outcome.skipped += 1;
                    continue;
                }
                None => {
                    tracing::debug!(
                        package = %package.name,
                        "legacy .tar.bz2 archive of unknown size; license details skipped"
                    );
                    outcome.skipped += 1;
                    continue;
                }
            }
        }
        let key = package
            .sha256
            .clone()
            .unwrap_or_else(|| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, package.location.as_bytes()).to_string());
        jobs.push(Job {
            index,
            location: package.location.clone(),
            key,
        });
    }
    if jobs.is_empty() {
        return outcome;
    }

    let results = crate::parallel::map(&jobs, CONCURRENCY, |job| {
        info_for(&job.location, &job.key, cache_dir, texts)
    });
    for (job, result) in jobs.iter().zip(results) {
        match result {
            Ok(info) => {
                pkgcache::apply(&mut sbom.packages[job.index], info, LICENSE_SOURCE);
                outcome.fetched += 1;
            }
            Err(err) => {
                tracing::warn!(package = %sbom.packages[job.index].name, location = %job.location, %err, "cannot read license details from the archive");
                outcome.failed += 1;
            }
        }
    }
    outcome
}

/// The info directory for one archive: from the sbom cache when present, otherwise fetched.
fn info_for(location: &str, key: &str, cache_dir: &Path, texts: bool) -> io::Result<CondaInfo> {
    let dir = cache_dir.join("conda-info").join(key);
    if let Some(info) = pkgcache::read_extracted(&dir, texts) {
        return Ok(info);
    }
    extract_info(location, &dir)?;
    pkgcache::read_extracted(&dir, texts).ok_or_else(|| io::Error::other("archive has no info/index.json"))
}

/// Whether `location` names a legacy `.tar.bz2` archive rather than a `.conda` zip.
fn is_legacy(location: &str) -> bool {
    location.ends_with(".tar.bz2")
}

/// Pull the `info/` files out of the archive at `location` and write `about.json`,
/// `index.json` and `licenses/` under `dir/info/`: from the `info-*.tar.zst` member of a
/// `.conda` zip by range, or from a whole `.tar.bz2` archive of at most
/// [`MAX_LEGACY_ARCHIVE_BYTES`].
pub fn extract_info(location: &str, dir: &Path) -> io::Result<()> {
    if is_legacy(location) {
        let compressed = read_whole(location, MAX_LEGACY_ARCHIVE_BYTES)?;
        let decoder = bzip2::read::MultiBzDecoder::new(compressed.as_slice()).take(MAX_INFO_BYTES);
        return write_info_files(decoder, dir);
    }
    let source = zipread::open(location)?;
    let entries = zipread::central_directory(source.as_ref())?;
    let info_entry = entries
        .iter()
        .find(|e| e.name.starts_with("info-") && e.name.ends_with(".tar.zst"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no info-*.tar.zst member; not a .conda archive",
            )
        })?;
    let compressed = zipread::read_entry(source.as_ref(), info_entry)?;
    let decoder = zstd::stream::read::Decoder::new(compressed.as_slice())?.take(MAX_INFO_BYTES);
    write_info_files(decoder, dir)
}

/// The whole archive at `location`, refusing anything larger than `limit` bytes.
fn read_whole(location: &str, limit: u64) -> io::Result<Vec<u8>> {
    if zipread::is_http(location) {
        // ureq's limit errors on the read that follows exactly `limit` bytes, so allow one more.
        let bytes = crate::http::get_bytes(location, limit + 1).map_err(io::Error::other)?;
        if bytes.len() as u64 > limit {
            return Err(io::Error::other(format!("archive is larger than {limit} bytes")));
        }
        return Ok(bytes);
    }
    let path = zipread::local_path(location);
    let len = std::fs::metadata(path)?.len();
    if len > limit {
        return Err(io::Error::other(format!("archive is {len} bytes, larger than {limit}")));
    }
    std::fs::read(path)
}

/// Write the files we care about from an `info` tar stream into `dir/info/`.
fn write_info_files(tar_stream: impl Read, dir: &Path) -> io::Result<()> {
    let info_dir = dir.join("info");
    let staging = dir.with_extension("partial");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(staging.join("info"))?;

    let mut archive = tar::Archive::new(tar_stream);
    let mut seen = HashSet::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?.into_owned();
        let relative = path.strip_prefix("info").unwrap_or(&path).to_path_buf();
        let wanted = relative == Path::new("about.json")
            || relative == Path::new("index.json")
            || relative.starts_with("licenses");
        if !wanted
            || relative
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            continue;
        }
        let target = staging.join("info").join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        std::fs::write(&target, bytes)?;
        seen.insert(relative);
    }
    if !seen.contains(Path::new("index.json")) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "info member has no index.json",
        ));
    }
    let _ = std::fs::remove_dir_all(&info_dir);
    std::fs::create_dir_all(dir)?;
    std::fs::rename(staging.join("info"), &info_dir)?;
    let _ = std::fs::remove_dir_all(&staging);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    fn archive() -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/archives/zlib-1.3.2-h25fd6f3_3.conda")
            .display()
            .to_string()
    }

    #[test]
    fn extracts_about_index_and_licenses_from_a_real_archive() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("zlib");
        extract_info(&archive(), &target).unwrap();
        let mut files: Vec<_> = walk(&target.join("info"));
        files.sort();
        assert_eq!(files, ["about.json", "index.json", "licenses/LICENSE"]);
        let info = pkgcache::read_extracted(&target, true).unwrap();
        assert_eq!(info.about.license.as_deref(), Some("Zlib"));
        assert_eq!(info.about.home.as_deref(), Some("http://zlib.net/"));
        assert_eq!(info.license_files.len(), 1);
        assert!(
            info.license_files[0]
                .text
                .as_deref()
                .unwrap()
                .contains("Jean-loup Gailly")
        );
        assert!(!target.with_extension("partial").exists(), "staging cleaned up");
    }

    fn legacy_archive() -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/archives/zlib-1.3.2-h25fd6f3_3.tar.bz2")
            .display()
            .to_string()
    }

    #[test]
    fn extracts_info_from_a_whole_legacy_archive() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("zlib-legacy");
        extract_info(&legacy_archive(), &target).unwrap();
        let mut files: Vec<_> = walk(&target.join("info"));
        files.sort();
        assert_eq!(files, ["about.json", "index.json", "licenses/LICENSE"]);
        let info = pkgcache::read_extracted(&target, true).unwrap();
        assert_eq!(info.about.license.as_deref(), Some("Zlib"));
        assert!(
            info.license_files[0]
                .text
                .as_deref()
                .unwrap()
                .contains("Jean-loup Gailly")
        );

        // The same file under a file:// URL, and a legacy archive that is not bzip2 at all.
        let url = format!("file://{}", legacy_archive());
        extract_info(&url, &dir.path().join("via-url")).unwrap();
        let bogus = dir.path().join("bogus.tar.bz2");
        std::fs::write(&bogus, b"not bzip2").unwrap();
        assert!(extract_info(&bogus.display().to_string(), &dir.path().join("bogus")).is_err());
    }

    #[test]
    fn read_whole_refuses_archives_over_the_limit() {
        let err = read_whole(&legacy_archive(), 100).unwrap_err();
        assert!(err.to_string().contains("larger than 100"));
        assert!(read_whole(&legacy_archive(), MAX_LEGACY_ARCHIVE_BYTES).is_ok());
        assert!(read_whole("/missing/pkg.tar.bz2", MAX_LEGACY_ARCHIVE_BYTES).is_err());
    }

    #[test]
    fn enrich_reads_small_legacy_archives_and_skips_large_or_unsized_ones() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        for package in &mut sbom.packages {
            package.license_files.clear();
            package.homepage = None;
        }
        // libzlib: the legacy fixture with its size; zlib: a legacy archive said to be huge.
        sbom.packages[0].location = legacy_archive();
        sbom.packages[0].sha256 = None;
        sbom.packages[0].properties.insert("pixi:size".into(), "4762".into());
        sbom.packages[1].location = "https://example.invalid/zlib.tar.bz2".into();
        sbom.packages[1]
            .properties
            .insert("pixi:size".into(), (MAX_LEGACY_ARCHIVE_BYTES + 1).to_string());
        let outcome = enrich(&mut sbom, &[0, 1], dir.path(), false);
        assert_eq!(
            outcome,
            Outcome {
                fetched: 1,
                failed: 0,
                skipped: 1
            }
        );
        assert_eq!(sbom.packages[0].license_files[0].name, "LICENSE");
        assert_eq!(sbom.packages[0].homepage.as_deref(), Some("http://zlib.net/"));
        assert!(sbom.packages[1].license_files.is_empty());
    }

    fn walk(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(
                    walk(&path)
                        .into_iter()
                        .map(|f| format!("{}/{f}", entry.file_name().to_string_lossy())),
                );
            } else {
                out.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        out
    }

    #[test]
    fn non_conda_archives_and_missing_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let wheel = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/archives/six-1.17.0-py2.py3-none-any.whl")
            .display()
            .to_string();
        let err = extract_info(&wheel, &dir.path().join("x")).unwrap_err();
        assert!(err.to_string().contains("not a .conda archive"));
        assert!(extract_info("/missing/pkg.conda", &dir.path().join("y")).is_err());

        // A tar without index.json is rejected and leaves nothing behind.
        let mut builder = tar::Builder::new(Vec::new());
        let data = b"{}";
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append_data(&mut header, "info/about.json", &data[..]).unwrap();
        let bytes = builder.into_inner().unwrap();
        let target = dir.path().join("noindex");
        let err = write_info_files(bytes.as_slice(), &target).unwrap_err();
        assert!(err.to_string().contains("no index.json"));
        assert!(!target.exists());
    }

    #[test]
    fn write_info_files_ignores_other_members() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = tar::Builder::new(Vec::new());
        for (name, data) in [
            ("info/index.json", "{}"),
            ("info/paths.json", "big"),
            ("info/licenses/sub/L.txt", "text"),
            ("info/recipe/meta.yaml", "no"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, name, data.as_bytes()).unwrap();
        }
        let bytes = builder.into_inner().unwrap();
        let target = dir.path().join("pkg");
        write_info_files(bytes.as_slice(), &target).unwrap();
        let mut files = walk(&target.join("info"));
        files.sort();
        assert_eq!(files, ["index.json", "licenses/sub/L.txt"]);
    }

    #[test]
    fn enrich_uses_the_cache_on_the_second_run_and_counts_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        for package in &mut sbom.packages {
            package.license_files.clear();
            package.description = None;
            package.homepage = None;
            package.repository = None;
        }
        // libzlib: points at the real archive; zlib: legacy tar.bz2 of unknown size; mylib: source package (ignored).
        sbom.packages[0].location = archive();
        sbom.packages[0].sha256 = Some("f".repeat(64));
        sbom.packages[1].location = "https://example.invalid/zlib.tar.bz2".into();
        let outcome = enrich(&mut sbom, &[0, 1, 2], dir.path(), false);
        assert_eq!(
            outcome,
            Outcome {
                fetched: 1,
                failed: 0,
                skipped: 1
            }
        );
        let libzlib = &sbom.packages[0];
        assert_eq!(libzlib.license_files[0].name, "LICENSE");
        assert_eq!(libzlib.license_files[0].text, None);
        assert_eq!(libzlib.properties["pixi:license-files-source"], LICENSE_SOURCE);
        assert_eq!(libzlib.homepage.as_deref(), Some("http://zlib.net/"));
        assert!(
            dir.path()
                .join("conda-info")
                .join("f".repeat(64))
                .join("info/index.json")
                .exists()
        );

        // Second run: the archive is gone, the cache still serves it (with texts this time).
        let mut again = sample_sbom();
        again.packages[0].location = "/no/longer/there.conda".into();
        again.packages[0].sha256 = Some("f".repeat(64));
        again.packages[0].license_files.clear();
        let outcome = enrich(&mut again, &[0], dir.path(), true);
        assert_eq!(outcome.fetched, 1);
        assert!(again.packages[0].license_files[0].text.is_some());

        // A missing archive with no cache entry is a failure, not a crash.
        let mut missing = sample_sbom();
        missing.packages[0].location = "/no/such/file.conda".into();
        missing.packages[0].sha256 = None;
        assert_eq!(enrich(&mut missing, &[0], dir.path(), false).failed, 1);
    }
}
