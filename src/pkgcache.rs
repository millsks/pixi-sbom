//! License details for conda packages from the local package cache.
//!
//! Every conda package pixi has installed is extracted under the rattler package cache as
//! `<cache>/pkgs/<name>-<version>-<build>/`, whose `info/about.json` carries the license,
//! license family, summary, description and project URLs, and whose `info/licenses/`
//! directory holds the license texts conda-build copied out of the source. Reading it is
//! offline and free, and covers the common case of generating the SBOM on the machine that
//! ran `pixi install`.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::{LicenseFile, PackageKind, Sbom};

/// Property recorded on packages whose license details came from the cache.
pub const LICENSE_SOURCE: &str = "package-cache";

/// Largest license file read, in bytes; anything bigger is not a license text.
const MAX_LICENSE_FILE_BYTES: u64 = 1024 * 1024;

/// `info/about.json` as conda-build writes it.
#[derive(Debug, Default, Deserialize)]
pub struct About {
    pub license: Option<String>,
    pub license_family: Option<String>,
    pub summary: Option<String>,
    pub home: Option<String>,
    pub dev_url: Option<String>,
    pub doc_url: Option<String>,
}

/// What one extracted package contributes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CondaInfo {
    /// Parsed `about.json`.
    pub about: About,
    /// License files under `info/licenses/`, sorted by path.
    pub license_files: Vec<LicenseFile>,
}

impl PartialEq for About {
    fn eq(&self, other: &Self) -> bool {
        self.license == other.license && self.license_family == other.license_family
    }
}
impl Eq for About {}

/// Read the `info/` directory of an extracted package. `None` when the directory is not a
/// complete extraction (no `info/index.json`). License file texts are read only with `texts`.
pub fn read_extracted(package_dir: &Path, texts: bool) -> Option<CondaInfo> {
    let info = package_dir.join("info");
    if !info.join("index.json").is_file() {
        return None;
    }
    let about = match std::fs::read_to_string(info.join("about.json")) {
        Ok(text) => match serde_json::from_str::<About>(&text) {
            Ok(about) => about,
            Err(err) => {
                tracing::warn!(path = %info.join("about.json").display(), %err, "cannot parse about.json");
                About::default()
            }
        },
        Err(_) => About::default(),
    };
    let mut license_files = Vec::new();
    collect_license_files(&info.join("licenses"), Path::new(""), texts, &mut license_files);
    license_files.sort_by(|a, b| a.name.cmp(&b.name));
    Some(CondaInfo { about, license_files })
}

fn collect_license_files(dir: &Path, prefix: &Path, texts: bool, out: &mut Vec<LicenseFile>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let relative = prefix.join(entry.file_name());
        if path.is_dir() {
            collect_license_files(&path, &relative, texts, out);
            continue;
        }
        let name = relative.to_string_lossy().replace('\\', "/");
        if !texts {
            out.push(LicenseFile { name, text: None });
            continue;
        }
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(u64::MAX);
        if size > MAX_LICENSE_FILE_BYTES {
            tracing::debug!(path = %path.display(), size, "skipping oversized license file");
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => out.push(LicenseFile {
                name,
                text: Some(String::from_utf8_lossy(&bytes).into_owned()),
            }),
            Err(err) => tracing::debug!(path = %path.display(), %err, "cannot read license file"),
        }
    }
}

/// Counts from one enrichment pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// conda packages found in the cache.
    pub found: usize,
    /// Packages whose license expression was filled from `about.json`.
    pub licenses_filled: usize,
    /// License files attached in total.
    pub files: usize,
    /// Indexes of conda binary packages that were not in the cache, for the network fallback.
    pub missing: Vec<usize>,
}

/// What [`apply`] changed on one package.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// The license expression was filled in.
    pub license_filled: bool,
    /// Number of license files attached.
    pub files: usize,
}

/// Enrich every conda binary package that is extracted under `pkgs_dir`; license file texts
/// are included only with `texts`.
pub fn enrich(sbom: &mut Sbom, pkgs_dir: &Path, texts: bool) -> Outcome {
    let mut outcome = Outcome::default();
    for (index, package) in sbom.packages.iter_mut().enumerate() {
        if package.kind != PackageKind::CondaBinary {
            continue;
        }
        let Some(dir_name) = package.properties.get("pixi:file-name").map(|f| archive_stem(f)) else {
            continue;
        };
        let Some(info) = read_extracted(&pkgs_dir.join(dir_name), texts) else {
            outcome.missing.push(index);
            continue;
        };
        outcome.found += 1;
        let applied = apply(package, info, LICENSE_SOURCE);
        outcome.licenses_filled += usize::from(applied.license_filled);
        outcome.files += applied.files;
    }
    outcome
}

/// Merge `info` into `package`: fill what is missing, never override what the lockfile
/// says, and record `source` as the provenance of what was added.
pub fn apply(package: &mut crate::model::Package, info: CondaInfo, source: &str) -> Applied {
    let mut applied = Applied::default();
    let about = info.about;
    if package.license.is_none()
        && let Some(license) = about.license.filter(|l| !l.trim().is_empty())
    {
        package.license = Some(license);
        package.properties.insert("pixi:license-source".into(), source.into());
        applied.license_filled = true;
    }
    if let Some(family) = about.license_family
        && !package.properties.contains_key("pixi:license-family")
    {
        package.properties.insert("pixi:license-family".into(), family);
    }
    package.description = package.description.take().or(about.summary);
    package.homepage = package.homepage.take().or(about.home);
    package.repository = package.repository.take().or(about.dev_url);
    package.documentation = package.documentation.take().or(about.doc_url);
    if package.license_files.is_empty() && !info.license_files.is_empty() {
        applied.files = info.license_files.len();
        package.license_files = info.license_files;
        package
            .properties
            .insert("pixi:license-files-source".into(), source.into());
    }
    applied
}

/// The extracted directory name for an archive file name: `foo-1.0-h1.conda` -> `foo-1.0-h1`.
fn archive_stem(file_name: &str) -> String {
    file_name
        .strip_suffix(".conda")
        .or_else(|| file_name.strip_suffix(".tar.bz2"))
        .unwrap_or(file_name)
        .to_string()
}

/// The rattler package cache (`pkgs/` under the pixi cache): `PIXI_CACHE_DIR`, then
/// `RATTLER_CACHE_DIR`, then the platform cache directory's `rattler/cache`.
pub fn package_cache_dir() -> PathBuf {
    package_cache_dir_from(|name| std::env::var_os(name).map(PathBuf::from))
}

fn package_cache_dir_from(env: impl Fn(&str) -> Option<PathBuf>) -> PathBuf {
    let base = env("PIXI_CACHE_DIR")
        .or_else(|| env("RATTLER_CACHE_DIR"))
        .unwrap_or_else(|| {
            let platform = if cfg!(windows) {
                env("LOCALAPPDATA")
            } else if cfg!(target_os = "macos") {
                env("HOME").map(|d| d.join("Library").join("Caches"))
            } else {
                env("XDG_CACHE_HOME").or_else(|| env("HOME").map(|d| d.join(".cache")))
            };
            platform
                .unwrap_or_else(std::env::temp_dir)
                .join("rattler")
                .join("cache")
        });
    base.join("pkgs")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    /// Build a fake extracted package: `<pkgs>/<stem>/info/{index.json,about.json,licenses/...}`.
    fn extracted(pkgs: &Path, stem: &str, about: &str, licenses: &[(&str, &str)]) {
        let info = pkgs.join(stem).join("info");
        std::fs::create_dir_all(info.join("licenses")).unwrap();
        std::fs::write(info.join("index.json"), "{}").unwrap();
        std::fs::write(info.join("about.json"), about).unwrap();
        for (name, text) in licenses {
            let path = info.join("licenses").join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
    }

    #[test]
    fn reads_about_and_license_files_recursively() {
        let dir = tempfile::tempdir().unwrap();
        extracted(
            dir.path(),
            "foo-1.0-h1",
            r#"{"license": "MIT", "license_family": "MIT", "summary": "Foo", "home": "https://foo.example",
                "dev_url": "https://github.com/x/foo", "doc_url": "https://foo.example/docs"}"#,
            &[("LICENSE", "MIT text"), ("third_party/zlib.txt", "zlib text")],
        );
        let info = read_extracted(&dir.path().join("foo-1.0-h1"), true).unwrap();
        assert_eq!(info.about.license.as_deref(), Some("MIT"));
        assert_eq!(info.about.summary.as_deref(), Some("Foo"));
        assert_eq!(info.about.doc_url.as_deref(), Some("https://foo.example/docs"));
        assert_eq!(
            info.license_files,
            vec![
                LicenseFile {
                    name: "LICENSE".into(),
                    text: Some("MIT text".into())
                },
                LicenseFile {
                    name: "third_party/zlib.txt".into(),
                    text: Some("zlib text".into())
                },
            ]
        );
        // Without texts the names are still listed, and even an oversized file counts.
        let info = read_extracted(&dir.path().join("foo-1.0-h1"), false).unwrap();
        assert!(info.license_files.iter().all(|f| f.text.is_none()));
        assert_eq!(info.license_files.len(), 2);
    }

    #[test]
    fn incomplete_or_malformed_extractions_are_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_extracted(&dir.path().join("missing"), true), None);

        std::fs::create_dir_all(dir.path().join("partial").join("info")).unwrap();
        assert_eq!(read_extracted(&dir.path().join("partial"), true), None, "no index.json");

        extracted(dir.path(), "bad-1.0-h1", "not json", &[]);
        let info = read_extracted(&dir.path().join("bad-1.0-h1"), true).unwrap();
        assert_eq!(info.about.license, None);
        assert!(info.license_files.is_empty());

        extracted(dir.path(), "noabout-1.0-h1", "{}", &[("LICENSE", "x")]);
        std::fs::remove_file(dir.path().join("noabout-1.0-h1/info/about.json")).unwrap();
        let info = read_extracted(&dir.path().join("noabout-1.0-h1"), true).unwrap();
        assert_eq!(info.license_files.len(), 1);
    }

    #[test]
    fn oversized_and_binary_license_files() {
        let dir = tempfile::tempdir().unwrap();
        extracted(dir.path(), "big-1.0-h1", "{}", &[("SMALL", "ok")]);
        let licenses = dir.path().join("big-1.0-h1/info/licenses");
        std::fs::write(licenses.join("HUGE"), vec![b'x'; (MAX_LICENSE_FILE_BYTES + 1) as usize]).unwrap();
        std::fs::write(licenses.join("BIN"), [0xff, 0xfe, b'a']).unwrap();
        let info = read_extracted(&dir.path().join("big-1.0-h1"), true).unwrap();
        let names: Vec<_> = info.license_files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["BIN", "SMALL"], "oversized file skipped, binary read lossily");
        assert!(info.license_files[0].text.as_deref().unwrap().contains('\u{fffd}'));
        let names_only = read_extracted(&dir.path().join("big-1.0-h1"), false).unwrap();
        assert_eq!(
            names_only.license_files.len(),
            3,
            "names are cheap, so nothing is skipped"
        );
    }

    #[test]
    fn enrich_fills_details_from_the_cache_without_overriding_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        for package in &mut sbom.packages {
            package.license_files.clear();
            package.description = None;
            package.homepage = None;
            package.repository = None;
        }
        // libzlib: lock has license Zlib; cache adds files and urls but must not change the license.
        sbom.packages[0]
            .properties
            .insert("pixi:file-name".into(), "libzlib-1.3.1-h1.conda".into());
        extracted(
            dir.path(),
            "libzlib-1.3.1-h1",
            r#"{"license": "BSD-3-Clause", "license_family": "BSD", "summary": "zlib data compression library",
                "home": "https://zlib.net", "dev_url": "https://github.com/madler/zlib"}"#,
            &[("LICENSE.txt", "zlib license text")],
        );
        // zlib: lock has a license and license family already; cache has neither files nor urls.
        sbom.packages[1]
            .properties
            .insert("pixi:file-name".into(), "zlib-1.3.1-h1.tar.bz2".into());
        sbom.packages[1]
            .properties
            .insert("pixi:license-family".into(), "Other".into());
        extracted(dir.path(), "zlib-1.3.1-h1", r#"{"license_family": "MIT"}"#, &[]);
        // mylib is a source package: never touched even if a directory existed.
        extracted(dir.path(), "mylib-0.1.0-", r#"{"license": "MIT"}"#, &[("L", "t")]);

        let outcome = enrich(&mut sbom, dir.path(), false);
        assert_eq!(
            outcome,
            Outcome {
                found: 2,
                licenses_filled: 0,
                files: 1,
                missing: vec![],
            }
        );
        let libzlib = &sbom.packages[0];
        assert_eq!(libzlib.license.as_deref(), Some("Zlib"), "lockfile license wins");
        assert_eq!(libzlib.properties["pixi:license-family"], "BSD");
        assert_eq!(libzlib.description.as_deref(), Some("zlib data compression library"));
        assert_eq!(libzlib.homepage.as_deref(), Some("https://zlib.net"));
        assert_eq!(libzlib.repository.as_deref(), Some("https://github.com/madler/zlib"));
        assert_eq!(libzlib.license_files[0].name, "LICENSE.txt");
        assert_eq!(libzlib.license_files[0].text, None, "texts only on request");
        assert_eq!(libzlib.properties["pixi:license-files-source"], LICENSE_SOURCE);
        assert!(!libzlib.properties.contains_key("pixi:license-source"));
        let zlib = &sbom.packages[1];
        assert_eq!(zlib.properties["pixi:license-family"], "Other", "existing family kept");
        assert!(zlib.license_files.is_empty());
        assert!(sbom.packages[2].license_files.is_empty());
    }

    #[test]
    fn enrich_fills_a_missing_license_expression() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        sbom.packages[0].license = None;
        sbom.packages[0]
            .properties
            .insert("pixi:file-name".into(), "libzlib-1.3.1-h1.conda".into());
        extracted(dir.path(), "libzlib-1.3.1-h1", r#"{"license": " Zlib "}"#, &[]);
        extracted(dir.path(), "zlib-1.3.1-h1", r#"{"license": ""}"#, &[]);
        sbom.packages[1].license = None;
        sbom.packages[1]
            .properties
            .insert("pixi:file-name".into(), "zlib-1.3.1-h1.conda".into());

        let outcome = enrich(&mut sbom, dir.path(), true);
        assert_eq!(outcome.licenses_filled, 1);
        assert!(outcome.missing.is_empty());
        assert_eq!(sbom.packages[0].license.as_deref(), Some(" Zlib "));
        assert_eq!(sbom.packages[0].properties["pixi:license-source"], LICENSE_SOURCE);
        assert_eq!(sbom.packages[1].license, None, "empty license string ignored");

        // A conda binary package that is not extracted is reported as missing.
        let mut sbom = sample_sbom();
        sbom.packages[0]
            .properties
            .insert("pixi:file-name".into(), "absent-1.0-h1.conda".into());
        let outcome = enrich(&mut sbom, dir.path(), false);
        assert_eq!(outcome.missing, vec![0]);
    }

    #[test]
    fn package_cache_dir_precedence() {
        let with = |vars: &[(&str, &str)]| {
            let vars: Vec<(String, PathBuf)> = vars.iter().map(|(k, v)| (k.to_string(), PathBuf::from(v))).collect();
            package_cache_dir_from(move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
        };
        assert_eq!(
            with(&[("PIXI_CACHE_DIR", "/pixi"), ("RATTLER_CACHE_DIR", "/rattler")]),
            Path::new("/pixi/pkgs")
        );
        assert_eq!(with(&[("RATTLER_CACHE_DIR", "/rattler")]), Path::new("/rattler/pkgs"));
        let platform = with(&[
            ("HOME", "/home/u"),
            ("XDG_CACHE_HOME", "/xdg"),
            ("LOCALAPPDATA", "/lad"),
        ]);
        assert!(platform.ends_with(Path::new("rattler/cache/pkgs")), "{platform:?}");
        assert!(with(&[]).ends_with(Path::new("rattler/cache/pkgs")));
        assert_eq!(archive_stem("a-1-b.conda"), "a-1-b");
        assert_eq!(archive_stem("a-1-b.tar.bz2"), "a-1-b");
        assert_eq!(archive_stem("weird"), "weird");
    }
}
