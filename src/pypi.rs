//! License lookup for PyPI packages via the index JSON API.
//!
//! `pixi.lock` records no license for wheels and sdists, so PyPI packages would otherwise
//! carry none at all. This opt-in step asks the index (`https://pypi.org/pypi/<name>/<version>/json`
//! by default) and reads, in order, the PEP 639 `license_expression`, the classic `license`
//! field, and the `License ::` trove classifiers. Responses are cached forever, since a
//! released version's metadata does not change, and a failed lookup never fails the run.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::http;
use crate::model::{PackageKind, Sbom};

/// Default base of the JSON API; `PIXI_SBOM_PYPI_URL` overrides it (mirrors, devpi, ...).
pub const DEFAULT_INDEX_URL: &str = "https://pypi.org/pypi";

/// Environment variable naming the JSON API base to query.
pub const INDEX_URL_ENV: &str = "PIXI_SBOM_PYPI_URL";

/// Property recorded on every package whose license came from the index.
pub const LICENSE_SOURCE_PROPERTY: &str = "pixi:license-source";

/// Largest metadata document accepted, in bytes.
const MAX_METADATA_BYTES: u64 = 8 * 1024 * 1024;

/// The classic `license` field sometimes holds an entire license text; longer values than
/// this are not a name and are ignored.
const MAX_LICENSE_FIELD_LEN: usize = 200;

#[derive(Debug, Deserialize)]
struct Metadata {
    info: Info,
}

#[derive(Debug, Default, Deserialize)]
struct Info {
    license_expression: Option<String>,
    license: Option<String>,
    #[serde(default)]
    classifiers: Vec<String>,
}

/// Pick the license from a JSON API response: `license_expression`, then `license`, then the
/// `License ::` classifiers mapped to SPDX identifiers where the classifier is unambiguous.
/// `None` when the metadata is unparsable or says nothing.
pub fn license_from_metadata(json: &str) -> Option<String> {
    let info = serde_json::from_str::<Metadata>(json).ok()?.info;
    let clean = |value: Option<String>| {
        value
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty() && v.len() <= MAX_LICENSE_FIELD_LEN && !v.contains('\n'))
    };
    if let Some(expression) = clean(info.license_expression) {
        return Some(expression);
    }
    if let Some(license) = clean(info.license) {
        return Some(license);
    }
    let classifiers: Vec<&str> = info
        .classifiers
        .iter()
        .filter_map(|c| c.strip_prefix("License :: "))
        .map(|c| c.strip_prefix("OSI Approved :: ").unwrap_or(c))
        .filter(|c| *c != "OSI Approved")
        .collect();
    match classifiers.as_slice() {
        [] => None,
        [single] => Some(classifier_to_spdx(single).unwrap_or(single).to_string()),
        many => {
            // Several classifiers usually mean "choose one"; only join them when every one
            // has an SPDX identifier, otherwise keep the first as free text.
            let ids: Option<Vec<&str>> = many.iter().map(|c| classifier_to_spdx(c)).collect();
            Some(match ids {
                Some(ids) => ids.join(" OR "),
                None => many[0].to_string(),
            })
        }
    }
}

/// SPDX identifiers for the common trove license classifiers. Deliberately conservative:
/// classifiers that do not pin a version ("GNU General Public License (GPL)") are left alone.
fn classifier_to_spdx(classifier: &str) -> Option<&'static str> {
    Some(match classifier {
        "MIT License" => "MIT",
        "BSD License" => "BSD-3-Clause",
        "Apache Software License" => "Apache-2.0",
        "ISC License (ISCL)" => "ISC",
        "Mozilla Public License 2.0 (MPL 2.0)" => "MPL-2.0",
        "GNU General Public License v2 (GPLv2)" => "GPL-2.0-only",
        "GNU General Public License v2 or later (GPLv2+)" => "GPL-2.0-or-later",
        "GNU General Public License v3 (GPLv3)" => "GPL-3.0-only",
        "GNU General Public License v3 or later (GPLv3+)" => "GPL-3.0-or-later",
        "GNU Lesser General Public License v2 (LGPLv2)" => "LGPL-2.0-only",
        "GNU Lesser General Public License v2 or later (LGPLv2+)" => "LGPL-2.0-or-later",
        "GNU Lesser General Public License v3 (LGPLv3)" => "LGPL-3.0-only",
        "GNU Lesser General Public License v3 or later (LGPLv3+)" => "LGPL-3.0-or-later",
        "GNU Affero General Public License v3" => "AGPL-3.0-only",
        "GNU Affero General Public License v3 or later (AGPLv3+)" => "AGPL-3.0-or-later",
        "Python Software Foundation License" => "PSF-2.0",
        "zlib/libpng License" => "Zlib",
        "The Unlicense (Unlicense)" => "Unlicense",
        "Eclipse Public License 2.0 (EPL-2.0)" => "EPL-2.0",
        "Boost Software License 1.0 (BSL-1.0)" => "BSL-1.0",
        "PostgreSQL License" => "PostgreSQL",
        "CC0 1.0 Universal (CC0 1.0) Public Domain Dedication" => "CC0-1.0",
        _ => return None,
    })
}

/// What happened during a lookup pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Packages that received a license.
    pub found: usize,
    /// Packages the index knows but that declare no license.
    pub missing: usize,
    /// Requests that failed; the network is left alone once it looks unavailable.
    pub failed: usize,
}

/// Configuration for a lookup pass.
pub struct Lookup<'a> {
    /// JSON API base, e.g. `https://pypi.org/pypi`.
    pub index_url: &'a str,
    /// Cache directory for responses.
    pub cache_dir: &'a Path,
}

impl Lookup<'_> {
    /// Fill in the license of every PyPI package that has none, querying the real index.
    pub fn run(&self, sbom: &mut Sbom, progress: crate::progress::Progress) -> Outcome {
        self.run_with(sbom, &|url| http::get_text(url, MAX_METADATA_BYTES), progress)
    }

    fn run_with(
        &self,
        sbom: &mut Sbom,
        fetch: &dyn Fn(&str) -> Result<String, Box<ureq::Error>>,
        progress: crate::progress::Progress,
    ) -> Outcome {
        let mut outcome = Outcome::default();
        let mut network_down = false;
        let total = sbom
            .packages
            .iter()
            .filter(|p| p.kind == PackageKind::Pypi && p.license.is_none())
            .count();
        let bar = progress.bar("PyPI lookups", total);
        for package in &mut sbom.packages {
            if package.kind != PackageKind::Pypi || package.license.is_some() {
                continue;
            }
            let Some(version) = package.version.as_deref() else {
                continue;
            };
            bar.advance(&package.name);
            let name = crate::purl::normalize_pypi_name(&package.name);
            let json = match self.metadata(&name, version, fetch, &mut network_down) {
                Some(json) => json,
                None => {
                    outcome.failed += 1;
                    continue;
                }
            };
            match license_from_metadata(&json) {
                Some(license) => {
                    package.license = Some(license);
                    package
                        .properties
                        .insert(LICENSE_SOURCE_PROPERTY.to_string(), "pypi".to_string());
                    outcome.found += 1;
                }
                None => outcome.missing += 1,
            }
        }
        bar.finish();
        outcome
    }

    /// The metadata document for one release, from the cache or the index. `None` when it
    /// could not be obtained; sets `network_down` when further requests are pointless.
    fn metadata(
        &self,
        name: &str,
        version: &str,
        fetch: &dyn Fn(&str) -> Result<String, Box<ureq::Error>>,
        network_down: &mut bool,
    ) -> Option<String> {
        let cache_file = self.cache_file(name, version);
        if let Ok(json) = std::fs::read_to_string(&cache_file) {
            return Some(json);
        }
        if *network_down {
            return None;
        }
        let url = format!("{}/{name}/{version}/json", self.index_url.trim_end_matches('/'));
        match fetch(&url) {
            Ok(json) => {
                if let Err(err) = cache_file
                    .parent()
                    .map_or(Ok(()), std::fs::create_dir_all)
                    .and_then(|()| std::fs::write(&cache_file, &json))
                {
                    tracing::warn!(path = %cache_file.display(), %err, "cannot cache PyPI metadata");
                }
                Some(json)
            }
            Err(err) => {
                if http::is_connectivity_error(&err) {
                    *network_down = true;
                    tracing::warn!(%url, %err, "PyPI index unreachable; skipping remaining license lookups");
                } else {
                    tracing::warn!(%url, %err, "cannot fetch PyPI metadata");
                }
                None
            }
        }
    }

    fn cache_file(&self, name: &str, version: &str) -> PathBuf {
        self.cache_dir.join("pypi").join(format!("{name}-{version}.json"))
    }
}

/// The JSON API base to use: `PIXI_SBOM_PYPI_URL` or the public index.
pub fn index_url() -> String {
    std::env::var(INDEX_URL_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_INDEX_URL.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use std::cell::RefCell;

    fn meta(expression: Option<&str>, license: Option<&str>, classifiers: &[&str]) -> String {
        serde_json::json!({"info": {
            "license_expression": expression,
            "license": license,
            "classifiers": classifiers,
        }})
        .to_string()
    }

    #[test]
    fn license_precedence_expression_then_field_then_classifiers() {
        assert_eq!(
            license_from_metadata(&meta(
                Some("MIT"),
                Some("BSD"),
                &["License :: OSI Approved :: Apache Software License"]
            )),
            Some("MIT".into())
        );
        assert_eq!(
            license_from_metadata(&meta(
                None,
                Some(" BSD-2-Clause "),
                &["License :: OSI Approved :: MIT License"]
            )),
            Some("BSD-2-Clause".into())
        );
        assert_eq!(
            license_from_metadata(&meta(None, None, &["License :: OSI Approved :: MIT License"])),
            Some("MIT".into())
        );
        assert_eq!(
            license_from_metadata(&meta(
                None,
                Some(""),
                &["Programming Language :: Python", "License :: Other/Proprietary License"]
            )),
            Some("Other/Proprietary License".into())
        );
        assert_eq!(license_from_metadata(&meta(None, None, &[])), None);
        assert_eq!(
            license_from_metadata(&meta(None, None, &["License :: OSI Approved"])),
            None
        );
        assert_eq!(license_from_metadata("not json"), None);
        assert_eq!(license_from_metadata(r#"{"info": {}}"#), None);
    }

    #[test]
    fn license_field_holding_a_whole_license_text_is_ignored() {
        let text = "MIT License\n\nPermission is hereby granted, free of charge...";
        assert_eq!(
            license_from_metadata(&meta(None, Some(text), &["License :: OSI Approved :: MIT License"])),
            Some("MIT".into())
        );
        let long = "x".repeat(MAX_LICENSE_FIELD_LEN + 1);
        assert_eq!(license_from_metadata(&meta(None, Some(&long), &[])), None);
    }

    #[test]
    fn several_classifiers_join_only_when_all_are_known() {
        assert_eq!(
            license_from_metadata(&meta(
                None,
                None,
                &[
                    "License :: OSI Approved :: MIT License",
                    "License :: OSI Approved :: Apache Software License"
                ]
            )),
            Some("MIT OR Apache-2.0".into())
        );
        assert_eq!(
            license_from_metadata(&meta(
                None,
                None,
                &[
                    "License :: OSI Approved :: GNU General Public License (GPL)",
                    "License :: OSI Approved :: MIT License"
                ]
            )),
            Some("GNU General Public License (GPL)".into())
        );
    }

    #[test]
    fn lookup_fills_pypi_packages_and_caches_responses() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        let requested = RefCell::new(Vec::new());
        let fetch = |url: &str| {
            requested.borrow_mut().push(url.to_string());
            Ok(meta(Some("MIT"), None, &[]))
        };
        let lookup = Lookup {
            index_url: "https://index.example/pypi/",
            cache_dir: dir.path(),
        };

        let outcome = lookup.run_with(&mut sbom, &fetch, crate::progress::Progress::default());
        assert_eq!(
            outcome,
            Outcome {
                found: 1,
                missing: 0,
                failed: 0
            }
        );
        assert_eq!(
            requested.borrow().as_slice(),
            ["https://index.example/pypi/six/1.17.0/json"]
        );
        let six = &sbom.packages[3];
        assert_eq!(six.license.as_deref(), Some("MIT"));
        assert_eq!(six.properties[LICENSE_SOURCE_PROPERTY], "pypi");
        assert!(dir.path().join("pypi").join("six-1.17.0.json").exists());
        assert_eq!(sbom.packages[0].license.as_deref(), Some("Zlib"), "conda untouched");

        // Second run: license already set, nothing requested.
        let outcome = lookup.run_with(&mut sbom, &fetch, crate::progress::Progress::default());
        assert_eq!(outcome, Outcome::default());

        // Cached response is used without fetching.
        let mut fresh = sample_sbom();
        let panic_fetch = |_: &str| panic!("must not fetch");
        assert_eq!(
            lookup
                .run_with(&mut fresh, &panic_fetch, crate::progress::Progress::default())
                .found,
            1
        );
    }

    #[test]
    fn lookup_counts_missing_and_failures_and_stops_when_offline() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        let mut second = sbom.packages[3].clone();
        second.id = "pkg:pypi/other@1.0".into();
        second.name = "other".into();
        second.version = Some("1.0".into());
        let mut third = second.clone();
        third.id = "pkg:pypi/unversioned".into();
        third.name = "unversioned".into();
        third.version = None;
        sbom.packages.extend([second, third]);

        // Each phase gets its own cache so the previous phase's responses do not short-circuit it.
        let lookup_in = |sub: &str| Lookup {
            index_url: DEFAULT_INDEX_URL,
            cache_dir: Box::leak(dir.path().join(sub).into_boxed_path()),
        };

        let no_license = |_: &str| Ok(meta(None, None, &[]));
        assert_eq!(
            lookup_in("a")
                .run_with(&mut sbom, &no_license, crate::progress::Progress::default())
                .missing,
            2
        );

        let calls = RefCell::new(0);
        let offline = |_: &str| {
            *calls.borrow_mut() += 1;
            Err(Box::new(ureq::Error::ConnectionFailed))
        };
        let outcome = lookup_in("b").run_with(&mut sbom, &offline, crate::progress::Progress::default());
        assert_eq!(outcome.failed, 2);
        assert_eq!(*calls.borrow(), 1, "stops after the first connectivity failure");

        let calls = RefCell::new(0);
        let not_found = |_: &str| {
            *calls.borrow_mut() += 1;
            Err(Box::new(ureq::Error::StatusCode(404)))
        };
        let outcome = lookup_in("c").run_with(&mut sbom, &not_found, crate::progress::Progress::default());
        assert_eq!(outcome.failed, 2);
        assert_eq!(*calls.borrow(), 2, "a 404 does not stop the other lookups");
    }

    #[test]
    fn index_url_comes_from_env_or_default() {
        assert_eq!(
            index_url(),
            std::env::var(INDEX_URL_ENV).unwrap_or_else(|_| DEFAULT_INDEX_URL.into())
        );
    }
}
