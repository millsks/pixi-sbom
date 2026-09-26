//! CISA's Known Exploited Vulnerabilities catalog, layered on the findings of
//! `--vulnerabilities`: a finding whose CVE alias is in the catalog is marked as known
//! exploited, rated critical (a KEV entry is a must-fix regardless of CVSS) and carries the
//! catalog's dates and required action. The catalog (about a megabyte) is cached for a day.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::http;
use crate::model::{Kev, Rating, Sbom, Severity};

/// Where CISA publishes the catalog; `PIXI_SBOM_KEV_URL` overrides it.
pub const DEFAULT_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// Environment variable naming the catalog URL to download.
pub const URL_ENV: &str = "PIXI_SBOM_KEV_URL";

/// The rating source recorded on known-exploited findings.
pub const RATING_SOURCE: &str = "CISA KEV";

/// How long a downloaded catalog is reused before it is fetched again.
const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Largest catalog accepted, in bytes.
const MAX_BYTES: u64 = 64 * 1024 * 1024;

const CACHE_FILE: &str = "known_exploited_vulnerabilities.json";

/// The catalog URL from the environment or the default.
pub fn url() -> String {
    std::env::var(URL_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_URL.to_string())
}

/// Why the catalog could not be loaded.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum KevError {
    /// The download failed and there is no cached copy.
    #[error("cannot download the CISA KEV catalog from {url}: {source}")]
    #[diagnostic(
        code(pixi_sbom::kev::fetch),
        help("check the network and proxy settings, or set PIXI_SBOM_OFFLINE=1 once a copy is cached")
    )]
    Fetch {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    /// The document is not the catalog.
    #[error("cannot parse the CISA KEV catalog from {origin}: {source}")]
    #[diagnostic(
        code(pixi_sbom::kev::parse),
        help(
            "a cached catalog truncated by an interrupted download reads like this: delete the file the \
             message names to fetch a fresh one, or `pixi clean cache` to clear the whole pixi cache"
        )
    )]
    Parse {
        origin: String,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Document {
    #[serde(default)]
    catalog_version: Option<String>,
    #[serde(default)]
    vulnerabilities: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(default)]
    date_added: Option<String>,
    #[serde(default)]
    due_date: Option<String>,
    #[serde(default)]
    known_ransomware_campaign_use: Option<String>,
    #[serde(default)]
    required_action: Option<String>,
    #[serde(default)]
    vulnerability_name: Option<String>,
}

/// The catalog, keyed by CVE id.
#[derive(Debug)]
pub struct Catalog {
    entries: HashMap<String, Kev>,
    /// The catalog's own version stamp (`YYYY.MM.DD`), when present.
    pub version: Option<String>,
}

impl Catalog {
    fn from_json(json: &str, origin: &str) -> Result<Self, KevError> {
        let document: Document = serde_json::from_str(json).map_err(|source| KevError::Parse {
            origin: origin.to_string(),
            source,
        })?;
        let entries = document
            .vulnerabilities
            .into_iter()
            .map(|e| {
                let kev = Kev {
                    cve_id: e.cve_id.clone(),
                    name: e.vulnerability_name,
                    date_added: e.date_added,
                    due_date: e.due_date,
                    ransomware: e
                        .known_ransomware_campaign_use
                        .is_some_and(|v| v.eq_ignore_ascii_case("known")),
                    required_action: e.required_action,
                };
                (e.cve_id.to_ascii_uppercase(), kev)
            })
            .collect();
        Ok(Self {
            entries,
            version: document.catalog_version,
        })
    }

    /// Number of catalog entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The entry for a CVE id, if it is known exploited.
    pub fn get(&self, cve_id: &str) -> Option<&Kev> {
        self.entries.get(&cve_id.to_ascii_uppercase())
    }

    /// Load the catalog: from the cache when younger than a day (or offline), else downloaded;
    /// a stale copy stands in with a warning when the download fails.
    pub fn load(cache_dir: &Path) -> Result<Self, KevError> {
        Self::load_with(cache_dir, &url(), CACHE_MAX_AGE, SystemTime::now(), |url| {
            http::get_text(url, MAX_BYTES)
        })
    }

    fn load_with(
        cache_dir: &Path,
        url: &str,
        max_age: Duration,
        now: SystemTime,
        download: impl FnOnce(&str) -> Result<String, Box<ureq::Error>>,
    ) -> Result<Self, KevError> {
        let cache_file = cache_dir.join("kev").join(CACHE_FILE);
        let cached = std::fs::read_to_string(&cache_file).ok();
        // A file written "after" `now` (clock skew, a test's captured clock) counts as fresh.
        let age = std::fs::metadata(&cache_file)
            .and_then(|meta| meta.modified())
            .ok()
            .map(|modified| now.duration_since(modified).unwrap_or(Duration::ZERO));
        if let (Some(json), Some(age)) = (&cached, age)
            && (age <= max_age || http::offline())
        {
            tracing::debug!(path = %cache_file.display(), age_secs = age.as_secs(), "using the cached KEV catalog");
            return Self::from_json(json, &cache_file.display().to_string());
        }
        tracing::info!(url, "downloading the CISA KEV catalog");
        match download(url) {
            Ok(json) => {
                let catalog = Self::from_json(&json, url)?;
                if let Err(err) = cache_file
                    .parent()
                    .map_or(Ok(()), std::fs::create_dir_all)
                    .and_then(|()| std::fs::write(&cache_file, &json))
                {
                    tracing::warn!(path = %cache_file.display(), %err, "cannot cache the KEV catalog");
                }
                Ok(catalog)
            }
            Err(source) => match cached {
                Some(json) => {
                    tracing::warn!(
                        cause = crate::http::error_chain(source.as_ref()),
                        "download failed; using the stale cached KEV catalog"
                    );
                    Self::from_json(&json, &cache_file.display().to_string())
                }
                None => Err(KevError::Fetch {
                    url: url.to_string(),
                    source,
                }),
            },
        }
    }
}

/// Mark every finding whose id or alias is in the catalog. Returns how many were marked.
pub fn apply(sbom: &mut Sbom, catalog: &Catalog) -> usize {
    let mut marked = 0;
    for vuln in &mut sbom.vulnerabilities {
        let Some(kev) = std::iter::once(&vuln.id)
            .chain(&vuln.aliases)
            .find_map(|name| catalog.get(name))
        else {
            continue;
        };
        vuln.kev = Some(kev.clone());
        vuln.ratings.push(Rating {
            source: RATING_SOURCE.to_string(),
            score: None,
            severity: Severity::Critical,
            method: "other",
            vector: None,
        });
        vuln.severity = Severity::Critical;
        marked += 1;
    }
    // Severity changed for some findings; keep the list worst first.
    sbom.vulnerabilities
        .sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    marked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use crate::model::{Affected, Vulnerability};

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        let bad_json = serde_json::from_str::<Document>("{").expect_err("truncated JSON");
        for err in [
            KevError::Fetch {
                url: url(),
                source: Box::new(ureq::Error::ConnectionFailed),
            },
            KevError::Parse {
                origin: "/cache/kev/known_exploited_vulnerabilities.json".to_string(),
                source: bad_json,
            },
        ] {
            crate::assert_actionable(&err);
        }
    }

    fn fixture() -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kev/known_exploited_vulnerabilities.json"),
        )
        .unwrap()
    }

    fn finding(id: &str, aliases: &[&str], severity: Severity) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            source: "OSV".into(),
            url: format!("https://osv.dev/vulnerability/{id}"),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            summary: None,
            details: None,
            severity,
            ratings: vec![],
            cwes: vec![],
            references: vec![],
            published: None,
            modified: None,
            affects: vec![Affected {
                package_id: "pkg:pypi/six@1.17.0".into(),
                purl: "pkg:pypi/six@1.17.0".into(),
                fixed_version: None,
            }],
            analysis: None,
            kev: None,
        }
    }

    #[test]
    fn catalog_parses_and_looks_up_case_insensitively() {
        let catalog = Catalog::from_json(&fixture(), "fixture").unwrap();
        assert_eq!(catalog.len(), 2);
        assert_eq!(catalog.version.as_deref(), Some("2026.09.18"));
        let entry = catalog.get("cve-2021-33503").unwrap();
        assert_eq!(entry.date_added.as_deref(), Some("2026-09-01"));
        assert_eq!(entry.due_date.as_deref(), Some("2026-09-22"));
        assert!(!entry.ransomware);
        assert!(entry.required_action.as_deref().unwrap().starts_with("Apply"));
        assert!(catalog.get("CVE-2025-39964").unwrap().ransomware);
        assert!(catalog.get("CVE-2000-0001").is_none());
        assert!(Catalog::from_json("nope", "x").is_err());
    }

    #[test]
    fn applying_marks_findings_by_alias_and_rates_them_critical() {
        let catalog = Catalog::from_json(&fixture(), "fixture").unwrap();
        let mut sbom = sample_sbom();
        sbom.vulnerabilities = vec![
            finding("GHSA-b", &[], Severity::High),
            finding("GHSA-a", &["CVE-2021-33503"], Severity::Medium),
        ];
        assert_eq!(apply(&mut sbom, &catalog), 1);
        // Re-sorted: the known-exploited finding is now critical and first.
        assert_eq!(sbom.vulnerabilities[0].id, "GHSA-a");
        assert_eq!(sbom.vulnerabilities[0].severity, Severity::Critical);
        assert_eq!(sbom.vulnerabilities[0].ratings[0].source, RATING_SOURCE);
        assert_eq!(sbom.vulnerabilities[0].kev.as_ref().unwrap().cve_id, "CVE-2021-33503");
        assert_eq!(sbom.vulnerabilities[1].kev, None);
        assert_eq!(sbom.vulnerabilities[1].severity, Severity::High);
    }

    #[test]
    fn cache_is_reused_for_a_day_and_stale_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let calls = std::cell::Cell::new(0);
        let download = |_: &str| {
            calls.set(calls.get() + 1);
            Ok(fixture())
        };
        Catalog::load_with(dir.path(), "https://kev.example", CACHE_MAX_AGE, now, download).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(dir.path().join("kev").join(CACHE_FILE).exists());
        // Fresh: not downloaded again.
        Catalog::load_with(dir.path(), "https://kev.example", CACHE_MAX_AGE, now, download).unwrap();
        assert_eq!(calls.get(), 1);
        // Expired and the download fails: the stale copy serves.
        let later = now + CACHE_MAX_AGE + Duration::from_secs(60);
        let failing = |_: &str| Err(Box::new(ureq::Error::ConnectionFailed));
        let catalog = Catalog::load_with(dir.path(), "https://kev.example", CACHE_MAX_AGE, later, failing).unwrap();
        assert_eq!(catalog.len(), 2);
        // No cache at all and a failed download is an error.
        let empty = tempfile::tempdir().unwrap();
        let err = Catalog::load_with(empty.path(), "https://kev.example", CACHE_MAX_AGE, now, failing).unwrap_err();
        assert!(err.to_string().contains("cannot download"), "{err}");
    }
}
