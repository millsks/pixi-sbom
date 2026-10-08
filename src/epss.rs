//! FIRST's Exploit Prediction Scoring System, layered on the findings of `--vulnerabilities`:
//! a finding with a CVE alias gets the probability (0 to 1) that the CVE is exploited in the
//! next 30 days, and its percentile among every scored CVE. KEV says what is already exploited;
//! EPSS ranks the rest. Scores are asked for in batches, once per run, and cached per CVE for a
//! day, which is how often FIRST recomputes them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::http;
use crate::model::{Epss, Sbom};

/// FIRST's EPSS API; `PIXI_SBOM_EPSS_URL` overrides it.
pub const DEFAULT_URL: &str = "https://api.first.org/data/v1/epss";

/// Environment variable naming the API to ask.
pub const URL_ENV: &str = "PIXI_SBOM_EPSS_URL";

/// How long a CVE's score is reused before it is asked for again.
const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// CVEs per request: the API pages at 100 rows, and 100 ids keep the URL well under 2 KB.
const BATCH: usize = 100;

/// Largest answer accepted, in bytes.
const MAX_BYTES: u64 = 4 * 1024 * 1024;

const CACHE_FILE: &str = "scores.json";

/// The API URL from the environment or the default.
pub fn url() -> String {
    std::env::var(URL_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_URL.to_string())
}

/// Why the scores could not be loaded.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum EpssError {
    /// A request failed and some CVE it asked about has no cached score.
    #[error("cannot ask the EPSS API at {url}: {source}")]
    #[diagnostic(
        code(pixi_sbom::epss::fetch),
        help("check the network and proxy settings, or set PIXI_SBOM_OFFLINE=1 once the scores are cached")
    )]
    Fetch {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    /// The answer is not the API's.
    #[error("cannot parse the EPSS answer from {origin}: {source}")]
    #[diagnostic(
        code(pixi_sbom::epss::parse),
        help(
            "a mirror set with PIXI_SBOM_EPSS_URL has to answer like api.first.org/data/v1/epss, \
             a JSON object with a `data` array of `cve`, `epss`, `percentile` and `date`"
        )
    )]
    Parse {
        origin: String,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Deserialize)]
struct Answer {
    #[serde(default)]
    data: Vec<Row>,
}

#[derive(Debug, Deserialize)]
struct Row {
    cve: String,
    #[serde(deserialize_with = "number")]
    epss: f64,
    #[serde(deserialize_with = "number")]
    percentile: f64,
    #[serde(default)]
    date: Option<String>,
}

/// The API sends numbers as strings (`"0.029740000"`); a mirror may send numbers.
fn number<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<f64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Number(f64),
        Text(String),
    }
    match Either::deserialize(deserializer)? {
        Either::Number(n) => Ok(n),
        Either::Text(text) => text.trim().parse().map_err(serde::de::Error::custom),
    }
}

/// One CVE in the cache: its score, or nothing when FIRST has not scored it, and when it was
/// asked.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epss: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    percentile: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    date: Option<String>,
    /// Seconds since the epoch.
    fetched: u64,
}

/// The scores this run found, keyed by upper-case CVE id.
#[derive(Debug, Default)]
pub struct Scores {
    scores: HashMap<String, Epss>,
}

impl Scores {
    /// The score for a CVE, when FIRST has one.
    pub fn get(&self, cve_id: &str) -> Option<&Epss> {
        self.scores.get(&cve_id.to_ascii_uppercase())
    }

    /// How many CVEs have a score.
    pub fn len(&self) -> usize {
        self.scores.len()
    }

    /// Whether no CVE has a score.
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

/// The CVE ids among the findings' ids and aliases, upper-cased.
pub fn cves(sbom: &Sbom) -> BTreeSet<String> {
    sbom.vulnerabilities
        .iter()
        .flat_map(|v| std::iter::once(&v.id).chain(&v.aliases))
        .map(|name| name.to_ascii_uppercase())
        .filter(|name| name.starts_with("CVE-"))
        .collect()
}

/// Look `cves` up: cached scores younger than a day (any age offline) are reused, the rest are
/// asked for in batches; a failed batch falls back to stale cached scores when every CVE in it
/// has one.
pub fn lookup(cache_dir: &Path, cves: &BTreeSet<String>) -> Result<Scores, EpssError> {
    lookup_with(cache_dir, &url(), cves, CACHE_MAX_AGE, SystemTime::now(), |url| {
        http::get_text(url, MAX_BYTES)
    })
}

fn lookup_with(
    cache_dir: &Path,
    url: &str,
    cves: &BTreeSet<String>,
    max_age: Duration,
    now: SystemTime,
    mut download: impl FnMut(&str) -> Result<String, Box<ureq::Error>>,
) -> Result<Scores, EpssError> {
    use crate::cache::Service;
    let cache_file = cache_dir.join("epss").join(CACHE_FILE);
    let mut cache: BTreeMap<String, Entry> = if crate::cache::may_read(Service::Epss) {
        read_cache(&cache_file)
    } else {
        BTreeMap::new()
    };
    let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let age = |entry: &Entry| Duration::from_secs(now_secs.saturating_sub(entry.fetched));
    let fresh = |entry: &Entry| age(entry) <= max_age || http::offline();
    let missing: Vec<&String> = cves.iter().filter(|cve| !cache.get(*cve).is_some_and(fresh)).collect();
    if missing.is_empty() {
        if let Some(oldest) = cves.iter().filter_map(|cve| cache.get(cve)).map(age).max() {
            crate::cache::hit(Service::Epss, oldest);
        }
    } else {
        crate::cache::miss(Service::Epss);
        tracing::info!(cves = missing.len(), url, "asking FIRST for EPSS scores");
    }
    let mut asked = false;
    for batch in missing.chunks(BATCH) {
        let request = format!(
            "{url}?cve={}",
            batch.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(",")
        );
        match download(&request) {
            Ok(text) => {
                let answer: Answer = serde_json::from_str(&text).map_err(|source| EpssError::Parse {
                    origin: url.to_string(),
                    source,
                })?;
                let mut rows: HashMap<String, Row> = answer
                    .data
                    .into_iter()
                    .map(|row| (row.cve.to_ascii_uppercase(), row))
                    .collect();
                // A CVE the answer leaves out has no score yet; that is cached too, so it is
                // not asked about again until tomorrow.
                for cve in batch {
                    let row = rows.remove(*cve);
                    cache.insert(
                        (*cve).clone(),
                        Entry {
                            epss: row.as_ref().map(|r| r.epss),
                            percentile: row.as_ref().map(|r| r.percentile),
                            date: row.and_then(|r| r.date),
                            fetched: now_secs,
                        },
                    );
                }
                asked = true;
            }
            Err(source) => {
                if !batch.iter().all(|cve| cache.contains_key(*cve)) {
                    return Err(EpssError::Fetch {
                        url: url.to_string(),
                        source,
                    });
                }
                let oldest = batch
                    .iter()
                    .filter_map(|cve| cache.get(*cve))
                    .map(age)
                    .max()
                    .unwrap_or_default();
                crate::cache::stale(Service::Epss, oldest);
                tracing::warn!(
                    cause = crate::http::error_chain(source.as_ref()),
                    age_secs = oldest.as_secs(),
                    "EPSS request failed; using the stale cached scores"
                );
            }
        }
    }
    if asked
        && crate::cache::may_write(Service::Epss)
        && let Err(err) = write_cache(&cache_file, &cache)
    {
        tracing::warn!(path = %cache_file.display(), %err, "cannot cache the EPSS scores");
    }
    let scores = cves
        .iter()
        .filter_map(|cve| {
            let entry = cache.get(cve)?;
            Some((
                cve.clone(),
                Epss {
                    cve_id: cve.clone(),
                    score: entry.epss?,
                    percentile: entry.percentile?,
                    date: entry.date.clone(),
                },
            ))
        })
        .collect();
    Ok(Scores { scores })
}

/// The cached scores; an unreadable cache is logged and starts over, since every entry in it
/// can be asked for again.
fn read_cache(path: &Path) -> BTreeMap<String, Entry> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    serde_json::from_str(&text).unwrap_or_else(|err| {
        tracing::warn!(path = %path.display(), %err, "ignoring an unreadable EPSS cache");
        BTreeMap::new()
    })
}

fn write_cache(path: &Path, cache: &BTreeMap<String, Entry>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec(cache)?)
}

/// Give every finding the highest score among its CVEs. Returns how many were scored.
pub fn apply(sbom: &mut Sbom, scores: &Scores) -> usize {
    let mut scored = 0;
    for vuln in &mut sbom.vulnerabilities {
        let best = std::iter::once(&vuln.id)
            .chain(&vuln.aliases)
            .filter_map(|name| scores.get(name))
            .max_by(|a, b| a.score.total_cmp(&b.score));
        vuln.epss = best.cloned();
        scored += usize::from(vuln.epss.is_some());
    }
    scored
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use crate::model::{Affected, Severity, Vulnerability};

    fn fixture() -> String {
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/epss/epss.json")).unwrap()
    }

    fn finding(id: &str, aliases: &[&str]) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            source: "OSV".into(),
            url: format!("https://osv.dev/vulnerability/{id}"),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            summary: None,
            details: None,
            severity: Severity::Medium,
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
            epss: None,
        }
    }

    fn set(cves: &[&str]) -> BTreeSet<String> {
        cves.iter().map(|c| c.to_string()).collect()
    }

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        let bad_json = serde_json::from_str::<Answer>("{").expect_err("truncated JSON");
        for err in [
            EpssError::Fetch {
                url: url(),
                source: Box::new(ureq::Error::ConnectionFailed),
            },
            EpssError::Parse {
                origin: url(),
                source: bad_json,
            },
        ] {
            crate::assert_actionable(&err);
        }
    }

    #[test]
    fn cves_come_from_ids_and_aliases() {
        let mut sbom = sample_sbom();
        sbom.vulnerabilities = vec![
            finding("GHSA-a", &["cve-2021-33503", "PYSEC-1"]),
            finding("CVE-2023-43804", &[]),
        ];
        assert_eq!(cves(&sbom), set(&["CVE-2021-33503", "CVE-2023-43804"]));
    }

    #[test]
    fn the_recorded_answer_scores_findings_and_a_missing_cve_has_none() {
        let dir = tempfile::tempdir().unwrap();
        let requests = std::cell::RefCell::new(Vec::new());
        let wanted = set(&["CVE-2021-33503", "CVE-2023-43804", "CVE-2099-0001"]);
        let scores = lookup_with(
            dir.path(),
            "https://epss.example/v1",
            &wanted,
            CACHE_MAX_AGE,
            SystemTime::now(),
            |url| {
                requests.borrow_mut().push(url.to_string());
                Ok(fixture())
            },
        )
        .unwrap();
        assert_eq!(
            requests.borrow().as_slice(),
            ["https://epss.example/v1?cve=CVE-2021-33503,CVE-2023-43804,CVE-2099-0001"],
            "one batched request"
        );
        assert_eq!(scores.len(), 2);
        assert!(scores.get("CVE-2099-0001").is_none(), "not scored by FIRST");
        let score = scores.get("cve-2021-33503").unwrap();
        assert!((score.score - 0.03273).abs() < 1e-9, "{score:?}");
        assert!((score.percentile - 0.88073).abs() < 1e-9, "{score:?}");
        assert_eq!(score.date.as_deref(), Some("2026-10-08"));

        let mut sbom = sample_sbom();
        sbom.vulnerabilities = vec![
            finding("GHSA-a", &["CVE-2023-43804", "CVE-2021-33503"]),
            finding("GHSA-b", &["CVE-2099-0001"]),
            finding("GHSA-c", &[]),
        ];
        assert_eq!(apply(&mut sbom, &scores), 1);
        let best = sbom.vulnerabilities[0].epss.as_ref().unwrap();
        assert_eq!(best.cve_id, "CVE-2021-33503", "the higher of the two aliases");
        assert_eq!(sbom.vulnerabilities[1].epss, None);
        assert_eq!(sbom.vulnerabilities[2].epss, None);
    }

    #[test]
    fn scores_are_cached_for_a_day_batched_by_hundred_and_stale_on_failure() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        let calls = std::cell::Cell::new(0);
        let answer = |_: &str| {
            calls.set(calls.get() + 1);
            Ok(fixture())
        };
        let wanted = set(&["CVE-2021-33503"]);
        lookup_with(dir.path(), "https://e", &wanted, CACHE_MAX_AGE, now, answer).unwrap();
        assert_eq!(calls.get(), 1);
        assert!(dir.path().join("epss").join(CACHE_FILE).exists());
        // Fresh: not asked again, including a CVE cached as unscored.
        let unscored = set(&["CVE-2099-0001"]);
        lookup_with(dir.path(), "https://e", &unscored, CACHE_MAX_AGE, now, answer).unwrap();
        assert_eq!(calls.get(), 2);
        lookup_with(dir.path(), "https://e", &unscored, CACHE_MAX_AGE, now, answer).unwrap();
        let scores = lookup_with(dir.path(), "https://e", &wanted, CACHE_MAX_AGE, now, answer).unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(scores.len(), 1);

        // A day later the request fails: the stale scores serve.
        let later = now + CACHE_MAX_AGE + Duration::from_secs(60);
        let failing = |_: &str| Err(Box::new(ureq::Error::ConnectionFailed));
        let scores = lookup_with(dir.path(), "https://e", &wanted, CACHE_MAX_AGE, later, failing).unwrap();
        assert_eq!(scores.len(), 1);
        // A CVE never cached cannot be served stale.
        let err = lookup_with(
            dir.path(),
            "https://e",
            &set(&["CVE-2021-33503", "CVE-2000-0001"]),
            CACHE_MAX_AGE,
            later,
            failing,
        )
        .unwrap_err();
        assert!(err.to_string().contains("cannot ask the EPSS API"), "{err}");

        // 250 CVEs are three requests.
        let many: BTreeSet<String> = (0..250).map(|n| format!("CVE-2030-{n:05}")).collect();
        let mut sizes = Vec::new();
        lookup_with(dir.path(), "https://e", &many, CACHE_MAX_AGE, now, |url| {
            sizes.push(url.matches("CVE-").count());
            Ok(r#"{"data":[]}"#.to_string())
        })
        .unwrap();
        assert_eq!(sizes, [100, 100, 50]);
    }

    #[test]
    fn an_answer_that_is_not_the_apis_is_a_parse_error_and_a_bad_cache_starts_over() {
        let dir = tempfile::tempdir().unwrap();
        let wanted = set(&["CVE-2021-33503"]);
        let err = lookup_with(
            dir.path(),
            "https://e",
            &wanted,
            CACHE_MAX_AGE,
            SystemTime::now(),
            |_| Ok("<html>".to_string()),
        )
        .unwrap_err();
        assert!(matches!(err, EpssError::Parse { .. }), "{err}");
        // Numbers as numbers, from a mirror, read the same.
        let numeric = r#"{"data":[{"cve":"CVE-2021-33503","epss":0.5,"percentile":0.9}]}"#;
        std::fs::create_dir_all(dir.path().join("epss")).unwrap();
        std::fs::write(dir.path().join("epss").join(CACHE_FILE), "not json").unwrap();
        let scores = lookup_with(
            dir.path(),
            "https://e",
            &wanted,
            CACHE_MAX_AGE,
            SystemTime::now(),
            |_| Ok(numeric.to_string()),
        )
        .unwrap();
        assert_eq!(scores.get("CVE-2021-33503").unwrap().score, 0.5);
        assert!(!scores.is_empty());
    }
}
