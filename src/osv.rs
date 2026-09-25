//! Vulnerability lookup through [OSV](https://osv.dev) for every package with a purl OSV
//! can answer: PyPI, crates.io, npm and the other ecosystems it indexes. Conda purls have no
//! ecosystem there and are skipped; the outcome says how many packages had no queryable
//! identity so the gap stays visible.
//!
//! One `querybatch` request per thousand purls yields the advisory ids, then each record is
//! fetched for its severity, aliases, fixed versions and references. Query results are cached
//! for an hour (advisories change) and records until their `modified` stamp moves, all under
//! the pixi-sbom cache directory, so repeated runs are cheap and `PIXI_SBOM_OFFLINE` works from
//! the cache. Records that describe the same vulnerability (a GHSA and a PYSEC entry sharing a
//! CVE) are merged into one finding.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cvss;
use crate::http;
use crate::model::{Affected, Rating, Sbom, Severity, Vulnerability};

/// Default API base; `PIXI_SBOM_OSV_URL` overrides it (mirrors, tests).
pub const DEFAULT_API_URL: &str = "https://api.osv.dev";

/// Environment variable naming the API base to query.
pub const API_URL_ENV: &str = "PIXI_SBOM_OSV_URL";

/// The source name recorded on every finding.
pub const SOURCE_NAME: &str = "OSV";

/// Purls per `querybatch` request (the API's maximum).
const BATCH_SIZE: usize = 1000;

/// How long a query result is trusted before the API is asked again.
const QUERY_MAX_AGE: Duration = Duration::from_secs(60 * 60);

/// Largest response accepted, in bytes.
const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;

/// Record fetches in flight at once.
const CONCURRENCY: usize = 10;

/// The API base from the environment or the default.
pub fn api_url() -> String {
    std::env::var(API_URL_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_API_URL.to_string())
}

/// What the lookup did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Distinct purls asked about.
    pub queried: usize,
    /// Packages with no purl OSV can answer (conda-only identities).
    pub without_identity: usize,
    /// Findings recorded in the document, after merging duplicates.
    pub findings: usize,
    /// Advisory records that could not be fetched; they are recorded by id only.
    pub failed: usize,
}

/// Why the lookup could not run at all.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum OsvError {
    /// A batch query failed and no fresh cache could stand in.
    #[error("cannot query OSV at {url}: {source}")]
    #[diagnostic(
        code(pixi_sbom::osv::query),
        help("check the network and proxy settings, or set PIXI_SBOM_OFFLINE=1 to use cached results only")
    )]
    Query {
        url: String,
        #[source]
        source: Box<ureq::Error>,
    },
    /// The API answered with something that is not a query result.
    #[error("unexpected OSV response from {url}: {source}")]
    #[diagnostic(code(pixi_sbom::osv::parse))]
    Parse {
        url: String,
        #[source]
        source: serde_json::Error,
    },
}

/// Configuration for one lookup.
pub struct Lookup<'a> {
    /// API base, e.g. `https://api.osv.dev`.
    pub api_url: &'a str,
    /// Cache directory (the pixi-sbom cache).
    pub cache_dir: &'a Path,
}

/// What a lookup needs from the network, so tests can record it.
pub trait Client: Sync {
    /// POST `body` to `url`, returning the JSON text.
    fn post(&self, url: &str, body: &str) -> Result<String, Box<ureq::Error>>;
    /// GET `url`, returning the JSON text.
    fn get(&self, url: &str) -> Result<String, Box<ureq::Error>>;
}

struct HttpClient;

impl Client for HttpClient {
    fn post(&self, url: &str, body: &str) -> Result<String, Box<ureq::Error>> {
        http::post_json(url, body, MAX_RESPONSE_BYTES)
    }

    fn get(&self, url: &str) -> Result<String, Box<ureq::Error>> {
        http::get_text(url, MAX_RESPONSE_BYTES)
    }
}

#[derive(Debug, Serialize)]
struct BatchRequest<'a> {
    queries: Vec<Query<'a>>,
}

#[derive(Debug, Serialize)]
struct Query<'a> {
    package: QueryPackage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct QueryPackage<'a> {
    purl: &'a str,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    results: Vec<QueryResult>,
}

#[derive(Debug, Default, Deserialize)]
struct QueryResult {
    #[serde(default)]
    vulns: Vec<VulnRef>,
    next_page_token: Option<String>,
}

/// An advisory id with its last-modified stamp, as `querybatch` returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VulnRef {
    pub id: String,
    #[serde(default)]
    pub modified: Option<String>,
}

/// A cached query result.
#[derive(Debug, Serialize, Deserialize)]
struct CachedQuery {
    purl: String,
    fetched_at: u64,
    vulns: Vec<VulnRef>,
}

/// `null` and a missing key both mean "none" for list fields.
fn null_as_empty<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// The parts of an OSV record this tool reads.
#[derive(Debug, Default, Deserialize)]
pub struct Record {
    pub id: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub published: Option<String>,
    pub modified: Option<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub severity: Vec<RecordSeverity>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub affected: Vec<RecordAffected>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub references: Vec<RecordReference>,
    #[serde(default)]
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RecordSeverity {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct RecordAffected {
    #[serde(default)]
    pub package: Option<RecordPackage>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub ranges: Vec<RecordRange>,
}

#[derive(Debug, Deserialize)]
pub struct RecordPackage {
    pub purl: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RecordRange {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub events: Vec<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct RecordReference {
    pub url: String,
}

/// The purl OSV is asked about: type, namespace, name and version, without qualifiers or a
/// subpath. `None` for purl types OSV has no ecosystem for.
pub fn queryable_purl(purl: &str) -> Option<String> {
    let bare = purl.split(['?', '#']).next().unwrap_or(purl);
    if bare.starts_with("pkg:conda/") || !bare.contains('@') {
        return None;
    }
    Some(bare.to_string())
}

/// The file name a purl's query result is cached under.
pub fn query_cache_name(purl: &str) -> String {
    let mut name: String = purl
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    name.push_str(".json");
    name
}

impl Lookup<'_> {
    /// Look every package up on OSV and record the findings in `sbom.vulnerabilities`.
    pub fn run(&self, sbom: &mut Sbom, progress: crate::progress::Progress) -> Result<Outcome, OsvError> {
        self.run_with(sbom, &HttpClient, SystemTime::now(), progress)
    }

    /// [`run`](Self::run) with an injectable client and clock.
    /// [`run`](Self::run) with an injectable client and clock.
    pub fn run_with(
        &self,
        sbom: &mut Sbom,
        client: &dyn Client,
        now: SystemTime,
        progress: crate::progress::Progress,
    ) -> Result<Outcome, OsvError> {
        let mut outcome = Outcome::default();
        // Which packages each queryable purl stands for; a conda package with a PyPI purl is
        // reachable through the latter.
        let mut purls: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, package) in sbom.packages.iter().enumerate() {
            let mut any = false;
            for purl in std::iter::once(&package.purl).chain(&package.extra_purls) {
                if let Some(purl) = queryable_purl(purl) {
                    purls.entry(purl).or_default().push(index);
                    any = true;
                }
            }
            if !any {
                outcome.without_identity += 1;
            }
        }
        outcome.queried = purls.len();
        let offline = http::offline();

        let refs = self.query(purls.keys().map(String::as_str).collect(), client, now, offline)?;

        // Which purls (and so packages) each advisory id was reported for.
        let mut hits: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut modified: HashMap<&str, Option<&str>> = HashMap::new();
        for (purl, vulns) in &refs {
            for vuln in vulns {
                hits.entry(&vuln.id).or_default().insert(purl);
                modified.insert(&vuln.id, vuln.modified.as_deref());
            }
        }
        let ids: Vec<&str> = hits.keys().copied().collect();
        let bar = progress.bar("advisories", ids.len());
        let records = crate::parallel::map(
            &ids,
            CONCURRENCY,
            Some(&bar),
            |id| (*id).to_string(),
            |id| self.record(id, modified[id], client, offline),
        );
        bar.finish();

        let mut findings = Vec::new();
        for (id, record) in ids.iter().zip(records) {
            let record = match record {
                Some(record) => record,
                None => {
                    outcome.failed += 1;
                    Record {
                        id: id.to_string(),
                        ..Record::default()
                    }
                }
            };
            let mut affects = Vec::new();
            for purl in &hits[id] {
                for &index in &purls[*purl] {
                    let package = &sbom.packages[index];
                    affects.push(Affected {
                        package_id: package.id.clone(),
                        purl: purl.to_string(),
                        fixed_version: fixed_version(&record, purl, package.version.as_deref()),
                    });
                }
            }
            findings.push(vulnerability(record, affects));
        }
        let mut merged = merge_duplicates(findings);
        merged.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
        outcome.findings = merged.len();
        sbom.vulnerabilities = merged;
        Ok(outcome)
    }

    /// The advisory refs for every purl, from the cache when fresh enough and from the API
    /// otherwise.
    fn query<'p>(
        &self,
        purls: Vec<&'p str>,
        client: &dyn Client,
        now: SystemTime,
        offline: bool,
    ) -> Result<BTreeMap<&'p str, Vec<VulnRef>>, OsvError> {
        let mut out = BTreeMap::new();
        let mut pending = Vec::new();
        for purl in purls {
            match self.cached_query(purl) {
                Some(cached) if offline || is_fresh(cached.fetched_at, now) => {
                    out.insert(purl, cached.vulns);
                }
                _ if offline => {
                    tracing::warn!(
                        purl,
                        "offline and no cached OSV result; treated as no known vulnerabilities"
                    );
                    out.insert(purl, Vec::new());
                }
                _ => pending.push(purl),
            }
        }
        let url = format!("{}/v1/querybatch", self.api_url.trim_end_matches('/'));
        for chunk in pending.chunks(BATCH_SIZE) {
            let mut done = vec![false; chunk.len()];
            let mut tokens: Vec<Option<String>> = vec![None; chunk.len()];
            let mut collected: Vec<Vec<VulnRef>> = vec![Vec::new(); chunk.len()];
            while done.iter().any(|d| !d) {
                let open: Vec<usize> = (0..chunk.len()).filter(|&i| !done[i]).collect();
                let body = serde_json::to_string(&BatchRequest {
                    queries: open
                        .iter()
                        .map(|&i| Query {
                            package: QueryPackage { purl: chunk[i] },
                            page_token: tokens[i].clone(),
                        })
                        .collect(),
                })
                .expect("serializable request");
                let text = client.post(&url, &body).map_err(|source| OsvError::Query {
                    url: url.clone(),
                    source,
                })?;
                let response: BatchResponse = serde_json::from_str(&text).map_err(|source| OsvError::Parse {
                    url: url.clone(),
                    source,
                })?;
                let mut results = response.results.into_iter();
                for i in open {
                    // A missing result means the API answered fewer entries than asked; treat
                    // it as no findings rather than looping forever.
                    let result = results.next().unwrap_or_default();
                    collected[i].extend(result.vulns);
                    tokens[i] = result.next_page_token;
                    done[i] = tokens[i].is_none();
                }
            }
            for (purl, vulns) in chunk.iter().zip(collected) {
                self.store_query(purl, &vulns, now);
                out.insert(purl, vulns);
            }
        }
        Ok(out)
    }

    fn query_cache_file(&self, purl: &str) -> PathBuf {
        self.cache_dir.join("osv").join("queries").join(query_cache_name(purl))
    }

    fn cached_query(&self, purl: &str) -> Option<CachedQuery> {
        let text = std::fs::read_to_string(self.query_cache_file(purl)).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn store_query(&self, purl: &str, vulns: &[VulnRef], now: SystemTime) {
        let cached = CachedQuery {
            purl: purl.to_string(),
            fetched_at: now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            vulns: vulns.to_vec(),
        };
        let file = self.query_cache_file(purl);
        if let Err(err) = file
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(&file, serde_json::to_vec(&cached).expect("serializable cache")))
        {
            tracing::warn!(path = %file.display(), %err, "cannot cache the OSV query result");
        }
    }

    fn record_cache_file(&self, id: &str) -> PathBuf {
        self.cache_dir.join("osv").join("vulns").join(format!("{id}.json"))
    }

    /// One advisory record: cached when its `modified` stamp matches the query's, fetched
    /// otherwise. `None` when it cannot be obtained.
    fn record(&self, id: &str, modified: Option<&str>, client: &dyn Client, offline: bool) -> Option<Record> {
        let file = self.record_cache_file(id);
        if let Ok(text) = std::fs::read_to_string(&file)
            && let Ok(record) = serde_json::from_str::<Record>(&text)
            && (offline || modified.is_none() || same_instant(record.modified.as_deref(), modified))
        {
            return Some(record);
        }
        if offline {
            tracing::warn!(id, "offline and no cached OSV record; recorded by id only");
            return None;
        }
        let url = format!("{}/v1/vulns/{id}", self.api_url.trim_end_matches('/'));
        let text = match client.get(&url) {
            Ok(text) => text,
            Err(err) => {
                tracing::warn!(id, %err, "cannot fetch the OSV record");
                return None;
            }
        };
        let record = match serde_json::from_str::<Record>(&text) {
            Ok(record) => record,
            Err(err) => {
                tracing::warn!(id, %err, "cannot parse the OSV record");
                return None;
            }
        };
        if let Err(err) = file
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(&file, &text))
        {
            tracing::warn!(path = %file.display(), %err, "cannot cache the OSV record");
        }
        Some(record)
    }
}

/// Whether two RFC 3339 stamps name the same microsecond. `querybatch` reports `modified`
/// with microseconds and the record itself with nanoseconds, so the strings never match.
fn same_instant(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let micros = |s: &str| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .ok()
                    .map(|t| t.timestamp_micros())
            };
            match (micros(a), micros(b)) {
                (Some(a), Some(b)) => a == b,
                _ => a == b,
            }
        }
        _ => false,
    }
}

fn is_fresh(fetched_at: u64, now: SystemTime) -> bool {
    let now = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    now.saturating_sub(fetched_at) < QUERY_MAX_AGE.as_secs()
}

/// The URL of a record on osv.dev.
pub fn record_url(id: &str) -> String {
    format!("https://osv.dev/vulnerability/{id}")
}

/// Build the finding for one record.
fn vulnerability(record: Record, mut affects: Vec<Affected>) -> Vulnerability {
    affects.sort_by(|a, b| a.package_id.cmp(&b.package_id).then_with(|| a.purl.cmp(&b.purl)));
    affects.dedup();
    let db = record.database_specific.as_ref();
    let mut ratings = Vec::new();
    if let Some(severity) = db
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .and_then(Severity::parse)
    {
        ratings.push(Rating {
            source: database_name(&record.id).to_string(),
            score: None,
            severity,
            method: "other",
            vector: None,
        });
    }
    for entry in &record.severity {
        let vector = entry.score.trim().to_string();
        let (method, score) = match entry.kind.as_str() {
            "CVSS_V3" => (
                if vector.starts_with("CVSS:3.1") {
                    "CVSSv31"
                } else {
                    "CVSSv3"
                },
                cvss::v3_base_score(&vector),
            ),
            "CVSS_V4" => ("CVSSv4", None),
            "CVSS_V2" => ("CVSSv2", None),
            _ => ("other", None),
        };
        let severity = score.map(Severity::from_cvss_score).unwrap_or_else(|| {
            // A vector without a computed score inherits the database's word for it.
            ratings.first().map(|r| r.severity).unwrap_or(Severity::Unknown)
        });
        ratings.push(Rating {
            source: SOURCE_NAME.to_string(),
            score,
            severity,
            method,
            vector: Some(vector),
        });
    }
    let severity = ratings.iter().map(|r| r.severity).max().unwrap_or(Severity::Unknown);
    let cwes = db
        .and_then(|d| d.get("cwe_ids"))
        .and_then(|c| c.as_array())
        .map(|ids| {
            ids.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| s.strip_prefix("CWE-")?.parse::<u32>().ok())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    let mut aliases: Vec<String> = record.aliases.iter().filter(|a| **a != record.id).cloned().collect();
    aliases.sort();
    aliases.dedup();
    let mut references: Vec<String> = record.references.iter().map(|r| r.url.clone()).collect();
    references.dedup();
    Vulnerability {
        url: record_url(&record.id),
        id: record.id,
        source: SOURCE_NAME.to_string(),
        aliases,
        summary: record.summary.filter(|s| !s.trim().is_empty()),
        details: record.details.filter(|s| !s.trim().is_empty()),
        severity,
        ratings,
        cwes,
        references,
        published: record.published,
        modified: record.modified,
        affects,
        analysis: None,
        kev: None,
    }
}

/// Which database an id comes from, for the qualitative rating's source.
fn database_name(id: &str) -> &'static str {
    match id.split('-').next().unwrap_or("") {
        "GHSA" => "GitHub Advisory Database",
        "PYSEC" => "PyPI Advisory Database",
        "RUSTSEC" => "RustSec Advisory Database",
        "GO" => "Go Vulnerability Database",
        _ => SOURCE_NAME,
    }
}

/// The smallest fixed version above `version` among the record's ranges for `purl`, or the
/// first fixed version listed when versions cannot be compared.
fn fixed_version(record: &Record, purl: &str, version: Option<&str>) -> Option<String> {
    let bare = purl.split('@').next().unwrap_or(purl).to_ascii_lowercase();
    let mut fixed: Vec<String> = Vec::new();
    for affected in &record.affected {
        let matches = affected
            .package
            .as_ref()
            .and_then(|p| p.purl.as_deref())
            .is_some_and(|p| p.split(['@', '?']).next().unwrap_or(p).eq_ignore_ascii_case(&bare));
        if !matches {
            continue;
        }
        for range in &affected.ranges {
            if range.kind == "GIT" {
                continue;
            }
            fixed.extend(range.events.iter().filter_map(|e| e.get("fixed").cloned()));
        }
    }
    if fixed.is_empty() {
        return None;
    }
    let current = version.and_then(|v| v.parse::<rattler_conda_types::Version>().ok());
    let mut candidates: Vec<(rattler_conda_types::Version, String)> = fixed
        .iter()
        .filter_map(|f| f.parse::<rattler_conda_types::Version>().ok().map(|v| (v, f.clone())))
        .collect();
    candidates.sort();
    match current {
        Some(current) => candidates
            .iter()
            .find(|(v, _)| *v > current)
            .map(|(_, f)| f.clone())
            .or_else(|| candidates.last().map(|(_, f)| f.clone()))
            .or_else(|| fixed.first().cloned()),
        None => candidates
            .first()
            .map(|(_, f)| f.clone())
            .or_else(|| fixed.first().cloned()),
    }
}

/// Merge records that describe the same vulnerability (they share an id or alias) into one
/// finding, keeping the best-described record as the representative.
fn merge_duplicates(findings: Vec<Vulnerability>) -> Vec<Vulnerability> {
    // Union-find over ids: every alias links its record to whichever record owns that id.
    let n = findings.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], i: usize) -> usize {
        let mut i = i;
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut owner: HashMap<&str, usize> = HashMap::new();
    for (i, finding) in findings.iter().enumerate() {
        for name in std::iter::once(&finding.id).chain(&finding.aliases) {
            match owner.get(name.as_str()) {
                Some(&j) => {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    if a != b {
                        parent[a] = b;
                    }
                }
                None => {
                    owner.insert(name, i);
                }
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..n {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(i);
    }
    let mut findings: Vec<Option<Vulnerability>> = findings.into_iter().map(Some).collect();
    let mut merged = Vec::new();
    for members in groups.into_values() {
        let rep = *members
            .iter()
            .max_by_key(|&&i| {
                let f = findings[i].as_ref().expect("unmerged");
                (
                    f.ratings.iter().any(|r| r.score.is_some()),
                    !f.ratings.is_empty(),
                    f.summary.is_some(),
                    f.id.starts_with("GHSA-"),
                    std::cmp::Reverse(f.id.clone()),
                )
            })
            .expect("non-empty group");
        let mut result = findings[rep].take().expect("unmerged");
        for &i in &members {
            if i == rep {
                continue;
            }
            let other = findings[i].take().expect("unmerged");
            result.aliases.push(other.id.clone());
            result.aliases.extend(other.aliases);
            for rating in other.ratings {
                if !result
                    .ratings
                    .iter()
                    .any(|r| r.vector == rating.vector && r.source == rating.source)
                {
                    result.ratings.push(rating);
                }
            }
            result.cwes.extend(other.cwes);
            result.references.extend(other.references);
            if result.summary.is_none() {
                result.summary = other.summary;
            }
            if result.details.is_none() {
                result.details = other.details;
            }
            for affected in other.affects {
                match result.affects.iter_mut().find(|a| a.package_id == affected.package_id) {
                    Some(existing) => {
                        if existing.fixed_version.is_none() {
                            existing.fixed_version = affected.fixed_version;
                        }
                    }
                    None => result.affects.push(affected),
                }
            }
        }
        result.aliases.retain(|a| *a != result.id);
        result.aliases.sort();
        result.aliases.dedup();
        result.cwes.sort_unstable();
        result.cwes.dedup();
        let mut seen = BTreeSet::new();
        result.references.retain(|r| seen.insert(r.clone()));
        result.affects.sort_by(|a, b| a.package_id.cmp(&b.package_id));
        result.severity = result
            .ratings
            .iter()
            .map(|r| r.severity)
            .max()
            .unwrap_or(Severity::Unknown);
        merged.push(result);
    }
    merged
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::format::testing::sample_sbom;
    use crate::model::{Package, PackageKind};

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/osv")
    }

    /// Serves the recorded fixtures: batch queries from `queries/`, records from `vulns/`.
    struct Recorded {
        posts: Mutex<Vec<String>>,
        gets: Mutex<Vec<String>>,
    }

    impl Recorded {
        fn new() -> Self {
            Self {
                posts: Mutex::new(Vec::new()),
                gets: Mutex::new(Vec::new()),
            }
        }
    }

    impl Client for Recorded {
        fn post(&self, url: &str, body: &str) -> Result<String, Box<ureq::Error>> {
            assert!(url.ends_with("/v1/querybatch"), "{url}");
            self.posts.lock().unwrap().push(body.to_string());
            let request: serde_json::Value = serde_json::from_str(body).unwrap();
            let results: Vec<serde_json::Value> = request["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| {
                    let purl = q["package"]["purl"].as_str().unwrap();
                    let file = fixtures().join("queries").join(query_cache_name(purl));
                    match std::fs::read_to_string(file) {
                        Ok(text) => {
                            let cached: serde_json::Value = serde_json::from_str(&text).unwrap();
                            serde_json::json!({ "vulns": cached["vulns"] })
                        }
                        Err(_) => serde_json::json!({}),
                    }
                })
                .collect();
            Ok(serde_json::json!({ "results": results }).to_string())
        }

        fn get(&self, url: &str) -> Result<String, Box<ureq::Error>> {
            self.gets.lock().unwrap().push(url.to_string());
            let id = url.rsplit('/').next().unwrap();
            std::fs::read_to_string(fixtures().join("vulns").join(format!("{id}.json")))
                .map_err(|e| Box::new(ureq::Error::Io(e)))
        }
    }

    /// A client that must not be used.
    struct Offline;

    impl Client for Offline {
        fn post(&self, url: &str, _: &str) -> Result<String, Box<ureq::Error>> {
            panic!("unexpected request to {url}")
        }

        fn get(&self, url: &str) -> Result<String, Box<ureq::Error>> {
            panic!("unexpected request to {url}")
        }
    }

    struct Failing(&'static str);

    impl Client for Failing {
        fn post(&self, _: &str, _: &str) -> Result<String, Box<ureq::Error>> {
            Ok(self.0.to_string())
        }

        fn get(&self, _: &str) -> Result<String, Box<ureq::Error>> {
            Err(Box::new(ureq::Error::StatusCode(500)))
        }
    }

    fn vulnerable_sbom() -> Sbom {
        let mut sbom = sample_sbom();
        // six (pypi) is clean; make zlib reachable through a PyPI purl and add urllib3 1.26.4.
        sbom.packages[0].extra_purls = vec!["pkg:pypi/six@1.17.0".into()];
        let six = sbom
            .packages
            .iter()
            .find(|p| p.kind == PackageKind::Pypi)
            .unwrap()
            .clone();
        sbom.packages.push(Package {
            id: "pkg:pypi/urllib3@1.26.4".into(),
            name: "urllib3".into(),
            version: Some("1.26.4".into()),
            purl: "pkg:pypi/urllib3@1.26.4".into(),
            extra_purls: vec![],
            ..six
        });
        sbom
    }

    #[test]
    fn purls_are_stripped_and_conda_is_not_queryable() {
        assert_eq!(
            queryable_purl("pkg:pypi/urllib3@1.26.4?x=y#sub").as_deref(),
            Some("pkg:pypi/urllib3@1.26.4")
        );
        assert_eq!(queryable_purl("pkg:conda/python@3.12?build=x"), None);
        assert_eq!(queryable_purl("pkg:pypi/noversion"), None);
        assert_eq!(
            query_cache_name("pkg:pypi/urllib3@1.26.4"),
            "pkg_pypi_urllib3_1.26.4.json"
        );
    }

    #[test]
    fn lookup_merges_records_and_caches_them() {
        let dir = tempfile::tempdir().unwrap();
        let lookup = Lookup {
            api_url: "https://osv.example",
            cache_dir: dir.path(),
        };
        let client = Recorded::new();
        let mut sbom = vulnerable_sbom();
        let outcome = lookup
            .run_with(
                &mut sbom,
                &client,
                SystemTime::now(),
                crate::progress::Progress::default(),
            )
            .unwrap();
        assert_eq!(
            outcome,
            Outcome {
                queried: 3,
                without_identity: 1,
                findings: 9,
                failed: 0
            }
        );
        assert_eq!(client.posts.lock().unwrap().len(), 1, "one batch for three purls");
        assert_eq!(client.gets.lock().unwrap().len(), 18, "every record fetched once");

        let ids: Vec<&str> = sbom.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        assert!(ids.iter().all(|id| id.starts_with("GHSA-")), "{ids:?}");
        let severities: Vec<Severity> = sbom.vulnerabilities.iter().map(|v| v.severity).collect();
        assert!(
            severities.windows(2).all(|w| w[0] >= w[1]),
            "sorted worst first: {severities:?}"
        );

        let regex = sbom
            .vulnerabilities
            .iter()
            .find(|v| v.id == "GHSA-q2q7-5pp4-w6pg")
            .unwrap();
        assert_eq!(regex.aliases, ["CVE-2021-33503", "PYSEC-2021-108"]);
        assert_eq!(regex.severity, Severity::High);
        assert_eq!(regex.cwes, [400]);
        assert!(regex.summary.as_deref().unwrap().contains("backtracking"));
        assert_eq!(regex.ratings[0].source, "GitHub Advisory Database");
        let cvss = regex.ratings.iter().find(|r| r.method == "CVSSv31").unwrap();
        assert_eq!(cvss.score, Some(7.5));
        assert_eq!(regex.affects.len(), 1);
        assert_eq!(regex.affects[0].package_id, "pkg:pypi/urllib3@1.26.4");
        assert_eq!(regex.affects[0].fixed_version.as_deref(), Some("1.26.5"));
        assert_eq!(regex.url, "https://osv.dev/vulnerability/GHSA-q2q7-5pp4-w6pg");

        // The fixed version is the smallest one above the installed version.
        let cookie = sbom
            .vulnerabilities
            .iter()
            .find(|v| v.id == "GHSA-v845-jxx5-vc9f")
            .unwrap();
        assert_eq!(cookie.affects[0].fixed_version.as_deref(), Some("1.26.17"));

        // Everything is cached: a second run works offline and asks nothing.
        assert!(dir.path().join("osv/queries/pkg_pypi_urllib3_1.26.4.json").exists());
        assert!(dir.path().join("osv/vulns/PYSEC-2021-108.json").exists());
        let mut again = vulnerable_sbom();
        let outcome = lookup
            .run_with(
                &mut again,
                &Offline,
                SystemTime::now(),
                crate::progress::Progress::default(),
            )
            .unwrap();
        assert_eq!(outcome.findings, 9);
        assert_eq!(again.vulnerabilities, sbom.vulnerabilities);

        // A stale query result is asked again once the hour is over; unchanged records are not.
        let later = SystemTime::now() + QUERY_MAX_AGE + Duration::from_secs(1);
        let client = Recorded::new();
        lookup
            .run_with(&mut again, &client, later, crate::progress::Progress::default())
            .unwrap();
        assert_eq!(client.posts.lock().unwrap().len(), 1);
        assert_eq!(client.gets.lock().unwrap().len(), 0);
    }

    #[test]
    fn clean_packages_and_no_identity() {
        let dir = tempfile::tempdir().unwrap();
        let lookup = Lookup {
            api_url: "https://osv.example",
            cache_dir: dir.path(),
        };
        let mut sbom = sample_sbom();
        let outcome = lookup
            .run_with(
                &mut sbom,
                &Recorded::new(),
                SystemTime::now(),
                crate::progress::Progress::default(),
            )
            .unwrap();
        assert_eq!(
            outcome,
            Outcome {
                queried: 2,
                without_identity: 2,
                findings: 0,
                failed: 0
            }
        );
        assert!(sbom.vulnerabilities.is_empty());
    }

    #[test]
    fn query_errors_are_fatal_and_record_errors_are_not() {
        let dir = tempfile::tempdir().unwrap();
        let lookup = Lookup {
            api_url: "https://osv.example",
            cache_dir: dir.path(),
        };
        let mut sbom = vulnerable_sbom();
        let err = lookup
            .run_with(
                &mut sbom,
                &Failing("not json"),
                SystemTime::now(),
                crate::progress::Progress::default(),
            )
            .unwrap_err();
        assert!(matches!(err, OsvError::Parse { .. }), "{err}");

        struct Down;
        impl Client for Down {
            fn post(&self, _: &str, _: &str) -> Result<String, Box<ureq::Error>> {
                Err(Box::new(ureq::Error::ConnectionFailed))
            }
            fn get(&self, _: &str) -> Result<String, Box<ureq::Error>> {
                unreachable!()
            }
        }
        let err = lookup
            .run_with(
                &mut sbom,
                &Down,
                SystemTime::now(),
                crate::progress::Progress::default(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("cannot query OSV"), "{err}");

        // Records that cannot be fetched are kept by id, with nothing known about them.
        let one = Failing(r#"{"results":[{"vulns":[{"id":"GHSA-xxxx-yyyy-zzzz"}]},{},{}]}"#);
        let outcome = lookup
            .run_with(&mut sbom, &one, SystemTime::now(), crate::progress::Progress::default())
            .unwrap();
        assert_eq!(outcome.failed, 1);
        assert_eq!(outcome.findings, 1);
        let finding = &sbom.vulnerabilities[0];
        assert_eq!(finding.id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(finding.severity, Severity::Unknown);
        assert!(finding.ratings.is_empty());
        // The first purl (six) stands for the PyPI package and the conda one carrying it.
        assert_eq!(finding.affects.len(), 2);
    }

    #[test]
    fn modified_stamps_compare_by_microsecond() {
        assert!(same_instant(
            Some("2026-07-08T06:00:54.217433740Z"),
            Some("2026-07-08T06:00:54.217433Z")
        ));
        assert!(!same_instant(
            Some("2026-07-08T06:00:54.217433Z"),
            Some("2026-07-08T06:00:55Z")
        ));
        assert!(same_instant(Some("x"), Some("x")));
        assert!(!same_instant(None, Some("x")));
    }

    #[test]
    fn paginated_results_are_followed() {
        struct Paged(Mutex<usize>);
        impl Client for Paged {
            fn post(&self, _: &str, body: &str) -> Result<String, Box<ureq::Error>> {
                let mut calls = self.0.lock().unwrap();
                *calls += 1;
                let request: serde_json::Value = serde_json::from_str(body).unwrap();
                let queries = request["queries"].as_array().unwrap();
                Ok(if *calls == 1 {
                    assert_eq!(queries.len(), 3);
                    r#"{"results":[{"vulns":[{"id":"A-1"}],"next_page_token":"t"},{"vulns":[]},{}]}"#.into()
                } else {
                    assert_eq!(queries.len(), 1, "only the purl with a token is asked again");
                    assert_eq!(queries[0]["page_token"], "t");
                    r#"{"results":[{"vulns":[{"id":"A-2"}]}]}"#.into()
                })
            }
            fn get(&self, url: &str) -> Result<String, Box<ureq::Error>> {
                let id = url.rsplit('/').next().unwrap();
                Ok(format!(r#"{{"id":"{id}","summary":"s"}}"#))
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let lookup = Lookup {
            api_url: "https://osv.example",
            cache_dir: dir.path(),
        };
        let mut sbom = vulnerable_sbom();
        let outcome = lookup
            .run_with(
                &mut sbom,
                &Paged(Mutex::new(0)),
                SystemTime::now(),
                crate::progress::Progress::default(),
            )
            .unwrap();
        assert_eq!(outcome.findings, 2);
        let ids: Vec<&str> = sbom.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, ["A-1", "A-2"]);
    }

    fn record(json: &str) -> Record {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn severity_comes_from_the_database_word_then_cvss() {
        let v = vulnerability(
            record(
                r#"{"id":"X-1","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}"#,
            ),
            vec![],
        );
        assert_eq!(v.severity, Severity::Critical);
        assert_eq!(v.ratings.len(), 1);
        assert_eq!(v.ratings[0].score, Some(9.8));
        assert_eq!(v.ratings[0].source, "OSV");

        // A CVSS v4 vector has no computed score and takes the database's word.
        let v = vulnerability(
            record(
                r#"{"id":"GHSA-a","database_specific":{"severity":"MODERATE","cwe_ids":["CWE-79","bogus"]},"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N"}]}"#,
            ),
            vec![],
        );
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.ratings[1].method, "CVSSv4");
        assert_eq!(v.ratings[1].severity, Severity::Medium);
        assert_eq!(v.cwes, [79]);

        let v = vulnerability(record(r#"{"id":"X-2","summary":"  "}"#), vec![]);
        assert_eq!(v.severity, Severity::Unknown);
        assert_eq!(v.summary, None);
    }

    #[test]
    fn fixed_version_picks_the_next_fix_and_ignores_other_packages() {
        let rec = record(
            r#"{"id":"X","affected":[
                {"package":{"purl":"pkg:pypi/other"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.9"}]}]},
                {"package":{"purl":"pkg:pypi/urllib3"},"ranges":[
                    {"type":"GIT","events":[{"fixed":"abc"}]},
                    {"type":"ECOSYSTEM","events":[{"introduced":"2.0.0"},{"fixed":"2.0.6"}]},
                    {"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.26.17"}]}]}]}"#,
        );
        assert_eq!(
            fixed_version(&rec, "pkg:pypi/urllib3@1.26.4", Some("1.26.4")).as_deref(),
            Some("1.26.17")
        );
        assert_eq!(
            fixed_version(&rec, "pkg:pypi/urllib3@2.0.1", Some("2.0.1")).as_deref(),
            Some("2.0.6")
        );
        // Above every fix: the latest fix is still the best advice.
        assert_eq!(
            fixed_version(&rec, "pkg:pypi/urllib3@3.0", Some("3.0")).as_deref(),
            Some("2.0.6")
        );
        assert_eq!(
            fixed_version(&rec, "pkg:pypi/urllib3@x", None).as_deref(),
            Some("1.26.17")
        );
        assert_eq!(fixed_version(&rec, "pkg:pypi/nothing@1", Some("1")), None);
    }

    #[test]
    fn duplicates_merge_into_the_best_described_record() {
        let a = vulnerability(
            record(r#"{"id":"PYSEC-1","aliases":["CVE-1"],"references":[{"url":"u1"}]}"#),
            vec![Affected {
                package_id: "p".into(),
                purl: "pkg:pypi/p@1".into(),
                fixed_version: Some("2".into()),
            }],
        );
        let b = vulnerability(
            record(
                r#"{"id":"GHSA-1","aliases":["CVE-1"],"summary":"s","database_specific":{"severity":"LOW"},"references":[{"url":"u2"},{"url":"u1"}]}"#,
            ),
            vec![Affected {
                package_id: "p".into(),
                purl: "pkg:pypi/p@1".into(),
                fixed_version: None,
            }],
        );
        let c = vulnerability(record(r#"{"id":"OTHER-1"}"#), vec![]);
        let merged = merge_duplicates(vec![a, b, c]);
        assert_eq!(merged.len(), 2);
        let ghsa = merged.iter().find(|v| v.id == "GHSA-1").unwrap();
        assert_eq!(ghsa.aliases, ["CVE-1", "PYSEC-1"]);
        assert_eq!(ghsa.references, ["u2", "u1"]);
        assert_eq!(ghsa.severity, Severity::Low);
        assert_eq!(ghsa.affects.len(), 1);
        assert_eq!(ghsa.affects[0].fixed_version.as_deref(), Some("2"));
        assert!(merged.iter().any(|v| v.id == "OTHER-1"));
    }
}
