//! How far behind its index each package is: the version in the environment, when it was
//! published, the newest release, and how many releases sit in between.
//!
//! PyPI answers this from the project document (`/pypi/<name>/json`), which lists every
//! release with its upload time. Conda channels do not: `repodata.json` is hundreds of
//! megabytes, so for channels hosted on anaconda.org the package API
//! (`https://api.anaconda.org/package/<channel>/<name>`) is asked instead, and packages from
//! anywhere else are reported as unknown rather than guessed at.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use std::collections::BTreeMap;

use crate::http;
use crate::model::{PackageKind, Sbom};

/// Where conda versions are looked up; `PIXI_SBOM_ANACONDA_URL` overrides it.
pub const DEFAULT_ANACONDA_URL: &str = "https://api.anaconda.org";

/// Environment variable naming the anaconda.org API base.
pub const ANACONDA_URL_ENV: &str = "PIXI_SBOM_ANACONDA_URL";

/// The channel a package is checked against when its own channel is not one the index knows.
///
/// conda-forge because that is what the overwhelming majority of mirrored channels proxy, and
/// because a wrong guess is caught by the hash rather than believed.
pub const DEFAULT_FALLBACK_CHANNEL: &str = "conda-forge";

/// Environment variable naming the channel to fall back to.
pub const FALLBACK_CHANNEL_ENV: &str = "PIXI_SBOM_CONDA_FALLBACK_CHANNEL";

/// The fallback channel from the environment or the default; empty disables the fallback.
pub fn fallback_channel() -> Option<String> {
    match std::env::var(FALLBACK_CHANNEL_ENV) {
        Ok(value) if value.trim().is_empty() => None,
        Ok(value) => Some(value.trim().to_string()),
        Err(_) => Some(DEFAULT_FALLBACK_CHANNEL.to_string()),
    }
}

/// Where prefix.dev answers GraphQL.
pub const DEFAULT_PREFIX_INDEX_URL: &str = "https://prefix.dev/api/graphql";

/// Environment variable naming the prefix.dev GraphQL endpoint.
pub const PREFIX_INDEX_URL_ENV: &str = "PIXI_SBOM_PREFIX_INDEX_URL";

/// Project documents list every release, so they change with each one: a day is long enough
/// to make a CI run cheap and short enough to stay useful.
const CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// How one document is fetched: a GET, or a POST carrying a query body for an index that is asked
/// rather than read. Taken as a parameter so the tests need no network.
type Fetch<'a> = &'a (dyn Fn(&str, Option<&str>) -> Result<String, Box<ureq::Error>> + Sync);

/// Largest project document accepted, in bytes.
const MAX_BYTES: u64 = 32 * 1024 * 1024;

/// The prefix.dev GraphQL endpoint from the environment or the default.
pub fn prefix_index_url() -> String {
    std::env::var(PREFIX_INDEX_URL_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_PREFIX_INDEX_URL.to_string())
}

/// The anaconda.org API base from the environment or the default.
pub fn anaconda_url() -> String {
    std::env::var(ANACONDA_URL_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ANACONDA_URL.to_string())
}

/// One published release of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: String,
    /// RFC 3339 publication time, when the index records one.
    pub published: Option<String>,
    /// Withdrawn (PEP 592); never offered as the newest release.
    pub yanked: bool,
}

/// How big a step separates two versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Patch,
    Minor,
    Major,
    /// The versions cannot be compared segment by segment.
    Unknown,
}

impl Step {
    /// The word the reports print.
    pub fn name(self) -> &'static str {
        match self {
            Step::Patch => "patch",
            Step::Minor => "minor",
            Step::Major => "major",
            Step::Unknown => "-",
        }
    }
}

/// What the index says about one package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// When the pinned version was published, when the index records it.
    pub current_published: Option<String>,
    /// The newest release that is neither yanked nor a prerelease.
    pub latest: Option<String>,
    pub latest_published: Option<String>,
    /// Releases published after the pinned one, excluding prereleases and yanked ones.
    pub behind: usize,
    pub step: Step,
}

/// Whether a version string names a prerelease (`2.0.0rc1`, `1.4.0b2`, `0.9.dev3`).
pub fn is_prerelease(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    for marker in ["rc", "alpha", "beta", "dev", "pre", "a", "b"] {
        let mut from = 0;
        while let Some(at) = lower[from..].find(marker) {
            let at = from + at;
            let before = at.checked_sub(1).map(|i| bytes[i]);
            let after = bytes.get(at + marker.len()).copied();
            // A marker counts only between a digit (or separator) and a digit or the end:
            // `2.0.0rc1` and `1.0b` do, `alpine` and `libarrow` do not.
            let starts = before.is_none_or(|b| b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_');
            let ends = after.is_none_or(|b| b.is_ascii_digit());
            if starts && ends && at > 0 {
                return true;
            }
            from = at + 1;
        }
    }
    false
}

/// Compare two version strings the way the ecosystems do, falling back to a plain string
/// comparison when either cannot be parsed.
pub fn compare(a: &str, b: &str) -> Ordering {
    match (
        a.parse::<rattler_conda_types::Version>(),
        b.parse::<rattler_conda_types::Version>(),
    ) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        _ => a.cmp(b),
    }
}

/// The size of the step from `current` to `latest`, by leading numeric segments.
pub fn step(current: &str, latest: &str) -> Step {
    // A version with no digits at all cannot be placed on a scale.
    let segments = |v: &str| -> Option<Vec<u64>> {
        v.chars().any(|c| c.is_ascii_digit()).then(|| {
            v.split(['.', '-', '+', '_'])
                .map(|s| s.trim_start_matches(|c: char| !c.is_ascii_digit()))
                .map(|s| {
                    s.chars()
                        .take_while(char::is_ascii_digit)
                        .collect::<String>()
                        .parse()
                        .unwrap_or(0)
                })
                .collect()
        })
    };
    let (Some(current), Some(latest)) = (segments(current), segments(latest)) else {
        return Step::Unknown;
    };
    match (current.first(), latest.first()) {
        (Some(a), Some(b)) if a != b => Step::Major,
        _ => match (current.get(1), latest.get(1)) {
            (Some(a), Some(b)) if a != b => Step::Minor,
            (None, Some(_)) | (Some(_), None) => Step::Minor,
            _ => Step::Patch,
        },
    }
}

/// Reduce a list of releases and the pinned version into a [`Status`].
pub fn status(releases: &[Release], current: &str) -> Status {
    let usable: Vec<&Release> = releases
        .iter()
        .filter(|r| !r.yanked && !is_prerelease(&r.version))
        .collect();
    let newest = usable.iter().max_by(|a, b| compare(&a.version, &b.version));
    let behind = usable
        .iter()
        .filter(|r| compare(&r.version, current) == Ordering::Greater)
        .count();
    Status {
        current_published: releases
            .iter()
            .find(|r| r.version == current)
            .and_then(|r| r.published.clone()),
        latest: newest.map(|r| r.version.clone()),
        latest_published: newest.and_then(|r| r.published.clone()),
        behind,
        step: newest.map(|r| step(current, &r.version)).unwrap_or(Step::Unknown),
    }
}

// ---- Index documents -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PypiProject {
    #[serde(default)]
    releases: std::collections::BTreeMap<String, Vec<PypiFile>>,
}

#[derive(Debug, Deserialize)]
struct PypiFile {
    #[serde(default)]
    upload_time_iso_8601: Option<String>,
    #[serde(default)]
    yanked: bool,
}

/// Every release in a PyPI project document. Versions with no files were never published.
pub fn pypi_releases(json: &str) -> Vec<Release> {
    let Ok(project) = serde_json::from_str::<PypiProject>(json) else {
        return Vec::new();
    };
    project
        .releases
        .into_iter()
        .filter(|(_, files)| !files.is_empty())
        .map(|(version, files)| Release {
            version,
            published: files.iter().find_map(|f| f.upload_time_iso_8601.clone()),
            yanked: files.iter().all(|f| f.yanked),
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct AnacondaPackage {
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    files: Vec<AnacondaFile>,
}

#[derive(Debug, Deserialize)]
struct AnacondaFile {
    version: String,
    /// Identifies the exact build; top-level on the file rather than under `attrs`.
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    attrs: AnacondaAttrs,
}

#[derive(Debug, Default, Deserialize)]
struct AnacondaAttrs {
    /// Milliseconds since the epoch, as conda records build times.
    #[serde(default)]
    timestamp: Option<i64>,
}

/// The versions a package has, and the first build of the installed one.
///
/// `orderBy CREATED_AT ASC` with `limit:1` is the whole trick: the server caps a page, so taking
/// the minimum of a page gives the earliest of the *newest* builds rather than the earliest build.
/// Asking the server to sort and returning one row is exact in a single request, however many
/// builds a version has.
pub fn prefix_versions_query(channel: &str, name: &str, installed: &str) -> String {
    let query = "query($c:String!,$n:String!,$v:String){ package(channelName:$c, name:$n) { \
                 versions(limit:500) { page { version } } \
                 current: variants(limit:200, version:$v, orderBy:{byField:{field:CREATED_AT, direction:ASC}}) \
                 { page { createdAt rawIndex sha256 } } \
                 newest: variants(limit:200, version:$v, orderBy:{byField:{field:CREATED_AT, direction:DESC}}) \
                 { page { sha256 } } } }";
    serde_json::json!({
        "query": query,
        "variables": { "c": channel, "n": name, "v": installed },
    })
    .to_string()
}

/// The first build of one named version.
pub fn prefix_version_date_query(channel: &str, name: &str, version: &str) -> String {
    let query = "query($c:String!,$n:String!,$v:String){ package(channelName:$c, name:$n) { \
                 current: variants(limit:200, version:$v, orderBy:{byField:{field:CREATED_AT, direction:ASC}}) \
                 { page { createdAt rawIndex } } } }";
    serde_json::json!({
        "query": query,
        "variables": { "c": channel, "n": name, "v": version },
    })
    .to_string()
}

#[derive(Debug, Deserialize)]
struct PrefixEnvelope {
    #[serde(default)]
    data: Option<PrefixData>,
}

#[derive(Debug, Deserialize)]
struct PrefixData {
    #[serde(default)]
    package: Option<PrefixPackage>,
}

#[derive(Debug, Deserialize)]
struct PrefixPackage {
    #[serde(default)]
    versions: Option<PrefixVersionPage>,
    /// The oldest builds of the installed version: the first of them is its release date.
    #[serde(default)]
    current: Option<PrefixVariantPage>,
    /// The newest builds of the same version. A page is capped, so a version with more builds
    /// than fit needs both ends to be sure the installed one is seen at all.
    #[serde(default)]
    newest: Option<PrefixVariantPage>,
}

#[derive(Debug, Deserialize)]
struct PrefixVersionPage {
    #[serde(default)]
    page: Vec<PrefixVersion>,
}

#[derive(Debug, Deserialize)]
struct PrefixVersion {
    version: String,
}

#[derive(Debug, Deserialize)]
struct PrefixVariantPage {
    #[serde(default)]
    page: Vec<PrefixVariant>,
}

#[derive(Debug, Deserialize)]
struct PrefixVariant {
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
    /// Identifies the exact build, so a mirrored package can be matched to its upstream.
    #[serde(default)]
    sha256: Option<String>,
    /// The build's own `index.json`, whose `timestamp` is when conda-forge built it rather than
    /// when prefix.dev ingested it. Served as an object or as a string holding one.
    #[serde(rename = "rawIndex", default)]
    raw_index: Option<serde_json::Value>,
}

impl PrefixVariant {
    /// When this build was made, preferring its own record over the mirror's ingest time.
    ///
    /// For anything built before prefix.dev mirrored conda-forge the two differ by years, and the
    /// build's own timestamp is the one anaconda.org reports.
    fn built(&self) -> Option<String> {
        self.raw_index
            .as_ref()
            .and_then(|raw| match raw {
                serde_json::Value::String(text) => serde_json::from_str(text).ok(),
                other => Some(other.clone()),
            })
            .and_then(|index| index.get("timestamp")?.as_i64())
            .and_then(timestamp_to_rfc3339)
            .or_else(|| self.created_at.clone())
    }
}

/// What a prefix.dev lookup is reduced to before caching: the version list and the first build
/// date of the versions the report needs dated.
///
/// Normalised at fetch time rather than at parse time because the dates take a request each: the
/// cache then holds the answer rather than the raw response, and a second run needs no network
/// even for a package that took two requests the first time.
#[derive(Debug, Default, serde::Serialize, Deserialize)]
pub struct PrefixDocument {
    pub versions: Vec<String>,
    /// Version to its first build, RFC 3339.
    pub dates: std::collections::BTreeMap<String, String>,
    /// The sha256 of every build of the installed version this channel has, which is how a
    /// package from a mirror is matched to the channel it was mirrored from.
    #[serde(default)]
    pub installed_hashes: Vec<String>,
}

/// The versions and the installed version's first build, from one `prefix_versions_query`.
pub fn prefix_page(json: &str, installed: &str) -> PrefixDocument {
    let Ok(envelope) = serde_json::from_str::<PrefixEnvelope>(json) else {
        return PrefixDocument::default();
    };
    let Some(package) = envelope.data.and_then(|data| data.package) else {
        return PrefixDocument::default();
    };
    let mut document = PrefixDocument {
        versions: package
            .versions
            .map(|p| p.page)
            .unwrap_or_default()
            .into_iter()
            .map(|entry| entry.version)
            .collect(),
        dates: Default::default(),
        installed_hashes: [&package.current, &package.newest]
            .into_iter()
            .flatten()
            .flat_map(|page| page.page.iter().filter_map(|v| v.sha256.clone()))
            .collect(),
    };
    if let Some(date) = prefix_first_date(&package.current) {
        document.dates.insert(installed.to_string(), date);
    }
    document
}

/// The one date in a `prefix_version_date_query` response.
pub fn prefix_date(json: &str) -> Option<String> {
    let envelope = serde_json::from_str::<PrefixEnvelope>(json).ok()?;
    prefix_first_date(&envelope.data?.package?.current)
}

/// The earliest build on a page, by each build's own timestamp.
fn prefix_first_date(page: &Option<PrefixVariantPage>) -> Option<String> {
    page.as_ref()?.page.iter().filter_map(PrefixVariant::built).min()
}

/// The releases a normalised prefix.dev document describes, matching what [`anaconda_releases`]
/// takes from anaconda.org. A version with no date is still a release; it is only its age that is
/// unknown.
pub fn prefix_releases(json: &str) -> Vec<Release> {
    let Ok(document) = serde_json::from_str::<PrefixDocument>(json) else {
        return Vec::new();
    };
    document
        .versions
        .into_iter()
        .map(|version| Release {
            published: document.dates.get(&version).cloned(),
            version,
            yanked: false,
        })
        .collect()
}

/// The sha256 of every build of one version in an anaconda.org package document.
pub fn anaconda_hashes(json: &str, version: &str) -> Vec<String> {
    serde_json::from_str::<AnacondaPackage>(json)
        .map(|package| {
            package
                .files
                .into_iter()
                .filter(|file| file.version == version)
                .filter_map(|file| file.sha256)
                .collect()
        })
        .unwrap_or_default()
}

/// Every version in an anaconda.org package document, with the earliest build time of each as
/// its publication date.
pub fn anaconda_releases(json: &str) -> Vec<Release> {
    let Ok(package) = serde_json::from_str::<AnacondaPackage>(json) else {
        return Vec::new();
    };
    package
        .versions
        .into_iter()
        .map(|version| {
            let published = package
                .files
                .iter()
                .filter(|f| f.version == version)
                .filter_map(|f| f.attrs.timestamp)
                .min()
                .and_then(timestamp_to_rfc3339);
            Release {
                version,
                published,
                yanked: false,
            }
        })
        .collect()
}

fn timestamp_to_rfc3339(milliseconds: i64) -> Option<String> {
    chrono::DateTime::from_timestamp_millis(milliseconds).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// Whether this run chose its index rather than falling back to the default.
///
/// Choosing one is a statement that it answers for this workspace's channels, which is the only
/// signal available: the lockfile records where packages were *fetched from*, which says nothing
/// about what the chosen index can answer for.
pub fn index_is_configured(kind: crate::cli::CondaIndexKind) -> bool {
    // Choosing `prefix` is as much a statement as naming an address: prefix.dev answers for a
    // channel by name, whatever host the lockfile happened to fetch the package from.
    //
    // A fallback channel does the same for a different reason: an unrecognised channel is then
    // recoverable by matching the package's hash, which is a better guard than its host ever was.
    // Asking and being told nothing costs a request; not asking costs the answer.
    kind == crate::cli::CondaIndexKind::Prefix
        || fallback_channel().is_some()
        || std::env::var(ANACONDA_URL_ENV).is_ok_and(|value| !value.trim().is_empty())
}

/// The channel name to ask the index about, or `None` when there is no reason to think it would
/// answer.
///
/// By default the test is whether the package came from anaconda.org, because the default index
/// *is* anaconda.org and asking it about a channel it does not host wastes a request per package
/// to be told nothing.
///
/// That test is wrong the moment an index is configured. It reads `pixi:channel-url`, which is
/// where the package was fetched from, so a workspace solved against a mirror failed it for every
/// package and reported them all unknown however the index was pointed — the override was
/// unreachable in exactly the situation anyone would set it. With one named, the channel is
/// returned and the index gets to answer for itself.
pub fn anaconda_channel(package: &crate::model::Package, configured: bool) -> Option<String> {
    let url = package.properties.get("pixi:channel-url")?;
    (configured || url.contains("anaconda.org"))
        .then(|| package.properties.get("pixi:channel").cloned())
        .flatten()
}

// ---- Looking it up -------------------------------------------------------------------------

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Packages whose index answered.
    pub checked: usize,
    /// Packages behind their newest release.
    pub outdated: usize,
    /// Packages the indexes could not answer for (private channels, source packages).
    pub unknown: usize,
}

/// Configuration for a pass.
pub struct Lookup<'a> {
    /// PyPI JSON API base.
    pub index_url: &'a str,
    /// anaconda.org API base.
    pub anaconda_url: &'a str,
    /// Whether that base was named rather than defaulted; see [`anaconda_channel`].
    pub index_is_configured: bool,
    /// Which index to ask.
    pub kind: crate::cli::CondaIndexKind,
    /// The prefix.dev GraphQL endpoint, used when `kind` is `Prefix`.
    pub prefix_index_url: &'a str,
    pub cache_dir: &'a Path,
}

/// One package to ask about.
#[derive(Debug)]
struct Job {
    index: usize,
    display_name: String,
    url: String,
    /// The channel and the installed version, for an index that needs a second request to date
    /// the newest release.
    follow_up: Option<(String, String)>,
    /// The GraphQL request body, for an index that is asked rather than read.
    body: Option<String>,
    cache_file: PathBuf,
    kind: PackageKind,
}

impl Lookup<'_> {
    /// Fill `statuses` with what each index says, keyed by the package's position in `sbom`.
    pub fn run(&self, sbom: &Sbom, progress: crate::progress::Progress) -> (Vec<Option<Status>>, Outcome) {
        self.run_with(
            sbom,
            &|url, body| match body {
                Some(body) => http::post_json(url, body, MAX_BYTES),
                None => http::get_text(url, MAX_BYTES),
            },
            SystemTime::now(),
            progress,
        )
    }

    /// One job asking `channel` about `package`.
    fn conda_job(&self, index: usize, package: &crate::model::Package, channel: &str, version: &str) -> Job {
        match self.kind {
            crate::cli::CondaIndexKind::Prefix => Job {
                index,
                display_name: package.name.clone(),
                url: self.prefix_index_url.to_string(),
                follow_up: Some((channel.to_string(), version.to_string())),
                body: Some(prefix_versions_query(channel, &package.name, version)),
                cache_file: self
                    .cache_dir
                    .join("outdated")
                    .join(format!("prefix-{channel}-{}.json", package.name)),
                kind: package.kind,
            },
            crate::cli::CondaIndexKind::Anaconda => Job {
                index,
                display_name: package.name.clone(),
                url: format!(
                    "{}/package/{channel}/{}",
                    self.anaconda_url.trim_end_matches('/'),
                    package.name
                ),
                follow_up: None,
                body: None,
                cache_file: self
                    .cache_dir
                    .join("outdated")
                    .join(format!("conda-{channel}-{}.json", package.name)),
                kind: package.kind,
            },
        }
    }

    /// Which channel to ask about each of the workspace's channels, decided once.
    ///
    /// A mirrored channel is named after the local repository, so no index knows it, and every
    /// package in it would otherwise pay a doomed request before falling back. The answer is the
    /// same for the whole channel, so it is worth one probe rather than one per package: ask about
    /// a representative package, and if the channel is unknown, point the whole channel at the
    /// candidate. Each package's own response is still hash-checked before its releases are used,
    /// so a package that is not really from there is still refused.
    fn channel_targets(&self, sbom: &Sbom, fetch: Fetch<'_>, now: SystemTime) -> BTreeMap<String, String> {
        let mut representative: BTreeMap<String, &crate::model::Package> = BTreeMap::new();
        for package in &sbom.packages {
            if package.kind != PackageKind::CondaBinary {
                continue;
            }
            if let Some(channel) = package.properties.get("pixi:channel") {
                representative.entry(channel.clone()).or_insert(package);
            }
        }

        let Some(candidate) = fallback_channel() else {
            return representative.keys().map(|c| (c.clone(), c.clone())).collect();
        };
        let channels: Vec<(String, &crate::model::Package)> = representative.into_iter().collect();

        let probes = crate::concurrency::map(
            &channels,
            None,
            |(channel, _)| channel.clone(),
            |(channel, package)| {
                if channel == &candidate {
                    return true;
                }
                let version = package.version.clone().unwrap_or_default();
                let job = self.conda_job(0, package, channel, &version);
                self.document(&job, fetch, now)
                    .map(|document| !self.releases_of(&document, &version).is_empty())
                    .unwrap_or(false)
            },
        );

        channels
            .into_iter()
            .zip(probes)
            .map(|((channel, _), known)| {
                if !known {
                    tracing::debug!(
                        channel = %channel,
                        candidate = %candidate,
                        "the index does not know this channel; its packages are checked against the candidate by hash"
                    );
                }
                let target = if known { channel.clone() } else { candidate.clone() };
                (channel, target)
            })
            .collect()
    }

    /// The releases an index document describes, for whichever kind this run asks.
    fn releases_of(&self, document: &str, installed: &str) -> Vec<Release> {
        match self.kind {
            crate::cli::CondaIndexKind::Prefix => prefix_releases(document),
            crate::cli::CondaIndexKind::Anaconda => {
                let _ = installed;
                anaconda_releases(document)
            }
        }
    }

    fn run_with(
        &self,
        sbom: &Sbom,
        fetch: Fetch<'_>,
        now: SystemTime,
        progress: crate::progress::Progress,
    ) -> (Vec<Option<Status>>, Outcome) {
        let mut outcome = Outcome::default();
        let targets = self.channel_targets(sbom, fetch, now);
        let mut jobs = Vec::new();
        for (index, package) in sbom.packages.iter().enumerate() {
            let job = match package.kind {
                PackageKind::Pypi => {
                    let name = crate::purl::normalize_pypi_name(&package.name);
                    Some(Job {
                        index,
                        display_name: package.name.clone(),
                        url: format!("{}/{name}/json", self.index_url.trim_end_matches('/')),
                        follow_up: None,
                        body: None,
                        cache_file: self.cache_dir.join("outdated").join(format!("pypi-{name}.json")),
                        kind: package.kind,
                    })
                }
                PackageKind::CondaBinary => anaconda_channel(package, self.index_is_configured).map(|channel| {
                    // The whole channel was resolved once; a package whose channel the index knows
                    // is asked about directly, one from a mirror goes straight to the candidate.
                    let target = targets.get(&channel).cloned().unwrap_or(channel);
                    let version = package.version.clone().unwrap_or_default();
                    self.conda_job(index, package, &target, &version)
                }),
                _ => None,
            };
            match job {
                Some(job) if package.version.is_some() => jobs.push(job),
                _ => outcome.unknown += 1,
            }
        }

        let bar = progress.bar("releases", jobs.len());
        let documents = crate::concurrency::map(
            &jobs,
            Some(&bar),
            |job| job.display_name.clone(),
            |job| self.document(job, fetch, now),
        );
        bar.finish();

        let mut statuses = vec![None; sbom.packages.len()];
        for (job, document) in jobs.iter().zip(documents) {
            let current = sbom.packages[job.index].version.clone().unwrap_or_default();
            // A channel the index does not know answers two ways: prefix.dev returns a document
            // saying nothing, anaconda.org returns 404 and no document at all. Both mean the same
            // thing here, so both fall through to the hash check below.
            let releases = match (&document, job.kind, self.kind) {
                (Some(document), PackageKind::Pypi, _) => pypi_releases(document),
                (Some(document), _, crate::cli::CondaIndexKind::Prefix) => prefix_releases(document),
                (Some(document), _, crate::cli::CondaIndexKind::Anaconda) => anaconda_releases(document),
                (None, _, _) => Vec::new(),
            };
            if document.is_none() && job.kind != PackageKind::CondaBinary {
                outcome.unknown += 1;
                continue;
            }
            // An empty answer means the index does not know this package's channel, which is the
            // normal case for a mirror: the channel is named after the local repository and the
            // upstream has never heard of it. The package's own hash says which channel it really
            // came from, so ask a candidate and believe it only if a build matches.
            if releases.is_empty() {
                outcome.unknown += 1;
                continue;
            }
            // A package whose channel the index did not know was asked of the candidate instead.
            // Its releases are another channel's until the recorded hash says the build is the
            // same one, so a package that merely shares a name is refused here.
            let package = &sbom.packages[job.index];
            if job.kind == PackageKind::CondaBinary
                && let Some(asked) = package.properties.get("pixi:channel")
                && targets.get(asked).is_some_and(|target| target != asked)
                && !self.hash_vouches_for(&document, package, &current)
            {
                outcome.unknown += 1;
                continue;
            }
            let status = status(&releases, &current);
            outcome.checked += 1;
            if status.behind > 0 {
                outcome.outdated += 1;
            }
            statuses[job.index] = Some(status);
        }
        (statuses, outcome)
    }

    /// One project document, from the cache when young enough (or offline), else fetched.
    /// Reduce a response to what the report needs, before it is cached.
    ///
    /// For prefix.dev that means dating the newest release, which takes a second request because
    /// its version is only known once the first answers. Packages already on their newest release
    /// need no second request, which is most of them. Every other index answers in one document
    /// and passes straight through.
    fn resolve(&self, job: &Job, json: String, fetch: Fetch<'_>) -> String {
        let Some((channel, installed)) = &job.follow_up else {
            return json;
        };
        let mut document = prefix_page(&json, installed);
        self.date_the_newest(&mut document, channel, &job.display_name, &job.url, fetch);
        serde_json::to_string(&document).unwrap_or(json)
    }

    /// Fill in the newest release's date, which takes a second request because its version is
    /// only known once the first has answered.
    ///
    /// Shared with the fallback path: a package rescued by its hash deserves the same `Released`
    /// column as one whose channel the index recognised.
    fn date_the_newest(&self, document: &mut PrefixDocument, channel: &str, name: &str, url: &str, fetch: Fetch<'_>) {
        let newest = document
            .versions
            .iter()
            .filter(|version| !is_prerelease(version))
            .max_by(|a, b| compare(a, b))
            .cloned();
        if let Some(newest) = newest
            && !document.dates.contains_key(&newest)
            && let Ok(answer) = fetch(url, Some(&prefix_version_date_query(channel, name, &newest)))
            && let Some(date) = prefix_date(&answer)
        {
            document.dates.insert(newest, date);
        }
    }

    /// Whether the package's recorded hash appears among this channel's builds of its version.
    ///
    /// This is what makes a channel substitution safe. A proxying mirror serves the upstream bytes
    /// unchanged, so a matching hash proves the package came from the channel just asked. A mirror
    /// that rebuilds produces different bytes and is refused, which is the right answer rather
    /// than another channel's version history.
    fn hash_vouches_for(&self, document: &Option<String>, package: &crate::model::Package, installed: &str) -> bool {
        let Some(sha256) = package.sha256.as_deref() else {
            tracing::debug!(
                package = %package.name,
                "no recorded hash, so the channel cannot be confirmed"
            );
            return false;
        };
        let Some(document) = document else { return false };
        let hashes = match self.kind {
            // The prefix response was normalised before it was cached, so the hashes are read
            // back from that shape rather than from the GraphQL envelope they arrived in.
            crate::cli::CondaIndexKind::Prefix => serde_json::from_str::<PrefixDocument>(document)
                .map(|page| page.installed_hashes)
                .unwrap_or_default(),
            crate::cli::CondaIndexKind::Anaconda => anaconda_hashes(document, installed),
        };
        let vouched = hashes.iter().any(|known| known.eq_ignore_ascii_case(sha256));
        if !vouched {
            tracing::debug!(
                package = %package.name,
                builds = hashes.len(),
                "no build in the candidate channel has the recorded hash; it is not a mirror of it"
            );
        }
        vouched
    }

    fn document(&self, job: &Job, fetch: Fetch<'_>, now: SystemTime) -> Option<String> {
        let cached = std::fs::read_to_string(&job.cache_file).ok();
        let age = std::fs::metadata(&job.cache_file)
            .and_then(|meta| meta.modified())
            .ok()
            .map(|modified| now.duration_since(modified).unwrap_or(Duration::ZERO));
        if let (Some(json), Some(age)) = (&cached, age)
            && (age <= CACHE_MAX_AGE || http::offline())
            && crate::cache::may_read(crate::cache::Service::Outdated)
        {
            crate::cache::hit(crate::cache::Service::Outdated, age);
            return Some(json.clone());
        }
        crate::cache::miss(crate::cache::Service::Outdated);
        match fetch(&job.url, job.body.as_deref()).map(|json| self.resolve(job, json, fetch)) {
            Ok(json) => {
                if crate::cache::may_write(crate::cache::Service::Outdated)
                    && let Err(err) = job
                        .cache_file
                        .parent()
                        .map_or(Ok(()), std::fs::create_dir_all)
                        .and_then(|()| std::fs::write(&job.cache_file, &json))
                {
                    tracing::warn!(path = %job.cache_file.display(), %err, "cannot cache the project document");
                }
                Some(json)
            }
            Err(err) => {
                tracing::warn!(
                    package = %job.display_name,
                    url = %job.url,
                    cause = crate::http::error_chain(err.as_ref()),
                    "cannot read the project's releases"
                );
                cached
            }
        }
    }
}

/// How old a publication date is, in whole days, at `now`.
pub fn age_in_days(published: &str, now: SystemTime) -> Option<i64> {
    let published = chrono::DateTime::parse_from_rfc3339(published).ok()?;
    let now = now.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some((now - published.timestamp()) / 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, published: Option<&str>, yanked: bool) -> Release {
        Release {
            version: version.into(),
            published: published.map(str::to_string),
            yanked,
        }
    }

    #[test]
    fn prereleases_are_recognised_without_catching_ordinary_names() {
        for version in ["2.0.0rc1", "1.4.0b2", "0.9.dev3", "3.15.0rc2", "1.0a", "2.0.0-alpha1"] {
            assert!(is_prerelease(version), "{version}");
        }
        for version in ["1.2.3", "2026.7.22", "1.3.2", "0.4.1", "4.5", "2.32.4"] {
            assert!(!is_prerelease(version), "{version}");
        }
    }

    #[test]
    fn steps_are_measured_on_the_leading_segments() {
        assert_eq!(step("1.26.4", "2.8.0"), Step::Major);
        assert_eq!(step("2.0.0", "2.8.0"), Step::Minor);
        assert_eq!(step("1.26.4", "1.26.20"), Step::Patch);
        assert_eq!(step("1.26.4", "1.26.4"), Step::Patch);
        assert_eq!(
            step("4.5", "4.5.1"),
            Step::Patch,
            "a third segment appearing is a patch"
        );
        assert_eq!(step("4", "4.5"), Step::Minor, "a second segment appearing is not");
        assert_eq!(step("", "1.0"), Step::Unknown);
    }

    #[test]
    fn status_ignores_prereleases_and_yanked_releases() {
        let releases = [
            release("1.26.4", Some("2021-03-15T15:04:35Z"), false),
            release("2.0.0", Some("2023-04-26T00:00:00Z"), true),
            release("2.7.0", Some("2026-01-01T00:00:00Z"), false),
            release("2.8.0", Some("2026-09-15T19:29:34Z"), false),
            release("3.0.0rc1", Some("2026-09-20T00:00:00Z"), false),
        ];
        let status = status(&releases, "1.26.4");
        assert_eq!(status.latest.as_deref(), Some("2.8.0"));
        assert_eq!(status.latest_published.as_deref(), Some("2026-09-15T19:29:34Z"));
        assert_eq!(status.current_published.as_deref(), Some("2021-03-15T15:04:35Z"));
        assert_eq!(status.behind, 2, "the yanked and the prerelease do not count");
        assert_eq!(status.step, Step::Major);

        // Already current.
        let status = status_of(&releases, "2.8.0");
        assert_eq!(status.behind, 0);
        assert_eq!(status.step, Step::Patch);
    }

    fn status_of(releases: &[Release], current: &str) -> Status {
        status(releases, current)
    }

    #[test]
    fn pypi_and_anaconda_documents_are_read() {
        let pypi = serde_json::json!({
            "releases": {
                "1.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": false}],
                "1.1": [{"upload_time_iso_8601": "2021-01-01T00:00:00Z", "yanked": true}],
                "1.2": [],
            }
        })
        .to_string();
        let releases = pypi_releases(&pypi);
        assert_eq!(releases.len(), 2, "a version with no files was never published");
        assert!(releases.iter().any(|r| r.version == "1.1" && r.yanked));
        assert_eq!(pypi_releases("nonsense"), Vec::new());

        let anaconda = serde_json::json!({
            "versions": ["1.2.11", "1.3.2"],
            "files": [
                {"version": "1.3.2", "attrs": {"timestamp": 1_700_000_000_000i64}},
                {"version": "1.3.2", "attrs": {"timestamp": 1_800_000_000_000i64}},
                {"version": "1.2.11", "attrs": {}},
            ]
        })
        .to_string();
        let releases = anaconda_releases(&anaconda);
        assert_eq!(releases.len(), 2);
        let newest = releases.iter().find(|r| r.version == "1.3.2").unwrap();
        assert_eq!(
            newest.published.as_deref(),
            Some("2023-11-14T22:13:20Z"),
            "the earliest build of that version"
        );
        assert_eq!(releases.iter().find(|r| r.version == "1.2.11").unwrap().published, None);
    }

    #[test]
    fn a_pass_asks_each_index_once_and_reports_the_unaskable() {
        use crate::format::testing::sample_sbom;
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        // zlib and libzlib are conda-forge packages from anaconda.org; six is a wheel; mylib is
        // a source package, which no index can answer for.
        for package in &mut sbom.packages {
            if package.kind == PackageKind::CondaBinary {
                package.properties.insert(
                    "pixi:channel-url".into(),
                    "https://conda.anaconda.org/conda-forge/".into(),
                );
            }
        }
        let asked = std::sync::Mutex::new(Vec::new());
        let fetch = |url: &str, _body: Option<&str>| {
            asked.lock().unwrap().push(url.to_string());
            Ok(if url.contains("/package/") {
                serde_json::json!({
                    "versions": ["1.3.1", "1.3.2", "1.4.0rc1"],
                    "files": [{"version": "1.3.2", "attrs": {"timestamp": 1_700_000_000_000i64}}]
                })
                .to_string()
            } else {
                serde_json::json!({
                    "releases": {
                        "1.17.0": [{"upload_time_iso_8601": "2024-12-04T00:00:00Z", "yanked": false}],
                        "1.18.0": [{"upload_time_iso_8601": "2026-01-01T00:00:00Z", "yanked": false}],
                    }
                })
                .to_string()
            })
        };
        let lookup = Lookup {
            index_url: "https://index.example/pypi",
            anaconda_url: "https://anaconda.example",
            index_is_configured: false,
            kind: crate::cli::CondaIndexKind::Anaconda,
            prefix_index_url: "https://prefix.example/api/graphql",
            cache_dir: dir.path(),
        };
        let now = SystemTime::now();
        let (statuses, outcome) = lookup.run_with(&sbom, &fetch, now, crate::progress::Progress::default());
        assert_eq!(
            outcome,
            Outcome {
                checked: 3,
                outdated: 3,
                unknown: 1
            },
            "the source package has no index"
        );
        let by_name = |name: &str| {
            let index = sbom.packages.iter().position(|p| p.name == name).unwrap();
            statuses[index].clone().unwrap()
        };
        assert_eq!(
            by_name("zlib").latest.as_deref(),
            Some("1.3.2"),
            "the prerelease is skipped"
        );
        assert_eq!(by_name("zlib").behind, 1);
        assert_eq!(by_name("six").latest.as_deref(), Some("1.18.0"));
        assert_eq!(
            by_name("six").current_published.as_deref(),
            Some("2024-12-04T00:00:00Z")
        );
        assert_eq!(
            statuses[sbom.packages.iter().position(|p| p.name == "mylib").unwrap()],
            None
        );
        assert_eq!(asked.lock().unwrap().len(), 3);
        assert!(
            asked
                .lock()
                .unwrap()
                .iter()
                .any(|u| u == "https://anaconda.example/package/conda-forge/zlib")
        );
        assert!(
            asked
                .lock()
                .unwrap()
                .iter()
                .any(|u| u == "https://index.example/pypi/six/json")
        );

        // The documents are cached: a second pass asks nothing.
        let (again, _) = lookup.run_with(
            &sbom,
            &|url, _body| panic!("must not fetch {url}"),
            now,
            crate::progress::Progress::default(),
        );
        assert_eq!(again, statuses);
    }

    #[test]
    fn packages_from_other_channels_have_no_index_to_ask() {
        use crate::format::testing::sample_sbom;
        let mut sbom = sample_sbom();
        let zlib = sbom.packages.iter_mut().find(|p| p.name == "zlib").unwrap();
        zlib.properties
            .insert("pixi:channel-url".into(), "https://prefix.dev/my-channel/".into());
        assert_eq!(anaconda_channel(&sbom.packages[1], false), None);
        let libzlib = sbom.packages.iter_mut().find(|p| p.name == "libzlib").unwrap();
        libzlib.properties.insert(
            "pixi:channel-url".into(),
            "https://conda.anaconda.org/conda-forge/".into(),
        );
        assert_eq!(
            anaconda_channel(sbom.packages.iter().find(|p| p.name == "libzlib").unwrap(), false),
            Some("conda-forge".into())
        );
    }

    #[test]
    fn a_prefix_page_takes_the_version_list_and_the_installed_version_date() {
        let json = r#"{"data":{"package":{
            "versions":{"page":[{"version":"1.3.2"},{"version":"1.3.1"},{"version":"1.2.11"}]},
            "current":{"page":[{"createdAt":"2019-09-09T23:22:40Z"}]}}}}"#;
        let document = prefix_page(json, "1.2.11");
        assert_eq!(document.versions, ["1.3.2", "1.3.1", "1.2.11"]);
        // The server sorted ascending and returned one row, so this is the first build, not the
        // earliest of a capped page.
        assert_eq!(
            document.dates.get("1.2.11").map(String::as_str),
            Some("2019-09-09T23:22:40Z")
        );
        assert_eq!(
            document.dates.len(),
            1,
            "only the version that was asked about is dated"
        );
    }

    #[test]
    fn a_builds_own_timestamp_beats_the_mirrors_ingest_time() {
        // yaml 0.2.5 as prefix.dev serves it: ingested in 2023, built in 2020, which is the date
        // anaconda.org reports and the one the report should show.
        let json = r#"{"data":{"package":{
            "versions":{"page":[{"version":"0.2.5"}]},
            "current":{"page":[
                {"createdAt":"2023-03-15T00:00:00Z","rawIndex":{"timestamp":1591056000000}},
                {"createdAt":"2023-03-16T00:00:00Z","rawIndex":{"timestamp":1600000000000}}]}}}}"#;
        let document = prefix_page(json, "0.2.5");
        assert_eq!(
            document.dates.get("0.2.5").map(String::as_str),
            Some("2020-06-02T00:00:00Z")
        );

        // rawIndex also arrives as a string holding the object.
        let as_text = r#"{"data":{"package":{"versions":{"page":[{"version":"1.0"}]},
            "current":{"page":[{"createdAt":"2023-01-01T00:00:00Z",
                                "rawIndex":"{\"timestamp\":1591056000000}"}]}}}}"#;
        assert_eq!(
            prefix_page(as_text, "1.0").dates.get("1.0").map(String::as_str),
            Some("2020-06-02T00:00:00Z")
        );

        // With no rawIndex at all the ingest time is all there is, and is better than nothing.
        let bare = r#"{"data":{"package":{"versions":{"page":[{"version":"1.0"}]},
            "current":{"page":[{"createdAt":"2023-01-01T00:00:00Z"}]}}}}"#;
        assert_eq!(
            prefix_page(bare, "1.0").dates.get("1.0").map(String::as_str),
            Some("2023-01-01T00:00:00Z")
        );
    }

    #[test]
    fn both_ends_of_the_build_list_contribute_hashes() {
        // A version with more builds than a page holds: the installed one may be at either end,
        // so the query asks for both and the hashes are the union.
        let json = r#"{"data":{"package":{
            "versions":{"page":[{"version":"3.14.7"}]},
            "current":{"page":[{"createdAt":"2026-01-01T00:00:00Z","sha256":"oldest"}]},
            "newest":{"page":[{"sha256":"newest"}]}}}}"#;
        let document = prefix_page(json, "3.14.7");
        assert_eq!(document.installed_hashes, ["oldest", "newest"]);
        // The date still comes from the oldest build only.
        assert_eq!(
            document.dates.get("3.14.7").map(String::as_str),
            Some("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn anaconda_hashes_are_read_from_the_top_of_each_file() {
        // sha256 sits beside `version` on the file, not under `attrs`.
        let json = r#"{"versions":["1.0"],"files":[
            {"version":"1.0","sha256":"aaa","attrs":{"timestamp":1700000000000}},
            {"version":"1.0","sha256":"bbb","attrs":{}},
            {"version":"0.9","sha256":"ccc","attrs":{}}]}"#;
        assert_eq!(anaconda_hashes(json, "1.0"), ["aaa", "bbb"]);
        assert!(anaconda_hashes(json, "2.0").is_empty());
        assert!(anaconda_hashes("not json", "1.0").is_empty());
    }

    #[test]
    fn a_prefix_document_becomes_releases_dated_where_known() {
        let document = PrefixDocument {
            versions: vec!["1.3.2".into(), "1.3.1".into()],
            dates: [("1.3.2".to_string(), "2026-03-21T06:58:29Z".to_string())]
                .into_iter()
                .collect(),
            installed_hashes: Vec::new(),
        };
        let releases = prefix_releases(&serde_json::to_string(&document).unwrap());
        assert_eq!(releases.len(), 2);
        let find = |v: &str| releases.iter().find(|r| r.version == v).unwrap().published.clone();
        assert_eq!(find("1.3.2").as_deref(), Some("2026-03-21T06:58:29Z"));
        // A version nobody asked the date of is still a release; only its age is unknown.
        assert_eq!(find("1.3.1"), None);
    }

    #[test]
    fn a_prefix_response_that_says_nothing_yields_nothing() {
        for json in [
            r#"{"data":{"package":null}}"#,
            r#"{"errors":[{"message":"nope"}]}"#,
            "not json",
        ] {
            assert!(prefix_page(json, "1.0").versions.is_empty(), "{json}");
            assert!(prefix_date(json).is_none(), "{json}");
        }
        assert!(prefix_releases("not json").is_empty());
    }

    #[test]
    fn the_queries_sort_oldest_first_and_ask_for_each_build_own_record() {
        let body = prefix_versions_query("conda-forge", "zlib", "1.3.2");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["variables"]["c"], "conda-forge");
        assert_eq!(parsed["variables"]["n"], "zlib");
        assert_eq!(parsed["variables"]["v"], "1.3.2");
        let query = parsed["query"].as_str().unwrap();
        // A page is capped, so the oldest builds have to be the ones the server returns.
        assert!(query.contains("direction:ASC"), "{query}");
        // rawIndex carries the build's own timestamp; createdAt is only when prefix.dev ingested
        // it, which for anything older than the mirror is years out.
        assert!(query.contains("rawIndex"), "{query}");
        assert!(query.contains("versions(limit:500)"), "{query}");

        let follow_up = prefix_version_date_query("conda-forge", "zlib", "1.4.0");
        let parsed: serde_json::Value = serde_json::from_str(&follow_up).unwrap();
        assert_eq!(parsed["variables"]["v"], "1.4.0");
        assert!(parsed["query"].as_str().unwrap().contains("direction:ASC"));
    }

    #[test]
    fn a_prefix_date_response_is_the_one_row() {
        let json = r#"{"data":{"package":{"current":{"page":[{"createdAt":"2026-03-21T06:58:29Z"}]}}}}"#;
        assert_eq!(prefix_date(json).as_deref(), Some("2026-03-21T06:58:29Z"));
        assert_eq!(prefix_date(r#"{"data":{"package":{"current":{"page":[]}}}}"#), None);
    }

    #[test]
    fn a_named_index_is_asked_about_every_channel_including_a_mirrored_one() {
        use crate::format::testing::sample_sbom;
        let mut sbom = sample_sbom();
        // A workspace solved against a mirror: nothing in the lockfile mentions anaconda.org.
        for package in sbom.packages.iter_mut() {
            package.properties.insert(
                "pixi:channel-url".into(),
                "https://artifactory.corp/conda/conda-forge/".into(),
            );
            package.properties.insert("pixi:channel".into(), "conda-forge".into());
        }
        let mirrored = &sbom.packages[1];

        // Defaulted, the index is anaconda.org, so a channel it does not host is not worth asking
        // about and the package is reported unknown rather than costing a request.
        assert_eq!(anaconda_channel(mirrored, false), None);

        // Named, it is the operator saying this index answers for their channels.
        assert_eq!(anaconda_channel(mirrored, true), Some("conda-forge".into()));
    }

    #[test]
    fn a_package_with_no_channel_url_is_never_asked_about() {
        use crate::format::testing::sample_sbom;
        let mut sbom = sample_sbom();
        for package in sbom.packages.iter_mut() {
            package.properties.remove("pixi:channel-url");
        }
        // Even with an index named: there is nothing to attribute the package to.
        assert_eq!(anaconda_channel(&sbom.packages[1], true), None);
    }

    #[test]
    fn ages_are_whole_days() {
        let now = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert_eq!(age_in_days("2027-01-15T08:00:00Z", now), Some(0));
        let published = chrono::DateTime::from_timestamp(1_800_000_000 - 86_400 * 30, 0).unwrap();
        assert_eq!(age_in_days(&published.to_rfc3339(), now), Some(30));
        assert_eq!(age_in_days("not a date", now), None);
    }
}
