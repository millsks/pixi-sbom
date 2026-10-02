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

use crate::http;
use crate::model::{PackageKind, Sbom};

/// Where conda versions are looked up; `PIXI_SBOM_ANACONDA_URL` overrides it.
pub const DEFAULT_ANACONDA_URL: &str = "https://api.anaconda.org";

/// Environment variable naming the anaconda.org API base.
pub const ANACONDA_URL_ENV: &str = "PIXI_SBOM_ANACONDA_URL";

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
    #[serde(default)]
    attrs: AnacondaAttrs,
}

#[derive(Debug, Default, Deserialize)]
struct AnacondaAttrs {
    /// Milliseconds since the epoch, as conda records build times.
    #[serde(default)]
    timestamp: Option<i64>,
}

/// The one GraphQL request a package needs.
///
/// `versions` is the release list. `recent` is the newest builds across every version, which is
/// where the latest release's date comes from — it is the latest precisely because its builds are
/// the most recent. `current` is filtered to the installed version, so its date is exact however
/// far behind it is. The server caps an unfiltered `variants` page, which is why the installed
/// version is asked for by name rather than hunted for in `recent`.
pub fn prefix_query(channel: &str, name: &str, installed: &str) -> String {
    let query = "query($c:String!,$n:String!,$v:String){ package(channelName:$c, name:$n) {                  latestVersion { version }                  versions(limit:200) { page { version } }                  recent: variants(limit:200) { page { version createdAt } }                  current: variants(limit:200, version:$v) { page { createdAt } } } }";
    serde_json::json!({
        "query": query,
        "variables": { "c": channel, "n": name, "v": installed },
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
    #[serde(default)]
    recent: Option<PrefixVariantPage>,
    #[serde(default)]
    current: Option<PrefixVariantPage>,
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
    #[serde(default)]
    version: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
}

/// Every version in a prefix.dev package response, with the earliest build time of each as its
/// publication date, matching what [`anaconda_releases`] takes from anaconda.org.
///
/// `installed` names the version the `current` alias was filtered to, so its builds are attributed
/// to it; `recent` carries its own version per build.
pub fn prefix_releases(json: &str, installed: &str) -> Vec<Release> {
    let Ok(envelope) = serde_json::from_str::<PrefixEnvelope>(json) else {
        return Vec::new();
    };
    let Some(package) = envelope.data.and_then(|data| data.package) else {
        return Vec::new();
    };

    let mut earliest: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut note = |version: &str, created: &Option<String>| {
        if let Some(created) = created {
            earliest
                .entry(version.to_string())
                .and_modify(|held| {
                    if created < held {
                        *held = created.clone();
                    }
                })
                .or_insert_with(|| created.clone());
        }
    };
    for variant in package.recent.map(|p| p.page).unwrap_or_default() {
        if let Some(version) = &variant.version {
            note(version, &variant.created_at);
        }
    }
    for variant in package.current.map(|p| p.page).unwrap_or_default() {
        note(installed, &variant.created_at);
    }

    package
        .versions
        .map(|p| p.page)
        .unwrap_or_default()
        .into_iter()
        .map(|entry| Release {
            published: earliest.get(&entry.version).cloned(),
            version: entry.version,
            yanked: false,
        })
        .collect()
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

/// Whether an index base was named rather than defaulted.
///
/// Naming one is a statement that it answers for this workspace's channels, which is the only
/// signal available: the lockfile records where packages were *fetched from*, which says nothing
/// about what the configured index can answer for.
pub fn index_is_configured() -> bool {
    std::env::var(ANACONDA_URL_ENV).is_ok_and(|value| !value.trim().is_empty())
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

    fn run_with(
        &self,
        sbom: &Sbom,
        fetch: Fetch<'_>,
        now: SystemTime,
        progress: crate::progress::Progress,
    ) -> (Vec<Option<Status>>, Outcome) {
        let mut outcome = Outcome::default();
        let mut jobs = Vec::new();
        for (index, package) in sbom.packages.iter().enumerate() {
            let job = match package.kind {
                PackageKind::Pypi => {
                    let name = crate::purl::normalize_pypi_name(&package.name);
                    Some(Job {
                        index,
                        display_name: package.name.clone(),
                        url: format!("{}/{name}/json", self.index_url.trim_end_matches('/')),
                        body: None,
                        cache_file: self.cache_dir.join("outdated").join(format!("pypi-{name}.json")),
                        kind: package.kind,
                    })
                }
                PackageKind::CondaBinary => {
                    anaconda_channel(package, self.index_is_configured).map(|channel| match self.kind {
                        crate::cli::CondaIndexKind::Prefix => Job {
                            index,
                            display_name: package.name.clone(),
                            url: self.prefix_index_url.to_string(),
                            body: Some(prefix_query(
                                &channel,
                                &package.name,
                                package.version.as_deref().unwrap_or_default(),
                            )),
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
                            body: None,
                            cache_file: self
                                .cache_dir
                                .join("outdated")
                                .join(format!("conda-{channel}-{}.json", package.name)),
                            kind: package.kind,
                        },
                    })
                }
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
            let Some(document) = document else {
                outcome.unknown += 1;
                continue;
            };
            let current = sbom.packages[job.index].version.clone().unwrap_or_default();
            let releases = match (job.kind, self.kind) {
                (PackageKind::Pypi, _) => pypi_releases(&document),
                (_, crate::cli::CondaIndexKind::Prefix) => prefix_releases(&document, &current),
                (_, crate::cli::CondaIndexKind::Anaconda) => anaconda_releases(&document),
            };
            if releases.is_empty() {
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
        match fetch(&job.url, job.body.as_deref()) {
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
    fn a_prefix_response_yields_the_same_releases_an_anaconda_one_would() {
        let json = r#"{"data":{"package":{
            "latestVersion":{"version":"1.3.2"},
            "versions":{"page":[{"version":"1.3.2"},{"version":"1.3.1"},{"version":"1.2.11"}]},
            "recent":{"page":[
                {"version":"1.3.2","createdAt":"2026-03-21T06:58:29Z"},
                {"version":"1.3.2","createdAt":"2026-03-21T07:40:00Z"},
                {"version":"1.3.1","createdAt":"2024-03-05T13:14:38Z"}]},
            "current":{"page":[
                {"createdAt":"2019-09-09T23:22:40Z"},
                {"createdAt":"2019-09-10T01:00:00Z"}]}}}}"#;
        let releases = prefix_releases(json, "1.2.11");
        assert_eq!(releases.len(), 3);
        // The earliest build of a version is its release date, as anaconda_releases does.
        let find = |v: &str| releases.iter().find(|r| r.version == v).unwrap().published.clone();
        assert_eq!(find("1.3.2").as_deref(), Some("2026-03-21T06:58:29Z"));
        assert_eq!(find("1.3.1").as_deref(), Some("2024-03-05T13:14:38Z"));
        // The installed version is dated from `current`, which is filtered to it, so a version too
        // old to appear among the recent builds is still exact.
        assert_eq!(find("1.2.11").as_deref(), Some("2019-09-09T23:22:40Z"));
    }

    #[test]
    fn a_prefix_response_that_says_nothing_yields_nothing() {
        for json in [
            r#"{"data":{"package":null}}"#,
            r#"{"errors":[{"message":"nope"}]}"#,
            "not json",
            r#"{"data":{"package":{"versions":{"page":[]}}}}"#,
        ] {
            assert!(prefix_releases(json, "1.0").is_empty(), "{json}");
        }
    }

    #[test]
    fn the_query_names_the_channel_the_package_and_the_installed_version() {
        let body = prefix_query("conda-forge", "zlib", "1.3.2");
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["variables"]["c"], "conda-forge");
        assert_eq!(parsed["variables"]["n"], "zlib");
        assert_eq!(parsed["variables"]["v"], "1.3.2");
        let query = parsed["query"].as_str().unwrap();
        for part in [
            "latestVersion",
            "versions(limit:200)",
            "recent: variants",
            "current: variants",
        ] {
            assert!(query.contains(part), "{part} missing from {query}");
        }
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
