//! What the caches are allowed to do this run, and what they did.
//!
//! Seven caches back the network features — the conda-forge mapping, OSV queries and records,
//! the CISA KEV catalog, wheel `dist-info`, conda archive reads, `--report outdated` documents
//! and scorecards — with lifetimes from an hour to a week. They are what makes a second run
//! fast and an offline run possible, and they are also why "it works on my machine" is often
//! "my cache is warm". `--refresh` and `--no-cache` take them out of the picture, and the
//! counts below say, per service, how much of an answer came from disk.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// A cache a run may read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Service {
    /// The conda-forge name mapping (`--pypi-mapping prefix`).
    Mapping,
    /// OSV query results and advisory records.
    Osv,
    /// The CISA KEV catalog.
    Kev,
    /// Wheel `dist-info` extracted for licenses and embedded SBOMs.
    Wheels,
    /// PyPI release metadata.
    Pypi,
    /// `--report outdated` project documents.
    Outdated,
    /// OpenSSF scorecards.
    Scorecard,
}

impl Service {
    /// The name used in the flag and in the log.
    pub fn name(self) -> &'static str {
        match self {
            Service::Mapping => "mapping",
            Service::Osv => "osv",
            Service::Kev => "kev",
            Service::Wheels => "wheels",
            Service::Pypi => "pypi",
            Service::Outdated => "outdated",
            Service::Scorecard => "scorecard",
        }
    }
}

/// What this run may do with the caches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    /// Services whose cached answers are ignored for this run; empty means none, and with
    /// `all` every service is in it.
    refresh: Vec<Service>,
    /// Neither read nor write anything.
    no_cache: bool,
}

impl Policy {
    /// `--refresh` (with no service means every one) and `--no-cache`.
    pub fn new(refresh: Vec<Service>, refresh_all: bool, no_cache: bool) -> Self {
        Self {
            refresh: if refresh_all {
                vec![
                    Service::Mapping,
                    Service::Osv,
                    Service::Kev,
                    Service::Wheels,
                    Service::Pypi,
                    Service::Outdated,
                    Service::Scorecard,
                ]
            } else {
                refresh
            },
            no_cache,
        }
    }

    fn may_read(&self, service: Service) -> bool {
        !self.no_cache && !self.refresh.contains(&service)
    }

    fn may_write(&self, _service: Service) -> bool {
        // Refreshing still writes what it fetched; only --no-cache leaves nothing behind.
        !self.no_cache
    }
}

/// The policy for this run, set once from the command line.
static POLICY: OnceLock<Policy> = OnceLock::new();

/// What each cache did, so the run can say where its answers came from.
static COUNTS: OnceLock<Mutex<BTreeMap<Service, Counts>>> = OnceLock::new();

/// Caches that served an answer past its lifetime because the fetch failed, with the age of
/// the oldest such answer.
static STALE: OnceLock<Mutex<BTreeMap<Service, Duration>>> = OnceLock::new();

/// One service's tally.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    /// Answers served from disk.
    pub hits: usize,
    /// Answers that had to be fetched.
    pub misses: usize,
    /// The age of the oldest answer served.
    pub oldest: Duration,
    /// Set when an answer was served past its lifetime because the fetch failed. A document
    /// built on stale data should not look like one built on fresh data.
    pub stale: Option<Duration>,
}

/// Set the policy for this run. Later calls are ignored, which keeps the tests honest.
pub fn init(policy: Policy) {
    let _ = POLICY.set(policy);
}

fn policy() -> &'static Policy {
    POLICY.get_or_init(Policy::default)
}

fn counts() -> &'static Mutex<BTreeMap<Service, Counts>> {
    COUNTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn stale_counts() -> &'static Mutex<BTreeMap<Service, Duration>> {
    STALE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Whether a cached answer may be used for `service`.
pub fn may_read(service: Service) -> bool {
    policy().may_read(service)
}

/// Whether an answer may be written to the cache for `service`.
pub fn may_write(service: Service) -> bool {
    policy().may_write(service)
}

/// Note that a cached answer was used, and how old it was.
pub fn hit(service: Service, age: Duration) {
    if let Ok(mut counts) = counts().lock() {
        let entry = counts.entry(service).or_default();
        entry.hits += 1;
        entry.oldest = entry.oldest.max(age);
    }
}

/// Note that an answer was served past its lifetime because the fetch failed.
pub fn stale(service: Service, age: Duration) {
    if let Ok(mut counts) = counts().lock() {
        let entry = counts.entry(service).or_default();
        entry.stale = Some(entry.stale.map_or(age, |current| current.max(age)));
    }
}

/// The services that served data past its lifetime, with how old it was.
pub fn stale_services() -> Vec<(Service, Duration)> {
    tally()
        .into_iter()
        .filter_map(|(service, counts)| counts.stale.map(|age| (service, age)))
        .collect()
}

/// Note that an answer had to be fetched.
pub fn miss(service: Service) {
    if let Ok(mut counts) = counts().lock() {
        counts.entry(service).or_default().misses += 1;
    }
}

/// Note that a copy older than its lifetime stood in because the fetch failed. What the
/// document then says came from `age` ago, which is the part a reader months later needs.
pub fn stale(service: Service, age: Duration) {
    if let Ok(mut stale) = stale_counts().lock() {
        let entry = stale.entry(service).or_default();
        *entry = (*entry).max(age);
    }
}

/// One line per cache that served data past its lifetime, as `kev: 9 days old`, sorted.
pub fn stale_services() -> Vec<String> {
    stale_counts()
        .lock()
        .map(|stale| {
            stale
                .iter()
                .map(|(service, age)| format!("{}: {} old", service.name(), how_old(*age)))
                .collect()
        })
        .unwrap_or_default()
}

/// An age as a reader says it: `9 days`, `3 hours`, `12 minutes`.
fn how_old(age: Duration) -> String {
    let seconds = age.as_secs();
    if seconds < 60 {
        return "less than a minute".to_string();
    }
    let (count, unit) = match seconds {
        0..=5399 => (seconds / 60, "minute"),
        5400..=172_799 => (seconds / 3600, "hour"),
        _ => (seconds / 86_400, "day"),
    };
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

/// What every cache did this run, for the log.
pub fn tally() -> Vec<(Service, Counts)> {
    counts()
        .lock()
        .map(|counts| counts.iter().map(|(service, counts)| (*service, *counts)).collect())
        .unwrap_or_default()
}

/// Say where the answers came from, one line per cache that was consulted.
pub fn log_tally() {
    for (service, counts) in tally() {
        tracing::info!(
            cache = service.name(),
            from_cache = counts.hits,
            fetched = counts.misses,
            oldest_s = counts.oldest.as_secs(),
            "cache"
        );
    }
}

/// How old a cached file is, `None` when it cannot be told.
pub fn age(path: &std::path::Path, now: std::time::SystemTime) -> Option<Duration> {
    let modified = std::fs::metadata(path).and_then(|meta| meta.modified()).ok()?;
    Some(now.duration_since(modified).unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stale_cache_is_reported_with_the_age_of_the_oldest_copy_served() {
        assert!(
            stale_services().iter().all(|line| !line.starts_with("scorecard")),
            "nothing has gone stale yet"
        );
        stale(Service::Scorecard, Duration::from_secs(3 * 86_400));
        // The oldest copy served is what the document should say.
        stale(Service::Scorecard, Duration::from_secs(9 * 86_400));
        stale(Service::Scorecard, Duration::from_secs(86_400));
        let lines = stale_services();
        assert!(
            lines.contains(&"scorecard: 9 days old".to_string()),
            "expected the oldest age, got {lines:?}"
        );
    }

    #[test]
    fn an_age_is_said_the_way_a_reader_says_it() {
        assert_eq!(how_old(Duration::from_secs(30)), "less than a minute");
        assert_eq!(how_old(Duration::from_secs(60)), "1 minute");
        assert_eq!(how_old(Duration::from_secs(25 * 60)), "25 minutes");
        assert_eq!(how_old(Duration::from_secs(2 * 3600)), "2 hours");
        // Up to two days reads in hours, as the doctor's ages do.
        assert_eq!(how_old(Duration::from_secs(86_400)), "24 hours");
        assert_eq!(how_old(Duration::from_secs(2 * 86_400)), "2 days");
        assert_eq!(how_old(Duration::from_secs(9 * 86_400)), "9 days");
    }

    #[test]
    fn refreshing_one_service_leaves_the_others_alone() {
        let policy = Policy::new(vec![Service::Osv], false, false);
        assert!(!policy.may_read(Service::Osv));
        assert!(policy.may_read(Service::Kev));
        // A refresh still writes what it fetched; that is the point of refreshing.
        assert!(policy.may_write(Service::Osv));
    }

    #[test]
    fn refreshing_everything_and_refusing_the_cache_are_different_things() {
        let all = Policy::new(Vec::new(), true, false);
        for service in [Service::Mapping, Service::Osv, Service::Scorecard] {
            assert!(!all.may_read(service), "{}", service.name());
            assert!(all.may_write(service), "{}", service.name());
        }
        let none = Policy::new(Vec::new(), false, true);
        assert!(!none.may_read(Service::Osv));
        assert!(!none.may_write(Service::Osv), "--no-cache leaves nothing behind");
    }

    #[test]
    fn the_default_policy_uses_the_caches() {
        let policy = Policy::default();
        for service in [Service::Mapping, Service::Wheels, Service::Pypi] {
            assert!(policy.may_read(service));
            assert!(policy.may_write(service));
        }
    }

    #[test]
    fn the_tally_counts_hits_misses_and_the_oldest_answer() {
        hit(Service::Outdated, Duration::from_secs(60));
        hit(Service::Outdated, Duration::from_secs(3600));
        miss(Service::Outdated);
        let counts = tally()
            .into_iter()
            .find(|(service, _)| *service == Service::Outdated)
            .map(|(_, counts)| counts)
            .unwrap();
        assert_eq!(counts.hits, 2);
        assert_eq!(counts.misses, 1);
        assert_eq!(counts.oldest, Duration::from_secs(3600), "the oldest, not the last");
    }

    #[test]
    fn stale_data_is_remembered_with_the_worst_age() {
        stale(Service::Kev, Duration::from_secs(86_400));
        stale(Service::Kev, Duration::from_secs(3 * 86_400));
        let (service, age) = stale_services()
            .into_iter()
            .find(|(service, _)| *service == Service::Kev)
            .unwrap();
        assert_eq!(service, Service::Kev);
        assert_eq!(age, Duration::from_secs(3 * 86_400), "the worst, not the last");
        assert!(
            !stale_services().iter().any(|(service, _)| *service == Service::Mapping),
            "a service that answered is not stale"
        );
    }

    #[test]
    fn the_age_of_a_file_that_is_not_there_cannot_be_told() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(age(&dir.path().join("nope"), std::time::SystemTime::now()), None);
        let path = dir.path().join("here");
        std::fs::write(&path, "x").unwrap();
        assert!(age(&path, std::time::SystemTime::now()).is_some());
    }
}
