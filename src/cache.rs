//! What the caches are allowed to do this run, and what they did.
//!
//! Eight caches back the network features — the conda-forge mapping, OSV queries and records,
//! the CISA KEV catalog, wheel `dist-info`, conda archive `info/` directories, `--report
//! outdated` documents and scorecards — with lifetimes from an hour to a week. They are what makes a second run
//! fast and an offline run possible, and they are also why "it works on my machine" is often
//! "my cache is warm". `--refresh` and `--no-cache` take them out of the picture, and the
//! counts below say, per service, how much of an answer came from disk.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// `info/` directories extracted from conda archives, for licenses and package details.
    CondaInfo,
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
            Service::CondaInfo => "conda-info",
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
                    Service::CondaInfo,
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

/// Whether a cached answer may be used for `service`.
pub fn may_read(service: Service) -> bool {
    policy().may_read(service)
}

/// Whether an answer may be written to the cache for `service`.
pub fn may_write(service: Service) -> bool {
    policy().may_write(service)
}

/// Extract into a directory this run is allowed to write, and give `work` its path.
///
/// Two of the caches are directories of files pulled out of an archive rather than one
/// downloaded document, so their answer has to be on disk before it can be read at all. Under
/// `--no-cache` it cannot be `cached`, because the flag promised not to write there — it goes to
/// a scratch directory outside the cache, which is removed before this returns whether `work`
/// succeeded or not. `--refresh` is different: it means the cached answer is stale, not that the
/// cache is off, so a refreshed answer is written where it belongs.
pub fn extract_into<T>(
    service: Service,
    cached: &Path,
    extract: impl FnOnce(&Path) -> io::Result<()>,
    work: impl FnOnce(&Path) -> io::Result<T>,
) -> io::Result<T> {
    extract_into_where(may_write(service), service, cached, extract, work)
}

/// [`extract_into`] with the decision handed to it. The policy is a process-wide `OnceLock`, so
/// a test cannot set it twice; this is what lets both branches be tested in one binary.
fn extract_into_where<T>(
    write_cache: bool,
    service: Service,
    cached: &Path,
    extract: impl FnOnce(&Path) -> io::Result<()>,
    work: impl FnOnce(&Path) -> io::Result<T>,
) -> io::Result<T> {
    if write_cache {
        extract(cached)?;
        return work(cached);
    }
    let scratch = scratch_dir(service);
    let outcome = extract(&scratch).and_then(|()| work(&scratch));
    // Both the directory and the `.partial` staging its writer may have left beside it.
    let _ = std::fs::remove_dir_all(&scratch);
    let _ = std::fs::remove_dir_all(scratch.with_extension("partial"));
    outcome
}

/// A directory outside any cache, unique to this call. The counter is because the archive
/// readers run several jobs at once and two of them must not land on the same path.
fn scratch_dir(service: Service) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nth = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "pixi-sbom-no-cache-{}-{}-{nth}",
        std::process::id(),
        service.name()
    ))
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

/// The same thing as [`stale_services`], said the way the document says it: `kev: 9 days
/// old`, one line per cache, sorted by service.
pub fn stale_lines() -> Vec<String> {
    stale_services()
        .into_iter()
        .map(|(service, age)| format!("{}: {} old", service.name(), how_old(age)))
        .collect()
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

/// What one service's cache did this run, in the words the timings table uses. `None` when that
/// cache was never consulted, so a phase that did no caching says nothing rather than `0 cached`.
pub fn describe(service: Service) -> Option<String> {
    describe_from(&tally(), service)
}

/// [`describe`] for a given tally, which is what makes it testable: the real one is shared by
/// every test in the process, any of which may have touched any service.
fn describe_from(tally: &[(Service, Counts)], service: Service) -> Option<String> {
    let counts = tally
        .iter()
        .find_map(|(found, counts)| (*found == service).then_some(counts))?;
    Some(format!("{} fetched, {} cached", counts.misses, counts.hits))
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
    #[test]
    fn a_cache_that_was_never_consulted_describes_as_nothing() {
        // `0 fetched, 0 cached` on a phase that does no caching would be a statement about work
        // that never happened; saying nothing is the honest row. On a tally of its own: the
        // process-wide one is shared with every test that touches a cache, so asserting that a
        // service is absent from it raced with them (stale_data_is_remembered_with_the_worst_age).
        assert_eq!(super::describe_from(&[], super::Service::Kev), None);
        let used = super::Counts {
            hits: 2,
            misses: 1,
            ..super::Counts::default()
        };
        assert_eq!(
            super::describe_from(&[(super::Service::Kev, used)], super::Service::Kev).as_deref(),
            Some("1 fetched, 2 cached")
        );
        assert_eq!(
            super::describe_from(&[(super::Service::Osv, used)], super::Service::Kev),
            None
        );
    }

    use super::*;

    #[test]
    fn a_stale_cache_is_reported_with_the_age_of_the_oldest_copy_served() {
        assert!(
            stale_lines().iter().all(|line| !line.starts_with("scorecard")),
            "nothing has gone stale yet"
        );
        stale(Service::Scorecard, Duration::from_secs(3 * 86_400));
        // The oldest copy served is what the document should say.
        stale(Service::Scorecard, Duration::from_secs(9 * 86_400));
        stale(Service::Scorecard, Duration::from_secs(86_400));
        let lines = stale_lines();
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
    fn a_cache_it_may_write_is_extracted_into_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cached = dir.path().join("conda-info").join("abc");
        let read = extract_into_where(
            true,
            Service::CondaInfo,
            &cached,
            |into| {
                std::fs::create_dir_all(into)?;
                std::fs::write(into.join("index.json"), b"{}")
            },
            |from| Ok(from.to_path_buf()),
        )
        .unwrap();
        assert_eq!(read, cached, "the work saw the cache directory");
        assert!(cached.join("index.json").is_file(), "and it is still there afterwards");
    }

    #[test]
    fn a_cache_it_may_not_write_is_extracted_somewhere_else_and_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        let cached = dir.path().join("conda-info").join("abc");
        let used = extract_into_where(
            false,
            Service::CondaInfo,
            &cached,
            |into| {
                std::fs::create_dir_all(into)?;
                // What the archive writers leave beside the directory while they work.
                std::fs::create_dir_all(into.with_extension("partial"))?;
                std::fs::write(into.join("index.json"), b"{}")
            },
            |from| {
                assert!(from.join("index.json").is_file(), "the work still gets its files");
                Ok(from.to_path_buf())
            },
        )
        .unwrap();

        assert_ne!(used, cached, "--no-cache did not write where the cache lives");
        assert!(!cached.exists(), "and left nothing there at all");
        assert!(!used.exists(), "the scratch directory is removed");
        assert!(!used.with_extension("partial").exists(), "staging too");
    }

    #[test]
    fn a_failed_extraction_still_cleans_up_after_itself() {
        let dir = tempfile::tempdir().unwrap();
        let outcome: io::Result<()> = extract_into_where(
            false,
            Service::Wheels,
            &dir.path().join("wheel-info").join("abc"),
            |into| {
                std::fs::create_dir_all(into)?;
                std::fs::write(into.join("half-written"), b"x")?;
                Err(io::Error::other("the archive was truncated"))
            },
            |_| unreachable!("work does not run when the extraction failed"),
        );
        assert!(outcome.is_err());
        // The scratch path is not returned on the error path, so check no leftovers of ours
        // remain in the temp directory for this service.
        let leftovers: Vec<_> = std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(&format!("pixi-sbom-no-cache-{}-wheels", std::process::id()))
            })
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    #[test]
    fn two_scratch_directories_never_collide() {
        // The archive readers run several jobs at once against the same service.
        let a = scratch_dir(Service::CondaInfo);
        let b = scratch_dir(Service::CondaInfo);
        assert_ne!(a, b);
    }

    #[test]
    fn every_service_has_a_name_and_refresh_all_covers_all_of_them() {
        // A service added without a `--refresh all` entry would silently keep serving stale
        // answers, which is the failure this pins.
        let all = Policy::new(Vec::new(), true, false);
        for service in [
            Service::Mapping,
            Service::Osv,
            Service::Kev,
            Service::Wheels,
            Service::CondaInfo,
            Service::Pypi,
            Service::Outdated,
            Service::Scorecard,
        ] {
            assert!(!service.name().is_empty());
            assert!(
                !all.may_read(service),
                "{} is not refreshed by --refresh",
                service.name()
            );
        }
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
