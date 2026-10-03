//! Where a run spent its time.
//!
//! The progress bars show that something is happening, not what is expensive. A run that takes
//! four minutes on CI cannot be turned into "three and a half of those were the conda archive
//! reads" without a profiler, which is a high price for a question this simple. Each phase
//! records how long it took and how much it did, and `--timings` prints the table.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// One step of a run, in the order they happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Reading and parsing the lockfile, prefix or source document.
    Input,
    /// Reading the workspace manifest.
    Manifest,
    /// The conda-forge PyPI mapping.
    Mapping,
    /// Wheel `dist-info`, over the network or out of the cache.
    Wheels,
    /// The local conda package cache.
    PackageCache,
    /// Conda archives read over HTTP ranges.
    Archives,
    /// PyPI release metadata.
    Pypi,
    /// The OSV lookup, including the KEV catalog.
    Vulnerabilities,
    /// OpenSSF scorecards.
    Scorecard,
    /// `--report outdated` index lookups.
    Outdated,
    /// Reading the workspace's Python sources.
    Imports,
    /// Serializing and writing the documents.
    Write,
}

impl Phase {
    /// The name the table shows.
    pub fn name(self) -> &'static str {
        match self {
            Phase::Input => "input",
            Phase::Manifest => "manifest",
            Phase::Mapping => "pypi mapping",
            Phase::Wheels => "wheels (dist-info)",
            Phase::PackageCache => "package cache",
            Phase::Archives => "conda archives",
            Phase::Pypi => "pypi metadata",
            Phase::Vulnerabilities => "vulnerabilities",
            Phase::Scorecard => "scorecards",
            Phase::Outdated => "outdated",
            Phase::Imports => "imports",
            Phase::Write => "write",
        }
    }
}

/// What one phase cost.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Timing {
    pub elapsed: Duration,
    /// What it covered, in the phase's own words: `38 fetched, 4 cached`.
    pub detail: String,
    /// Requests this phase actually sent. Zero means it was served entirely from the cache, and
    /// none of its time was spent waiting on an upstream however much it could have been.
    pub requests: u64,
}

static TIMINGS: OnceLock<Mutex<BTreeMap<Phase, Timing>>> = OnceLock::new();

fn timings() -> &'static Mutex<BTreeMap<Phase, Timing>> {
    TIMINGS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// Time `work`, adding what it took to `phase`. Phases that run more than once (a batch of
/// documents) add up, which is what the table should show.
pub fn time<T>(phase: Phase, work: impl FnOnce() -> T) -> T {
    let before = crate::http::requests_made();
    let started = Instant::now();
    let out = work();
    let elapsed = started.elapsed();
    add(phase, elapsed, String::new());
    note_requests(phase, crate::http::requests_made().saturating_sub(before));
    out
}

/// Add an elapsed time to a phase, and its description when there is one to give.
pub fn add(phase: Phase, elapsed: Duration, detail: String) {
    if let Ok(mut timings) = timings().lock() {
        let entry = timings.entry(phase).or_default();
        entry.elapsed += elapsed;
        if !detail.is_empty() {
            entry.detail = detail;
        }
    }
}

/// Record how many requests a phase sent. Phases that run more than once add up, as their times do.
fn note_requests(phase: Phase, requests: u64) {
    if let Ok(mut timings) = timings().lock() {
        timings.entry(phase).or_default().requests += requests;
    }
}

/// Say what a phase covered, without touching its time.
pub fn describe(phase: Phase, detail: String) {
    add(phase, Duration::ZERO, detail);
}

/// Every phase that took part, in run order.
pub fn tally() -> Vec<(Phase, Timing)> {
    timings()
        .lock()
        .map(|timings| timings.iter().map(|(phase, timing)| (*phase, timing.clone())).collect())
        .unwrap_or_default()
}

/// The table, as lines, with the totals at the end. `total` is the whole run, so the gap
/// between it and the phases is visible rather than hidden.
pub fn table(total: Duration) -> Vec<String> {
    table_of(tally(), total)
}

/// [`table`] over a tally given to it, which is how the zero-network case is tested: the
/// run's own tally is global and one test cannot empty it for another.
fn table_of(tally: Vec<(Phase, Timing)>, total: Duration) -> Vec<String> {
    let width = tally
        .iter()
        .map(|(phase, _)| phase.name().len())
        .chain(std::iter::once("total".len()))
        .max()
        .unwrap_or(8);
    let mut lines = vec![format!("{:<width$}  {:>8}  {}", "Phase", "Time", "Detail")];
    for (phase, timing) in &tally {
        lines.push(format!(
            "{:<width$}  {:>8}  {}",
            phase.name(),
            seconds(timing.elapsed),
            timing.detail
        ));
    }
    // The time of phases that actually sent a request. A phase that *could* reach the network but
    // was served from the cache waited on nothing, and saying otherwise answers the one question
    // this line exists for — "was it the tool or the link" — with the wrong half.
    let network: Duration = tally
        .iter()
        .filter(|(_, timing)| timing.requests > 0)
        .map(|(_, timing)| timing.elapsed)
        .sum();
    lines.push(format!(
        "{:<width$}  {:>8}  {}",
        "total",
        seconds(total),
        // Always said, even when it is none of it: "the network was not the problem" is the
        // answer the table is most often consulted for, and a line that disappears when the
        // answer is no cannot give it.
        if network.is_zero() {
            "none of it waiting on the network".to_string()
        } else {
            format!("of which {} waiting on the network", seconds(network))
        }
    ));
    lines
}

/// A duration with two decimals and a unit, which is how long these are read.
fn seconds(duration: Duration) -> String {
    format!("{:.2} s", duration.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phase_that_runs_twice_adds_up_and_keeps_its_last_description() {
        add(Phase::Write, Duration::from_millis(40), "one document".into());
        add(Phase::Write, Duration::from_millis(60), "two documents".into());
        let timing = tally()
            .into_iter()
            .find(|(phase, _)| *phase == Phase::Write)
            .map(|(_, timing)| timing)
            .unwrap();
        assert_eq!(timing.elapsed, Duration::from_millis(100));
        assert_eq!(timing.detail, "two documents");
    }

    #[test]
    fn describing_a_phase_does_not_charge_it_any_time() {
        add(Phase::Imports, Duration::from_millis(10), String::new());
        describe(Phase::Imports, "12 files".into());
        let timing = tally()
            .into_iter()
            .find(|(phase, _)| *phase == Phase::Imports)
            .map(|(_, timing)| timing)
            .unwrap();
        assert_eq!(timing.elapsed, Duration::from_millis(10));
        assert_eq!(timing.detail, "12 files");
    }

    /// A phase as the table sees it.
    fn phase(elapsed_ms: u64, detail: &str, requests: u64) -> Timing {
        Timing {
            elapsed: Duration::from_millis(elapsed_ms),
            detail: detail.into(),
            requests,
        }
    }

    #[test]
    fn the_table_separates_waiting_on_the_network_from_working() {
        let lines = table_of(
            vec![
                (Phase::Input, phase(40, "240 packages", 0)),
                (Phase::Pypi, phase(12_000, "38 fetched", 38)),
            ],
            Duration::from_secs(13),
        );
        assert!(lines[0].starts_with("Phase"), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("pypi metadata") && line.contains("12.00 s"))
        );
        assert!(
            lines
                .last()
                .unwrap()
                .contains("of which 12.00 s waiting on the network"),
            "{:?}",
            lines.last()
        );
    }

    #[test]
    fn a_phase_served_from_the_cache_did_not_wait_on_the_network() {
        // The reported bug: the outdated phase can reach an index, so it was counted as network
        // wait even on a run that fetched nothing. What decides it is whether a request was sent,
        // not whether one could have been.
        let warm = vec![
            (Phase::Input, phase(40, "240 packages", 0)),
            (Phase::Outdated, phase(340, "0 fetched, 52 cached", 0)),
        ];
        let lines = table_of(warm, Duration::from_millis(400));
        assert!(
            lines.last().unwrap().contains("none of it waiting on the network"),
            "a phase that sent no request waited on nothing: {:?}",
            lines.last()
        );
        assert!(
            lines.iter().any(|line| line.contains("0 fetched, 52 cached")),
            "and the row still says what it covered: {lines:?}"
        );

        // One request is enough to make the phase's time network wait again.
        let cold = vec![(Phase::Outdated, phase(340, "1 fetched, 51 cached", 1))];
        assert!(
            table_of(cold, Duration::from_millis(400))
                .last()
                .unwrap()
                .contains("of which 0.34 s waiting on the network")
        );
    }

    #[test]
    fn timing_a_phase_records_the_requests_it_sent() {
        // Nothing in this test reaches the network, so the phase must be charged none.
        let before = tally()
            .into_iter()
            .find(|(phase, _)| *phase == Phase::Scorecard)
            .map_or(0, |(_, timing)| timing.requests);
        time(Phase::Scorecard, || ());
        let after = tally()
            .into_iter()
            .find(|(phase, _)| *phase == Phase::Scorecard)
            .map_or(0, |(_, timing)| timing.requests);
        assert_eq!(after, before, "no request was sent, so none was counted");
    }

    #[test]
    fn a_run_that_never_waited_says_so_rather_than_leaving_the_line_out() {
        let offline = vec![(Phase::Input, phase(40, "240 packages", 0))];
        let lines = table_of(offline, Duration::from_millis(50));
        assert!(
            lines.last().unwrap().contains("none of it waiting on the network"),
            "{:?}",
            lines.last()
        );

        // And the same when a network phase ran but took no measurable time, which is what an
        // offline run with a warm cache looks like.
        let cached = vec![(Phase::Pypi, phase(0, "", 0))];
        assert!(
            table_of(cached, Duration::from_millis(10))
                .last()
                .unwrap()
                .contains("none of it waiting on the network")
        );
    }

    #[test]
    fn timing_a_closure_returns_what_it_returns() {
        assert_eq!(time(Phase::Manifest, || 7), 7);
        assert!(
            tally().into_iter().any(|(phase, _)| phase == Phase::Manifest),
            "the phase is recorded even when it is instant"
        );
    }
}
