//! How many things happen at once, decided once for the whole run.
//!
//! Every fetcher used to carry its own `const CONCURRENCY: usize = 10` and its own scoped
//! thread pool, so the number could not be changed from outside and six copies had to agree.
//! Now one setting decides it, `PIXI_SBOM_CONCURRENCY` overrides it, and the work runs on
//! rayon, which steals work rather than handing each thread a fixed share — the difference
//! shows whenever one request is slow and the others are not.

use std::sync::OnceLock;

use rayon::prelude::*;

use crate::progress::Bar;

/// How many jobs may run at once, for a run that wants to be gentler or faster than the
/// default.
pub const CONCURRENCY_ENV: &str = "PIXI_SBOM_CONCURRENCY";

/// The most requests in flight at once by default, however many cores there are. Beyond this
/// an upstream starts refusing rather than answering faster.
const MAX_NETWORK: usize = 10;

/// Past this, a value is unusual enough to be worth mentioning. It is honoured: an operator
/// pointing at their own mirror is entitled to ask for more than a public index would tolerate,
/// and the largest value anyone has reported using in anger is 50.
const UNUSUAL_NETWORK: usize = 100;

/// Past this, a value is not a tuning choice but a resource failure waiting to happen. Measured on
/// macOS: 1000 threads build in 53 ms, 10 000 fail after **34 seconds** with
/// `Resource temporarily unavailable`, and 50 000 after nearly three minutes. Clamping costs
/// nothing anybody wanted and saves a run that would otherwise hang and then die.
const MAX_SANE_NETWORK: usize = 1000;

/// What this run decided, and what decided it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Requests in flight at once.
    pub network: usize,
    /// Threads for work that is not waiting on anything.
    pub cpu: usize,
    /// Whether `PIXI_SBOM_CONCURRENCY` chose this rather than the machine.
    pub from_env: bool,
}

impl Limits {
    /// `PIXI_SBOM_CONCURRENCY` if it is a positive number, else the machine: one thread per core
    /// for work, and [`MAX_NETWORK`] requests in flight **whatever the core count**.
    ///
    /// Those are different resources and only one of them is cores. A request in flight is a
    /// thread blocked on a socket, costing no CPU at all, so a two-core laptop can hold ten
    /// connections as easily as a workstation — every browser on it holds far more. Tying the two
    /// together throttled the machines least able to afford it: `available_parallelism` reports
    /// cgroup quotas, so a container limited to one CPU made **one request at a time**, turning a
    /// half-minute run into several minutes with nothing in the output to say why.
    ///
    /// A value that is not a positive number is ignored rather than fatal, with the text
    /// returned so the caller can say so once logging exists. Refusing to run over a
    /// misspelled tuning knob would be the wrong trade.
    pub fn resolve(env: Option<&str>, cores: usize) -> (Self, Option<String>) {
        let cores = cores.max(1);
        let default = Self {
            network: MAX_NETWORK,
            cpu: cores,
            from_env: false,
        };
        let Some(value) = env.map(str::trim).filter(|value| !value.is_empty()) else {
            return (default, None);
        };
        match value.parse::<usize>() {
            Ok(requested) if requested > 0 => (
                Self {
                    network: requested.min(MAX_SANE_NETWORK),
                    cpu: requested.min(MAX_SANE_NETWORK),
                    from_env: true,
                },
                None,
            ),
            _ => (default, Some(value.to_string())),
        }
    }

    /// What this run should say out loud about the number it was given, if anything.
    pub fn concern(requested: usize) -> Option<String> {
        if requested > MAX_SANE_NETWORK {
            Some(format!(
                "{requested} requests at once is more threads than an operating system will give; \
                 using {MAX_SANE_NETWORK}"
            ))
        } else if requested > UNUSUAL_NETWORK {
            Some(format!(
                "{requested} requests at once is unusually high; public indexes commonly refuse \
                 well below this, and a refused run is slower than a patient one"
            ))
        } else {
            None
        }
    }

    /// The same, read from the process environment.
    pub fn from_env() -> (Self, Option<String>) {
        Self::resolve(
            std::env::var(CONCURRENCY_ENV).ok().as_deref(),
            std::thread::available_parallelism().map_or(1, |cores| cores.get()),
        )
    }
}

/// The limits for this run.
static LIMITS: OnceLock<Limits> = OnceLock::new();

/// The pool the network jobs run on, kept apart from rayon's global pool so a slow upstream
/// cannot take every thread the machine has.
static NETWORK_POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();

/// Fix the limits for this run and size rayon's global pool. Later calls are ignored, which
/// keeps the tests honest.
pub fn init(limits: Limits) {
    if LIMITS.set(limits).is_err() {
        return;
    }
    // A failure here means something else built the global pool first, which only happens in
    // a test binary running several cases at once; rayon's default is then already in place
    // and the run is correct, only differently sized.
    if let Err(err) = rayon::ThreadPoolBuilder::new()
        .num_threads(limits.cpu)
        .thread_name(|index| format!("pixi-sbom-{index}"))
        .build_global()
    {
        tracing::debug!(%err, "the global thread pool was already built; keeping it");
    }
    tracing::debug!(
        network = limits.network,
        cpu = limits.cpu,
        source = if limits.from_env {
            CONCURRENCY_ENV
        } else {
            "the machine"
        },
        "concurrency"
    );
}

fn limits() -> Limits {
    *LIMITS.get_or_init(|| Limits::from_env().0)
}

/// The most packages this run will ever ask about, once the lockfile has been read.
static WORK: OnceLock<usize> = OnceLock::new();

/// Say how much work there is, so the pool is not sized past it.
///
/// Threads beyond the number of jobs can only park: 200 threads for 50 packages leaves 150 doing
/// nothing. Capping is **only ever downward** — the configured value stays a ceiling, because it
/// says what this network and its upstreams tolerate while the package count says how much there
/// is to do. Having more to do is no evidence an index will take more at once; it is the run where
/// that matters most.
///
/// Worth almost nothing in time (100 threads build in 1 ms) and quite a lot in robustness: a
/// container with a low process limit can refuse a large pool, and a machine-wide
/// `concurrency = 1000` carried into a five-package workspace is exactly how that happens.
pub fn limit_to_work(jobs: usize) {
    let _ = WORK.set(jobs);
}

/// How many requests may be in flight at once, after the work cap.
pub fn network() -> usize {
    capped(limits().network, WORK.get().copied())
}

/// `configured` requests, never more than there is work to do, never fewer than one.
///
/// `.max(1)` is not decoration: rayon reads `num_threads(0)` as "choose automatically" and would
/// build a pool the size of the machine — *more* than was configured, which is the one outcome
/// every limit here exists to prevent. An empty workspace is the way to hit it.
fn capped(configured: usize, work: Option<usize>) -> usize {
    configured.min(work.unwrap_or(usize::MAX)).max(1)
}

/// The pool, or `None` when the operating system would not give us one.
fn network_pool() -> Option<&'static rayon::ThreadPool> {
    NETWORK_POOL
        .get_or_init(|| {
            let wanted = network();
            // Falling back rather than failing: a pool that cannot be built is the operating
            // system being out of threads, which a smaller pool may still survive. Dying over it
            // would turn a resource squeeze into a failed run for no gain.
            for threads in [wanted, MAX_NETWORK.min(wanted), 1] {
                match rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .thread_name(|index| format!("pixi-sbom-net-{index}"))
                    .build()
                {
                    Ok(pool) => {
                        if threads != wanted {
                            tracing::warn!(
                                wanted,
                                threads,
                                "the system would not give us that many threads; using fewer"
                            );
                        }
                        return Some(pool);
                    }
                    Err(err) => tracing::debug!(threads, %err, "cannot build a thread pool that size"),
                }
            }
            tracing::warn!("no thread pool could be built; requests will run one at a time");
            None
        })
        .as_ref()
}

/// Run `work` over `jobs` on the network pool; results come back in job order however the
/// threads interleave, because a document that changed with the scheduler would not be
/// reproducible. Each finished job is counted on `bar`, named with `label`.
pub fn map<J: Sync, R: Send>(
    jobs: &[J],
    bar: Option<&Bar>,
    label: impl Fn(&J) -> String + Sync,
    work: impl Fn(&J) -> R + Sync,
) -> Vec<R> {
    if jobs.is_empty() {
        return Vec::new();
    }
    let run = || {
        jobs.par_iter()
            .map(|job| {
                let result = work(job);
                if let Some(bar) = bar {
                    bar.advance(&label(job));
                }
                result
            })
            .collect()
    };
    match network_pool() {
        Some(pool) => pool.install(run),
        // One at a time is slow, and it is a great deal better than not running.
        None => jobs
            .iter()
            .map(|job| {
                let result = work(job);
                if let Some(bar) = bar {
                    bar.advance(&label(job));
                }
                result
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn requests_in_flight_do_not_follow_the_core_count() {
        use super::{Limits, MAX_NETWORK};
        // Waiting on a socket costs no CPU, so the number of them owes nothing to the number of
        // cores. A one-core container used to make one request at a time, which is the whole bug.
        for cores in [1, 2, 4, 8, 10, 32, 128] {
            let (limits, _) = Limits::resolve(None, cores);
            assert_eq!(limits.network, MAX_NETWORK, "{cores} cores");
            assert_eq!(limits.cpu, cores, "work still scales with cores: {cores}");
            assert!(!limits.from_env);
        }
        // Nothing here raises the ceiling: a big machine gets the same ten as a small one.
        let (big, _) = Limits::resolve(None, 128);
        let (small, _) = Limits::resolve(None, 1);
        assert_eq!(big.network, small.network);

        // And the escape hatch goes both ways, which matters most for a machine this does not suit.
        let (down, _) = Limits::resolve(Some("2"), 1);
        assert_eq!(down.network, 2, "a machine that wants fewer can ask for fewer");
        let (up, _) = Limits::resolve(Some("50"), 1);
        assert_eq!(up.network, 50, "and one core is no longer a reason to refuse more");
    }

    #[test]
    fn work_only_ever_lowers_the_number_of_requests() {
        use super::capped;
        // Fewer packages than configured: no thread is created that could only park.
        assert_eq!(capped(100, Some(50)), 50);
        // More packages than configured: the configured value is a ceiling and stays one. What the
        // network tolerates is not evidence about how much there is to do, and the big workspace is
        // the run where asking an index for more at once is least welcome.
        assert_eq!(capped(10, Some(356)), 10);
        // Before the lockfile is read there is no work count, and nothing changes.
        assert_eq!(capped(10, None), 10);
        // An empty workspace must not become "choose automatically", which is how rayon reads 0 and
        // would give a pool the size of the machine.
        assert_eq!(capped(10, Some(0)), 1);
        assert_eq!(capped(0, None), 1);
    }

    #[test]
    fn an_unusable_number_of_requests_is_said_and_clamped() {
        use super::{Limits, MAX_SANE_NETWORK, UNUSUAL_NETWORK};
        // Ordinary values pass without comment.
        for requested in [1, 10, 50, UNUSUAL_NETWORK] {
            assert_eq!(Limits::concern(requested), None, "{requested}");
        }
        // Unusual is said, and honoured: a private mirror may well take it.
        let unusual = Limits::concern(UNUSUAL_NETWORK + 1).expect("worth mentioning");
        assert!(unusual.contains("unusually high"), "{unusual}");
        let (limits, _) = Limits::resolve(Some("150"), 8);
        assert_eq!(limits.network, 150, "and is still what the run uses");

        // Past the point where an operating system refuses, it is clamped rather than attempted:
        // 10 000 threads fail after 34 seconds, which is a hang followed by a crash.
        let absurd = Limits::concern(20_000).expect("worth mentioning");
        assert!(
            absurd.contains("more threads than an operating system will give"),
            "{absurd}"
        );
        let (limits, unusable) = Limits::resolve(Some("20000"), 8);
        assert_eq!(limits.network, MAX_SANE_NETWORK);
        assert_eq!(limits.cpu, MAX_SANE_NETWORK);
        assert_eq!(unusable, None, "a clamped value is still a usable one");
    }

    use super::*;

    #[test]
    fn the_limits_are_the_variable_then_the_machine() {
        let (eight, complaint) = Limits::resolve(None, 8);
        assert_eq!(
            eight,
            Limits {
                network: MAX_NETWORK,
                cpu: 8,
                from_env: false
            }
        );
        assert_eq!(complaint, None);

        // However many cores there are, an upstream is not asked more than ten things at once.
        let (many, _) = Limits::resolve(None, 64);
        assert_eq!(many.network, MAX_NETWORK);
        assert_eq!(many.cpu, 64, "work that waits on nothing can use every core");

        // A machine that cannot say how many cores it has still runs.
        assert_eq!(Limits::resolve(None, 0).0.cpu, 1);

        let (asked, complaint) = Limits::resolve(Some(" 3 "), 64);
        assert_eq!(
            asked,
            Limits {
                network: 3,
                cpu: 3,
                from_env: true
            }
        );
        assert_eq!(complaint, None);

        // Nonsense is named and ignored: a misspelled tuning knob should not stop a run.
        for bad in ["0", "-1", "lots", "3.5"] {
            let (limits, complaint) = Limits::resolve(Some(bad), 8);
            assert!(!limits.from_env, "{bad} is not a concurrency");
            assert_eq!(complaint.as_deref(), Some(bad));
        }
        assert_eq!(
            Limits::resolve(Some("  "), 8).1,
            None,
            "an empty value is not a mistake"
        );
    }

    #[test]
    fn results_keep_job_order_and_every_job_runs_once() {
        let jobs: Vec<u64> = (0..50).collect();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let out = map(
            &jobs,
            None,
            |_| String::new(),
            |j| {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Uneven work, so a pool that handed out fixed shares would finish out of
                // order and a pool that steals would not.
                std::thread::sleep(std::time::Duration::from_micros(50 * (j % 7)));
                j * 2
            },
        );
        assert_eq!(out, jobs.iter().map(|j| j * 2).collect::<Vec<_>>());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 50);
        assert!(map(&Vec::<u8>::new(), None, |_| String::new(), |_| 0).is_empty());
    }

    #[test]
    fn a_bar_counts_every_job_exactly_once() {
        let jobs: Vec<u64> = (0..50).collect();
        let progress = crate::progress::Progress::default();
        let bar = progress.bar("jobs", jobs.len());
        let seen = std::sync::Mutex::new(Vec::new());
        map(
            &jobs,
            Some(&bar),
            |j| j.to_string(),
            |j| {
                seen.lock().expect("seen").push(*j);
                *j
            },
        );
        bar.finish();
        assert_eq!(seen.lock().expect("seen").len(), 50);
    }
}
