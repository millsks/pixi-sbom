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
    /// `PIXI_SBOM_CONCURRENCY` if it is a positive number, else the machine: one thread per
    /// core for work, and no more than [`MAX_NETWORK`] requests in flight.
    ///
    /// A value that is not a positive number is ignored rather than fatal, with the text
    /// returned so the caller can say so once logging exists. Refusing to run over a
    /// misspelled tuning knob would be the wrong trade.
    pub fn resolve(env: Option<&str>, cores: usize) -> (Self, Option<String>) {
        let cores = cores.max(1);
        let default = Self {
            network: cores.min(MAX_NETWORK),
            cpu: cores,
            from_env: false,
        };
        let Some(value) = env.map(str::trim).filter(|value| !value.is_empty()) else {
            return (default, None);
        };
        match value.parse::<usize>() {
            Ok(requested) if requested > 0 => (
                Self {
                    network: requested,
                    cpu: requested,
                    from_env: true,
                },
                None,
            ),
            _ => (default, Some(value.to_string())),
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
static NETWORK_POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

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

/// How many requests may be in flight at once.
pub fn network() -> usize {
    limits().network
}

fn network_pool() -> &'static rayon::ThreadPool {
    NETWORK_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(limits().network)
            .thread_name(|index| format!("pixi-sbom-net-{index}"))
            .build()
            .expect("a thread pool of a positive size")
    })
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
    network_pool().install(|| {
        jobs.par_iter()
            .map(|job| {
                let result = work(job);
                if let Some(bar) = bar {
                    bar.advance(&label(job));
                }
                result
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limits_are_the_variable_then_the_machine() {
        let (eight, complaint) = Limits::resolve(None, 8);
        assert_eq!(
            eight,
            Limits {
                network: 8,
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
