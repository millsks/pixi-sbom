//! A tiny bounded thread pool for the enrichment fetches: no async runtime, no dependency.

use std::sync::Mutex;

/// Run `work` over `jobs` on up to `concurrency` threads; results come back in job order.
pub fn map<J: Sync, R: Send>(jobs: &[J], concurrency: usize, work: impl Fn(&J) -> R + Sync) -> Vec<R> {
    if jobs.is_empty() {
        return Vec::new();
    }
    let next = Mutex::new(0usize);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..jobs.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..concurrency.clamp(1, jobs.len()) {
            scope.spawn(|| {
                loop {
                    let i = {
                        let mut next = next.lock().expect("job counter");
                        let i = *next;
                        *next += 1;
                        i
                    };
                    let Some(job) = jobs.get(i) else { break };
                    let result = work(job);
                    results.lock().expect("results")[i] = Some(result);
                }
            });
        }
    });
    results
        .into_inner()
        .expect("results")
        .into_iter()
        .map(|r| r.expect("every job produces a result"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_keep_job_order_and_every_job_runs_once() {
        let jobs: Vec<u64> = (0..50).collect();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let out = map(&jobs, 8, |j| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_micros(50 * (j % 7)));
            j * 2
        });
        assert_eq!(out, jobs.iter().map(|j| j * 2).collect::<Vec<_>>());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 50);
        assert!(map(&Vec::<u8>::new(), 4, |_| 0).is_empty());
        assert_eq!(map(&[1], 0, |j| *j), [1], "concurrency is clamped to at least one");
    }
}
