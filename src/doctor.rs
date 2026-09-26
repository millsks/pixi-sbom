//! `--doctor`: ask every upstream whether it answers, and say what the run is set up to do.
//!
//! When a report comes back empty on one network and full on another, the questions are which
//! service could not be reached, whether it was DNS, the proxy, the TLS chain or an HTTP
//! status, and whether a cache is hiding the answer. Answering that used to mean reading the
//! source for the URLs and reaching for `curl`.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::http;

/// What one probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The service answered, with its status and how long it took.
    Answered { status: u16, took: Duration },
    /// The request failed, with the whole error chain.
    Failed(String),
    /// Nothing was asked, because the run is offline.
    Skipped,
}

impl Outcome {
    /// Whether this counts as a working upstream.
    pub fn is_ok(&self) -> bool {
        !matches!(self, Outcome::Failed(_))
    }

    /// The cell the table shows. A status of 400 or more still means the host answered — the
    /// probe asks a base address, which is often not a document — so it is reported as
    /// reachable rather than as success or failure.
    pub fn text(&self) -> String {
        match self {
            Outcome::Answered { status, took } if *status < 400 => {
                format!("ok {status}, {} ms", took.as_millis())
            }
            Outcome::Answered { status, took } => {
                format!("reachable, HTTP {status}, {} ms", took.as_millis())
            }
            Outcome::Failed(cause) => format!("failed: {cause}"),
            Outcome::Skipped => "skipped, offline".to_string(),
        }
    }
}

/// One upstream, probed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub service: String,
    pub url: String,
    pub source: String,
    pub outcome: Outcome,
}

/// What a cache directory holds, for the part of the report that answers "is this only working
/// because something is cached".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheReport {
    pub name: String,
    pub entries: usize,
    /// How old the newest entry is; `None` when there are none.
    pub newest: Option<Duration>,
}

/// Ask each service for something small and cheap, in the order they were given.
///
/// `probe` is the request; it is a parameter so the tests do not need a network.
pub fn probes(configuration: &http::Configuration, probe: &dyn Fn(&str) -> Result<u16, String>) -> Vec<Probe> {
    configuration
        .services
        .iter()
        // A per-package download has no one address to ask about.
        .filter(|service| service.url.starts_with("http"))
        .map(|service| {
            let outcome = if configuration.offline {
                Outcome::Skipped
            } else {
                let started = Instant::now();
                match probe(&service.url) {
                    Ok(status) => Outcome::Answered {
                        status,
                        took: started.elapsed(),
                    },
                    Err(cause) => Outcome::Failed(cause),
                }
            };
            Probe {
                service: service.name.to_string(),
                url: service.url.clone(),
                source: service.source().to_string(),
                outcome,
            }
        })
        .collect()
}

/// A real probe: ask for the document and read nothing but its status.
pub fn request(url: &str) -> Result<u16, String> {
    // A few kilobytes is enough to know the answer came from the service rather than from a
    // captive portal, and small enough to be polite.
    classify(http::get_text(url, 8 * 1024))
}

/// What a probe's response says about the host: a status, or the transport failure.
fn classify(response: Result<String, Box<ureq::Error>>) -> Result<u16, String> {
    match response {
        Ok(_) => Ok(200),
        Err(err) => match err.as_ref() {
            // A status is an answer: the host is reachable and speaking HTTP, which is what the
            // probe is for. Only a transport failure is a failure here.
            ureq::Error::StatusCode(code) => Ok(*code),
            // A body past the read cap came after a successful status; the feed is just large.
            ureq::Error::BodyExceedsLimit(_) => Ok(200),
            other => Err(http::error_chain(other)),
        },
    }
}

/// What each cache directory holds, newest first entry age.
pub fn caches(cache_dir: &Path, now: std::time::SystemTime) -> Vec<CacheReport> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(cache_dir) else {
        return out;
    };
    let mut dirs: Vec<_> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|p| p.is_dir())
        .collect();
    dirs.sort();
    for dir in dirs {
        let mut count = 0;
        let mut newest: Option<Duration> = None;
        walk(&dir, now, &mut count, &mut newest);
        out.push(CacheReport {
            name: dir
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            entries: count,
            newest,
        });
    }
    out
}

fn walk(dir: &Path, now: std::time::SystemTime, count: &mut usize, newest: &mut Option<Duration>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, now, count, newest);
            continue;
        }
        *count += 1;
        if let Some(age) = crate::cache::age(&path, now) {
            *newest = Some(newest.map_or(age, |current: Duration| current.min(age)));
        }
    }
}

/// How long ago, in words a person reads rather than seconds.
pub fn ago(age: Duration) -> String {
    let seconds = age.as_secs();
    match seconds {
        0..=90 => format!("{seconds}s"),
        91..=5400 => format!("{}m", seconds / 60),
        5401..=172_800 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configuration(offline: bool) -> http::Configuration {
        let mut configuration = http::Configuration::resolve(
            vec![
                http::Service::fixed("OSV", "https://api.osv.dev"),
                http::Service::fixed("package archives", "each package's own download URL"),
            ],
            std::path::PathBuf::from("/nowhere"),
            &http::TlsRoots::Platform,
        );
        configuration.offline = offline;
        configuration
    }

    #[test]
    fn a_status_is_an_answer_and_a_transport_failure_is_not() {
        let answered = probes(&configuration(false), &|url| {
            assert_eq!(url, "https://api.osv.dev");
            Ok(404)
        });
        assert_eq!(answered.len(), 1, "the per-package downloads have no address to ask");
        assert!(answered[0].outcome.is_ok(), "404 means the host answered");
        assert!(
            answered[0].outcome.text().starts_with("reachable, HTTP 404"),
            "a 404 on a base address is reachability, not success: {}",
            answered[0].outcome.text()
        );
        let ok = probes(&configuration(false), &|_| Ok(200));
        assert!(ok[0].outcome.text().starts_with("ok 200"));

        let failed = probes(&configuration(false), &|_| {
            Err("io: invalid peer certificate: UnknownIssuer".to_string())
        });
        assert!(!failed[0].outcome.is_ok());
        assert_eq!(
            failed[0].outcome.text(),
            "failed: io: invalid peer certificate: UnknownIssuer"
        );
    }

    #[test]
    fn a_body_past_the_read_cap_is_an_answer() {
        assert_eq!(classify(Ok(String::new())), Ok(200));
        assert_eq!(classify(Err(Box::new(ureq::Error::StatusCode(404)))), Ok(404));
        assert_eq!(
            classify(Err(Box::new(ureq::Error::BodyExceedsLimit(8192)))),
            Ok(200),
            "a large feed such as CISA KEV answered; it is not unreachable"
        );
        assert!(
            classify(Err(Box::new(ureq::Error::HostNotFound)))
                .unwrap_err()
                .contains("host not found")
        );
    }

    #[test]
    fn offline_asks_nothing_and_fails_nothing() {
        let skipped = probes(&configuration(true), &|_| panic!("offline must not ask"));
        assert_eq!(skipped[0].outcome, Outcome::Skipped);
        assert!(skipped[0].outcome.is_ok(), "not asking is not a failure");
    }

    #[test]
    fn the_caches_are_counted_with_the_age_of_the_newest_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("osv").join("queries")).unwrap();
        std::fs::write(dir.path().join("osv").join("queries").join("a.json"), "{}").unwrap();
        std::fs::write(dir.path().join("osv").join("b.json"), "{}").unwrap();
        std::fs::create_dir_all(dir.path().join("empty")).unwrap();

        let reports = caches(dir.path(), std::time::SystemTime::now());
        let osv = reports.iter().find(|report| report.name == "osv").unwrap();
        assert_eq!(osv.entries, 2, "nested entries count too");
        assert!(osv.newest.is_some());
        let empty = reports.iter().find(|report| report.name == "empty").unwrap();
        assert_eq!(empty.entries, 0);
        assert_eq!(empty.newest, None);
        // A directory that is not there is not an error.
        assert!(caches(&dir.path().join("nope"), std::time::SystemTime::now()).is_empty());
    }

    #[test]
    fn an_age_reads_as_a_person_would_say_it() {
        assert_eq!(ago(Duration::from_secs(5)), "5s");
        assert_eq!(ago(Duration::from_secs(600)), "10m");
        assert_eq!(ago(Duration::from_secs(7200)), "2h");
        assert_eq!(ago(Duration::from_secs(5 * 86_400)), "5d");
    }
}
