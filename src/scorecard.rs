//! `--scorecard`: what the OpenSSF Scorecard says about each package's repository.
//!
//! Vulnerabilities and licenses answer two supply-chain questions; "is this dependency
//! maintained, reviewed, signed, pinned?" is the third, and nothing in a lockfile speaks to
//! it. `api.securityscorecards.dev` answers it for a repository with an aggregate out of ten
//! and the checks behind it, and `--fetch-licenses` has already collected the repository URLs.
//!
//! Only repositories the service knows are scored: a package without a repository URL, or one
//! hosted somewhere the service does not cover, is reported as unknown and never fails a gate.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use crate::http;
use crate::model::Sbom;

/// Where scores are looked up; `PIXI_SBOM_SCORECARD_URL` overrides it.
pub const DEFAULT_URL: &str = "https://api.securityscorecards.dev";

/// Environment variable naming the Scorecard API base.
pub const SCORECARD_URL_ENV: &str = "PIXI_SBOM_SCORECARD_URL";

/// The aggregate, out of ten.
pub const SCORE_PROPERTY: &str = "pixi:scorecard";
/// When the service last scored the repository (`YYYY-MM-DD`).
pub const DATE_PROPERTY: &str = "pixi:scorecard-date";
/// Prefix of the per-check properties, e.g. `pixi:scorecard-check-Signed-Releases`.
pub const CHECK_PROPERTY_PREFIX: &str = "pixi:scorecard-check-";

/// A repository is scored weekly at most, so a week-old answer is the current one.
const CACHE_MAX_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Largest response accepted, in bytes.
const MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Lookups in flight at once.
const CONCURRENCY: usize = 10;

/// The Scorecard API base from the environment or the default.
pub fn url() -> String {
    std::env::var(SCORECARD_URL_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_URL.to_string())
}

/// One check of a scorecard.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Check {
    pub name: String,
    /// Out of ten; `-1` means the check did not apply.
    pub score: f64,
    #[serde(default)]
    pub reason: Option<String>,
}

/// What the service says about one repository.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Scorecard {
    /// The aggregate, out of ten.
    pub score: f64,
    /// When it was computed, as the service reports it.
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub checks: Vec<Check>,
}

impl Scorecard {
    /// The checks that scored below `min`, worst first. Checks that did not apply (a negative
    /// score) are not failures.
    pub fn below(&self, min: f64) -> Vec<&Check> {
        let mut below: Vec<&Check> = self
            .checks
            .iter()
            .filter(|check| check.score >= 0.0 && check.score < min)
            .collect();
        below.sort_by(|a, b| a.score.total_cmp(&b.score).then_with(|| a.name.cmp(&b.name)));
        below
    }
}

/// Counts from one pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Packages the service scored.
    pub scored: usize,
    /// Packages with no repository the service covers, or none at all.
    pub unknown: usize,
    /// Lookups that failed (the network, or a response that made no sense).
    pub failed: usize,
}

/// The `<host>/<org>/<repo>` path the service keys on, for the repository URLs it covers.
pub fn project(repository: &str) -> Option<String> {
    let url = repository.trim().trim_end_matches('/');
    let rest = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .trim_start_matches("www.");
    let (host, path) = rest.split_once('/')?;
    // Only the forges the service covers; anything else has no scorecard to fetch.
    let host = match host.split_once('@') {
        // `git@github.com:org/repo` style remotes.
        Some((_, host)) => host,
        None => host,
    };
    if !matches!(host, "github.com" | "gitlab.com") {
        return None;
    }
    let mut segments = path.split('/').filter(|s| !s.is_empty());
    let org = segments.next()?;
    let repo = segments.next()?.trim_end_matches(".git");
    (!org.is_empty() && !repo.is_empty()).then(|| format!("{host}/{org}/{repo}"))
}

/// Where the scores are looked up and cached.
#[derive(Debug)]
pub struct Lookup<'a> {
    pub url: &'a str,
    pub cache_dir: &'a Path,
}

#[derive(Debug)]
struct Job {
    index: usize,
    display_name: String,
    project: String,
    url: String,
    cache_file: PathBuf,
}

impl Lookup<'_> {
    /// Record what the service says on every package with a repository it covers.
    pub fn run(&self, sbom: &mut Sbom, min: f64, progress: crate::progress::Progress) -> Outcome {
        self.run_with(
            sbom,
            min,
            &|url| http::get_text(url, MAX_BYTES),
            SystemTime::now(),
            progress,
        )
    }

    fn run_with(
        &self,
        sbom: &mut Sbom,
        min: f64,
        fetch: &(dyn Fn(&str) -> Result<String, Box<ureq::Error>> + Sync),
        now: SystemTime,
        progress: crate::progress::Progress,
    ) -> Outcome {
        let mut outcome = Outcome::default();
        let mut jobs = Vec::new();
        for (index, package) in sbom.packages.iter().enumerate() {
            match package.repository.as_deref().and_then(project) {
                Some(project) => jobs.push(Job {
                    index,
                    display_name: package.name.clone(),
                    url: format!("{}/projects/{project}", self.url.trim_end_matches('/')),
                    cache_file: self
                        .cache_dir
                        .join("scorecard")
                        .join(format!("{}.json", project.replace('/', "-"))),
                    project,
                }),
                None => outcome.unknown += 1,
            }
        }

        let bar = progress.bar("repositories", jobs.len());
        let answers = crate::parallel::map(
            &jobs,
            CONCURRENCY,
            Some(&bar),
            |job| job.display_name.clone(),
            |job| self.scorecard(job, fetch, now),
        );
        bar.finish();

        for (job, answer) in jobs.iter().zip(answers) {
            let Some(card) = answer else {
                outcome.failed += 1;
                continue;
            };
            outcome.scored += 1;
            let package = &mut sbom.packages[job.index];
            package
                .properties
                .insert(SCORE_PROPERTY.to_string(), format!("{:.1}", card.score));
            if let Some(date) = &card.date {
                package.properties.insert(DATE_PROPERTY.to_string(), date.clone());
            }
            for check in card.below(min) {
                package.properties.insert(
                    format!("{CHECK_PROPERTY_PREFIX}{}", check.name),
                    format!("{:.1}", check.score),
                );
            }
        }
        outcome
    }

    /// One scorecard, from the cache while it is young enough (or offline), else fetched.
    fn scorecard(
        &self,
        job: &Job,
        fetch: &(dyn Fn(&str) -> Result<String, Box<ureq::Error>> + Sync),
        now: SystemTime,
    ) -> Option<Scorecard> {
        let cached = std::fs::read_to_string(&job.cache_file).ok();
        let age = std::fs::metadata(&job.cache_file)
            .and_then(|meta| meta.modified())
            .ok()
            .map(|modified| now.duration_since(modified).unwrap_or(Duration::ZERO));
        let text = match (&cached, age) {
            (Some(text), Some(age)) if age <= CACHE_MAX_AGE || http::offline() => text.clone(),
            _ => match fetch(&job.url) {
                Ok(text) => {
                    if let Err(err) = job
                        .cache_file
                        .parent()
                        .map_or(Ok(()), std::fs::create_dir_all)
                        .and_then(|()| std::fs::write(&job.cache_file, &text))
                    {
                        tracing::warn!(path = %job.cache_file.display(), %err, "cannot cache the scorecard");
                    }
                    text
                }
                Err(err) => {
                    // A repository the service has never scored answers 404; that is an
                    // answer, not a failure of the run.
                    tracing::debug!(
                        package = %job.display_name,
                        project = %job.project,
                        cause = crate::http::error_chain(err.as_ref()),
                        "no scorecard"
                    );
                    cached?
                }
            },
        };
        match serde_json::from_str::<Scorecard>(&text) {
            Ok(card) => Some(card),
            Err(err) => {
                tracing::warn!(package = %job.display_name, %err, "cannot read the scorecard");
                None
            }
        }
    }
}

/// The packages that scored below `min`, as `name (score)`, worst first.
pub fn below(sbom: &Sbom, min: f64) -> Vec<String> {
    let mut low: Vec<(f64, String)> = sbom
        .packages
        .iter()
        .filter_map(|p| {
            let score: f64 = p.properties.get(SCORE_PROPERTY)?.parse().ok()?;
            (score < min).then(|| (score, format!("{} ({score:.1})", p.name)))
        })
        .collect();
    low.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    low.into_iter().map(|(_, text)| text).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use crate::progress::Progress;

    const CARD: &str = r#"{
        "date": "2026-09-01",
        "repo": {"name": "github.com/madler/zlib"},
        "score": 4.2,
        "checks": [
            {"name": "Maintained", "score": 10, "reason": "30 commits out of 30"},
            {"name": "Signed-Releases", "score": 0, "reason": "no releases found"},
            {"name": "Pinned-Dependencies", "score": 3, "reason": "dependency not pinned"},
            {"name": "Branch-Protection", "score": -1, "reason": "no data"}
        ]
    }"#;

    #[test]
    fn the_project_path_is_only_for_the_forges_the_service_covers() {
        for (url, expected) in [
            ("https://github.com/madler/zlib", Some("github.com/madler/zlib")),
            ("https://github.com/madler/zlib.git", Some("github.com/madler/zlib")),
            ("http://www.github.com/madler/zlib/", Some("github.com/madler/zlib")),
            (
                "https://github.com/madler/zlib/tree/develop",
                Some("github.com/madler/zlib"),
            ),
            ("git@github.com:madler/zlib.git", None),
            ("https://gitlab.com/group/project", Some("gitlab.com/group/project")),
            ("https://bitbucket.org/team/repo", None),
            ("https://example.org/", None),
            ("https://github.com/madler", None),
            ("not a url", None),
        ] {
            assert_eq!(project(url).as_deref(), expected, "{url}");
        }
    }

    #[test]
    fn the_checks_below_a_threshold_come_worst_first_and_skip_the_ones_that_did_not_apply() {
        let card: Scorecard = serde_json::from_str(CARD).unwrap();
        assert_eq!(card.score, 4.2);
        assert_eq!(card.date.as_deref(), Some("2026-09-01"));
        let below: Vec<(&str, f64)> = card.below(5.0).iter().map(|c| (c.name.as_str(), c.score)).collect();
        assert_eq!(below, [("Signed-Releases", 0.0), ("Pinned-Dependencies", 3.0)]);
        assert!(card.below(0.0).is_empty(), "nothing is below zero");
        assert_eq!(
            card.below(10.0).len(),
            2,
            "a perfect check is not below ten, and the -1 check never counts"
        );
    }

    /// The sample with a repository on `libzlib` and nothing on the rest.
    fn sbom_with_repository() -> Sbom {
        let mut sbom = sample_sbom();
        for package in &mut sbom.packages {
            package.repository = (package.name == "libzlib").then(|| "https://github.com/madler/zlib".to_string());
        }
        sbom
    }

    #[test]
    fn scores_and_failing_checks_are_recorded_on_the_package() {
        let dir = tempfile::tempdir().unwrap();
        let lookup = Lookup {
            url: "https://scorecard.example",
            cache_dir: dir.path(),
        };
        let mut sbom = sbom_with_repository();
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let fetch = |url: &str| {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(url, "https://scorecard.example/projects/github.com/madler/zlib");
            Ok(CARD.to_string())
        };
        let outcome = lookup.run_with(&mut sbom, 5.0, &fetch, SystemTime::now(), Progress::default());
        assert_eq!(
            outcome,
            Outcome {
                scored: 1,
                unknown: 3,
                failed: 0
            }
        );
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);

        let libzlib = sbom.packages.iter().find(|p| p.name == "libzlib").unwrap();
        assert_eq!(libzlib.properties[SCORE_PROPERTY], "4.2");
        assert_eq!(libzlib.properties[DATE_PROPERTY], "2026-09-01");
        assert_eq!(
            libzlib.properties[&format!("{CHECK_PROPERTY_PREFIX}Signed-Releases")],
            "0.0"
        );
        assert!(
            !libzlib
                .properties
                .contains_key(&format!("{CHECK_PROPERTY_PREFIX}Maintained")),
            "a check that passed is not a property"
        );
        assert!(
            !libzlib
                .properties
                .contains_key(&format!("{CHECK_PROPERTY_PREFIX}Branch-Protection")),
            "and neither is one that did not apply"
        );
        assert_eq!(below(&sbom, 5.0), ["libzlib (4.2)"]);
        assert!(below(&sbom, 4.0).is_empty(), "the gate only fires below its own line");

        // The answer is cached for a week, so a second run asks nothing.
        let mut again = sbom_with_repository();
        let outcome = lookup.run_with(
            &mut again,
            5.0,
            &|_| panic!("the cache should have answered"),
            SystemTime::now(),
            Progress::default(),
        );
        assert_eq!(outcome.scored, 1);
    }

    #[test]
    fn a_repository_the_service_does_not_know_is_not_a_failure_of_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let lookup = Lookup {
            url: "https://scorecard.example",
            cache_dir: dir.path(),
        };
        let mut sbom = sbom_with_repository();
        let outcome = lookup.run_with(
            &mut sbom,
            5.0,
            // The service answers 404 for a repository it has never scored.
            &|_| Err(Box::new(ureq::Error::StatusCode(404))),
            SystemTime::now(),
            Progress::default(),
        );
        assert_eq!(
            outcome,
            Outcome {
                scored: 0,
                unknown: 3,
                failed: 1
            }
        );
        assert!(sbom.packages.iter().all(|p| !p.properties.contains_key(SCORE_PROPERTY)));
        assert!(below(&sbom, 10.0).is_empty(), "an unscored package never fails");

        // A response that is not a scorecard is a failure of that lookup, not of the run.
        let mut sbom = sbom_with_repository();
        let outcome = lookup.run_with(
            &mut sbom,
            5.0,
            &|_| Ok("<html>not json</html>".to_string()),
            SystemTime::now(),
            Progress::default(),
        );
        assert_eq!(outcome.failed, 1);
    }
}
