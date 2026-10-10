//! `--format github`: GitHub's dependency submission snapshot (#456), which the dependency graph
//! and Dependabot alerts read. It is not an SBOM format, so `--spec-version` does not apply.
//!
//! The snapshot names the commit and workflow run it describes. Those come from the variables
//! GitHub Actions sets (`GITHUB_SHA`, `GITHUB_REF`, `GITHUB_RUN_ID`, `GITHUB_WORKFLOW`,
//! `GITHUB_JOB`); outside Actions they are absent, and the API refuses a snapshot without a sha
//! and a ref until they are set.
//!
//! A conda package that has a PyPI identity is submitted by it, whichever purl is primary in the
//! SBOM: GitHub's advisory database has PyPI advisories and no conda ones, so that is the identity
//! an alert can come from.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::model::Sbom;
use crate::scope::Scope;

use super::WriteContext;

/// Where the detector links to.
const DETECTOR_URL: &str = "https://github.com/millsks/pixi-sbom";

#[derive(Debug, Serialize)]
pub struct Snapshot {
    version: u32,
    job: Job,
    sha: Option<String>,
    #[serde(rename = "ref")]
    git_ref: Option<String>,
    detector: Detector,
    metadata: BTreeMap<&'static str, String>,
    scanned: String,
    manifests: BTreeMap<String, Manifest>,
}

#[derive(Debug, Serialize)]
struct Job {
    correlator: String,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    html_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct Detector {
    name: &'static str,
    version: String,
    url: &'static str,
}

#[derive(Debug, Serialize)]
struct Manifest {
    name: String,
    file: File,
    resolved: BTreeMap<String, Resolved>,
}

#[derive(Debug, Serialize)]
struct File {
    source_location: String,
}

#[derive(Debug, Serialize)]
struct Resolved {
    package_url: String,
    relationship: &'static str,
    scope: &'static str,
    dependencies: Vec<String>,
}

/// A purl without its qualifiers and subpath: the key a package is filed under, and how
/// another package's `dependencies` name it.
fn key(purl: &str) -> &str {
    purl.split(['?', '#']).next().unwrap_or(purl)
}

/// The identity GitHub can raise an alert for: the PyPI purl when the package has one.
fn submitted_purl(package: &crate::model::Package) -> &str {
    std::iter::once(&package.purl)
        .chain(&package.extra_purls)
        .find(|purl| purl.starts_with("pkg:pypi/"))
        .unwrap_or(&package.purl)
}

/// The snapshot for `sbom`, reading the run's identity through `env` (`std::env::var` in a run).
pub fn document(sbom: &Sbom, ctx: &WriteContext, env: &dyn Fn(&str) -> Option<String>) -> Snapshot {
    let direct: BTreeSet<&str> = super::top_level_ids(sbom).into_iter().collect();
    let keys: BTreeMap<&str, &str> = sbom
        .packages
        .iter()
        .filter(|p| p.purl.starts_with("pkg:"))
        .map(|p| (p.id.as_str(), key(submitted_purl(p))))
        .collect();
    let mut resolved = BTreeMap::new();
    for package in &sbom.packages {
        let Some(&name) = keys.get(package.id.as_str()) else {
            continue;
        };
        // A vendored copy has the same identity as an installed one; the first is enough.
        resolved.entry(name.to_string()).or_insert_with(|| Resolved {
            package_url: submitted_purl(package).to_string(),
            relationship: if direct.contains(package.id.as_str()) {
                "direct"
            } else {
                "indirect"
            },
            scope: match sbom.scopes.get(&package.id) {
                Some(Scope::Development) => "development",
                _ => "runtime",
            },
            dependencies: package
                .dependencies
                .iter()
                .filter_map(|id| keys.get(id.as_str()).map(|k| k.to_string()))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        });
    }
    let source = sbom.prefix.clone().unwrap_or_else(|| sbom.lockfile.clone());
    let label = [sbom.environment.as_str(), sbom.platform.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    // One snapshot per environment and platform, so each needs its own correlator: a later
    // submission with the same one replaces the earlier.
    let correlator = [env("GITHUB_WORKFLOW"), env("GITHUB_JOB")]
        .into_iter()
        .flatten()
        .chain([format!("pixi-sbom {label}")])
        .collect::<Vec<_>>()
        .join(" ");
    let html_url = match (env("GITHUB_SERVER_URL"), env("GITHUB_REPOSITORY"), env("GITHUB_RUN_ID")) {
        (Some(server), Some(repository), Some(run)) => Some(format!("{server}/{repository}/actions/runs/{run}")),
        _ => None,
    };
    let mut metadata = BTreeMap::new();
    if !sbom.environment.is_empty() {
        metadata.insert("pixi:environment", sbom.environment.clone());
    }
    if !sbom.platform.is_empty() {
        metadata.insert("pixi:platform", sbom.platform.clone());
    }
    Snapshot {
        version: 0,
        job: Job {
            correlator,
            id: env("GITHUB_RUN_ID").unwrap_or_default(),
            html_url,
        },
        sha: env("GITHUB_SHA"),
        git_ref: env("GITHUB_REF"),
        detector: Detector {
            name: "pixi-sbom",
            version: ctx.tool_version.clone(),
            url: DETECTOR_URL,
        },
        metadata,
        scanned: ctx.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        manifests: BTreeMap::from([(
            source.clone(),
            Manifest {
                name: source.clone(),
                file: File {
                    source_location: source,
                },
                resolved,
            },
        )]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::{fixed_context, sample_sbom};

    fn actions(name: &str) -> Option<String> {
        Some(
            match name {
                "GITHUB_SHA" => "0123456789abcdef0123456789abcdef01234567",
                "GITHUB_REF" => "refs/heads/main",
                "GITHUB_RUN_ID" => "42",
                "GITHUB_WORKFLOW" => "sbom",
                "GITHUB_JOB" => "submit",
                "GITHUB_SERVER_URL" => "https://github.com",
                "GITHUB_REPOSITORY" => "owner/repo",
                _ => return None,
            }
            .to_string(),
        )
    }

    #[test]
    fn a_snapshot_names_the_run_and_files_each_package_once() {
        let sbom = sample_sbom();
        let value = serde_json::to_value(document(&sbom, &fixed_context(), &actions)).unwrap();
        assert_eq!(value["version"], 0);
        assert_eq!(value["sha"], "0123456789abcdef0123456789abcdef01234567");
        assert_eq!(value["ref"], "refs/heads/main");
        assert_eq!(value["job"]["id"], "42");
        assert_eq!(
            value["job"]["html_url"],
            "https://github.com/owner/repo/actions/runs/42"
        );
        assert!(
            value["job"]["correlator"]
                .as_str()
                .unwrap()
                .starts_with("sbom submit pixi-sbom ")
        );
        assert_eq!(value["detector"]["name"], "pixi-sbom");
        let manifests = value["manifests"].as_object().unwrap();
        assert_eq!(manifests.len(), 1);
        let resolved = manifests.values().next().unwrap()["resolved"].as_object().unwrap();
        for (name, entry) in resolved {
            assert_eq!(name, key(entry["package_url"].as_str().unwrap()), "keyed by purl");
            assert!(["direct", "indirect"].contains(&entry["relationship"].as_str().unwrap()));
            for dependency in entry["dependencies"].as_array().unwrap() {
                assert!(resolved.contains_key(dependency.as_str().unwrap()), "{dependency}");
            }
        }
    }

    #[test]
    fn a_conda_package_is_submitted_by_its_pypi_identity() {
        let mut sbom = sample_sbom();
        let package = &mut sbom.packages[0];
        package.purl = "pkg:conda/django@3.2.12?channel=conda-forge".into();
        package.extra_purls = vec!["pkg:pypi/django@3.2.12".into()];
        let id = package.id.clone();
        let snapshot = document(&sbom, &fixed_context(), &actions);
        let resolved = &snapshot.manifests.values().next().unwrap().resolved;
        assert_eq!(resolved["pkg:pypi/django@3.2.12"].package_url, "pkg:pypi/django@3.2.12");
        assert!(!resolved.contains_key("pkg:conda/django@3.2.12"), "{id}");
    }

    #[test]
    fn outside_actions_the_run_identity_is_absent() {
        let snapshot = document(&sample_sbom(), &fixed_context(), &|_| None);
        assert_eq!(snapshot.sha, None);
        assert_eq!(snapshot.git_ref, None);
        assert_eq!(snapshot.job.id, "");
        assert!(snapshot.job.html_url.is_none());
        assert!(snapshot.job.correlator.starts_with("pixi-sbom "));
    }

    #[test]
    fn development_scope_and_direct_relationships_come_from_the_model() {
        let mut sbom = sample_sbom();
        let id = sbom.packages[0].id.clone();
        sbom.scopes.insert(id.clone(), Scope::Development);
        let snapshot = document(&sbom, &fixed_context(), &actions);
        let resolved = &snapshot.manifests.values().next().unwrap().resolved;
        let entry = resolved
            .values()
            .find(|r| r.package_url == submitted_purl(&sbom.packages[0]))
            .unwrap();
        assert_eq!(entry.scope, "development");
        let direct: Vec<_> = resolved.values().filter(|r| r.relationship == "direct").collect();
        assert!(
            !direct.is_empty() && direct.len() < resolved.len(),
            "some direct, some not"
        );
    }
}
