//! What goes over the wire (#318): connections, overlap, retries and the cache counters, checked
//! against a local server rather than by hand against the live indexes.
//!
//! These run the real binary with every upstream pointed at [`support::Server`], so they test the
//! requests the program actually issues, not a stub of the client.

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use assert_cmd::Command;
use serde_json::{Value, json};
use support::{Request, Response, Server};

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn workspace(name: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for file in ["pixi.toml", "pixi.lock"] {
        std::fs::copy(
            tests_dir().join("fixtures").join(name).join(file),
            dir.path().join(file),
        )
        .unwrap();
    }
    dir
}

/// `--report outdated` on the fixture, with every upstream this run could reach pointed at
/// `server` so nothing leaves the machine, and its own empty caches.
fn outdated(dir: &Path, server: &Server, cache: &str, extra: &[&str]) -> Command {
    let mut command = Command::cargo_bin("pixi-sbom").expect("binary builds");
    let home = dir.join("pixi-home");
    std::fs::create_dir_all(&home).unwrap();
    command
        .current_dir(dir)
        .env("PIXI_HOME", home)
        .env("PIXI_CACHE_DIR", dir.join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.join(cache))
        .env_remove("PIXI_SBOM_OFFLINE")
        .env_remove("PIXI_SBOM_CONCURRENCY")
        .env("PIXI_SBOM_PYPI_URL", format!("{}/pypi", server.url()))
        .env("PIXI_SBOM_PREFIX_INDEX_URL", format!("{}/graphql", server.url()))
        .env("PIXI_SBOM_ANACONDA_URL", server.url())
        .env("PIXI_SBOM_OSV_URL", server.url())
        .env("PIXI_SBOM_KEV_URL", format!("{}/kev.json", server.url()))
        .env("PIXI_SBOM_MAPPING_URL", format!("{}/mapping.json", server.url()))
        .env("PIXI_SBOM_SCORECARD_URL", server.url())
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--report",
            "outdated",
            "--report-format",
            "json",
        ])
        .args(extra);
    command
}

/// What prefix.dev says about one package: the installed version and a newer one, so every
/// package is behind and needs its newest release dated.
fn prefix_package(installed: &str) -> Value {
    json!({
        "versions": { "page": [ { "version": installed }, { "version": "999.0.0" } ] },
        "current": { "page": [ { "createdAt": "2025-06-01T00:00:00Z" } ] },
        "build": { "page": [ { "sha256": "00" } ] },
    })
}

/// Whether a request is a batched prefix.dev query.
fn is_batch(request: &Request) -> bool {
    request.json()["variables"].get("n0").is_some()
}

/// Whether a request is the follow-up that dates a package's newest release.
fn is_dating(request: &Request) -> bool {
    request.path == "/graphql"
        && !is_batch(request)
        && !request.json()["query"].as_str().unwrap_or("").contains("versions(")
}

/// A canned index: prefix.dev GraphQL (single, batched and dating queries) and the PyPI JSON API.
fn index(request: &Request) -> Response {
    let body = request.json();
    let variables = &body["variables"];
    if request.path == "/graphql" {
        if is_batch(request) {
            let mut data = serde_json::Map::new();
            for i in 0.. {
                let Some(installed) = variables.get(format!("v{i}")) else {
                    break;
                };
                data.insert(format!("p{i}"), prefix_package(installed.as_str().unwrap_or("")));
            }
            return Response::json(json!({ "data": data }));
        }
        if is_dating(request) {
            return Response::json(json!({
                "data": { "package": { "current": { "page": [ { "createdAt": "2026-01-01T00:00:00Z" } ] } } }
            }));
        }
        return Response::json(json!({
            "data": { "package": prefix_package(variables["v"].as_str().unwrap_or("")) }
        }));
    }
    if request.path.starts_with("/pypi/") && request.path.ends_with("/json") {
        return Response::json(json!({
            "releases": {
                "0.1.0": [ { "upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": false } ],
                "999.0.0": [ { "upload_time_iso_8601": "2026-01-01T00:00:00Z", "yanked": false } ],
            }
        }));
    }
    Response::status(404)
}

/// The report's rows, sorted by package name: everything the report says about each package,
/// including the release dates a batch has to carry through.
fn rows(stdout: &[u8]) -> Vec<Value> {
    let report: Value = serde_json::from_slice(stdout).expect("a JSON report");
    let mut rows = report["outdated"].as_array().unwrap().clone();
    rows.sort_by_key(|row| row["name"].as_str().unwrap_or("").to_string());
    rows
}

/// The `cache` log line for one service, as `(from_cache, fetched)`.
fn cache_counts(stderr: &[u8], service: &str) -> Option<(u64, u64)> {
    String::from_utf8_lossy(stderr).lines().find_map(|line| {
        let entry: Value = serde_json::from_str(line).ok()?;
        let fields = &entry["fields"];
        (fields["message"] == "cache" && fields["cache"] == service).then(|| {
            (
                fields["from_cache"].as_u64().unwrap_or(0),
                fields["fetched"].as_u64().unwrap_or(0),
            )
        })
    })
}

#[test]
fn one_agent_reuses_its_connections() {
    // #292: requests made one after another go over one connection rather than one each.
    let dir = workspace("with-pypi");
    let server = Server::start(|request, _| index(request));
    outdated(dir.path(), &server, "cache", &["--concurrency", "1"])
        .assert()
        .success();
    let requests = server.requests().len();
    assert!(requests > 5, "the run asked the index about its packages: {requests}");
    assert_eq!(
        server.connections(),
        1,
        "{requests} serial requests should share one connection"
    );
    assert!(server.requests().iter().all(|r| r.connection == 0));
}

#[test]
fn batches_respect_a_lower_concurrency() {
    // #354: batches are throttled to four at a time, but never above what --concurrency allows.
    // At 1, nothing overlaps and one connection carries everything, batches included.
    let dir = workspace("with-pypi");
    let server = Server::start(|request, _| index(request).after(Duration::from_millis(50)));
    outdated(
        dir.path(),
        &server,
        "cache",
        &["--conda-index-kind", "prefix", "--concurrency", "1"],
    )
    .assert()
    .success();
    let batches = server.requests().iter().filter(|r| is_batch(r)).count();
    assert!(batches >= 2, "enough conda packages for more than one batch: {batches}");
    assert_eq!(
        server.peak_overlap(|_| true),
        1,
        "a request overlapped another at --concurrency 1"
    );
    assert_eq!(server.connections(), 1);
}

#[test]
fn batches_and_their_follow_ups_run_in_parallel() {
    // #313: the batched queries overlap, and so do the requests that date each package's newest
    // release once the batches have answered.
    let dir = workspace("with-pypi");
    let server = Server::start(|request, _| index(request).after(Duration::from_millis(150)));
    outdated(dir.path(), &server, "cache", &["--conda-index-kind", "prefix"])
        .assert()
        .success();
    let requests = server.requests();
    let batches = requests.iter().filter(|r| is_batch(r)).count();
    assert!(requests.iter().filter(|r| is_batch(r)).all(|r| r.method == "POST"));
    assert!(batches >= 2, "enough conda packages for more than one batch: {batches}");
    assert!(
        server.peak_overlap(is_batch) >= 2,
        "the batches were asked one after another"
    );
    assert!(
        server.peak_overlap(is_dating) >= 2,
        "the follow-up datings were asked one after another"
    );
}

#[test]
fn a_batched_fetch_counts_as_a_fetch() {
    // #314: a cold run reports what it fetched, including what came back in a batch, and a warm
    // run reports it all from the cache and asks nothing.
    let dir = workspace("with-pypi");
    let server = Server::start(|request, _| index(request));
    let cold = outdated(
        dir.path(),
        &server,
        "cache",
        &["--conda-index-kind", "prefix", "--log-format", "json"],
    )
    .assert()
    .success();
    assert!(server.requests().iter().any(is_batch), "the cold run batched");
    let (from_cache, fetched) = cache_counts(&cold.get_output().stderr, "outdated").expect("a cache line");
    assert_eq!(from_cache, 0, "nothing was cached before the cold run");
    assert!(fetched > 10, "every package was fetched: {fetched}");

    let asked = server.requests().len();
    let warm = outdated(
        dir.path(),
        &server,
        "cache",
        &["--conda-index-kind", "prefix", "--log-format", "json"],
    )
    .assert()
    .success();
    assert_eq!(server.requests().len(), asked, "the warm run asked nothing");
    assert_eq!(
        cache_counts(&warm.get_output().stderr, "outdated"),
        Some((fetched, 0)),
        "the warm run answered everything from the cache"
    );
}

#[test]
fn batched_unbatched_and_partly_failed_batches_agree() {
    // #295: a batch is an optimisation, so the report must not depend on it. The same index
    // answers three ways: batches work, batches are refused, and one alias comes back null.
    let dir = workspace("with-pypi");

    let batched = Server::start(|request, _| index(request));
    let with_batches = outdated(dir.path(), &batched, "cache-batched", &["--conda-index-kind", "prefix"])
        .assert()
        .success();
    assert!(batched.requests().iter().any(is_batch));

    let refused = Server::start(|request, _| {
        if is_batch(request) {
            Response::status(400)
        } else {
            index(request)
        }
    });
    let without_batches = outdated(dir.path(), &refused, "cache-refused", &["--conda-index-kind", "prefix"])
        .assert()
        .success();

    let nulled = Server::start(|request, _| {
        let mut answer = index(request);
        if is_batch(request) && request.json()["variables"]["n1"].is_string() {
            let mut body: Value = serde_json::from_str(&answer.body).unwrap();
            body["data"]["p1"] = Value::Null;
            body["errors"] = json!([{ "message": "scripted failure", "path": ["p1"] }]);
            answer.body = body.to_string();
        }
        answer
    });
    let partly = outdated(dir.path(), &nulled, "cache-nulled", &["--conda-index-kind", "prefix"])
        .assert()
        .success();

    let expected = rows(&with_batches.get_output().stdout);
    assert!(expected.len() > 10, "{expected:?}");
    assert_eq!(rows(&without_batches.get_output().stdout), expected);
    assert_eq!(rows(&partly.get_output().stdout), expected);

    // The package whose alias came back null was asked about on its own.
    let first_batch = nulled.requests().into_iter().find(is_batch).unwrap().json();
    let dropped = first_batch["variables"]["n1"].as_str().unwrap().to_string();
    assert!(
        nulled
            .requests()
            .iter()
            .any(|r| !is_batch(r) && !is_dating(r) && r.json()["variables"]["n"] == dropped.as_str()),
        "{dropped} was asked about again on its own"
    );
}

#[test]
fn a_rate_limit_is_waited_out_and_a_refusal_is_not() {
    // #298: 429 and 503 are retried until the upstream answers; 403 is policy and asked once.
    let dir = workspace("with-pypi");
    let server = Server::start(|request, earlier| match request.path.as_str() {
        "/pypi/urllib3/json" if earlier < 2 => Response::status(if earlier == 0 { 429 } else { 503 }),
        "/pypi/requests/json" => Response::status(403),
        _ => index(request),
    });
    let assert = outdated(dir.path(), &server, "cache", &[]).assert().success();
    let report: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();

    let asked = |path: &str| server.requests().iter().filter(|r| r.path == path).count();
    assert_eq!(asked("/pypi/urllib3/json"), 3, "two refusals, then the answer");
    let urllib3 = report["outdated"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == "urllib3")
        .expect("urllib3 was answered in the end");
    assert_eq!(urllib3["latest"], "999.0.0");

    assert_eq!(asked("/pypi/requests/json"), 1, "a 403 is not retried");
}
