//! Every report, `--explain` and every gate on every input kind (#344), with no live network.
//!
//! Each reader has its own tests for the document it builds. What they cannot show is a reader
//! that leaves out a field some report depends on: that shows up as an empty column or a gate
//! that never fires, not as a failure. So every input runs every report against one local
//! upstream that answers for any package, and each cell of the grid is reduced to a stable
//! outcome — the exit code and how many rows the report has, or the diagnostic it gave instead.
//! The whole grid is one snapshot: a reader or report that changes what it can do changes the
//! table, and the table is the "what works with which input" page in the docs.

// Shared with network.rs, which uses the parts this suite does not (timing, connections).
#[allow(dead_code)]
mod support;

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::{Value, json};
use support::{Request, Response, Server};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The upstream every service is pointed at. Every PyPI package has one critical advisory whose
/// CVE is in the KEV catalog, a newer release, a license, a repository and a scorecard; `six` is
/// yanked. Conda packages get nothing from OSV (it has no conda ecosystem) and their versions
/// from the prefix.dev answer.
fn upstream(request: &Request) -> Response {
    let path = request.path.as_str();
    let pypi_name = |purl: &str| {
        purl.strip_prefix("pkg:pypi/")
            .map(|rest| rest.split('@').next().unwrap_or("").to_string())
    };
    if path == "/v1/querybatch" {
        let results: Vec<Value> = request.json()["queries"]
            .as_array()
            .into_iter()
            .flatten()
            .map(
                |query| match pypi_name(query["package"]["purl"].as_str().unwrap_or("")) {
                    Some(name) => {
                        json!({ "vulns": [ { "id": format!("TEST-{name}"), "modified": "2026-01-01T00:00:00Z" } ] })
                    }
                    None => json!({}),
                },
            )
            .collect();
        return Response::json(json!({ "results": results }));
    }
    if let Some(id) = path.strip_prefix("/v1/vulns/TEST-") {
        return Response::json(json!({
            "id": format!("TEST-{id}"),
            "aliases": ["CVE-2099-0001"],
            "summary": format!("a test advisory for {id}"),
            "published": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "severity": [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } ],
            "affected": [ {
                "package": { "purl": format!("pkg:pypi/{id}") },
                "ranges": [ { "type": "ECOSYSTEM", "events": [ { "introduced": "0" }, { "fixed": "999.0.0" } ] } ]
            } ],
        }));
    }
    if path == "/kev.json" {
        return Response::json(json!({
            "title": "test", "catalogVersion": "2026.01.01", "dateReleased": "2026-01-01T00:00:00Z", "count": 1,
            "vulnerabilities": [ {
                "cveID": "CVE-2099-0001", "vendorProject": "test", "product": "test",
                "vulnerabilityName": "test", "dateAdded": "2026-01-01", "shortDescription": "test",
                "requiredAction": "test", "dueDate": "2026-02-01", "knownRansomwareCampaignUse": "Unknown",
                "notes": "", "cwes": []
            } ],
        }));
    }
    if let Some(rest) = path.strip_prefix("/pypi/") {
        let parts: Vec<&str> = rest.split('/').collect();
        return match parts.as_slice() {
            [name, "json"] => Response::json(json!({
                "releases": {
                    "0.1.0": [ { "upload_time_iso_8601": "2020-01-01T00:00:00Z", "yanked": false } ],
                    "999.0.0": [ { "upload_time_iso_8601": "2026-01-01T00:00:00Z", "yanked": false } ],
                },
                "info": { "name": name },
            })),
            [name, version, "json"] => Response::json(json!({
                "info": {
                    "name": name, "version": version, "license_expression": "MIT",
                    "requires_python": ">=3.8",
                    "project_urls": { "Source": format!("https://github.com/test/{name}") },
                    "yanked": *name == "six", "yanked_reason": if *name == "six" { "a test" } else { "" },
                },
                "urls": [],
            })),
            _ => Response::status(404),
        };
    }
    if path.ends_with(".whl") {
        return Response::bytes(wheel(path.rsplit('/').next().unwrap_or("")));
    }
    if let Some(project) = path.strip_prefix("/projects/") {
        return Response::json(json!({
            "date": "2026-01-01",
            "repo": { "name": project, "commit": "0" },
            "scorecard": { "version": "v5", "commit": "0" },
            "score": 4.2,
            "checks": [ { "name": "Signed-Releases", "score": 0, "reason": "no releases found" } ],
        }));
    }
    if path == "/graphql" {
        let body = request.json();
        let package = |installed: &str| {
            json!({
                "versions": { "page": [ { "version": installed }, { "version": "999.0.0" } ] },
                "current": { "page": [ { "createdAt": "2026-01-01T00:00:00Z" } ] },
                "build": { "page": [ { "sha256": "00" } ] },
            })
        };
        let variables = &body["variables"];
        if variables.get("n0").is_some() {
            let mut data = serde_json::Map::new();
            for i in 0.. {
                let Some(installed) = variables.get(format!("v{i}")) else {
                    break;
                };
                data.insert(format!("p{i}"), package(installed.as_str().unwrap_or("")));
            }
            return Response::json(json!({ "data": data }));
        }
        if !body["query"].as_str().unwrap_or("").contains("versions(") {
            return Response::json(
                json!({ "data": { "package": { "current": { "page": [ { "createdAt": "2026-01-01T00:00:00Z" } ] } } } }),
            );
        }
        return Response::json(json!({ "data": { "package": package(variables["v"].as_str().unwrap_or("")) } }));
    }
    Response::status(404)
}

/// A wheel holding only its `METADATA`, stored without compression: enough for the zip reader
/// to find a license and the repository the scorecard is looked up for.
fn wheel(file_name: &str) -> Vec<u8> {
    let mut parts = file_name.splitn(3, '-');
    let (dist, version) = (parts.next().unwrap_or("x"), parts.next().unwrap_or("0"));
    let project = dist.to_lowercase().replace('_', "-");
    let member = format!("{dist}-{version}.dist-info/METADATA");
    let metadata = format!(
        "Metadata-Version: 2.4\nName: {project}\nVersion: {version}\nLicense-Expression: MIT\n\
         Project-URL: Source, https://github.com/test/{project}\n"
    );
    stored_zip(&member, metadata.as_bytes())
}

/// A one-member zip, stored: local header, data, central directory, end record.
fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let crc = crc32(data);
    let (size, name_len) = (data.len() as u32, name.len() as u16);
    let mut zip = Vec::new();
    zip.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    zip.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // version, flags, method, time, date
    for field in [crc, size, size] {
        zip.extend_from_slice(&field.to_le_bytes());
    }
    zip.extend_from_slice(&name_len.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip.extend_from_slice(name.as_bytes());
    zip.extend_from_slice(data);
    let directory = zip.len() as u32;
    zip.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    zip.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // made by, needed, flags, method, time, date
    for field in [crc, size, size] {
        zip.extend_from_slice(&field.to_le_bytes());
    }
    zip.extend_from_slice(&name_len.to_le_bytes());
    zip.extend_from_slice(&[0; 12]); // extra, comment, disk, internal and external attributes
    zip.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    zip.extend_from_slice(name.as_bytes());
    let directory_len = zip.len() as u32 - directory;
    zip.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    zip.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]); // disks, entries here and in all
    zip.extend_from_slice(&directory_len.to_le_bytes());
    zip.extend_from_slice(&directory.to_le_bytes());
    zip.extend_from_slice(&0u16.to_le_bytes());
    zip
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// What the grid shows that is not a fault, cell by cell: the input does not record what the
/// column needs. Each is documented where the reader is.
const NOTES: &str = "
Exit codes: 0 ok, 3 license policy, 4 vulnerability gate (severity or KEV), 7 yanked, 9 scorecard gate.
The upstream gives every PyPI package a critical, KEV-listed advisory, a newer release, an MIT license, a
repository with a 4.2 scorecard, and yanks six; conda packages get no advisory (OSV has no conda ecosystem).

- vulnerabilities, severity and KEV gates on conda-only inputs (explicit spec): nothing to find, since OSV has
  no conda ecosystem; conda-lock.yml and the conda prefix find their one PyPI package.
- python on the explicit spec: no rows, since the format records no dependencies and so no package that pins
  an interpreter.
- phantom on pylock.toml and the explicit spec: the inputs record no graph (uv export writes no per-package
  dependencies; an explicit spec none at all), so every transitive package is a root and counts as undeclared.
- licenses on conda-lock.yml and the explicit spec: neither records a conda package's license, and the conda
  archives --fetch-licenses would read them from are not reachable here, so only conda-lock's PyPI package has
  one. The license gate (an allow-list) has nothing to refuse on the explicit spec; --require-license is what
  gates unknown licenses.
- scorecard: the repository comes from the wheel, or from the PyPI JSON API's project_urls where no wheel is
  read (poetry.lock and pdm.lock record no URLs; an installed dist-info names none here). The git and local
  packages are not looked up by name, so 25 of 27 are scored.
- yanked gate: six is the yanked one; inputs without it pass.
- the syft documents (tests/fixtures/syft) describe a venv: 9 PyPI packages and 6 executables syft found
  ('Simple Launcher', no purl), which outdated lists as not checked. syft names no repositories, so the scores
  come from the PyPI lookup. The diff counts 10, not 15: it matches by kind and name, and the six executables
  share one.
- licenses and outdated on the Python lockfiles count 25 of 27: the git checkout (django-debug-toolbar) and the
  local directory (internal-utils) are not asked about by name, since the index would describe an unrelated
  project of that name.
";

/// One input kind: how to point the tool at it.
struct Input {
    name: &'static str,
    args: Vec<String>,
}

fn inputs(work: &Path) -> Vec<Input> {
    let examples = root().join("examples/projects");
    let fixtures = root().join("tests/fixtures");
    let lockfile = |path: PathBuf| {
        vec![
            "--lockfile".to_string(),
            path.display().to_string(),
            "-p".into(),
            "linux-64".into(),
        ]
    };
    // A document to start from: the pixi fixture, written once without the network.
    let document = work.join("previous.cdx.json");
    Command::cargo_bin("pixi-sbom")
        .unwrap()
        .current_dir(work)
        .env("PIXI_SBOM_OFFLINE", "1")
        .env("PIXI_CACHE_DIR", work.join("empty-pkgs-cache"))
        .args(["--lockfile", fixtures.join("with-pypi/pixi.lock").to_str().unwrap()])
        .args(["-e", "web", "-p", "linux-64", "--output", document.to_str().unwrap()])
        .assert()
        .success();
    let mut pixi = lockfile(fixtures.join("with-pypi/pixi.lock"));
    pixi.extend(["-e".into(), "web".into()]);
    vec![
        Input {
            name: "pixi.lock",
            args: pixi,
        },
        Input {
            name: "uv.lock",
            args: lockfile(examples.join("uv/01-django/uv.lock")),
        },
        Input {
            name: "pylock.toml",
            args: lockfile(examples.join("pylock/01-django/pylock.toml")),
        },
        Input {
            name: "poetry.lock",
            args: lockfile(examples.join("poetry/01-django/poetry.lock")),
        },
        Input {
            name: "pdm.lock",
            args: lockfile(examples.join("pdm/01-django/pdm.lock")),
        },
        Input {
            name: "conda-lock.yml",
            args: lockfile(examples.join("conda-lock/01-django/conda-lock.yml")),
        },
        Input {
            name: "explicit spec",
            args: vec![
                "--lockfile".into(),
                examples
                    .join("conda-explicit/01-django/explicit-linux-64.txt")
                    .display()
                    .to_string(),
            ],
        },
        Input {
            name: "--prefix (conda)",
            args: vec!["--prefix".into(), fixtures.join("prefix").display().to_string()],
        },
        Input {
            name: "--prefix (venv)",
            args: vec!["--prefix".into(), fixtures.join("venv-posix").display().to_string()],
        },
        Input {
            name: "--from-sbom",
            args: vec!["--from-sbom".into(), document.display().to_string()],
        },
        Input {
            name: "--from-sbom (syft CycloneDX)",
            args: vec![
                "--from-sbom".into(),
                fixtures.join("syft/app.cdx.json").display().to_string(),
            ],
        },
        Input {
            name: "--from-sbom (syft SPDX)",
            args: vec![
                "--from-sbom".into(),
                fixtures.join("syft/app.spdx.json").display().to_string(),
            ],
        },
    ]
}

/// What to run in one column, and how to count its rows in the JSON report.
struct Column {
    name: &'static str,
    args: &'static [&'static str],
    /// The JSON key holding the report's rows; `None` for a column judged by its exit code alone.
    rows: Option<&'static str>,
    /// A row field that only some rows have a value for, counted too: whether the enrichment the
    /// column depends on reached the packages, not just whether the report has rows.
    with: Option<&'static str>,
    /// `--against` the input itself (a lockfile or directory), for the diff.
    against_self: bool,
}

const COLUMNS: &[Column] = &[
    Column {
        name: "packages",
        args: &["--report", "packages", "--report-format", "json"],
        rows: Some("packages"),
        with: None,
        against_self: false,
    },
    Column {
        name: "licenses",
        args: &["--fetch-licenses", "--report", "licenses", "--report-format", "json"],
        rows: Some("packages"),
        with: Some("license"),
        against_self: false,
    },
    Column {
        name: "vulnerabilities",
        args: &[
            "--vulnerabilities",
            "osv",
            "--kev",
            "--report",
            "vulnerabilities",
            "--report-format",
            "json",
        ],
        rows: Some("vulnerabilities"),
        with: None,
        against_self: false,
    },
    Column {
        name: "diff",
        args: &["--report", "diff", "--report-format", "json"],
        rows: None,
        with: None,
        against_self: true,
    },
    Column {
        name: "outdated",
        args: &["--report", "outdated", "--report-format", "json"],
        rows: Some("outdated"),
        with: None,
        against_self: false,
    },
    Column {
        name: "python",
        args: &["--report", "python", "--report-format", "json"],
        rows: Some("python"),
        with: None,
        against_self: false,
    },
    Column {
        name: "phantom",
        args: &["--report", "phantom", "--report-format", "json"],
        rows: Some("phantom"),
        with: None,
        against_self: false,
    },
    Column {
        name: "scorecard",
        args: &[
            "--fetch-licenses",
            "--scorecard",
            "--report",
            "scorecard",
            "--report-format",
            "json",
        ],
        rows: Some("scorecard"),
        with: Some("score"),
        against_self: false,
    },
    Column {
        name: "explain",
        args: &["--explain", "*"],
        rows: None,
        with: None,
        against_self: false,
    },
    Column {
        name: "license gate",
        args: &["--fetch-licenses", "--allow-license", "0BSD", "--output", "-"],
        rows: None,
        with: None,
        against_self: false,
    },
    Column {
        name: "severity gate",
        args: &[
            "--vulnerabilities",
            "osv",
            "--fail-on-severity",
            "critical",
            "--output",
            "-",
        ],
        rows: None,
        with: None,
        against_self: false,
    },
    Column {
        name: "KEV gate",
        args: &["--vulnerabilities", "osv", "--kev", "--fail-on-kev", "--output", "-"],
        rows: None,
        with: None,
        against_self: false,
    },
    Column {
        name: "yanked gate",
        args: &["--fetch-licenses", "--fail-on-yanked", "--output", "-"],
        rows: None,
        with: None,
        against_self: false,
    },
    Column {
        name: "scorecard gate",
        args: &[
            "--fetch-licenses",
            "--scorecard",
            "--fail-on-scorecard",
            "5",
            "--output",
            "-",
        ],
        rows: None,
        with: None,
        against_self: false,
    },
];

/// The comparison side for `--report diff`: the input against itself.
fn against(input: &Input) -> String {
    let at = |flag: &str| {
        input
            .args
            .iter()
            .position(|a| a == flag)
            .map(|i| input.args[i + 1].clone())
    };
    at("--lockfile")
        .or_else(|| at("--prefix"))
        .or_else(|| at("--from-sbom"))
        .expect("every input names its source")
}

/// One cell: the exit code, and the row count or the diagnostic code it gave.
fn cell(work: &Path, server: &Server, input: &Input, column: &Column) -> String {
    let mut command = Command::cargo_bin("pixi-sbom").unwrap();
    command
        .current_dir(work)
        .env_remove("PIXI_SBOM_OFFLINE")
        .env("PIXI_HOME", work.join("pixi-home"))
        .env("PIXI_CACHE_DIR", work.join("empty-pkgs-cache"))
        .env(
            "PIXI_SBOM_CACHE_DIR",
            work.join(format!("cache-{}-{}", input.name, column.name).replace(['/', ' ', '(', ')'], "_")),
        )
        .env("PIXI_SBOM_PYPI_URL", format!("{}/pypi", server.url()))
        .env("PIXI_SBOM_PREFIX_INDEX_URL", format!("{}/graphql", server.url()))
        .env("PIXI_SBOM_ANACONDA_URL", server.url())
        .env("PIXI_SBOM_OSV_URL", server.url())
        .env("PIXI_SBOM_KEV_URL", format!("{}/kev.json", server.url()))
        .env("PIXI_SBOM_MAPPING_URL", format!("{}/mapping.json", server.url()))
        .env("PIXI_SBOM_SCORECARD_URL", server.url())
        .env("PIXI_SBOM_WHEEL_ARCHIVE_URL", server.url())
        .env("PIXI_SBOM_CONDA_ARCHIVE_URL", server.url())
        .env("COLUMNS", "200")
        .args(&input.args)
        .args(column.args);
    if column.against_self {
        command.args(["--against", &against(input)]);
    }
    let output = command.output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if let Some(diagnostic) = stderr.lines().find_map(|l| l.trim().strip_prefix("Error: ")) {
        return format!("{code}: {diagnostic}");
    }
    if code == 2 {
        let usage = stderr
            .lines()
            .find(|l| l.starts_with("error:"))
            .unwrap_or("usage error");
        return format!("2: {usage}");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    match column.rows {
        Some(key) => match serde_json::from_str::<Value>(&stdout) {
            Ok(report) => {
                let rows = report[key].as_array().cloned().unwrap_or_default();
                match column.with {
                    Some(field) => {
                        let with = rows.iter().filter(|row| !row[field].is_null()).count();
                        format!("{code}: {} rows, {with} with {field}", rows.len())
                    }
                    None => format!("{code}: {} rows", rows.len()),
                }
            }
            Err(_) => format!("{code}: not JSON"),
        },
        None if column.against_self => match serde_json::from_str::<Value>(&stdout) {
            Ok(report) => format!("{code}: {} unchanged", report["unchanged"]),
            Err(_) => format!("{code}: not JSON"),
        },
        None => format!("{code}"),
    }
}

#[test]
fn every_report_and_gate_on_every_input() {
    let work = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(work.path().join("pixi-home")).unwrap();
    let server = Server::start(|request, _| upstream(request));
    let inputs = inputs(work.path());

    let mut table = String::from("| input |");
    for column in COLUMNS {
        table += &format!(" {} |", column.name);
    }
    table += "\n|---|";
    table += &"---|".repeat(COLUMNS.len());
    table += "\n";
    for input in &inputs {
        table += &format!("| {} |", input.name);
        for column in COLUMNS {
            let outcome = cell(work.path(), &server, input, column);
            assert!(!outcome.is_empty(), "{} × {}: a blank cell", input.name, column.name);
            table += &format!(" {outcome} |");
        }
        table += "\n";
    }
    // Nothing reached a host other than the local upstream: every service was pointed at it,
    // and it saw requests from every networked column.
    let paths: Vec<String> = server.requests().iter().map(|r| r.path.clone()).collect();
    for expected in [
        "/v1/querybatch",
        "/v1/vulns/",
        "/kev.json",
        "/pypi/",
        "/graphql",
        "/projects/",
    ] {
        assert!(
            paths.iter().any(|p| p.starts_with(expected)),
            "nothing asked {expected}"
        );
    }
    table += NOTES;
    insta::assert_snapshot!(table);
}
