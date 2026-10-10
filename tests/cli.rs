//! End-to-end tests that drive the `pixi-sbom` binary and validate what it writes
//! against the official CycloneDX 1.6 and SPDX 2.3 JSON schemas.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use jsonschema::{Registry, Validator};
use predicates::prelude::*;
use serde_json::Value;

/// The binary, with the machine's own configuration kept out of the way.
///
/// Since the user-level configuration layer was added, a `~/.pixi/pixi-sbom-config.toml` on the
/// developer's machine is read by every run — including these. One line in it (`conda-index-kind`,
/// say) silently changes what the tests assert against, and the suite passes on CI only because a
/// fresh runner happens to have no such file. `PIXI_HOME` is what the user layer resolves through,
/// so pointing it at an empty directory makes these runs depend on the fixture and nothing else.
fn pixi_sbom() -> Command {
    let mut command = Command::cargo_bin("pixi-sbom").expect("binary builds");
    command.env("PIXI_HOME", empty_pixi_home());
    command
}

/// A directory with no configuration in it, shared by every test and never written to.
fn empty_pixi_home() -> &'static Path {
    static HOME: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        let dir = std::env::temp_dir().join("pixi-sbom-tests-empty-home");
        std::fs::create_dir_all(&dir).expect("a directory for an empty PIXI_HOME");
        dir
    })
}

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Copy a fixture workspace (manifest + lockfile) into a fresh temp dir so the
/// binary can write output next to it without touching the repo.
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

fn schema(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(tests_dir().join("schemas").join(name)).unwrap()).unwrap()
}

fn cyclonedx_validator() -> Validator {
    let registry = Registry::new()
        .add(
            "http://cyclonedx.org/schema/spdx.schema.json",
            schema("spdx.schema.json"),
        )
        .unwrap()
        .add(
            "http://cyclonedx.org/schema/jsf-0.82.schema.json",
            schema("jsf-0.82.schema.json"),
        )
        .unwrap()
        .prepare()
        .unwrap();
    jsonschema::options()
        .with_registry(&registry)
        .offline()
        .build(&schema("bom-1.6.schema.json"))
        .unwrap()
}

fn spdx_validator() -> Validator {
    jsonschema::options()
        .offline()
        .build(&schema("spdx-2.3.schema.json"))
        .unwrap()
}

fn assert_valid(validator: &Validator, doc: &Value) {
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| format!("{} at {}", e, e.instance_path()))
        .collect();
    assert!(errors.is_empty(), "schema violations:\n{}", errors.join("\n"));
}

fn read_json(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn help_lists_all_options() {
    pixi_sbom()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--lockfile"))
        .stdout(predicate::str::contains("--format"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--environment"))
        .stdout(predicate::str::contains("--platform"))
        .stdout(predicate::str::contains("--all-environments"))
        .stdout(predicate::str::contains("--all-platforms"))
        .stdout(predicate::str::contains("https://millsks.github.io/pixi-sbom/"));
}

#[test]
fn version_prints_crate_version() {
    pixi_sbom()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn version_details_prints_what_a_bug_report_needs() {
    let assert = pixi_sbom()
        .env("PIXI_SBOM_OFFLINE", "1")
        .env("HTTPS_PROXY", "http://someone:hunter2@proxy.corp:8080")
        .arg("--version-details")
        .assert()
        .success();
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
    // The facts that decide answers: what is compiled in, where the caches are, how the
    // network is set up.
    assert!(text.contains("socks-proxy"), "{text}");
    assert!(
        !text.contains("socks-proxy: no"),
        "this build can use a socks5:// proxy: {text}"
    );
    assert!(text.contains("platform-verifier"), "{text}");
    assert!(text.contains("caches:"), "{text}");
    assert!(text.contains("offline:  true"), "{text}");
    assert!(
        text.contains("proxy: HTTPS_PROXY=http://someone:***@proxy.corp:8080"),
        "{text}"
    );
    assert!(!text.contains("hunter2"), "a pasted banner must not carry a password");
    // It answers without a workspace and without touching the network.
    assert_eq!(text.lines().count(), 6, "{text}");

    // The alias is the name people guess.
    pixi_sbom().arg("--build-info").assert().success();
}

#[test]
fn missing_explicit_lockfile_fails_with_diagnostic() {
    let dir = tempfile::tempdir().unwrap();

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--lockfile", "does-not-exist.lock"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does-not-exist.lock"))
        .stderr(predicate::str::contains("does not exist"));
}

#[test]
fn no_lockfile_in_tree_fails_with_help() {
    let dir = tempfile::tempdir().unwrap();

    pixi_sbom()
        .current_dir(dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no pixi.lock, uv.lock, pylock.toml, poetry.lock, pdm.lock or conda-lock.yml found",
        ))
        .stderr(predicate::str::contains("--lockfile"));
}

#[test]
fn corrupt_lockfile_fails_with_diagnostic() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("pixi.lock"), "version: 7\nnot: [valid\n").unwrap();

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read lockfile"));
}

#[test]
fn default_run_writes_cyclonedx_next_to_discovered_lockfile() {
    let dir = workspace("conda-only");
    let nested = dir.path().join("src").join("deep");
    std::fs::create_dir_all(&nested).unwrap();

    pixi_sbom()
        .current_dir(&nested)
        .args(["-p", "linux-64"])
        .assert()
        .success()
        .stderr(predicate::str::contains("wrote SBOM"));

    let doc = read_json(&dir.path().join("sbom.cdx.json"));
    assert_valid(&cyclonedx_validator(), &doc);
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert_eq!(doc["specVersion"], "1.6");
    assert_eq!(doc["metadata"]["component"]["name"], "conda-only");
    assert_eq!(doc["metadata"]["component"]["version"], "1.2.3");
    let names: Vec<_> = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["libzlib", "zlib"]);
    assert!(doc["serialNumber"].as_str().unwrap().starts_with("urn:uuid:"));

    // CISA minimum elements: author, generation context, supplier, root metadata.
    assert_eq!(doc["metadata"]["authors"][0]["name"], "Test Author");
    assert_eq!(doc["metadata"]["authors"][0]["email"], "author@example.org");
    assert_eq!(doc["metadata"]["lifecycles"][0]["phase"], "pre-build");
    assert_eq!(doc["metadata"]["component"]["licenses"][0]["expression"], "MIT");
    assert_eq!(
        doc["metadata"]["component"]["externalReferences"][1]["url"],
        "https://github.com/example/conda-only"
    );
    assert!(doc["components"].as_array().unwrap().iter().all(|c| {
        c["supplier"]["name"] == "conda-forge" && c["supplier"]["url"][0] == "https://conda.anaconda.org/conda-forge/"
    }));
}

#[test]
fn documents_are_byte_identical_with_source_date_epoch() {
    let dir = workspace("with-pypi");
    let mut outputs = Vec::new();
    for (i, format) in ["cyclonedx", "spdx", "cyclonedx"].iter().enumerate() {
        let out = dir.path().join(format!("run-{i}.json"));
        pixi_sbom()
            .current_dir(dir.path())
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .args(["--format", format, "-e", "web", "-p", "linux-64", "--output"])
            .arg(&out)
            .assert()
            .success();
        outputs.push(std::fs::read(&out).unwrap());
    }
    assert_eq!(outputs[0], outputs[2], "same input, same bytes");
    let cdx = read_json(&dir.path().join("run-0.json"));
    let spdx = read_json(&dir.path().join("run-1.json"));
    assert_eq!(cdx["metadata"]["timestamp"], "2023-11-14T22:13:20Z");
    assert_eq!(spdx["creationInfo"]["created"], "2023-11-14T22:13:20Z");
    let serial = cdx["serialNumber"].as_str().unwrap();
    assert!(
        !spdx["documentNamespace"]
            .as_str()
            .unwrap()
            .ends_with(&serial["urn:uuid:".len()..]),
        "each format gets its own identifier"
    );

    // A different environment over the same lockfile is a different document.
    let other = dir.path().join("other.json");
    pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .args(["-e", "default", "-p", "linux-64", "--output"])
        .arg(&other)
        .assert()
        .success();
    assert_ne!(read_json(&other)["serialNumber"], cdx["serialNumber"]);
}

#[test]
fn invalid_source_date_epoch_warns_and_continues() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "not-a-number")
        .args(["-p", "linux-64"])
        .assert()
        .success()
        .stderr(predicate::str::contains("ignoring SOURCE_DATE_EPOCH"));
    assert_valid(&cyclonedx_validator(), &read_json(&dir.path().join("sbom.cdx.json")));
}

#[test]
fn dash_output_writes_only_the_document_to_stdout() {
    let dir = workspace("conda-only");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--format", "spdx", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("output=<stdout>"));
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let doc: Value = serde_json::from_str(&stdout).expect("stdout is exactly one JSON document");
    assert_valid(&spdx_validator(), &doc);
    assert_eq!(doc["spdxVersion"], "SPDX-2.3");
    assert!(stdout.ends_with("}\n"));
    assert!(
        !dir.path().join("sbom.spdx.json").exists(),
        "nothing written next to the lockfile"
    );
}

#[test]
fn dash_output_conflicts_with_batch_modes() {
    let dir = workspace("multi-env");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--all-environments", "--output", "-"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be combined with '--all-environments'"));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-platforms", "--output", "-"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be combined with '--all-platforms'"));
}

#[test]
fn all_platforms_writes_one_file_per_locked_platform() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-platforms"])
        .assert()
        .success()
        .stderr(predicate::str::contains("platform=linux-64"))
        .stderr(predicate::str::contains("platform=osx-arm64"));

    let validator = cyclonedx_validator();
    for platform in ["linux-64", "osx-arm64"] {
        let doc = read_json(&dir.path().join(format!("sbom-{platform}.cdx.json")));
        assert_valid(&validator, &doc);
        let props = doc["metadata"]["properties"].as_array().unwrap();
        assert!(
            props
                .iter()
                .any(|p| p["name"] == "pixi:platform" && p["value"] == platform),
            "{platform}"
        );
        assert!(doc["components"].as_array().unwrap().iter().all(|c| {
            c["properties"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["name"] == "pixi:subdir" && p["value"] == platform)
        }));
    }
    assert!(!dir.path().join("sbom.cdx.json").exists());
}

#[test]
fn all_environments_and_all_platforms_cover_every_pair() {
    let dir = workspace("with-pypi");
    let out = dir.path().join("sboms");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-environments", "--all-platforms", "--format", "spdx", "--output"])
        .arg(&out)
        .assert()
        .success();

    let mut written: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    assert_eq!(
        written,
        [
            "sbom-default-linux-64.spdx.json",
            "sbom-default-osx-arm64.spdx.json",
            "sbom-web-linux-64.spdx.json",
            "sbom-web-osx-arm64.spdx.json",
        ]
    );
    let doc = read_json(&out.join("sbom-web-osx-arm64.spdx.json"));
    assert_valid(&spdx_validator(), &doc);
    assert_eq!(doc["name"], "with-pypi-web-osx-arm64");
}

#[test]
fn all_platforms_conflicts_with_platform() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-platforms", "-p", "linux-64"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--all-platforms"));
}

fn mapping_file() -> PathBuf {
    tests_dir().join("fixtures").join("pypi-mapping.json")
}

#[test]
fn pypi_mapping_file_adds_purls_and_primary_purl_pypi_swaps_them() {
    let dir = workspace("conda-python");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--pypi-mapping-file"])
        .arg(mapping_file())
        .args(["--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("enriched=3"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let components = doc["components"].as_array().unwrap();
    let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
    let props = |c: &Value, key: &str| -> Vec<String> {
        c["properties"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["name"] == key)
            .map(|p| p["value"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(by_name("numpy")["purl"].as_str().unwrap().starts_with("pkg:conda/"));
    assert_eq!(props(by_name("numpy"), "pixi:purl"), ["pkg:pypi/numpy@2.3.1"]);
    assert_eq!(props(by_name("numpy"), "pixi:pypi-mapping"), ["file"]);
    assert_eq!(props(by_name("pytorch"), "pixi:purl"), ["pkg:pypi/torch@2.7.1"]);
    assert!(props(by_name("python"), "pixi:purl").is_empty());
    assert!(props(by_name("samtools"), "pixi:purl").is_empty(), "not conda-forge");

    // --primary-purl pypi: PyPI purl becomes `purl`, conda purl moves to pixi:purl, bom-ref unchanged.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--format", "spdx", "--pypi-mapping-file"])
        .arg(mapping_file())
        .args(["--primary-purl", "pypi", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("switched=3"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx_validator(), &doc);
    let numpy = doc["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "numpy")
        .unwrap();
    let refs: Vec<_> = numpy["externalRefs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["referenceLocator"].as_str().unwrap())
        .collect();
    assert_eq!(refs[0], "pkg:pypi/numpy@2.3.1");
    assert!(refs[1].starts_with("pkg:conda/numpy@2.3.1"));
    assert_eq!(numpy["SPDXID"], "SPDXRef-Package-conda-numpy-2.3.1");

    let cdx = pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--pypi-mapping-file"])
        .arg(mapping_file())
        .args(["--primary-purl", "pypi", "--output", "-"])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&cdx.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let numpy = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "numpy")
        .unwrap();
    assert_eq!(numpy["purl"], "pkg:pypi/numpy@2.3.1");
    assert!(numpy["bom-ref"].as_str().unwrap().starts_with("pkg:conda/numpy@2.3.1"));
    assert!(
        doc["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["ref"] == numpy["bom-ref"]),
        "dependency graph still keyed by the conda bom-ref"
    );
}

/// The default primary purl hides conda packages' PyPI identity from scanners: warned once, and
/// not at all once `--primary-purl` or the `primary-purl` key is set, `conda` included (#449).
#[test]
fn an_unchosen_conda_primary_purl_warns_that_scanners_will_miss_packages() {
    let dir = workspace("conda-python");
    let run = |extra: &[&str]| {
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .args(["-p", "linux-64", "--pypi-mapping-file"])
            .arg(mapping_file())
            .args(["--output", "-"])
            .args(extra)
            .assert()
            .success();
        String::from_utf8(assert.get_output().stderr.clone()).unwrap()
    };
    let warned = run(&[]);
    assert_eq!(
        warned.matches("scanners read only the primary purl").count(),
        1,
        "{warned}"
    );
    assert!(
        warned.contains("packages=3") && warned.contains("--primary-purl pypi"),
        "{warned}"
    );
    for chosen in [["--primary-purl", "conda"], ["--primary-purl", "pypi"]] {
        assert!(!run(&chosen).contains("scanners read only"), "{chosen:?}");
    }
    // Nothing that goes to a scanner: a report, an explanation, a GitHub snapshot.
    let quiet_runs: [&[&str]; 3] = [
        &["--report", "packages"],
        &["--explain", "numpy"],
        &["--format", "github", "--output", "-"],
    ];
    for quiet in quiet_runs {
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .args(["-p", "linux-64", "--pypi-mapping-file"])
            .arg(mapping_file())
            .args(quiet)
            .env("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
            .env("GITHUB_REF", "refs/heads/main")
            .assert()
            .success();
        let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
        assert!(!stderr.contains("scanners read only"), "{quiet:?}: {stderr}");
    }
    std::fs::create_dir_all(dir.path().join(".pixi")).unwrap();
    std::fs::write(
        dir.path().join(".pixi").join("pixi-sbom-config.toml"),
        "primary-purl = \"conda\"\n",
    )
    .unwrap();
    assert!(
        !run(&[]).contains("scanners read only"),
        "a configured choice silences it"
    );
}

#[test]
fn primary_purl_pypi_without_mapping_uses_lockfile_purls_only() {
    let dir = workspace("with-pypi");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "-e", "web", "--primary-purl", "pypi", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("switched=0"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
}

#[test]
fn pypi_mapping_prefix_uses_a_cached_mapping_without_network() {
    let dir = workspace("conda-python");
    let cache = dir.path().join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::copy(mapping_file(), cache.join("conda-forge-pypi-mapping.json")).unwrap();

    pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_CACHE_DIR", &cache)
        .args(["-p", "linux-64", "--pypi-mapping", "prefix"])
        .assert()
        .success()
        .stderr(predicate::str::contains("enriched=3"));
    let doc = read_json(&dir.path().join("sbom.cdx.json"));
    let numpy = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "numpy")
        .unwrap();
    assert!(
        numpy["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:pypi-mapping" && p["value"] == "prefix")
    );
}

#[test]
fn bad_mapping_file_and_conflicting_mapping_flags_are_reported() {
    let dir = workspace("conda-python");
    std::fs::write(dir.path().join("bad.json"), "[]").unwrap();

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--pypi-mapping-file", "bad.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pixi_sbom::mapping::parse"));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--pypi-mapping-file", "missing.json"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("pixi_sbom::mapping::read"));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--pypi-mapping", "prefix", "--pypi-mapping-file", "x.json"])
        .assert()
        .code(2);
}

#[test]
fn pypi_licenses_come_from_cached_index_metadata() {
    let dir = workspace("with-pypi");
    let cache = dir.path().join("cache").join("pypi");
    std::fs::create_dir_all(&cache).unwrap();
    for entry in std::fs::read_dir(tests_dir().join("fixtures").join("pypi-metadata")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), cache.join(entry.file_name())).unwrap();
    }

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["-e", "web", "-p", "linux-64", "--fetch-licenses", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "read PyPI license details from wheels fetched=0 failed=6 skipped=0",
        ))
        .stderr(predicate::str::contains("found=6 missing=0 failed=0"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let components = doc["components"].as_array().unwrap();
    let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
    assert_eq!(by_name("requests")["licenses"][0]["expression"], "Apache-2.0");
    assert_eq!(by_name("certifi")["licenses"][0]["expression"], "MPL-2.0");
    assert_eq!(by_name("idna")["licenses"][0]["expression"], "BSD-3-Clause");
    assert!(
        by_name("six")["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:license-source" && p["value"] == "pypi")
    );
    assert!(
        !by_name("python")["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:license-source"),
        "conda packages keep their lockfile license"
    );

    // SPDX carries the same expressions.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--fetch-licenses",
            "--output",
            "-",
        ])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx_validator(), &doc);
    let urllib3 = doc["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "urllib3")
        .unwrap();
    assert_eq!(urllib3["licenseDeclared"], "MIT");
}

#[test]
fn the_run_says_which_input_and_which_settings_it_chose() {
    let dir = workspace("with-pypi");
    // A configuration file that sets three things, one of which the command line overrides.
    std::fs::write(
        dir.path().join("pixi-sbom.toml"),
        "format = \"spdx\"\nfetch-licenses = false\nexclude = [\"tzdata\"]\n",
    )
    .unwrap();

    let stderr = |args: &[&str]| -> String {
        String::from_utf8(
            pixi_sbom()
                .current_dir(dir.path())
                .args(["-p", "linux-64", "-v"])
                .args(args)
                .assert()
                .success()
                .get_output()
                .stderr
                .clone(),
        )
        .unwrap()
    };

    let log = stderr(&["--format", "cyclonedx", "--output", "-"]);
    assert!(log.contains("pixi.lock\" how="), "{log}");
    assert!(log.contains("found by searching upward"), "{log}");
    assert!(log.contains("workspace manifest"), "{log}");
    assert!(log.contains("applied=\"exclude, fetch-licenses\""), "{log}");
    assert!(log.contains("overridden_on_the_command_line=\"format\""), "{log}");

    // --no-config says so rather than saying nothing.
    let none = stderr(&["--no-config", "--output", "-"]);
    assert!(none.contains("--no-config was given"), "{none}");

    // A workspace with no manifest explains what that costs the root component.
    let bare = tempfile::tempdir().unwrap();
    std::fs::copy(
        tests_dir().join("fixtures/with-pypi/pixi.lock"),
        bare.path().join("pixi.lock"),
    )
    .unwrap();
    let bare_log = String::from_utf8(
        pixi_sbom()
            .current_dir(bare.path())
            .args(["-p", "linux-64", "-v", "--output", "-"])
            .assert()
            .success()
            .get_output()
            .stderr
            .clone(),
    )
    .unwrap();
    assert!(bare_log.contains("no workspace manifest"), "{bare_log}");
    assert!(bare_log.contains("graph-root heuristic"), "{bare_log}");

    // A scan reads one configuration for the tree, which is worth saying out loud.
    let scan = String::from_utf8(
        pixi_sbom()
            .current_dir(dir.path())
            .args(["-p", "linux-64", "-v", "--scan"])
            .arg(dir.path())
            .args(["--output", dir.path().join("out").to_str().unwrap()])
            .assert()
            .success()
            .get_output()
            .stderr
            .clone(),
    )
    .unwrap();
    assert!(scan.contains("one lockfile per project under this directory"), "{scan}");
    assert!(scan.contains("not from each workspace"), "{scan}");
}

#[test]
fn the_run_says_what_it_will_talk_to_before_it_talks_to_anything() {
    let dir = workspace("with-pypi");
    // The block is logged before anything is fetched, so it is there whether or not the run
    // goes on to fail: offline, a missing KEV or mapping cache is fatal by design.
    let stderr = |args: &[&str], envs: &[(&str, &str)]| -> String {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["-e", "web", "-p", "linux-64", "--output", "-"])
            .args(args);
        for (name, value) in envs {
            command.env(name, value);
        }
        String::from_utf8(command.assert().get_output().stderr.clone()).unwrap()
    };

    // Every upstream the flags bring in is named, with where its address came from.
    let log = stderr(
        &[
            "-v",
            "--fetch-licenses",
            "--pypi-mapping",
            "prefix",
            "--vulnerabilities",
            "osv",
            "--kev",
        ],
        &[("PIXI_SBOM_OSV_URL", "https://osv.internal")],
    );
    assert!(log.contains("network configuration"), "{log}");
    assert!(log.contains("offline=true"), "{log}");
    assert!(log.contains("service=\"PyPI index\""), "{log}");
    assert!(log.contains("service=\"conda-forge PyPI mapping\""), "{log}");
    assert!(log.contains("service=\"CISA KEV\""), "{log}");
    assert!(
        log.contains("url=https://osv.internal source=\"PIXI_SBOM_OSV_URL\""),
        "an overridden address says which variable set it: {log}"
    );
    assert!(log.contains("cache directory"), "{log}");

    // The proxy in effect is named, with its password taken out.
    let proxied = stderr(
        &["-v", "--fetch-licenses"],
        &[("HTTPS_PROXY", "http://someone:hunter2@proxy.corp:8080")],
    );
    assert!(
        proxied.contains("proxy=\"HTTPS_PROXY=http://someone:***@proxy.corp:8080\""),
        "{proxied}"
    );
    assert!(!proxied.contains("hunter2"), "the password never reaches the log");

    // A run that touches nothing says nothing about the network.
    let quiet = String::from_utf8(
        pixi_sbom()
            .current_dir(dir.path())
            .args(["-e", "web", "-p", "linux-64", "-v", "--output", "-"])
            .assert()
            .success()
            .get_output()
            .stderr
            .clone(),
    )
    .unwrap();
    assert!(!quiet.contains("network configuration"), "{quiet}");
}

#[test]
fn the_caches_can_be_bypassed_and_say_what_they_served() {
    let dir = workspace_with_vulnerable_urllib3();
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args([
                "-e",
                "web",
                "-p",
                "linux-64",
                "--vulnerabilities",
                "osv",
                "--output",
                "-",
            ])
            .args(args);
        command
    };
    let findings = |assert: assert_cmd::assert::Assert| -> usize {
        let document: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
        document["vulnerabilities"].as_array().map(Vec::len).unwrap_or_default()
    };

    // The recorded answers are on disk, so the run finds everything and says where it came from.
    let assert = run(&[]).assert().success();
    let served = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert_eq!(findings(assert), 9);
    assert!(served.contains("cache=\"osv\""), "{served}");
    assert!(served.contains("from_cache=6"), "{served}");

    // --refresh ignores them, and offline there is nothing to replace them with: the run still
    // succeeds, and the difference is the point.
    let assert = run(&["--refresh", "osv"]).assert().success();
    assert_eq!(findings(assert), 0, "the cached answers were not used");

    // --no-cache is the same for reading and also leaves nothing behind.
    let empty = dir.path().join("fresh-cache");
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", &empty)
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--vulnerabilities",
            "osv",
            "--no-cache",
            "--output",
            "-",
        ])
        .assert()
        .success();
    assert_eq!(findings(assert), 0);
    assert!(!empty.join("osv").is_dir(), "--no-cache wrote a cache directory anyway");

    // The two flags are not compatible.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--refresh", "osv", "--refresh", "kev", "--no-cache"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn doctor_says_how_many_requests_and_which_index() {
    // The diagnostic that was missing: a container whose cgroup quota throttles the run, or a
    // configuration file nobody can see in the repository changing which index is asked. Both
    // decide how a run behaves and neither appeared in the one command whose job is to say so.
    let dir = workspace("with-pypi");
    let home = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_HOME", home.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "160")
            .args(["--doctor", "--color", "never"])
            .args(args);
        String::from_utf8(command.assert().get_output().stdout.clone()).unwrap()
    };

    let plain = run(&[]);
    assert!(plain.contains("requests   10 at once (the default)"), "{plain}");
    assert!(plain.contains("index      prefix.dev"), "{plain}");
    assert!(plain.contains("(the default)"), "{plain}");

    // Each source names itself, which is the half that makes it a diagnostic rather than a number.
    let flagged = run(&["--concurrency", "42", "--conda-index-kind", "anaconda"]);
    assert!(flagged.contains("requests   42 at once (--concurrency)"), "{flagged}");
    assert!(flagged.contains("index      anaconda.org"), "{flagged}");

    let mut command = pixi_sbom();
    let varied = String::from_utf8(
        command
            .current_dir(dir.path())
            .env("PIXI_HOME", home.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("PIXI_SBOM_CONCURRENCY", "7")
            .args(["--doctor", "--color", "never"])
            .assert()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        varied.contains("requests   7 at once (PIXI_SBOM_CONCURRENCY)"),
        "{varied}"
    );
}

#[test]
fn doctor_probes_every_upstream_and_fails_when_one_is_unreachable() {
    let dir = workspace("with-pypi");
    let run = |args: &[&str], envs: &[(&str, &str)]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("COLUMNS", "160")
            .args(["--doctor", "--color", "never"])
            .args(args);
        for (name, value) in envs {
            command.env(name, value);
        }
        command
    };

    // Offline: everything is reported as skipped and the command still succeeds, so it is safe
    // on a locked-down runner.
    let text = String::from_utf8(
        run(
            &["--fetch-licenses", "--vulnerabilities", "osv"],
            &[("PIXI_SBOM_OFFLINE", "1")],
        )
        .assert()
        .success()
        .get_output()
        .stdout
        .clone(),
    )
    .unwrap();
    assert!(text.contains("Configuration"), "{text}");
    assert!(text.contains("offline    true"), "{text}");
    assert!(text.contains("TLS roots"), "{text}");
    assert!(text.contains("Upstreams"), "{text}");
    assert!(text.contains("PyPI index"), "{text}");
    assert!(text.contains("skipped, offline"), "{text}");

    // A base address that nothing is listening on: that row fails, it is named in the summary,
    // and the exit code says so.
    let text = String::from_utf8(
        run(
            &["--vulnerabilities", "osv"],
            &[("PIXI_SBOM_OSV_URL", "http://127.0.0.1:1")],
        )
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone(),
    )
    .unwrap();
    assert!(text.contains("failed:"), "{text}");
    assert!(text.contains("http://127.0.0.1:1 (PIXI_SBOM_OSV_URL)"), "{text}");
    assert!(text.contains("could not be reached: OSV."), "{text}");

    // With no flag at all it probes every upstream the build knows about, which is the whole
    // point of asking a diagnostic what is wrong: you do not yet know which one to suspect.
    let text = String::from_utf8(
        run(&[], &[("PIXI_SBOM_OFFLINE", "1")])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    for upstream in [
        "PyPI index",
        "conda-forge PyPI mapping",
        "OSV",
        "CISA KEV",
        "FIRST EPSS",
        "conda package index",
        "OpenSSF Scorecard",
    ] {
        assert!(text.contains(upstream), "bare --doctor must probe {upstream}: {text}");
    }
    // Naming the flags of a run still narrows the probe to those.
    let text = String::from_utf8(
        run(&["--vulnerabilities", "osv"], &[("PIXI_SBOM_OFFLINE", "1")])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(text.contains("OSV"), "{text}");
    assert!(
        !text.contains("conda package index"),
        "--vulnerabilities must not drag in the conda package index: {text}"
    );

    // It needs no lockfile at all.
    let empty = tempfile::tempdir().unwrap();
    pixi_sbom()
        .current_dir(empty.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["--doctor", "--fetch-licenses", "--color", "never"])
        .assert()
        .success();
}

#[test]
fn doctor_probes_the_archive_hosts_from_the_base_or_the_lockfile() {
    let dir = workspace("with-pypi");
    let text = String::from_utf8(
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .env("PIXI_SBOM_MAPPING_URL", "https://mirror.invalid/mapping.json")
            .env("PIXI_SBOM_CONDA_ARCHIVE_URL", "https://mirror.invalid")
            .env("PIXI_SBOM_WHEEL_ARCHIVE_URL", "https://mirror.invalid/pypi")
            .args(["--doctor", "--color", "never"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();

    // A configured base is what the archives are probed at, and it is named as the source.
    for (upstream, variable) in [
        ("conda package archives", "PIXI_SBOM_CONDA_ARCHIVE_URL"),
        ("PyPI wheel archives", "PIXI_SBOM_WHEEL_ARCHIVE_URL"),
        ("conda-forge PyPI mapping", "PIXI_SBOM_MAPPING_URL"),
    ] {
        assert!(text.contains(upstream), "{upstream} missing: {text}");
        assert!(
            text.contains(variable),
            "{variable} should be named as the source: {text}"
        );
    }

    // Without a base the archives are still probed, from the hosts the lockfile itself names.
    let bare = String::from_utf8(
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .args(["--doctor", "--color", "never"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(bare.contains("conda package archives"), "{bare}");
    assert!(bare.contains("PyPI wheel archives"), "{bare}");
    assert!(
        bare.contains("(pixi.lock)"),
        "the archive hosts should be attributed to the lockfile: {bare}"
    );
    assert!(
        bare.contains("https://conda.anaconda.org"),
        "the fixture's own conda host should be the one probed: {bare}"
    );
}

#[test]
fn every_gate_that_fired_is_named_with_the_one_that_chose_the_exit_code() {
    let dir = workspace("with-pypi");

    // One gate: what failed, and what that means for the exit code.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--deny-license", "GPL-3.0-only", "--output", "-"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("Gate failed: license policy (2). Exiting 3."));

    // Two gates: both named, and the precedence spelled out rather than left to be inferred
    // from a number.
    let dir = workspace_with_vulnerable_urllib3();
    pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--vulnerabilities",
            "osv",
            "--fail-on-severity",
            "high",
            "--deny-license",
            "GPL-3.0-only",
            "--output",
            "-",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("2 gates failed:"))
        .stderr(predicate::str::contains("license policy ("))
        .stderr(predicate::str::contains("vulnerabilities ("))
        .stderr(predicate::str::contains(
            "Exiting 3 (license policy); the others would have been 4.",
        ));

    // No gate, nothing said.
    let clean = workspace("with-pypi");
    let quiet = String::from_utf8(
        pixi_sbom()
            .current_dir(clean.path())
            .args(["-p", "linux-64", "--output", "-"])
            .assert()
            .success()
            .get_output()
            .stderr
            .clone(),
    )
    .unwrap();
    assert!(!quiet.contains("Gate failed"), "{quiet}");
    assert!(!quiet.contains("gates failed"), "{quiet}");
}

#[test]
fn an_empty_vulnerability_report_says_whether_anything_could_be_asked() {
    let dir = workspace("conda-only");
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "160")
            .args([
                "-p",
                "linux-64",
                "--vulnerabilities",
                "osv",
                "--report",
                "vulnerabilities",
            ])
            .args(args);
        command
    };

    // A conda-only environment with no PyPI purls: the table is empty because nothing could be
    // asked, which is not the same answer as "nothing was found".
    let text = String::from_utf8(
        run(&["--color", "never"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(text.contains("Nothing could be queried"), "{text}");
    assert!(text.contains("--pypi-mapping prefix"), "{text}");

    // And the machine-readable form carries the same fact as a field.
    let report: Value =
        serde_json::from_slice(&run(&["--report-format", "json"]).assert().success().get_output().stdout).unwrap();
    assert_eq!(report["summary"]["queryable"], false);
    assert_eq!(report["vulnerabilities"].as_array().unwrap().len(), 0);

    // An environment that does carry PyPI purls says nothing of the kind.
    let pypi = workspace_with_vulnerable_urllib3();
    let text = String::from_utf8(
        pixi_sbom()
            .current_dir(pypi.path())
            .env("PIXI_CACHE_DIR", pypi.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", pypi.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "160")
            .args([
                "-e",
                "web",
                "-p",
                "linux-64",
                "--vulnerabilities",
                "osv",
                "--report",
                "vulnerabilities",
                "--color",
                "never",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(!text.contains("Nothing could be queried"), "{text}");
}

#[test]
fn timings_say_where_the_run_spent_its_time() {
    let dir = workspace("with-pypi");
    let stderr = |args: &[&str]| -> String {
        String::from_utf8(
            pixi_sbom()
                .current_dir(dir.path())
                .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
                .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
                .env("PIXI_SBOM_OFFLINE", "1")
                .args(["-e", "web", "-p", "linux-64", "--output", "-"])
                .args(args)
                .assert()
                .success()
                .get_output()
                .stderr
                .clone(),
        )
        .unwrap()
    };

    let table = stderr(&["--timings", "-q"]);
    assert!(table.contains("Phase") && table.contains("Detail"), "{table}");
    // The phases a plain run goes through, and the total.
    for phase in ["input", "manifest", "write", "total"] {
        assert!(table.contains(phase), "{phase} is missing from {table}");
    }
    // Offline, nothing was spent waiting, and the line says so rather than leaving it out —
    // whether the network phases took a measurable moment or no time at all.
    assert!(
        table.contains("none of it waiting on the network") || table.contains("of which 0.00 s waiting on the network"),
        "{table}"
    );

    // The enrichment phases appear only when they run.
    assert!(!table.contains("pypi metadata"), "{table}");
    let enriched = stderr(&["--timings", "-q", "--fetch-licenses"]);
    assert!(enriched.contains("pypi metadata"), "{enriched}");
    assert!(enriched.contains("wheels (dist-info)"), "{enriched}");

    // And nothing is printed without the flag.
    let quiet = stderr(&["-q"]);
    assert!(!quiet.contains("Phase"), "{quiet}");
}

#[test]
fn every_request_is_visible_at_debug_and_a_failure_names_its_cause() {
    let dir = workspace("with-pypi");
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .args(["-e", "web", "-p", "linux-64", "--output", "-"])
            .args(args);
        command
    };

    // Offline: the requests that were refused are named, so a run that came back with nothing
    // can be traced to what it did not ask.
    let refused = String::from_utf8(
        run(&["-v", "--fetch-licenses"])
            .env("PIXI_SBOM_OFFLINE", "1")
            .assert()
            .success()
            .get_output()
            .stderr
            .clone(),
    )
    .unwrap();
    assert!(refused.contains("refusing the request: offline"), "{refused}");
    assert!(refused.contains("url=https://pypi.org/pypi/"), "{refused}");
    // And the warning that follows carries the cause, not just "io".
    assert!(
        refused.contains("cause=") && refused.contains("PIXI_SBOM_OFFLINE is set"),
        "{refused}"
    );

    // A real request to a closed port: the debug line shows the attempt, the warning shows the
    // whole chain, and the run still succeeds.
    let unreachable = String::from_utf8(
        run(&["-v", "--fetch-licenses"])
            .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:1")
            .assert()
            .success()
            .get_output()
            .stderr
            .clone(),
    )
    .unwrap();
    assert!(unreachable.contains("requesting"), "{unreachable}");
    assert!(unreachable.contains("request failed"), "{unreachable}");
    assert!(
        unreachable.contains("127.0.0.1:1") && unreachable.contains("cause="),
        "{unreachable}"
    );

    // Nothing of this at the default level.
    let quiet = String::from_utf8(
        run(&["--fetch-licenses"])
            .env("PIXI_SBOM_OFFLINE", "1")
            .assert()
            .success()
            .get_output()
            .stderr
            .clone(),
    )
    .unwrap();
    assert!(!quiet.contains("requesting"), "{quiet}");
}

#[test]
fn fetch_licenses_never_fails_the_run_when_offline() {
    let dir = workspace("with-pypi");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["-e", "web", "-p", "linux-64", "--fetch-licenses", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("PIXI_SBOM_OFFLINE is set"))
        .stderr(predicate::str::contains("PyPI index unreachable"))
        .stderr(predicate::str::contains(
            "read PyPI license details from wheels fetched=0 failed=6",
        ))
        .stderr(predicate::str::contains("found=0 missing=0 failed=6"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let six = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "six")
        .unwrap();
    assert!(six.get("licenses").is_none());
}

fn cyclonedx_1_7_validator() -> Validator {
    let registry = Registry::new()
        .add(
            "http://cyclonedx.org/schema/spdx.schema.json",
            schema("spdx.schema.json"),
        )
        .unwrap()
        .add(
            "http://cyclonedx.org/schema/jsf-0.82.schema.json",
            schema("jsf-0.82.schema.json"),
        )
        .unwrap()
        .add(
            "http://cyclonedx.org/schema/cryptography-defs.schema.json",
            schema("cryptography-defs.schema.json"),
        )
        .unwrap()
        .prepare()
        .unwrap();
    jsonschema::options()
        .with_registry(&registry)
        .offline()
        .build(&schema("bom-1.7.schema.json"))
        .unwrap()
}

#[test]
fn spec_version_1_7_writes_a_valid_cyclonedx_1_7_document() {
    let dir = workspace("with-pypi");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["-e", "web", "-p", "linux-64", "--spec-version", "1.7", "--output", "-"])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_1_7_validator(), &doc);
    assert_eq!(doc["specVersion"], "1.7");
    assert_eq!(doc["$schema"], "http://cyclonedx.org/schema/bom-1.7.schema.json");
    let citation = &doc["citations"][0];
    assert_eq!(
        citation["attributedTo"],
        doc["metadata"]["tools"]["components"][0]["bom-ref"]
    );
    assert!(
        citation["note"]
            .as_str()
            .unwrap()
            .contains("environment web, platform linux-64")
    );

    // The default stays 1.6 and is unaffected.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["-e", "web", "-p", "linux-64", "--output", "-"])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(doc["specVersion"], "1.6");
    assert!(doc.get("citations").is_none());
}

#[test]
fn spec_version_must_belong_to_the_format() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--format", "spdx", "--spec-version", "1.7"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "'--spec-version 1.7' is not a version of '--format spdx'",
        ));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--spec-version", "3.0"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "'--spec-version 3.0' is not a version of '--format cyclonedx'",
        ));
}

fn sarif_validator() -> Validator {
    jsonschema::options()
        .offline()
        .build(&schema("sarif-schema-2.1.0.json"))
        .unwrap()
}

fn spdx3_validator() -> Validator {
    jsonschema::options()
        .offline()
        .build(&schema("spdx-3.0.1.schema.json"))
        .unwrap()
}

#[test]
fn spec_version_3_0_writes_a_valid_spdx_3_document() {
    let dir = workspace("with-pypi");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--spec-version",
            "3.0",
            "--output",
            "-",
        ])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx3_validator(), &doc);
    assert_eq!(doc["@context"], "https://spdx.org/rdf/3.0.1/spdx-context.jsonld");
    let graph = doc["@graph"].as_array().unwrap();
    let packages: Vec<_> = graph.iter().filter(|n| n["type"] == "software_Package").collect();
    assert_eq!(packages.len(), 1 + 30, "root + every locked package");
    assert!(packages.iter().any(|p| p["name"] == "requests"));
    let sbom = graph.iter().find(|n| n["type"] == "software_Sbom").unwrap();
    assert_eq!(sbom["name"], "with-pypi-web-linux-64");
    assert!(
        graph
            .iter()
            .any(|n| n["type"] == "Relationship" && n["relationshipType"] == "dependsOn")
    );

    // The default SPDX version is still 2.3.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["-e", "web", "-p", "linux-64", "--format", "spdx", "--output", "-"])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(doc["spdxVersion"], "SPDX-2.3");

    // Reproducible like the others.
    let a = pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .args([
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--spec-version",
            "3.0",
            "--output",
            "-",
        ])
        .assert()
        .success();
    let b = pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .args([
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--spec-version",
            "3.0",
            "--output",
            "-",
        ])
        .assert()
        .success();
    assert_eq!(a.get_output().stdout, b.get_output().stdout);
}

#[test]
fn fetch_licenses_reads_conda_details_from_the_package_cache() {
    let dir = workspace("conda-only");
    let cache = tests_dir().join("fixtures").join("package-cache");

    // Default: license type and file names, no texts.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", &cache)
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("sbom-cache"))
        .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
        .args(["-p", "linux-64", "--fetch-licenses", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("found=2 licenses_filled=0 files=1"));
    let stdout = assert.get_output().stdout.clone();
    let doc: Value = serde_json::from_slice(&stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let components = doc["components"].as_array().unwrap();
    let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
    let zlib = by_name("zlib");
    assert_eq!(zlib["licenses"][0]["expression"], "Zlib");
    assert!(
        zlib["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:license-file" && p["value"] == "license.txt")
    );
    assert!(
        !String::from_utf8_lossy(&stdout).contains("Jean-loup Gailly"),
        "texts are not embedded by default"
    );
    assert_eq!(
        zlib["description"],
        "Massively spiffy yet delicately unobtrusive compression library"
    );
    assert!(
        zlib["externalReferences"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["type"] == "documentation" && r["url"] == "https://zlib.net/manual.html")
    );
    assert!(
        zlib["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:license-files-source" && p["value"] == "package-cache")
    );
    let libzlib = by_name("libzlib");
    assert_eq!(
        libzlib["licenses"][0]["expression"], "Zlib",
        "no file: plain expression"
    );
    assert_eq!(libzlib["description"], "zlib shared library");

    // --license-texts embeds the text as a license object.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", &cache)
        .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
        .args(["-p", "linux-64", "--fetch-licenses", "--license-texts", "--output", "-"])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let zlib = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "zlib")
        .unwrap();
    assert_eq!(zlib["licenses"][0]["license"]["id"], "Zlib");
    assert!(
        zlib["licenses"][0]["license"]["text"]["content"]
            .as_str()
            .unwrap()
            .contains("Jean-loup Gailly")
    );

    // SPDX carries the file name and summary.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", &cache)
        .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
        .args([
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--fetch-licenses",
            "--output",
            "-",
        ])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx_validator(), &doc);
    let zlib = doc["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "zlib")
        .unwrap();
    assert_eq!(zlib["licenseComments"], "License files: license.txt");
    assert_eq!(zlib["homepage"], "https://zlib.net/");
    assert_eq!(
        zlib["summary"],
        "Massively spiffy yet delicately unobtrusive compression library"
    );
}
#[test]
fn pypi_licenses_is_a_deprecated_alias_and_license_texts_needs_fetch_licenses() {
    let dir = workspace("conda-only");
    let cache = tests_dir().join("fixtures").join("package-cache");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", &cache)
        .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
        .args(["-p", "linux-64", "--pypi-licenses", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("--pypi-licenses is deprecated"))
        .stderr(predicate::str::contains("found=2"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);

    // --license-texts alone is a usage error.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--license-texts"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--license-texts"));
}
#[test]
fn report_packages_prints_a_table_and_writes_nothing() {
    let dir = workspace("with-pypi");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("COLUMNS", "100")
        .args(["-e", "web", "-p", "linux-64", "--report", "packages"])
        .assert()
        .success();
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(text.starts_with("Name"), "{text}");
    assert!(text.contains("requests"));
    assert!(text.contains("  pypi  "));
    assert!(text.contains("  conda  "));
    assert!(
        text.lines().all(|l| l.chars().count() <= 100),
        "fits the terminal width"
    );
    assert!(!dir.path().join("sbom.cdx.json").exists());
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        2,
        "only pixi.toml and pixi.lock remain"
    );
}

#[test]
fn report_licenses_in_every_format_with_fetch_licenses() {
    let dir = workspace("conda-only");
    let cache = tests_dir().join("fixtures").join("package-cache");

    let run = |format: &str| {
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", &cache)
            .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
            .args([
                "-p",
                "linux-64",
                "--fetch-licenses",
                "--report",
                "licenses",
                "--report-format",
                format,
            ])
            .assert()
            .success();
        String::from_utf8(assert.get_output().stdout.clone()).unwrap()
    };

    let table = run("table");
    assert!(
        table.contains("zlib     1.3.2    conda  Zlib     Other   lockfile  1"),
        "{table}"
    );
    assert!(table.contains("Summary: 2 packages, 1 distinct licenses"));
    assert!(table.contains("No license: none"));

    let markdown = run("markdown");
    assert!(markdown.starts_with("## licenses (conda-only, environment default, platform linux-64)"));
    assert!(markdown.contains("| zlib | 1.3.2 | conda | Zlib | Other | lockfile | 1 |"));

    let csv = run("csv");
    assert_eq!(
        csv.lines().next().unwrap(),
        "environment,platform,name,version,kind,license,spdx,spdx_reason,license_family,license_source,license_files,purl"
    );
    assert!(
        csv.contains("default,linux-64,zlib,1.3.2,conda,Zlib,true,,Other,lockfile,license.txt,pkg:conda/zlib@1.3.2")
    );

    let json: Value = serde_json::from_str(&run("json")).unwrap();
    assert_eq!(json["report"], "licenses");
    assert_eq!(json["summary"]["by_license"][0][0], "Zlib");
    assert_eq!(json["summary"]["by_license"][0][1], 2);
    assert_eq!(json["packages"][1]["license_files"][0], "license.txt");
}

#[test]
fn report_batch_mode_prints_one_section_per_document() {
    let dir = workspace("conda-only");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-platforms", "--report", "packages"])
        .assert()
        .success();
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(text.contains("packages (conda-only, environment default, platform linux-64)"));
    assert!(text.contains("packages (conda-only, environment default, platform osx-arm64)"));
    assert!(!dir.path().join("sbom-linux-64.cdx.json").exists());

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-platforms", "--report", "packages", "--report-format", "json"])
        .assert()
        .success();
    let json: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 2);
}

#[test]
fn report_rejects_output_and_report_format_needs_report() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--report", "packages", "--output", "x.json"])
        .assert()
        .code(2);
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--report-format", "csv"])
        .assert()
        .code(2);
}

/// A copy of the `conda-only` fixture whose linux-64 zlib entry points at the real archive in
/// `tests/fixtures/archives/` through a `file://` URL, so the network fallback runs offline.
fn workspace_with_local_archive() -> tempfile::TempDir {
    let dir = workspace("conda-only");
    let archive = tests_dir()
        .join("fixtures")
        .join("archives")
        .join("zlib-1.3.2-h25fd6f3_3.conda");
    // Windows runners check out with CRLF; normalize so the replacements below match.
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n");
    // file:///D:/x on Windows, file:///abs/path elsewhere.
    let path = archive.display().to_string().replace('\\', "/");
    let url = format!("file://{}{path}", if path.starts_with('/') { "" } else { "/" });
    let lock = lock
        .replace(
            "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.3.2-h25fd6f3_3.conda",
            &url,
        )
        // A file:// location carries no channel/subdir, so the record must state it.
        .replace(
            &format!("- conda: {url}\n  sha256:"),
            &format!("- conda: {url}\n  subdir: linux-64\n  sha256:"),
        )
        // libzlib points at an archive that does not exist, so its fetch fails offline.
        .replace(
            "https://conda.anaconda.org/conda-forge/linux-64/libzlib-1.3.2-h25fd6f3_3.conda",
            "file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.conda",
        )
        .replace(
            "- conda: file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.conda\n  sha256:",
            "- conda: file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.conda\n  subdir: linux-64\n  sha256:",
        );
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();
    dir
}

#[test]
fn fetch_licenses_reads_the_archive_when_the_package_cache_misses() {
    let dir = workspace_with_local_archive();
    let empty_cache = dir.path().join("empty-pkgs-cache");
    let sbom_cache = dir.path().join("sbom-cache");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", &empty_cache)
        .env("PIXI_SBOM_CACHE_DIR", &sbom_cache)
        .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
        .args(["-p", "linux-64", "--fetch-licenses", "--license-texts", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "read conda license details from channel archives fetched=1 failed=1",
        ));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let zlib = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "zlib")
        .unwrap();
    assert_eq!(zlib["licenses"][0]["license"]["id"], "Zlib");
    assert!(
        zlib["licenses"][0]["license"]["text"]["content"]
            .as_str()
            .unwrap()
            .contains("Jean-loup Gailly")
    );
    assert_eq!(
        zlib["description"],
        "Massively spiffy yet delicately unobtrusive compression library"
    );
    assert!(
        zlib["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:license-files-source" && p["value"] == "conda-archive")
    );
    // The extracted info is cached by sha256 for the next run.
    let sha = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "zlib")
        .unwrap()["hashes"][0]["content"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        sbom_cache
            .join("conda-info")
            .join(&sha)
            .join("info/about.json")
            .exists()
    );

    // libzlib's archive does not exist; it kept the lockfile's license and the run succeeded.
    let libzlib = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "libzlib")
        .unwrap();
    assert_eq!(libzlib["licenses"][0]["expression"], "Zlib");
}

/// The `conda-only` fixture with zlib pointed at the small legacy `.tar.bz2` archive in
/// `tests/fixtures/archives/` and libzlib at a legacy archive the lockfile says is huge.
fn workspace_with_legacy_archive() -> tempfile::TempDir {
    let dir = workspace("conda-only");
    let archive = tests_dir()
        .join("fixtures")
        .join("archives")
        .join("zlib-1.3.2-h25fd6f3_3.tar.bz2");
    let path = archive.display().to_string().replace('\\', "/");
    let url = format!("file://{}{path}", if path.starts_with('/') { "" } else { "/" });
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n")
        .replace(
            "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.3.2-h25fd6f3_3.conda",
            &url,
        )
        .replace(
            &format!("- conda: {url}\n  sha256: 16080a1c7724f7d25727cdc23c7658e0cec2db52448c1dc0c33467ee2c6e1c62"),
            &format!("- conda: {url}\n  subdir: linux-64\n  sha256: d4b0036253168923ee9056a5198f1fc55c7e65cf8f826a4ba8e8afd94a72c97f"),
        )
        .replace("  size: 96132\n", "  size: 4762\n")
        .replace(
            "https://conda.anaconda.org/conda-forge/linux-64/libzlib-1.3.2-h25fd6f3_3.conda",
            "file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.tar.bz2",
        )
        .replace(
            "- conda: file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.tar.bz2\n  sha256:",
            "- conda: file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.tar.bz2\n  subdir: linux-64\n  sha256:",
        )
        .replace("  size: 63713\n", "  size: 40000000\n");
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();
    dir
}

#[test]
fn fetch_licenses_reads_small_legacy_archives_whole_and_skips_large_ones() {
    let dir = workspace_with_legacy_archive();
    let sbom_cache = dir.path().join("sbom-cache");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", &sbom_cache)
        .env("PIXI_SBOM_OFFLINE", "1")
        .env("RUST_LOG", "debug")
        .args(["-p", "linux-64", "--fetch-licenses", "--license-texts", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "read conda license details from channel archives fetched=1 failed=0 skipped=1",
        ))
        .stderr(predicate::str::contains("too large to download whole").and(predicate::str::contains("size=40000000")));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let components = doc["components"].as_array().unwrap();
    let zlib = components.iter().find(|c| c["name"] == "zlib").unwrap();
    assert_eq!(zlib["licenses"][0]["license"]["id"], "Zlib");
    assert!(
        zlib["licenses"][0]["license"]["text"]["content"]
            .as_str()
            .unwrap()
            .contains("Jean-loup Gailly")
    );
    assert!(
        zlib["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:license-files-source" && p["value"] == "conda-archive")
    );
    assert!(
        sbom_cache
            .join("conda-info")
            .join("d4b0036253168923ee9056a5198f1fc55c7e65cf8f826a4ba8e8afd94a72c97f")
            .join("info/about.json")
            .exists()
    );
    // libzlib's archive was too large to fetch; it kept the lockfile's license.
    let libzlib = components.iter().find(|c| c["name"] == "libzlib").unwrap();
    assert_eq!(libzlib["licenses"][0]["expression"], "Zlib");
    assert!(libzlib["licenses"][0]["license"].is_null());
}

/// The `with-pypi` fixture with urllib3 pinned to the vulnerable 1.26.4 wheel.
fn workspace_with_vulnerable_urllib3() -> tempfile::TempDir {
    let dir = workspace("with-pypi");
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n")
        .replace(
            "packages/92/9d/c4e665119135114480843e7ab388fa94d8480650450e6f8e26b70d323a4c/urllib3-2.8.0-py3-none-any.whl",
            "packages/09/c6/d3e3abe5b4f4f16cf0dfc9240ab7ce10c2baa0e268989a4e3ec19e90c84e/urllib3-1.26.4-py2.py3-none-any.whl",
        )
        .replace("\n  version: 2.8.0\n", "\n  version: 1.26.4\n")
        .replace(
            "0cf3cae568d36aa9576b28dfb35f11328f1cb974ca7647d9475ebb86c75ac6e3",
            "2f4da4594db7e1e110a944bb1b551fdf4e6c136ad42e4234131391e21eb5b0df",
        );
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();
    // Recorded OSV responses stand in for the API.
    let osv = tests_dir().join("fixtures").join("osv");
    for sub in ["queries", "vulns"] {
        let target = dir.path().join("cache").join("osv").join(sub);
        std::fs::create_dir_all(&target).unwrap();
        for entry in std::fs::read_dir(osv.join(sub)).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        }
    }
    dir
}

#[test]
fn the_packages_tree_and_the_grouped_licenses_view() {
    let dir = workspace("with-pypi");
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("COLUMNS", "160")
            .args(["-e", "web", "-p", "linux-64", "--color", "never"])
            .args(args);
        command
    };
    let text = |args: &[&str]| -> String {
        String::from_utf8(run(args).assert().success().get_output().stdout.clone()).unwrap()
    };

    let tree = text(&["--report", "packages", "--tree"]);
    assert!(tree.lines().next().unwrap().starts_with("Package"), "{tree}");
    // python is a root (the manifest declares it) and everything it needs hangs under it.
    assert!(tree.contains("\npython "), "{tree}");
    assert!(tree.contains("├── ") && tree.contains("└── "), "{tree}");
    assert!(
        tree.contains("(*)"),
        "a package that appears twice is marked once: {tree}"
    );
    // The graph is deep here, so a depth cap makes a real difference.
    let shallow = text(&["--report", "packages", "--tree", "--depth", "0"]);
    assert!(!shallow.contains("└── "), "{shallow}");
    assert!(shallow.lines().count() < tree.lines().count(), "{shallow}");

    // JSON keeps rows, with the place in the tree on each.
    let report: Value = serde_json::from_slice(
        &run(&["--report", "packages", "--tree", "--report-format", "json"])
            .assert()
            .success()
            .get_output()
            .stdout,
    )
    .unwrap();
    let rows = report["packages"].as_array().unwrap();
    assert!(rows.iter().all(|r| r["depth"].is_number()), "{rows:?}");
    assert!(
        rows.iter()
            .any(|r| r["depth"].as_u64() == Some(1) && r["parent"].is_string()),
        "{rows:?}"
    );

    let grouped = text(&["--report", "licenses", "--group-by", "license"]);
    assert!(grouped.contains("MIT ("), "{grouped}");
    assert!(
        !grouped.lines().next().unwrap().contains("License"),
        "the license is the heading, not a column: {grouped}"
    );
    assert!(grouped.contains("Summary: "), "the summary still follows: {grouped}");
    let markdown = text(&[
        "--report",
        "licenses",
        "--group-by",
        "license",
        "--report-format",
        "markdown",
    ]);
    assert!(markdown.contains("### MIT ("), "{markdown}");

    for (flag, message) in [
        (vec!["--report", "licenses", "--tree"], "'--tree' only applies"),
        (
            vec!["--report", "packages", "--group-by", "license"],
            "'--group-by' only applies",
        ),
    ] {
        run(&flag).assert().code(2).stderr(predicate::str::contains(message));
    }
}

#[test]
fn explain_says_where_every_fact_came_from_and_what_came_back_empty() {
    let dir = workspace("with-pypi");
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("COLUMNS", "160")
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["-e", "web", "-p", "linux-64", "--color", "never"])
            .args(args);
        command
    };
    let text = |args: &[&str]| -> String {
        String::from_utf8(run(args).assert().success().get_output().stdout.clone()).unwrap()
    };

    // The lockfile is what knows six is here at all, and it says so on every fact it supplied.
    let six = text(&["--explain", "six"]);
    assert!(six.lines().next().unwrap().starts_with("Package"), "{six}");
    assert!(
        six.contains("identity") && six.contains("pkg:pypi/six@1.17.0") && six.contains("lockfile pixi.lock"),
        "{six}"
    );
    assert!(
        six.contains("declared") && six.contains("the workspace manifest"),
        "the manifest declares six itself: {six}"
    );
    // Nothing was fetched, so the sources that could have answered say why they did not.
    assert!(six.contains("--fetch-licenses was not given"), "{six}");
    assert!(six.contains("--vulnerabilities was not given"), "{six}");
    assert!(six.contains("Summary: ") && six.contains("Asked about: six"), "{six}");
    assert!(!dir.path().join("sbom.cdx.json").exists(), "nothing is written");

    // A glob picks the packages the same way --exclude does.
    let globbed = text(&["--explain", "libz*"]);
    assert!(globbed.contains("libzlib"), "{globbed}");
    assert!(!globbed.contains("\nsix "), "only what the pattern matched: {globbed}");

    // The JSON form carries the same facts, one object per fact.
    let report: Value = serde_json::from_slice(
        &run(&["--explain", "six", "--report-format", "json"])
            .assert()
            .success()
            .get_output()
            .stdout,
    )
    .unwrap();
    assert_eq!(report["report"], "explain");
    let rows = report["explain"].as_array().unwrap();
    let fact = |name: &str| rows.iter().find(|row| row["fact"] == name).unwrap();
    assert_eq!(fact("identity")["value"], "pkg:pypi/six@1.17.0");
    assert_eq!(fact("identity")["source"], "lockfile pixi.lock");
    assert_eq!(fact("declared")["source"], "the workspace manifest");
    assert!(fact("license").get("value").is_none(), "the lockfile declares none");
    assert!(
        fact("license")["considered"]
            .as_array()
            .unwrap()
            .iter()
            .any(|line| line.as_str().unwrap().contains("--fetch-licenses was not given")),
        "{rows:?}"
    );
    assert_eq!(report["summary"]["matched"], 1);
    assert_eq!(report["summary"]["patterns"][0], "six");

    // A pattern nothing matches is said out loud rather than printed as an empty table.
    let nothing = text(&["--explain", "not-a-package"]);
    assert_eq!(
        nothing.trim(),
        "No package in this environment matches --explain not-a-package"
    );

    // It prints instead of writing, so it rules out --output exactly as --report does.
    run(&["--explain", "six", "--output", "-"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with '--output"));
}

#[test]
fn vex_is_written_beside_the_document_and_links_into_it() {
    let dir = workspace_with_vulnerable_urllib3();
    let sbom = dir.path().join("sbom.cdx.json");
    let vex = dir.path().join("vex.cdx.json");
    let run = |extra: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["-e", "web", "-p", "linux-64", "--vulnerabilities", "osv"])
            .args(extra);
        command
    };

    run(&["--output", sbom.to_str().unwrap(), "--vex", vex.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("wrote VEX"));

    let document = read_json(&sbom);
    let vexed = read_json(&vex);
    assert_valid(&cyclonedx_validator(), &vexed);
    assert_eq!(vexed["bomFormat"], "CycloneDX");
    assert!(
        vexed["components"].as_array().is_none_or(|c| c.is_empty()),
        "a VEX carries findings, not components"
    );
    assert_ne!(vexed["serialNumber"], document["serialNumber"], "its own identity");
    let properties: Vec<(&str, &str)> = vexed["metadata"]["properties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["name"].as_str().unwrap(), p["value"].as_str().unwrap()))
        .collect();
    assert!(
        properties.contains(&("pixi:vex-for", document["serialNumber"].as_str().unwrap())),
        "{properties:?}"
    );

    let findings = vexed["vulnerabilities"].as_array().unwrap();
    assert_eq!(findings.len(), document["vulnerabilities"].as_array().unwrap().len());
    // Every finding is assessed, and nobody has looked at these yet.
    assert!(
        findings
            .iter()
            .all(|v| v["analysis"]["state"].as_str() == Some("in_triage")),
        "{findings:?}"
    );
    // The references point into the SBOM by BOM-Link, and resolve to components in it.
    let serial = document["serialNumber"]
        .as_str()
        .unwrap()
        .trim_start_matches("urn:uuid:");
    let refs: Vec<&str> = findings
        .iter()
        .flat_map(|v| v["affects"].as_array().unwrap())
        .map(|a| a["ref"].as_str().unwrap())
        .collect();
    assert!(!refs.is_empty());
    for reference in &refs {
        let (link, bom_ref) = reference.split_once('#').expect("a BOM-Link element");
        assert_eq!(link, format!("urn:cdx:{serial}/1"), "{reference}");
        assert!(
            document["components"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["bom-ref"] == bom_ref),
            "{bom_ref} is in the SBOM"
        );
    }

    // An assessed finding keeps its own state; the rest take --vex-open.
    let assessed = document["vulnerabilities"][0]["id"].as_str().unwrap().to_string();
    run(&[
        "--output",
        sbom.to_str().unwrap(),
        "--vex",
        vex.to_str().unwrap(),
        "--vex-open",
        "exploitable",
        "--ignore-vuln",
        &format!("{assessed}:not reachable from our code"),
    ])
    .assert()
    .success();
    let vexed = read_json(&vex);
    let states: Vec<(&str, &str)> = vexed["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (v["id"].as_str().unwrap(), v["analysis"]["state"].as_str().unwrap()))
        .collect();
    assert!(states.contains(&(assessed.as_str(), "not_affected")), "{states:?}");
    assert!(
        states.iter().filter(|(_, state)| *state == "exploitable").count() >= 1,
        "{states:?}"
    );
    let detail = vexed["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == assessed.as_str())
        .unwrap()["analysis"]["detail"]
        .as_str()
        .unwrap();
    assert_eq!(detail, "not reachable from our code");

    // A machine-readable justification and a response reach the VEX, and 1.7 accepts them as
    // 1.6 does.
    let other = document["vulnerabilities"][1]["id"].as_str().unwrap().to_string();
    run(&[
        "--spec-version",
        "1.7",
        "--output",
        sbom.to_str().unwrap(),
        "--vex",
        vex.to_str().unwrap(),
        "--ignore-vuln",
        &format!("{assessed}:not_affected:code_not_present:the module is stripped"),
        "--ignore-vuln",
        &format!("{other}:exploitable:update,workaround_available:pin urllib3>=2"),
    ])
    .assert()
    .success();
    let vexed = read_json(&vex);
    assert_valid(&cyclonedx_1_7_validator(), &vexed);
    let responded = &vexed["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == other.as_str())
        .unwrap()["analysis"];
    assert_eq!(responded["state"], "exploitable");
    assert_eq!(
        responded["response"],
        serde_json::json!(["update", "workaround_available"])
    );
    assert_eq!(responded["detail"], "pin urllib3>=2");
    assert_valid(&cyclonedx_1_7_validator(), &read_json(&sbom));
    let analysis = &vexed["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == assessed.as_str())
        .unwrap()["analysis"];
    assert_eq!(analysis["justification"], "code_not_present");
    assert_eq!(analysis["detail"], "the module is stripped");

    // A justification explains not_affected and nothing else.
    run(&[
        "--output",
        "-",
        "--ignore-vuln",
        &format!("{assessed}:exploitable:code_not_present:text"),
    ])
    .assert()
    .code(2)
    .stderr(predicate::str::contains("only applies to the not_affected state"));

    // A VEX needs findings to assess, and one document to point at.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--vex", "vex.json", "--output", "-"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("needs '--vulnerabilities"));
    run(&["--vex", "vex.json", "--report", "vulnerabilities"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be combined with '--report'"));

    // A CycloneDX VEX links into a CycloneDX BOM, so SPDX output of any version is refused,
    // and nothing is written.
    for spec in ["2.3", "3.0"] {
        run(&["--format", "spdx", "--spec-version", spec, "--vex", "spdx-vex.json"])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("cannot be combined with '--format spdx'"))
            .stderr(predicate::str::contains("--spec-version 3.0"));
    }
    assert!(!dir.path().join("spdx-vex.json").exists());

    // The same holds when the configuration file asks for SPDX.
    std::fs::write(dir.path().join("pixi-sbom.toml"), "format = \"spdx\"\n").unwrap();
    run(&["--vex", "spdx-vex.json"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be combined with '--format spdx'"));
    std::fs::remove_file(dir.path().join("pixi-sbom.toml")).unwrap();
}

#[test]
fn from_sbom_runs_the_pipeline_on_an_existing_document() {
    let dir = workspace_with_vulnerable_urllib3();
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .args(args);
        command
    };

    // The document the lockfile produces, and the same document read back in.
    let source = dir.path().join("source.cdx.json");
    run(&["-e", "web", "-p", "linux-64", "--output"])
        .arg(&source)
        .assert()
        .success();
    let derived = dir.path().join("derived.cdx.json");
    run(&["--from-sbom"])
        .arg(&source)
        .arg("--output")
        .arg(&derived)
        .assert()
        .success()
        .stderr(predicate::str::contains("read the source document"));

    let (before, after) = (read_json(&source), read_json(&derived));
    assert_valid(&cyclonedx_validator(), &after);
    let packages = |document: &Value| -> Vec<(String, String)> {
        document["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["purl"].as_str().unwrap().to_string(), c["licenses"].to_string()))
            .collect()
    };
    assert_eq!(packages(&before), packages(&after), "packages and licenses survive");
    let edges = |document: &Value| -> Vec<String> {
        document["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| format!("{} -> {}", e["ref"], e["dependsOn"]))
            .collect()
    };
    assert_eq!(edges(&before), edges(&after), "and so does the graph");
    // The derivation is traceable, and the lockfile is no longer claimed as the input.
    let properties: Vec<(&str, &str)> = after["metadata"]["properties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["name"].as_str().unwrap(), p["value"].as_str().unwrap()))
        .collect();
    assert!(
        properties.contains(&("pixi:source-document", before["serialNumber"].as_str().unwrap())),
        "{properties:?}"
    );
    assert!(!properties.iter().any(|(name, _)| *name == "pixi:lockfile"));

    // The gates read the document as they read a lockfile: the same nine findings, and the
    // same license violation.
    let report: Value = serde_json::from_slice(
        &run(&[
            "--from-sbom",
            source.to_str().unwrap(),
            "--vulnerabilities",
            "osv",
            "--report",
            "vulnerabilities",
            "--report-format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout,
    )
    .unwrap();
    assert_eq!(report["vulnerabilities"].as_array().unwrap().len(), 9);
    run(&[
        "--from-sbom",
        source.to_str().unwrap(),
        "--deny-license",
        "Zlib",
        "--output",
        "-",
    ])
    .assert()
    .code(3)
    .stderr(predicate::str::contains("License policy violated"));

    // And the reports work on somebody else's document, purls being all they need.
    let table = String::from_utf8(
        run(&[
            "--from-sbom",
            source.to_str().unwrap(),
            "--report",
            "packages",
            "--color",
            "never",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone(),
    )
    .unwrap();
    assert!(table.contains("urllib3"), "{table}");

    // A file that is no document at all says so.
    run(&["--from-sbom", "pixi.toml", "--output", "-"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("pixi_sbom::from_sbom::parse"));
    run(&[
        "--from-sbom",
        source.to_str().unwrap(),
        "--all-environments",
        "--output",
        "out",
    ])
    .assert()
    .code(2)
    .stderr(predicate::str::contains("cannot be combined with '--from-sbom'"));
}

#[test]
fn vulnerabilities_from_osv_are_recorded_in_cyclonedx() {
    let dir = workspace_with_vulnerable_urllib3();
    let run = |extra: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args([
                "-e",
                "web",
                "-p",
                "linux-64",
                "--vulnerabilities",
                "osv",
                "--output",
                "-",
            ])
            .args(extra)
            .assert()
    };
    let assert = run(&[]).success().stderr(predicate::str::contains(
        "looked up vulnerabilities on OSV queried=6 without_identity=24 findings=9 failed=0",
    ));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let vulns = doc["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulns.len(), 9);
    // Worst first; every finding is a GHSA record with its PYSEC twin merged in as an alias.
    assert_eq!(vulns[0]["ratings"][0]["severity"], "high");
    assert_eq!(vulns[8]["ratings"][0]["severity"], "medium");
    assert!(vulns.iter().all(|v| v["id"].as_str().unwrap().starts_with("GHSA-")));
    let regex = vulns.iter().find(|v| v["id"] == "GHSA-q2q7-5pp4-w6pg").unwrap();
    assert_eq!(regex["affects"][0]["ref"], "pkg:pypi/urllib3@1.26.4");
    assert_eq!(regex["recommendation"], "Upgrade urllib3 to 1.26.5");
    assert!(
        regex["references"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "CVE-2021-33503")
    );
    // The affected component exists under that bom-ref.
    assert!(
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["bom-ref"] == "pkg:pypi/urllib3@1.26.4")
    );

    // CycloneDX 1.7 carries the same array and validates too.
    let assert = run(&["--spec-version", "1.7"]).success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_1_7_validator(), &doc);
    assert_eq!(doc["vulnerabilities"].as_array().unwrap().len(), 9);

    // SPDX 2.3 has no place for them: the document is written and a warning points at 3.0,
    // which since #118 does carry them.
    run(&["--format", "spdx"])
        .success()
        .stderr(predicate::str::contains("SPDX 2.3 does not record vulnerabilities"))
        .stderr(predicate::str::contains("--spec-version 3.0"));
}

#[test]
fn vulnerabilities_report_lists_findings_worst_first() {
    let dir = workspace_with_vulnerable_urllib3();
    let run = |format: &str| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .args(["-e", "web", "-p", "linux-64", "--vulnerabilities", "osv"])
            .args(["--report", "vulnerabilities", "--report-format", format])
            .assert()
            .success()
    };
    let table = String::from_utf8(run("table").get_output().stdout.clone()).unwrap();
    assert!(
        table.starts_with("Package  Version  Severity  Score  KEV  ID"),
        "{table}"
    );
    assert!(
        table.contains("urllib3  1.26.4   high      7.5    -    GHSA-q2q7-5pp4-w6pg"),
        "{table}"
    );
    assert!(table.contains("Summary: 9 findings in 1 packages"), "{table}");
    assert!(table.contains("high      6\nmedium    3"), "{table}");
    assert!(table.contains("No queryable identity (24):"), "{table}");
    let first_medium = table.find("medium").unwrap();
    let last_high = table.rfind("  high  ").unwrap();
    assert!(last_high < first_medium, "worst first");

    let csv = String::from_utf8(run("csv").get_output().stdout.clone()).unwrap();
    assert!(csv.starts_with(
        "environment,platform,package,version,purl,severity,score,kev,kev_due_date,id,aliases,fixed_version,status,summary,url\n"
    ));
    assert_eq!(csv.lines().count(), 10);

    let markdown = String::from_utf8(run("markdown").get_output().stdout.clone()).unwrap();
    assert!(markdown.contains("## vulnerabilities (with-pypi, environment web, platform linux-64)"));
    assert!(markdown.contains("| Severity | Findings |"));

    let json: Value = serde_json::from_slice(&run("json").get_output().stdout).unwrap();
    assert_eq!(json["report"], "vulnerabilities");
    assert_eq!(json["vulnerabilities"].as_array().unwrap().len(), 9);
    assert_eq!(json["summary"]["findings"], 9);
    assert_eq!(json["summary"]["without_identity"].as_array().unwrap().len(), 24);

    // The report needs something to report on.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--report", "vulnerabilities"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("needs '--vulnerabilities <SOURCE>'"));
}

#[test]
fn fail_on_severity_exits_4_after_writing_and_ignores_are_recorded() {
    let dir = workspace_with_vulnerable_urllib3();
    let base = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .args(["-e", "web", "-p", "linux-64", "--vulnerabilities", "osv"])
            .args(args)
            .assert()
    };
    // Six high findings trip a high gate; the document is still written.
    let out = dir.path().join("gated.cdx.json");
    base(&["--fail-on-severity", "high", "--output", out.to_str().unwrap()])
        .code(4)
        .stderr(predicate::str::contains(
            "Vulnerability gate failed: 6 finding(s) at or above high:",
        ))
        .stderr(predicate::str::contains("GHSA-q2q7-5pp4-w6pg (high): urllib3 1.26.4"));
    let doc = read_json(&out);
    assert_valid(&cyclonedx_validator(), &doc);
    assert_eq!(doc["vulnerabilities"].as_array().unwrap().len(), 9);

    // Nothing is critical, so a critical gate passes.
    base(&["--fail-on-severity", "critical", "--output", "-"]).success();

    // Ignoring every high finding (by GHSA id or CVE alias) lets the high gate pass; the
    // findings stay in the document with their analysis.
    let assert = base(&[
        "--fail-on-severity",
        "high",
        "--ignore-vuln",
        "GHSA-2xpw-w6gg-jr37:not_affected:code_not_reachable:streaming API unused",
        "--ignore-vuln",
        "GHSA-38jv-5279-wg99",
        "--ignore-vuln",
        "CVE-2025-66418",
        "--ignore-vuln",
        "GHSA-q2q7-5pp4-w6pg:false_positive:can_not_fix:wrong package",
        "--ignore-vuln",
        "GHSA-qccp-gfcp-xxvc",
        "--ignore-vuln",
        "GHSA-v845-jxx5-vc9f",
        "--output",
        "-",
    ])
    .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let vulns = doc["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulns.len(), 9, "ignored findings are still recorded");
    let streaming = vulns.iter().find(|v| v["id"] == "GHSA-2xpw-w6gg-jr37").unwrap();
    assert_eq!(streaming["analysis"]["state"], "not_affected");
    assert_eq!(streaming["analysis"]["detail"], "streaming API unused");
    assert_eq!(streaming["analysis"]["justification"], "code_not_reachable");
    let wrong = vulns.iter().find(|v| v["id"] == "GHSA-q2q7-5pp4-w6pg").unwrap();
    assert_eq!(wrong["analysis"]["response"], serde_json::json!(["can_not_fix"]));
    assert_eq!(wrong["analysis"]["detail"], "wrong package");
    let by_cve = vulns.iter().find(|v| v["id"] == "GHSA-gm62-xv2j-4w53").unwrap();
    assert_eq!(by_cve["analysis"]["state"], "not_affected");
    assert!(by_cve["analysis"].get("detail").is_none());
    let open = vulns.iter().find(|v| v["id"] == "GHSA-34jh-p97f-mpxf").unwrap();
    assert!(open.get("analysis").is_none());

    // The report shows ignored findings last and lists them with their justification.
    let table = String::from_utf8(
        base(&[
            "--ignore-vuln",
            "GHSA-q2q7-5pp4-w6pg:false_positive:wrong package",
            "--report",
            "vulnerabilities",
        ])
        .success()
        .get_output()
        .stdout
        .clone(),
    )
    .unwrap();
    assert!(
        table.contains("Summary: 8 open findings in 1 packages, 1 ignored"),
        "{table}"
    );
    assert!(
        table.contains("Ignored (1):\n  GHSA-q2q7-5pp4-w6pg (false_positive): wrong package"),
        "{table}"
    );
    let ignored_row = table.lines().find(|l| l.contains("GHSA-q2q7-5pp4-w6pg")).unwrap();
    assert!(ignored_row.contains("  ignored  "), "{ignored_row}");
    let lines: Vec<&str> = table.lines().collect();
    let last_open = lines.iter().rposition(|l| l.contains("  open  ")).unwrap();
    let ignored_at = lines.iter().position(|l| *l == ignored_row).unwrap();
    assert!(ignored_at > last_open, "ignored rows come last");

    // Both flags need --vulnerabilities; a malformed ignore is a usage error.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--fail-on-severity", "high"])
        .assert()
        .code(2);
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--vulnerabilities", "osv", "--ignore-vuln", ":nothing"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--ignore-vuln"));
}

#[test]
fn kev_marks_known_exploited_findings_and_gates_on_them() {
    let dir = workspace_with_vulnerable_urllib3();
    // The recorded catalog excerpt stands in for CISA's feed.
    let kev_dir = dir.path().join("cache").join("kev");
    std::fs::create_dir_all(&kev_dir).unwrap();
    std::fs::copy(
        tests_dir()
            .join("fixtures")
            .join("kev")
            .join("known_exploited_vulnerabilities.json"),
        kev_dir.join("known_exploited_vulnerabilities.json"),
    )
    .unwrap();
    let base = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "220")
            .args(["-e", "web", "-p", "linux-64", "--vulnerabilities", "osv", "--kev"])
            .args(args)
            .assert()
    };
    let assert = base(&["--output", "-"])
        .success()
        .stderr(predicate::str::contains("loaded the CISA KEV catalog entries=2"))
        .stderr(predicate::str::contains(
            "matched findings against the CISA KEV catalog known_exploited=1",
        ));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let vulns = doc["vulnerabilities"].as_array().unwrap();
    // Known exploited: rated critical, first in the list, with the catalog facts as properties.
    assert_eq!(vulns[0]["id"], "GHSA-q2q7-5pp4-w6pg");
    assert!(
        vulns[0]["ratings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["source"]["name"] == "CISA KEV" && r["severity"] == "critical")
    );
    let props = vulns[0]["properties"].as_array().unwrap();
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:kev-due-date" && p["value"] == "2026-09-22")
    );
    assert!(vulns[1].get("properties").is_none());

    // The KEV gate: exit 4 naming the finding; ignoring it passes.
    base(&["--fail-on-kev", "--output", "-"])
        .code(4)
        .stderr(predicate::str::contains(
            "Vulnerability gate failed: 1 finding(s) known exploited:",
        ))
        .stderr(predicate::str::contains(
            "GHSA-q2q7-5pp4-w6pg (critical, known exploited): urllib3 1.26.4",
        ));
    base(&[
        "--fail-on-kev",
        "--ignore-vuln",
        "CVE-2021-33503:mitigated",
        "--output",
        "-",
    ])
    .success();

    // The report carries a KEV column and the known-exploited list.
    let table = String::from_utf8(
        base(&["--report", "vulnerabilities"])
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(table.contains("  KEV  "), "{table}");
    assert!(table.contains("critical  7.5    yes  GHSA-q2q7-5pp4-w6pg"), "{table}");
    assert!(
        table.contains("Known exploited (CISA KEV) (1):\n  GHSA-q2q7-5pp4-w6pg (CVE-2021-33503, due 2026-09-22)"),
        "{table}"
    );

    // SARIF for code scanning: one run, rules and results, valid against the 2.1.0 schema.
    let assert = base(&[
        "--ignore-vuln",
        "GHSA-q2q7-5pp4-w6pg:mitigated upstream",
        "--report",
        "vulnerabilities",
        "--report-format",
        "sarif",
    ])
    .success();
    let log: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&sarif_validator(), &log);
    let run = &log["runs"][0];
    assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 9);
    let results = run["results"].as_array().unwrap();
    assert_eq!(results.len(), 9);
    let regex = results.iter().find(|r| r["ruleId"] == "GHSA-q2q7-5pp4-w6pg").unwrap();
    assert_eq!(regex["level"], "note");
    assert_eq!(
        regex["suppressions"][0]["justification"],
        "not_affected: mitigated upstream"
    );
    assert_eq!(
        regex["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "pixi.lock"
    );
    let open = results.iter().find(|r| r["ruleId"] == "GHSA-v845-jxx5-vc9f").unwrap();
    assert_eq!(open["level"], "error");
    assert_eq!(open["properties"]["fixedVersion"], "1.26.17");

    // SARIF is a vulnerabilities-only format.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--report", "licenses", "--report-format", "sarif"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("only applies to '--report vulnerabilities'"));

    // --kev needs --vulnerabilities; --fail-on-kev needs --kev.
    pixi_sbom().current_dir(dir.path()).args(["--kev"]).assert().code(2);
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--vulnerabilities", "osv", "--fail-on-kev"])
        .assert()
        .code(2);
    // --epss needs --vulnerabilities; --fail-on-epss needs --epss and a probability.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--epss"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("'--epss' needs '--vulnerabilities <SOURCE>'"));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--vulnerabilities", "osv", "--fail-on-epss", "0.1"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("'--fail-on-epss' needs '--epss'"));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--vulnerabilities", "osv", "--epss", "--fail-on-epss", "10"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("between 0.0 and 1.0"));
}

#[test]
fn a_vendors_vex_clears_the_findings_it_covers_and_reports_the_rest() {
    let dir = workspace_with_vulnerable_urllib3();
    let kev_dir = dir.path().join("cache").join("kev");
    std::fs::create_dir_all(&kev_dir).unwrap();
    std::fs::copy(
        tests_dir()
            .join("fixtures")
            .join("kev")
            .join("known_exploited_vulnerabilities.json"),
        kev_dir.join("known_exploited_vulnerabilities.json"),
    )
    .unwrap();
    let vex = |name: &str| tests_dir().join("fixtures").join("vex-in").join(name);
    let openvex = vex("vendor.openvex.json");
    let cdx = vex("vendor.cdx.json");
    let base = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "220")
            .args([
                "-e",
                "web",
                "-p",
                "linux-64",
                "--vulnerabilities",
                "osv",
                "--kev",
                "--fail-on-kev",
            ])
            .args(args)
            .assert()
    };
    // Without a VEX the known-exploited urllib3 finding fails the gate.
    base(&["--output", "-"]).code(4);

    // The vendor's OpenVEX says the product is not affected: the gate passes, the finding stays
    // in the document with the statement and where it came from, and the statements that
    // matched nothing here are named.
    let assert = base(&["--vex-in", openvex.to_str().unwrap(), "--output", "-"])
        .success()
        .stderr(predicate::str::contains("read VEX statements"))
        .stderr(predicate::str::contains("a VEX statement matches no finding"))
        .stderr(predicate::str::contains(
            "CVE-2023-32681 for pkg:pypi/requests (vendor.openvex.json)",
        ));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let urllib3 = doc["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "GHSA-q2q7-5pp4-w6pg")
        .unwrap();
    assert_eq!(urllib3["analysis"]["state"], "not_affected");
    assert_eq!(urllib3["analysis"]["justification"], "code_not_reachable");
    assert!(
        urllib3["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:vex-source" && p["value"] == "vendor.openvex.json")
    );

    // The same from the CycloneDX form, and the report says whose statement it was.
    let table = String::from_utf8(
        base(&["--vex-in", cdx.to_str().unwrap(), "--report", "vulnerabilities"])
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        table.contains("GHSA-q2q7-5pp4-w6pg (not_affected, from vendor.cdx.json): Only reachable with a proxy"),
        "{table}"
    );
    let json: Value = serde_json::from_slice(
        &base(&[
            "--vex-in",
            cdx.to_str().unwrap(),
            "--report",
            "vulnerabilities",
            "--report-format",
            "json",
        ])
        .success()
        .get_output()
        .stdout,
    )
    .unwrap();
    let row = json["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "GHSA-q2q7-5pp4-w6pg")
        .unwrap();
    assert_eq!(row["ignored"], "not_affected");
    assert_eq!(row["vex"], "not_affected (vendor.cdx.json)");

    // --explain names the statement.
    let explained = String::from_utf8(
        base(&["--vex-in", openvex.to_str().unwrap(), "--explain", "urllib3"])
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        explained.contains("GHSA-q2q7-5pp4-w6pg (not_affected, from vendor.openvex.json)"),
        "{explained}"
    );

    // A local --ignore-vuln wins over the vendor's statement.
    let doc: Value = serde_json::from_slice(
        &base(&[
            "--vex-in",
            openvex.to_str().unwrap(),
            "--ignore-vuln",
            "CVE-2021-33503:false_positive:our own reading",
            "--output",
            "-",
        ])
        .success()
        .get_output()
        .stdout,
    )
    .unwrap();
    let urllib3 = doc["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "GHSA-q2q7-5pp4-w6pg")
        .unwrap();
    assert_eq!(urllib3["analysis"]["state"], "false_positive");
    assert_eq!(urllib3["analysis"]["detail"], "our own reading");

    // A file that is not a VEX is an error naming what is read, and the flag needs findings.
    base(&["--vex-in", "pixi.toml", "--output", "-"])
        .code(1)
        .stderr(predicate::str::contains("cannot parse the VEX"));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--vex-in", openvex.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "'--vex-in' needs '--vulnerabilities <SOURCE>'",
        ));
}

/// The recorded EPSS answer, written into the cache the way a lookup leaves it, so an offline
/// run reads it.
fn seed_epss_cache(cache: &Path) {
    let answer: Value = serde_json::from_str(
        &std::fs::read_to_string(tests_dir().join("fixtures").join("epss").join("epss.json")).unwrap(),
    )
    .unwrap();
    let mut scores = serde_json::Map::new();
    for row in answer["data"].as_array().unwrap() {
        scores.insert(
            row["cve"].as_str().unwrap().to_string(),
            serde_json::json!({
                "epss": row["epss"].as_str().unwrap().parse::<f64>().unwrap(),
                "percentile": row["percentile"].as_str().unwrap().parse::<f64>().unwrap(),
                "date": row["date"],
                "fetched": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            }),
        );
    }
    std::fs::create_dir_all(cache.join("epss")).unwrap();
    std::fs::write(
        cache.join("epss").join("scores.json"),
        serde_json::to_vec(&Value::Object(scores)).unwrap(),
    )
    .unwrap();
}

#[test]
fn epss_scores_findings_in_every_output_and_gates_on_them() {
    let dir = workspace_with_vulnerable_urllib3();
    seed_epss_cache(&dir.path().join("cache"));
    let base = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "240")
            .args(["-e", "web", "-p", "linux-64", "--vulnerabilities", "osv", "--epss"])
            .args(args)
            .assert()
    };
    let assert = base(&["--output", "-"])
        .success()
        .stderr(predicate::str::contains("scored findings with FIRST EPSS"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let vulns = doc["vulnerabilities"].as_array().unwrap();
    let urllib3 = vulns.iter().find(|v| v["id"] == "GHSA-q2q7-5pp4-w6pg").unwrap();
    let props = urllib3["properties"].as_array().unwrap();
    let prop = |name: &str| props.iter().find(|p| p["name"] == name).map(|p| p["value"].clone());
    assert_eq!(prop("pixi:epss"), Some(serde_json::json!("0.03273")));
    assert_eq!(prop("pixi:epss-percentile"), Some(serde_json::json!("0.88073")));
    assert_eq!(prop("pixi:epss-cve"), Some(serde_json::json!("CVE-2021-33503")));
    assert_eq!(prop("pixi:epss-date"), Some(serde_json::json!("2026-10-08")));

    // The report: a column in the table, fields in JSON, columns after the frozen ones in CSV.
    let table = String::from_utf8(
        base(&["--report", "vulnerabilities"])
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(table.contains("  EPSS  "), "{table}");
    assert!(table.contains("0.033 (p88)  GHSA-q2q7-5pp4-w6pg"), "{table}");
    let json_report: Value = serde_json::from_slice(
        &base(&["--report", "vulnerabilities", "--report-format", "json"])
            .success()
            .get_output()
            .stdout,
    )
    .unwrap();
    let row = json_report["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "GHSA-q2q7-5pp4-w6pg")
        .unwrap();
    assert_eq!(row["epss"]["score"], 0.03273);
    assert_eq!(row["epss"]["percentile"], 0.88073);
    assert_eq!(row["epss"]["cve_id"], "CVE-2021-33503");
    let csv = String::from_utf8(
        base(&["--report", "vulnerabilities", "--report-format", "csv"])
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        csv.lines()
            .next()
            .unwrap()
            .ends_with(",summary,url,epss,epss_percentile"),
        "{csv}"
    );
    assert!(csv.contains(",0.03273,0.88073\n"), "{csv}");
    let markdown = String::from_utf8(
        base(&["--report", "vulnerabilities", "--report-format", "markdown"])
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(markdown.contains("| EPSS |"), "{markdown}");

    // SPDX 3 has a class for it.
    let doc: Value = serde_json::from_slice(
        &base(&["--format", "spdx", "--spec-version", "3.0", "--output", "-"])
            .success()
            .get_output()
            .stdout,
    )
    .unwrap();
    assert_valid(&spdx3_validator(), &doc);
    let epss: Vec<&Value> = doc["@graph"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["type"] == "security_EpssVulnAssessmentRelationship")
        .collect();
    assert!(!epss.is_empty());
    assert!(
        epss.iter()
            .all(|n| n["security_probability"].is_number() && n["security_percentile"].is_number())
    );
    assert!(
        epss.iter()
            .any(|n| n["security_publishedTime"] == "2026-10-08T00:00:00Z")
    );

    // The gate: exit 4 naming the finding and its score; an ignored finding leaves it.
    base(&["--fail-on-epss", "0.03", "--output", "-"])
        .code(4)
        .stderr(predicate::str::contains(
            "finding(s) with an EPSS score of 0.03 or more:",
        ))
        .stderr(predicate::str::contains(
            "GHSA-q2q7-5pp4-w6pg (high, EPSS 0.033): urllib3 1.26.4",
        ));
    base(&["--fail-on-epss", "0.5", "--output", "-"]).success();
    base(&[
        "--fail-on-epss",
        "0.03",
        "--ignore-vuln",
        "CVE-2021-33503:mitigated",
        "--output",
        "-",
    ])
    .success();
}

#[test]
fn color_follows_the_flag_and_the_environment() {
    let dir = workspace_with_vulnerable_urllib3();
    let run = |args: &[&str], env: &[(&str, &str)]| {
        let mut cmd = pixi_sbom();
        cmd.current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR_FORCE")
            .args(["-e", "web", "-p", "linux-64", "--vulnerabilities", "osv"])
            .args(["--report", "vulnerabilities"])
            .args(args);
        for (key, value) in env {
            cmd.env(key, value);
        }
        String::from_utf8(cmd.assert().success().get_output().stdout.clone()).unwrap()
    };
    // The test harness is not a terminal, so `auto` produces no escapes.
    let plain = run(&[], &[]);
    assert!(!plain.contains('\u{1b}'), "auto on a pipe stays plain");
    assert!(plain.contains("urllib3"));

    let coloured = run(&["--color", "always"], &[]);
    assert!(coloured.contains('\u{1b}'), "always colours even on a pipe");
    // The same rows, with styling around the words rather than inside them.
    assert!(coloured.contains("urllib3"));
    assert!(coloured.contains("Catastrophic backtracking"));
    assert!(!run(&["--color", "never"], &[("CLICOLOR_FORCE", "1")]).contains('\u{1b}'));
    assert!(run(&["--color", "auto"], &[("CLICOLOR_FORCE", "1")]).contains('\u{1b}'));
    assert!(
        !run(&["--color", "auto"], &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")]).contains('\u{1b}'),
        "NO_COLOR wins"
    );
    // Only the table format is ever coloured.
    for format in ["markdown", "csv", "json", "sarif"] {
        let text = run(&["--color", "always", "--report-format", format], &[]);
        assert!(!text.contains('\u{1b}'), "{format} stays plain");
    }
}

#[test]
fn wide_cells_wrap_instead_of_being_truncated() {
    let dir = workspace_with_vulnerable_urllib3();
    let run = |columns: &str| {
        String::from_utf8(
            pixi_sbom()
                .current_dir(dir.path())
                .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
                .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
                .env("PIXI_SBOM_OFFLINE", "1")
                .env("COLUMNS", columns)
                .args(["-e", "web", "-p", "linux-64", "--vulnerabilities", "osv"])
                .args(["--report", "vulnerabilities"])
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        )
        .unwrap()
    };
    let narrow = run("80");
    // The table wraps to the width; the summary lines below it are prose and are not wrapped.
    let table: Vec<&str> = narrow.lines().take_while(|l| !l.is_empty()).collect();
    assert!(
        table.iter().all(|l| l.chars().count() <= 80),
        "every table line fits 80 columns: {table:#?}"
    );
    // Nothing is cut: cells wrap onto further lines instead of ending in an ellipsis, so a
    // narrow terminal costs height rather than content.
    assert!(!narrow.contains('…'), "{table:#?}");
    assert!(table.len() > 4, "the rows wrapped onto extra lines: {table:#?}");

    // Given the room, every cell is on one line and nothing is wrapped at all.
    let wide = run("200");
    let table: Vec<&str> = wide.lines().take_while(|l| !l.is_empty()).collect();
    assert!(table.iter().all(|l| l.chars().count() <= 200));
    // Identifiers are never broken up when there is room for them.
    for id in ["GHSA-2xpw-w6gg-jr37", "GHSA-q2q7-5pp4-w6pg", "GHSA-v845-jxx5-vc9f"] {
        assert!(table.iter().any(|l| l.contains(id)), "{id} intact: {table:#?}");
    }
    assert!(
        table
            .iter()
            .any(|l| l.contains("urllib3  1.26.4") && l.contains("Catastrophic backtracking in URL authority parser")),
        "{table:#?}"
    );
}

#[test]
fn progress_bars_never_reach_a_pipe_or_a_ci_log() {
    // Every e2e test runs with stderr captured, which is exactly the "not a terminal" case;
    // this one states the expectation rather than relying on it silently.
    let dir = workspace_with_vulnerable_urllib3();
    let stderr = |extra: &[&str]| {
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env_remove("CI")
            .env_remove("PIXI_SBOM_NO_PROGRESS")
            .args([
                "-e",
                "web",
                "-p",
                "linux-64",
                "--vulnerabilities",
                "osv",
                "--output",
                "-",
            ])
            .args(extra)
            .assert()
            .success();
        String::from_utf8(assert.get_output().stderr.clone()).unwrap()
    };
    for extra in [vec![], vec!["-v"], vec!["-q"], vec!["--fetch-licenses"]] {
        let text = stderr(&extra);
        assert!(!text.contains('\r'), "no bar redraws with {extra:?}: {text:?}");
        assert!(!text.contains("advisories"), "no bar labels with {extra:?}: {text:?}");
    }
    // The log lines themselves are unchanged.
    assert!(stderr(&[]).contains("looked up vulnerabilities on OSV"));
}

#[test]
fn vulnerabilities_without_a_cache_fail_offline_only_when_the_query_is_missing() {
    // The clean fixture pins have cached "no findings" answers; nothing is looked up.
    let dir = workspace_with_vulnerable_urllib3();
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "default",
            "-p",
            "linux-64",
            "--vulnerabilities",
            "osv",
            "--output",
            "-",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("findings=0"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert!(doc.get("vulnerabilities").is_none());

    // Online but unreachable: the run fails with the query diagnostic rather than a document
    // that silently claims there are no vulnerabilities.
    pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("fresh-cache"))
        .env("PIXI_SBOM_OSV_URL", "http://127.0.0.1:9")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--vulnerabilities",
            "osv",
            "--output",
            "-",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("cannot query OSV"));
}

#[test]
fn exclude_drops_packages_and_what_only_they_needed() {
    let dir = workspace("with-pypi");
    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .args(["-e", "web", "-p", "linux-64", "--output", "-"])
            .args(args)
            .assert()
            .success()
    };
    let names = |doc: &Value| -> Vec<String> {
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_string())
            .collect()
    };
    let full: Value = serde_json::from_slice(&run(&[]).get_output().stdout).unwrap();
    assert!(names(&full).contains(&"requests".to_string()));

    // requests is a root; its four PyPI dependencies were only there for it.
    let assert =
        run(&["--exclude", "requests"]).stderr(predicate::str::contains("filtered packages excluded=1 orphans=4"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let kept = names(&doc);
    for gone in ["requests", "certifi", "charset-normalizer", "idna", "urllib3"] {
        assert!(!kept.contains(&gone.to_string()), "{gone} should be gone: {kept:?}");
    }
    assert!(kept.contains(&"six".to_string()));
    assert!(kept.contains(&"python".to_string()), "python is needed by six");
    let excluded = doc["metadata"]["properties"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "pixi:excluded")
        .unwrap()["value"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(excluded, "certifi, charset-normalizer, idna, requests, urllib3");
    // No dangling edges: every dependsOn names a component.
    let refs: std::collections::HashSet<&str> = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["bom-ref"].as_str().unwrap())
        .collect();
    for dep in doc["dependencies"].as_array().unwrap() {
        for on in dep["dependsOn"].as_array().unwrap() {
            assert!(refs.contains(on.as_str().unwrap()), "dangling {on}");
        }
    }

    // --keep-orphans keeps the four; --exclude-kind pypi drops every wheel; --include narrows.
    let doc: Value =
        serde_json::from_slice(&run(&["--exclude", "requests", "--keep-orphans"]).get_output().stdout).unwrap();
    assert!(names(&doc).contains(&"urllib3".to_string()));
    let doc: Value = serde_json::from_slice(&run(&["--exclude-kind", "pypi"]).get_output().stdout).unwrap();
    assert!(names(&doc).iter().all(|n| n != "six" && n != "requests"));
    let doc: Value = serde_json::from_slice(
        &run(&["--include", "python", "--include", "lib*", "--keep-orphans"])
            .get_output()
            .stdout,
    )
    .unwrap();
    assert!(
        names(&doc).iter().all(|n| n == "python" || n.starts_with("lib")),
        "{:?}",
        names(&doc)
    );

    // SPDX documents carry the same note on the root package.
    let doc: Value =
        serde_json::from_slice(&run(&["--exclude", "requests", "--format", "spdx"]).get_output().stdout).unwrap();
    assert_valid(&spdx_validator(), &doc);
    let root = doc["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["SPDXID"] == "SPDXRef-Package-root")
        .unwrap();
    assert!(root["comment"].as_str().unwrap().starts_with("pixi:excluded=certifi"));

    // A bad pattern is a usage error.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--exclude", " "])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--exclude ' ': empty pattern"));
}

#[test]
fn excluding_pre_commit_from_this_repository() {
    let lockfile = tests_dir().parent().unwrap().join("pixi.lock");
    let assert = pixi_sbom()
        .args(["--lockfile", lockfile.to_str().unwrap(), "-p", "linux-64"])
        .args([
            "--exclude",
            "pre-commit*",
            "--report",
            "packages",
            "--report-format",
            "json",
        ])
        .assert()
        .success();
    let report: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let names: Vec<&str> = report["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(!names.iter().any(|n| n.starts_with("pre-commit")), "{names:?}");
    assert!(names.contains(&"rust"), "the toolchain itself stays");
}

#[test]
fn the_user_layer_is_read_from_pixi_home_and_nothing_else() {
    // Two things at once. That a user-level file applies at all, which is the #289 feature, and
    // that `PIXI_HOME` is what decides where it is read from — which is what lets this suite run
    // on a machine that has a real `~/.pixi/pixi-sbom-config.toml` without inheriting it.
    let dir = workspace("with-pypi");
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("pixi-sbom-config.toml"), "format = \"spdx\"\n").unwrap();

    let run = |pixi_home: &Path| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_HOME", pixi_home)
            .args(["-e", "web", "-p", "linux-64", "--output", "-"])
            .assert()
            .success()
    };

    let assert = run(home.path()).stderr(predicate::str::contains("pixi-sbom-config.toml"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(doc["spdxVersion"], "SPDX-2.3", "the user layer chose the format");

    // Pointed somewhere with no file, the same run falls back to the default format. If the user
    // layer were read from anywhere but PIXI_HOME this would still be SPDX on a machine that has
    // one, and the suite's results would depend on who ran it.
    let empty = tempfile::tempdir().unwrap();
    let assert = run(empty.path());
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(doc["bomFormat"], "CycloneDX", "no user layer, so the default stands");
}

#[test]
fn each_source_of_concurrency_beats_the_one_below_it() {
    // Four sources now feed one setting, so "which one won?" has to be answerable. `-v` says, and
    // this pins the order: command line, then the variable, then a file, then the default.
    let dir = workspace("with-pypi");
    std::fs::create_dir_all(dir.path().join(".pixi")).unwrap();
    std::fs::write(
        dir.path().join(".pixi").join("pixi-sbom-config.toml"),
        "concurrency = 7\n",
    )
    .unwrap();

    let run = |args: &[&str], variable: Option<&str>| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("RUST_LOG", "pixi_sbom::concurrency=debug")
            .args(["-e", "web", "-p", "linux-64", "--output", "-"])
            .args(args);
        match variable {
            Some(value) => command.env("PIXI_SBOM_CONCURRENCY", value),
            None => command.env_remove("PIXI_SBOM_CONCURRENCY"),
        };
        String::from_utf8(command.assert().success().get_output().stderr.clone()).unwrap()
    };

    let all_three = run(&["--concurrency", "3"], Some("5"));
    assert!(all_three.contains("network=3"), "the flag wins: {all_three}");
    assert!(all_three.contains("--concurrency"), "and says so: {all_three}");

    let variable_and_file = run(&[], Some("5"));
    assert!(
        variable_and_file.contains("network=5"),
        "the variable beats the file: {variable_and_file}"
    );
    assert!(
        variable_and_file.contains("PIXI_SBOM_CONCURRENCY"),
        "{variable_and_file}"
    );

    let file_only = run(&[], None);
    assert!(file_only.contains("network=7"), "the file applies: {file_only}");
    assert!(file_only.contains("configuration file"), "{file_only}");

    // And asking for fewer requests does not shrink the pool for local work.
    let gentle = run(&["--concurrency", "1"], None);
    assert!(gentle.contains("network=1"), "{gentle}");
    assert!(!gentle.contains("cpu=1 "), "local work still follows cores: {gentle}");
}

#[test]
fn configuration_file_is_read_before_the_command_line() {
    let dir = workspace("with-pypi");
    std::fs::write(
        dir.path().join("pixi-sbom.toml"),
        "format = \"spdx\"\nexclude = [\"requests\"]\nrequire-license = true\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .args(["-e", "web", "-p", "linux-64", "--output", "-"])
            .args(args)
            .assert()
    };
    // The file decides the format and the filter; the policy it enables trips (exit 3). The
    // workspace-root spelling still works and says it is on its way out.
    let assert = run(&[])
        .code(3)
        .stderr(predicate::str::contains("applied the configuration"))
        .stderr(predicate::str::contains(
            "`pixi-sbom.toml` at the workspace root is deprecated",
        ))
        .stderr(predicate::str::contains("filtered packages excluded=1"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx_validator(), &doc);
    // The command line wins where it speaks: CycloneDX, and no policy.
    let assert = run(&["--format", "cyclonedx", "--no-config"]).success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(doc["bomFormat"], "CycloneDX");
    assert!(
        doc["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["name"] != "pixi:excluded")
    );
    let assert = run(&["--format", "cyclonedx"]).code(3);
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(doc["bomFormat"], "CycloneDX", "the flag wins over the file");
    assert!(
        doc["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:excluded"),
        "the file's filter still applies"
    );

    // [tool.pixi-sbom] in pyproject.toml takes precedence over pixi-sbom.toml.
    std::fs::write(
        dir.path().join("pyproject.toml"),
        "[project]\nname = \"x\"\n[tool.pixi-sbom]\nformat = \"cyclonedx\"\n",
    )
    .unwrap();
    let assert = run(&[]).success().stderr(predicate::str::contains("pyproject.toml"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(doc["bomFormat"], "CycloneDX");

    // --config points elsewhere; a bad file is a diagnostic, not a silent default.
    std::fs::write(dir.path().join("ci.toml"), "colour = \"spdx\"\n").unwrap();
    run(&["--config", "ci.toml"])
        .code(1)
        .stderr(predicate::str::contains("pixi_sbom::config::parse"))
        .stderr(predicate::str::contains("unknown field `colour`"));
    std::fs::write(
        dir.path().join("ci.toml"),
        "vulnerabilities = \"osv\"\nfail-on-kev = true\n",
    )
    .unwrap();
    // Relationships are checked after the file applies: fail-on-kev needs kev.
    run(&["--config", "ci.toml"])
        .code(2)
        .stderr(predicate::str::contains("'--fail-on-kev' needs '--kev'"));
    run(&["--config", "missing.toml"])
        .code(1)
        .stderr(predicate::str::contains("cannot read the configuration file"));

    // `.pixi/pixi-sbom-config.toml` outranks both older spellings, and is not deprecated.
    std::fs::create_dir_all(dir.path().join(".pixi")).unwrap();
    std::fs::write(
        dir.path().join(".pixi").join("pixi-sbom-config.toml"),
        "format = \"spdx\"\n",
    )
    .unwrap();
    let assert = run(&[])
        .success()
        .stderr(predicate::str::contains("pixi-sbom-config.toml"))
        .stderr(predicate::str::contains("deprecated").not());
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(
        doc["spdxVersion"], "SPDX-2.3",
        "the pixi-aligned file wins over pyproject.toml"
    );
}

/// A copy of the prefix fixture whose python record points at an extracted package directory
/// inside the temp dir (with `info/about.json` and a license file), as a real environment's does.
fn installed_prefix() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("envs").join("demo");
    copy_dir(&tests_dir().join("fixtures").join("prefix"), &prefix);
    let extracted = dir.path().join("pkgs").join("python-3.12.14-h5f976f7_3_cpython");
    std::fs::create_dir_all(extracted.join("info").join("licenses")).unwrap();
    std::fs::write(
        extracted.join("info").join("about.json"),
        r#"{"home":"https://www.python.org/","summary":"General purpose programming language","license":"Python-2.0"}"#,
    )
    .unwrap();
    std::fs::write(extracted.join("info").join("index.json"), r#"{"name":"python"}"#).unwrap();
    std::fs::write(
        extracted.join("info").join("licenses").join("LICENSE"),
        "PSF LICENSE AGREEMENT",
    )
    .unwrap();
    let record = prefix.join("conda-meta").join("python-3.12.14-h5f976f7_3_cpython.json");
    let text = std::fs::read_to_string(&record).unwrap().replace(
        "/opt/pkgs/python-3.12.14-h5f976f7_3_cpython",
        &extracted.display().to_string().replace('\\', "/"),
    );
    std::fs::write(&record, text).unwrap();
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A monorepo: two workspaces at different depths, plus a lockfile inside an installed
/// environment that a scan must never pick up.
fn monorepo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (relative, fixture) in [("services/api", "with-pypi"), ("tools/ci", "conda-only")] {
        let target = dir.path().join(relative);
        std::fs::create_dir_all(&target).unwrap();
        for file in ["pixi.toml", "pixi.lock"] {
            std::fs::copy(tests_dir().join("fixtures").join(fixture).join(file), target.join(file)).unwrap();
        }
    }
    let installed = dir.path().join("services/api/.pixi/envs/default");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::copy(
        tests_dir().join("fixtures/with-pypi/pixi.lock"),
        installed.join("pixi.lock"),
    )
    .unwrap();
    dir
}

#[test]
fn scan_writes_one_document_per_workspace_in_the_tree() {
    let dir = monorepo();
    let out = dir.path().join("sboms");
    pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "0")
        .args(["-p", "linux-64", "--scan"])
        .arg(dir.path())
        .arg("--output")
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::contains("scanned for workspaces"));

    let api = out.join("services/api/sbom.cdx.json");
    let ci = out.join("tools/ci/sbom.cdx.json");
    assert!(api.is_file() && ci.is_file(), "{out:?}");
    assert_eq!(
        std::fs::read_dir(out.join("services/api")).unwrap().count(),
        1,
        "the lockfile inside .pixi/ is not a workspace"
    );
    // Each workspace keeps its own identity, not the scanned directory's.
    let document = read_json(&api);
    assert_eq!(document["metadata"]["component"]["name"], "with-pypi");
    assert_eq!(read_json(&ci)["metadata"]["component"]["name"], "conda-only");

    // And each document is exactly what the single-workspace run would have written.
    let single = dir.path().join("single.cdx.json");
    pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "0")
        .args(["-p", "linux-64", "--lockfile"])
        .arg(dir.path().join("services/api/pixi.lock"))
        .arg("--output")
        .arg(&single)
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(&single).unwrap(),
        std::fs::read_to_string(&api).unwrap()
    );
}

#[test]
fn scan_merge_writes_one_document_for_the_whole_tree() {
    let dir = monorepo();
    let out = dir.path().join("product.cdx.json");
    pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "0")
        .args(["-p", "linux-64", "--merge", "--root-name", "product", "--scan"])
        .arg(dir.path())
        .arg("--output")
        .arg(&out)
        .assert()
        .success()
        .stderr(predicate::str::contains("merged the documents into one documents=2"));
    let document = read_json(&out);
    assert_valid(&cyclonedx_validator(), &document);
    assert_eq!(document["metadata"]["component"]["name"], "product");
    let components = document["components"].as_array().unwrap();
    let named = |name: &str| components.iter().find(|c| c["name"] == name).cloned();
    let api = named("with-pypi").expect("each workspace's root is a component");
    assert!(named("conda-only").is_some());
    let source = |c: &Value| {
        c["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "pixi:source-document")
            .map(|p| p["value"].as_str().unwrap().to_string())
    };
    assert_eq!(source(&api).as_deref(), Some("services/api/pixi.lock"));
    // The root depends on the two workspace roots, which keep their own graphs.
    let dependencies = document["dependencies"].as_array().unwrap();
    let root_ref = document["metadata"]["component"]["bom-ref"].as_str().unwrap();
    let root = dependencies.iter().find(|d| d["ref"] == root_ref).unwrap();
    assert_eq!(root["dependsOn"].as_array().unwrap().len(), 2, "{root}");
    let api_edges = dependencies.iter().find(|d| d["ref"] == api["bom-ref"]).unwrap();
    assert!(!api_edges["dependsOn"].as_array().unwrap().is_empty());
    // One document, so it can go to stdout.
    let stdout = pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "0")
        .args([
            "-p",
            "linux-64",
            "--merge",
            "--root-name",
            "product",
            "--output",
            "-",
            "--scan",
        ])
        .arg(dir.path())
        .assert()
        .success();
    let streamed: Value = serde_json::from_slice(&stdout.get_output().stdout).unwrap();
    assert_eq!(streamed["components"], document["components"]);
    // Without --scan, --merge is refused.
    pixi_sbom().current_dir(dir.path()).args(["--merge"]).assert().code(2);
}

#[test]
fn from_sbom_twice_merges_a_cyclonedx_and_an_spdx_document() {
    let dir = workspace("with-pypi");
    let write = |args: &[&str], out: &str| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("SOURCE_DATE_EPOCH", "0")
            .args(["-p", "linux-64"])
            .args(args)
            .args(["--output", out])
            .assert()
            .success();
        read_json(&dir.path().join(out))
    };
    let cdx = write(&["-e", "default"], "app.cdx.json");
    let mut spdx = write(&["-e", "web", "--format", "spdx"], "vendor.spdx.json");
    // The two overlap; make the vendor's document disagree about one shared package's license.
    let shared: Vec<String> = cdx["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str().map(str::to_string))
        .collect();
    let package = spdx["packages"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|p| shared.iter().any(|name| p["name"] == name.as_str()))
        .expect("the environments share packages");
    let name = package["name"].as_str().unwrap().to_string();
    package["licenseConcluded"] = "GPL-3.0-only".into();
    package["licenseDeclared"] = "GPL-3.0-only".into();
    std::fs::write(dir.path().join("vendor.spdx.json"), spdx.to_string()).unwrap();

    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .args([
                "--from-sbom",
                "app.cdx.json",
                "--from-sbom",
                "vendor.spdx.json",
                "--root-name",
                "product",
            ])
            .args(args)
            .assert()
            .success()
    };
    let assert = run(&["--output", "-"])
        .stderr(predicate::str::contains(
            "the merged documents disagree; keeping the first",
        ))
        .stderr(predicate::str::contains("merged the documents into one documents=2"));
    let merged: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &merged);
    assert_eq!(merged["metadata"]["component"]["name"], "product");
    let components = merged["components"].as_array().unwrap();
    let copies: Vec<&Value> = components.iter().filter(|c| c["name"] == name.as_str()).collect();
    assert_eq!(copies.len(), 1, "deduplicated by purl");
    let props = copies[0]["properties"].as_array().unwrap();
    let prop = |key: &str| {
        props
            .iter()
            .find(|p| p["name"] == key)
            .map(|p| p["value"].as_str().unwrap().to_string())
    };
    assert!(
        prop("pixi:source-document").unwrap().contains(", "),
        "both inputs named"
    );
    assert!(
        prop("pixi:merge-conflict").unwrap().contains("vs GPL-3.0-only"),
        "{props:?}"
    );
    // Both inputs' roots are kept under the new one.
    assert_eq!(components.iter().filter(|c| c["name"] == "with-pypi").count(), 2);

    // SPDX output of the merge validates too, and --explain shows the conflict.
    let assert = run(&["--format", "spdx", "--output", "-"]);
    assert_valid(
        &spdx_validator(),
        &serde_json::from_slice(&assert.get_output().stdout).unwrap(),
    );
    let explained = String::from_utf8(
        run(&["--explain", &name, "--report-format", "json"])
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(explained.contains("merge conflict"), "{explained}");
    assert!(explained.contains("vs GPL-3.0-only"), "{explained}");
}

#[test]
fn scan_reports_and_gates_across_every_workspace() {
    let dir = monorepo();
    // One report over the whole tree: a section per workspace, and the license policy sees
    // them all at once.
    let table = String::from_utf8(
        pixi_sbom()
            .current_dir(dir.path())
            .env("COLUMNS", "160")
            .args(["-p", "linux-64", "--report", "packages", "--color", "never", "--scan"])
            .arg(dir.path())
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(table.contains("packages (with-pypi, environment default"), "{table}");
    assert!(table.contains("packages (conda-only, environment default"), "{table}");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--deny-license", "Zlib", "--output"])
        .arg(dir.path().join("sboms"))
        .arg("--scan")
        .arg(dir.path())
        .assert()
        .code(3)
        .stderr(predicate::str::contains("License policy violated"));
}

#[test]
fn scan_usage_errors() {
    let dir = monorepo();
    let empty = tempfile::tempdir().unwrap();
    // A directory with nothing in it says so rather than writing nothing quietly.
    pixi_sbom()
        .current_dir(empty.path())
        .arg("--scan")
        .arg(empty.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("pixi_sbom::discover::none_found"));
    pixi_sbom()
        .arg("--scan")
        .arg(dir.path().join("services/api/pixi.lock"))
        .assert()
        .code(1)
        .stderr(predicate::str::contains("pixi_sbom::discover::not_a_directory"));
    for extra in [
        vec!["--output", "-"],
        vec!["--against", "previous.cdx.json", "--report", "diff"],
    ] {
        pixi_sbom()
            .current_dir(dir.path())
            .arg("--scan")
            .arg(dir.path())
            .args(&extra)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("--scan"));
    }
    // --scan-depth 0 finds nothing here, because neither workspace is at the top.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--scan-depth", "0", "--scan"])
        .arg(dir.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains("pixi_sbom::discover::none_found"));
}

/// An ELF binary carrying `json` in a `.dep-v0` section, the way `cargo auditable` writes it.
fn audited_binary(json: &str) -> Vec<u8> {
    use object::write::{Object, StandardSegment};
    use object::{Architecture, BinaryFormat, Endianness, SectionKind};
    use std::io::Write;

    let mut compressed = Vec::new();
    let mut encoder = flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::default());
    encoder.write_all(json.as_bytes()).unwrap();
    encoder.finish().unwrap();

    let mut object = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let section = object.add_section(
        object.segment_name(StandardSegment::Data).to_vec(),
        b".dep-v0".to_vec(),
        SectionKind::ReadOnlyData,
    );
    object.set_section_data(section, compressed, 1);
    object.write().unwrap()
}

#[test]
fn cargo_auditable_crates_are_read_out_of_an_installed_environment() {
    let dir = installed_prefix();
    let prefix = dir.path().join("envs").join("demo");
    // libzlib ships an audited program, as a conda-forge Rust package would.
    std::fs::create_dir_all(prefix.join("bin")).unwrap();
    std::fs::write(
        prefix.join("bin").join("rg"),
        audited_binary(
            r#"{"packages":[
                {"name":"ripgrep","version":"14.1.0","source":"local","root":true,"dependencies":[1]},
                {"name":"memchr","version":"2.7.4","source":"crates.io"},
                {"name":"cc","version":"1.0.0","source":"crates.io","kind":"build"}
            ]}"#,
        ),
    )
    .unwrap();
    let record = prefix.join("conda-meta").join("libzlib-1.3.2-h25fd6f3_3.json");
    let mut value: Value = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    value["files"] = serde_json::json!(["bin/rg", "lib/libz.so.1"]);
    std::fs::write(&record, value.to_string()).unwrap();

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("sbom-cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .arg("--prefix")
        .arg(&prefix)
        .args(["-p", "linux-64", "--embedded-sboms", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("read cargo auditable crate lists binaries=1"));
    let document: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &document);

    let components = document["components"].as_array().unwrap();
    let crate_ = |name: &str| components.iter().find(|c| c["name"] == name);
    let ripgrep = crate_("ripgrep").expect("the crate the binary was built from");
    assert_eq!(ripgrep["purl"], "pkg:cargo/ripgrep@14.1.0");
    let properties: Vec<(&str, &str)> = ripgrep["properties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["name"].as_str().unwrap(), p["value"].as_str().unwrap()))
        .collect();
    assert!(properties.contains(&("pixi:kind", "embedded")), "{properties:?}");
    assert!(
        properties.contains(&("pixi:embedded-sbom", "cargo-auditable:bin/rg")),
        "{properties:?}"
    );
    assert!(properties.contains(&("pixi:cargo-source", "local")), "{properties:?}");
    assert!(crate_("memchr").is_some());
    assert!(crate_("cc").is_none(), "a build dependency is not in the program");

    // The conda package depends on the crate, and the crate on its own dependencies.
    let edges = |reference: &str| -> Vec<String> {
        document["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["ref"] == reference)
            .map(|e| {
                e["dependsOn"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| d.as_str().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let libzlib = components.iter().find(|c| c["name"] == "libzlib").unwrap()["bom-ref"]
        .as_str()
        .unwrap();
    assert!(
        edges(libzlib).contains(&"pkg:cargo/ripgrep@14.1.0".to_string()),
        "{:?}",
        edges(libzlib)
    );
    assert_eq!(edges("pkg:cargo/ripgrep@14.1.0"), ["pkg:cargo/memchr@2.7.4"]);

    // Without --embedded-sboms nothing is read out of the binaries.
    let plain = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("sbom-cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .arg("--prefix")
        .arg(&prefix)
        .args(["-p", "linux-64", "--output", "-"])
        .assert()
        .success();
    let document: Value = serde_json::from_slice(&plain.get_output().stdout).unwrap();
    assert!(
        !document["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "ripgrep")
    );
}

#[test]
fn scorecards_are_recorded_reported_and_can_gate_the_run() {
    let dir = installed_prefix();
    let prefix = dir.path().join("envs").join("demo");
    // The package cache says where libzlib is developed, which is what the lookup keys on.
    let extracted = dir.path().join("pkgs").join("libzlib-1.3.2-h25fd6f3_3");
    std::fs::create_dir_all(extracted.join("info")).unwrap();
    std::fs::write(
        extracted.join("info").join("about.json"),
        r#"{"home":"https://zlib.net","dev_url":"https://github.com/madler/zlib","license":"Zlib"}"#,
    )
    .unwrap();
    // A complete extraction, which is what the reader checks for.
    std::fs::write(extracted.join("info").join("index.json"), r#"{"name":"libzlib"}"#).unwrap();
    let record = prefix.join("conda-meta").join("libzlib-1.3.2-h25fd6f3_3.json");
    let mut value: Value = serde_json::from_str(&std::fs::read_to_string(&record).unwrap()).unwrap();
    value["extracted_package_dir"] = serde_json::json!(extracted.display().to_string().replace('\\', "/"));
    std::fs::write(&record, value.to_string()).unwrap();
    // The recorded response, in the cache the lookup reads.
    let cache = dir.path().join("sbom-cache").join("scorecard");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::copy(
        tests_dir().join("fixtures/scorecard/github.com-madler-zlib.json"),
        cache.join("github.com-madler-zlib.json"),
    )
    .unwrap();

    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("pkgs-parent"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("sbom-cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .arg("--prefix")
            .arg(&prefix)
            .args(["-p", "linux-64", "--fetch-licenses", "--scorecard"])
            .args(args);
        command
    };

    let assert = run(&["--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("read OpenSSF scorecards scored=1"));
    let document: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &document);
    let properties: Vec<(&str, &str)> = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "libzlib")
        .unwrap()["properties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["name"].as_str().unwrap(), p["value"].as_str().unwrap()))
        .collect();
    assert!(properties.contains(&("pixi:scorecard", "4.2")), "{properties:?}");
    assert!(
        properties.contains(&("pixi:scorecard-date", "2026-09-01")),
        "{properties:?}"
    );
    assert!(
        properties.contains(&("pixi:scorecard-check-Signed-Releases", "0.0")),
        "{properties:?}"
    );
    assert!(
        !properties
            .iter()
            .any(|(name, _)| *name == "pixi:scorecard-check-Maintained"),
        "a check that passed is not recorded: {properties:?}"
    );

    // The report ranks the scored packages and says what the rest are.
    let report: Value = serde_json::from_slice(
        &run(&["--report", "scorecard", "--report-format", "json"])
            .assert()
            .success()
            .get_output()
            .stdout,
    )
    .unwrap();
    assert_eq!(report["report"], "scorecard");
    let rows = report["scorecard"].as_array().unwrap();
    assert_eq!(rows[0]["name"], "libzlib", "the worst score comes first");
    assert_eq!(rows[0]["score"], 4.2);
    assert_eq!(rows[0]["failing"][0], "Signed-Releases (0.0)");
    assert_eq!(report["summary"]["scored"], 1);
    assert!(report["summary"]["unknown"].as_u64().unwrap() >= 1);
    assert_eq!(report["summary"]["below"][0], "libzlib (4.2)");

    let table = String::from_utf8(
        run(&["--report", "scorecard", "--color", "never"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(table.lines().next().unwrap().starts_with("Package"), "{table}");
    assert!(table.contains("Summary: 1 repositories scored"), "{table}");
    assert!(table.contains("Below 5.0 (1): libzlib (4.2)"), "{table}");

    // The gate fires on a scored package below the line, and not on the unscored ones.
    run(&["--fail-on-scorecard", "5", "--output", "-"])
        .assert()
        .code(9)
        .stderr(predicate::str::contains("OpenSSF Scorecard below 5.0 for 1 package(s)"))
        .stderr(predicate::str::contains("libzlib (4.2)"));
    run(&["--fail-on-scorecard", "4", "--output", "-"]).assert().success();

    // And the flags say what they need.
    pixi_sbom()
        .current_dir(dir.path())
        .arg("--prefix")
        .arg(&prefix)
        .args(["--scorecard", "--output", "-"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("'--scorecard' needs '--fetch-licenses'"));
    pixi_sbom()
        .current_dir(dir.path())
        .arg("--prefix")
        .arg(&prefix)
        .args(["--fetch-licenses", "--report", "scorecard"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("'--report scorecard' needs '--scorecard'"));
}

#[test]
fn drift_between_an_installed_environment_and_its_lockfile() {
    let dir = installed_prefix();
    let prefix = dir.path().join("envs").join("demo");
    let workspace = workspace("with-pypi");
    let lockfile = workspace.path().join("pixi.lock");
    let site_packages = prefix.join("lib").join("python3.12").join("site-packages");

    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("sbom-cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "160")
            .arg("--prefix")
            .arg(&prefix)
            .args(["-p", "linux-64", "--report", "diff", "--against"])
            .arg(&lockfile)
            .args(args);
        command
    };
    let report = |args: &[&str]| -> Value {
        let out = run(args).args(["--report-format", "json"]).assert().success();
        serde_json::from_slice(&out.get_output().stdout).unwrap()
    };

    // As the fixture ships: the environment holds an older tzdata than the lockfile, and most
    // of the lockfile is simply not installed in it.
    let first = report(&[]);
    assert_eq!(first["against_format"], "lockfile pixi.lock");
    let versions: Vec<(&str, &str, &str)> = first["version_changed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap(),
                c["old_version"].as_str().unwrap(),
                c["new_version"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(versions, [("tzdata", "2026c", "2026b")]);
    assert!(!first["removed"].as_array().unwrap().is_empty());
    assert!(first["pip_installed"].as_array().unwrap().is_empty());
    assert!(first["build_changed"].as_array().unwrap().is_empty());

    // Now the two ways an image drifts without the version changing: something pip put there,
    // and the same version rebuilt.
    let attrs = site_packages.join("attrs-25.4.0.dist-info");
    std::fs::create_dir_all(&attrs).unwrap();
    std::fs::write(
        attrs.join("METADATA"),
        "Metadata-Version: 2.1\nName: attrs\nVersion: 25.4.0\n",
    )
    .unwrap();
    std::fs::write(attrs.join("INSTALLER"), "pip\n").unwrap();
    let meta = prefix.join("conda-meta");
    let record = std::fs::read_to_string(meta.join("libzlib-1.3.2-h25fd6f3_3.json")).unwrap();
    std::fs::remove_file(meta.join("libzlib-1.3.2-h25fd6f3_3.json")).unwrap();
    std::fs::write(
        meta.join("libzlib-1.3.2-hdrift_9.json"),
        record.replace("h25fd6f3_3", "hdrift_9"),
    )
    .unwrap();

    let second = report(&[]);
    let pip = second["pip_installed"].as_array().unwrap();
    assert_eq!(pip.len(), 1, "{pip:?}");
    assert_eq!(pip[0]["name"], "attrs");
    assert!(
        second["added"].as_array().unwrap().is_empty(),
        "a pip install is not an ordinary addition"
    );
    let builds = second["build_changed"].as_array().unwrap();
    assert_eq!(builds.len(), 1, "{builds:?}");
    assert_eq!(builds[0]["name"], "libzlib");
    assert_eq!(builds[0]["old_build"], "h25fd6f3_3");
    assert_eq!(builds[0]["new_build"], "hdrift_9");

    let table = String::from_utf8(run(&[]).assert().success().get_output().stdout.clone()).unwrap();
    assert!(table.contains("1 build changes, 1 pip installed"), "{table}");

    // The gate names the drift it was asked about, and nothing else.
    run(&["--fail-on-diff", "pip", "build"])
        .assert()
        .code(6)
        .stderr(predicate::str::contains("build changes (1), pip installed (1)"));
    run(&["--fail-on-diff", "added"]).assert().success();
}

#[test]
fn a_lockfile_compared_with_itself_has_not_changed() {
    let dir = workspace("with-pypi");
    let lockfile = dir.path().join("pixi.lock");
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .args(["-e", "web", "-p", "linux-64", "--report", "diff", "--against"])
            .arg(&lockfile)
            .args(args);
        command
    };
    let same = String::from_utf8(run(&[]).assert().success().get_output().stdout.clone()).unwrap();
    assert!(same.contains("No changes against"), "{same}");
    assert!(same.contains("(lockfile pixi.lock)"), "{same}");

    // The same lockfile with one package filtered out of the new side is a removal, and the
    // gate sees it.
    run(&["--exclude", "requests", "--keep-orphans", "--fail-on-diff", "removed"])
        .assert()
        .code(6)
        .stderr(predicate::str::contains("removed (1)"));
}

#[test]
fn prefix_describes_an_installed_environment_in_every_format() {
    let dir = installed_prefix();
    let prefix = dir.path().join("envs").join("demo");
    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("sbom-cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .arg("--prefix")
            .arg(&prefix)
            .args(["--output", "-"])
            .args(args)
            .assert()
            .success()
    };
    let assert = run(&["--fetch-licenses", "--license-texts"])
        .stderr(predicate::str::contains("read the installed environment"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    assert_eq!(doc["metadata"]["component"]["name"], "demo");
    // What is installed is in operation, not before a build (#329).
    assert_eq!(
        doc["metadata"]["lifecycles"],
        serde_json::json!([{"phase": "operations"}])
    );
    let props = doc["metadata"]["properties"].as_array().unwrap();
    assert!(props.iter().any(|p| p["name"] == "pixi:prefix" && p["value"] == "demo"));
    assert!(props.iter().all(|p| p["name"] != "pixi:lockfile"));
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:platform" && p["value"] == "linux-64")
    );
    let components = doc["components"].as_array().unwrap();
    let names: Vec<&str> = components.iter().map(|c| c["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["libzlib", "python", "tzdata", "six"]);
    // The license file came from the record's extracted package directory, with no network.
    let python = components.iter().find(|c| c["name"] == "python").unwrap();
    assert_eq!(python["licenses"][0]["license"]["id"], "Python-2.0");
    assert_eq!(
        python["licenses"][0]["license"]["text"]["content"],
        "PSF LICENSE AGREEMENT"
    );
    assert_eq!(python["description"], "General purpose programming language");
    let six = components.iter().find(|c| c["name"] == "six").unwrap();
    assert_eq!(six["purl"], "pkg:pypi/six@1.17.0");
    assert_eq!(six["licenses"][0]["expression"], "MIT");
    // The graph: python depends on libzlib and tzdata, six on python.
    let deps = doc["dependencies"].as_array().unwrap();
    let python_deps = deps.iter().find(|d| d["ref"] == python["bom-ref"]).unwrap()["dependsOn"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(python_deps, 2);

    // SPDX 2.3 and 3.0.1 validate and carry the prefix in the root's source info.
    let assert = run(&["--format", "spdx", "--root-name", "My App", "--root-version", "1.2.3"]);
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx_validator(), &doc);
    let root = doc["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["SPDXID"] == "SPDXRef-Package-root")
        .unwrap();
    assert_eq!(root["name"], "My App");
    assert_eq!(root["versionInfo"], "1.2.3");
    assert!(root["sourceInfo"].as_str().unwrap().contains("prefix demo"));
    let assert = run(&["--format", "spdx", "--spec-version", "3.0"]);
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx3_validator(), &doc);

    // Reproducible: two runs are byte-identical under SOURCE_DATE_EPOCH.
    let one = pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "0")
        .arg("--prefix")
        .arg(&prefix)
        .args(["--output", "-"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let two = pixi_sbom()
        .current_dir(dir.path())
        .env("SOURCE_DATE_EPOCH", "0")
        .arg("--prefix")
        .arg(&prefix)
        .args(["--output", "-"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(one, two);

    // Default output lands in the working directory; a non-environment is a diagnostic.
    pixi_sbom()
        .current_dir(dir.path())
        .arg("--prefix")
        .arg(&prefix)
        .assert()
        .success();
    assert!(dir.path().join("sbom.cdx.json").exists());
    pixi_sbom()
        .current_dir(dir.path())
        .arg("--prefix")
        .arg(dir.path())
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "is not an environment: looked for conda-meta/",
        ));
    pixi_sbom()
        .current_dir(dir.path())
        .arg("--prefix")
        .arg(&prefix)
        .args(["--all-environments"])
        .assert()
        .code(2);
}

#[test]
fn diff_report_shows_what_changed_since_a_previous_document() {
    // Yesterday's document: the with-pypi web environment with urllib3 1.26.4.
    let old = workspace_with_vulnerable_urllib3();
    for (format, extra) in [
        ("cyclonedx", vec![]),
        ("cyclonedx", vec!["--spec-version", "1.7"]),
        ("spdx", vec![]),
        ("spdx", vec!["--spec-version", "3.0"]),
    ] {
        let previous = old.path().join(format!("previous-{format}-{}.json", extra.len()));
        pixi_sbom()
            .current_dir(old.path())
            .args(["-e", "web", "-p", "linux-64", "--format", format, "--output"])
            .arg(&previous)
            .args(&extra)
            .assert()
            .success();

        // Today: urllib3 back at 2.8.0, requests excluded.
        let new = workspace("with-pypi");
        let assert = pixi_sbom()
            .current_dir(new.path())
            .args(["-e", "web", "-p", "linux-64", "--exclude", "requests", "--keep-orphans"])
            .args(["--report", "diff", "--against"])
            .arg(&previous)
            .args(["--report-format", "json"])
            .assert()
            .success()
            .stderr(predicate::str::contains("compared with the previous document"));
        let report: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
        assert_eq!(report["report"], "diff", "{format} {extra:?}");
        assert!(report["added"].as_array().unwrap().is_empty());
        let removed: Vec<&str> = report["removed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert_eq!(removed, ["requests"], "{format} {extra:?}");
        let changed = &report["version_changed"][0];
        assert_eq!(changed["name"], "urllib3");
        assert_eq!(changed["old_version"], "1.26.4");
        assert_eq!(changed["new_version"], "2.8.0");
        assert!(
            report["license_changed"].as_array().unwrap().is_empty(),
            "{format} {extra:?}"
        );
        assert!(report["unchanged"].as_u64().unwrap() > 20);
    }

    // Markdown for a PR comment; identical input reads as no changes.
    let previous = old.path().join("previous-cyclonedx-0.json");
    let new = workspace("with-pypi");
    let markdown = String::from_utf8(
        pixi_sbom()
            .current_dir(new.path())
            .args(["-e", "web", "-p", "linux-64", "--report", "diff", "--against"])
            .arg(&previous)
            .args(["--report-format", "markdown"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        markdown.contains("| version | urllib3 | pypi | 1.26.4 | 2.8.0 |"),
        "{markdown}"
    );
    assert!(markdown.contains("1 version changes"), "{markdown}");
    let same = String::from_utf8(
        pixi_sbom()
            .current_dir(old.path())
            .args(["-e", "web", "-p", "linux-64", "--report", "diff", "--against"])
            .arg(&previous)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(same.contains("No changes against"), "{same}");

    // --fail-on-diff gates on the sections it is given: the environment above has a version
    // change and nothing else.
    let gate = |sections: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(new.path())
            .args(["-e", "web", "-p", "linux-64", "--report", "diff", "--against"])
            .arg(&previous)
            .arg("--fail-on-diff")
            .args(sections);
        command
    };
    gate(&[])
        .assert()
        .code(6)
        .stderr(predicate::str::contains("version changes (1)"));
    gate(&["version"]).assert().code(6);
    gate(&["license"]).assert().success();
    gate(&["added", "removed"]).assert().success();
    // An unchanged environment passes whatever is asked for.
    pixi_sbom()
        .current_dir(old.path())
        .args(["-e", "web", "-p", "linux-64", "--report", "diff", "--against"])
        .arg(&previous)
        .arg("--fail-on-diff")
        .assert()
        .success();
    pixi_sbom()
        .current_dir(new.path())
        .args(["--report", "packages", "--fail-on-diff"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("only applies to '--report diff'"));

    // Usage: --against needs --report diff and vice versa; a non-document is a diagnostic.
    pixi_sbom()
        .current_dir(new.path())
        .args(["--report", "diff"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("needs '--against <PATH>'"));
    pixi_sbom()
        .current_dir(new.path())
        .args(["--report", "packages", "--against", "x.json"])
        .assert()
        .code(2);
    pixi_sbom()
        .current_dir(new.path())
        .args(["--report", "diff", "--against", "pixi.toml"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("pixi_sbom::diff::parse"));
}

#[test]
fn yanked_releases_are_flagged_and_can_fail_the_run() {
    let dir = workspace("with-pypi");
    // The recorded index metadata, with urllib3 pinned to the yanked 2.0.0 release.
    let cache = dir.path().join("cache").join("pypi");
    std::fs::create_dir_all(&cache).unwrap();
    for entry in std::fs::read_dir(tests_dir().join("fixtures").join("pypi-metadata")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), cache.join(entry.file_name())).unwrap();
    }
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n")
        .replace("\n  version: 2.8.0\n", "\n  version: 2.0.0\n");
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();

    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .args(["-e", "web", "-p", "linux-64", "--fetch-licenses"])
            .args(args)
            .assert()
    };
    let assert = run(&["--output", "-"])
        .success()
        .stderr(predicate::str::contains("looked up PyPI releases"))
        .stderr(predicate::str::contains("yanked=1"));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let urllib3 = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "urllib3")
        .unwrap();
    let props = urllib3["properties"].as_array().unwrap();
    assert!(props.iter().any(|p| p["name"] == "pixi:yanked" && p["value"] == "true"));
    assert!(
        props.iter().any(|p| p["name"] == "pixi:yanked-reason"
            && p["value"].as_str().unwrap().starts_with("Truncated response bodies")),
        "{props:#?}"
    );
    // Nothing else is flagged.
    assert_eq!(
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["properties"]
                .as_array()
                .map(|p| p.iter().any(|p| p["name"] == "pixi:yanked"))
                .unwrap_or(false))
            .count(),
        1
    );

    // The packages report says so, in the table and in the CSV.
    let table = String::from_utf8(run(&["--report", "packages"]).success().get_output().stdout.clone()).unwrap();
    let line = table.lines().find(|l| l.starts_with("urllib3")).unwrap();
    assert!(line.contains("yes: Truncated response bodies"), "{line}");
    let csv = String::from_utf8(
        run(&["--report", "packages", "--report-format", "csv"])
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(csv.lines().next().unwrap().contains(",yanked,yanked_reason,"));
    assert!(
        csv.lines()
            .any(|l| l.contains(",urllib3,2.0.0,") && l.contains(",true,"))
    );

    // The gate: exit 7 with the document still written, and the reason on stderr.
    let out = dir.path().join("gated.cdx.json");
    run(&["--fail-on-yanked", "--output", out.to_str().unwrap()])
        .code(7)
        .stderr(predicate::str::contains("Yanked release(s) in the environment: 1"))
        .stderr(predicate::str::contains("urllib3 2.0.0: Truncated response bodies"));
    assert!(out.exists());

    // It needs the flag that asks the index.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--fail-on-yanked"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("needs '--fetch-licenses'"));
}

#[test]
fn the_prefix_conda_index_reads_its_graphql_shape() {
    let dir = workspace("with-pypi");
    let cache = dir.path().join("cache").join("outdated");
    std::fs::create_dir_all(&cache).unwrap();
    // The cache holds the resolved answer, not the raw GraphQL response: the dates cost a request
    // each, so normalising at fetch time means a second run needs no network.
    std::fs::write(
        cache.join("prefix-conda-forge-python.json"),
        serde_json::json!({
            "versions": ["3.13.1", "3.12.14"],
            "dates": {"3.12.14": "2024-01-02T00:00:00Z", "3.13.1": "2026-05-28T00:00:00Z"}
        })
        .to_string(),
    )
    .unwrap();

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .env("COLUMNS", "160")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--report",
            "outdated",
            "--conda-index-kind",
            "prefix",
            "--report-format",
            "json",
        ])
        .assert()
        .success();
    let report: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    let rows = report["outdated"].as_array().unwrap();
    let python = rows
        .iter()
        .find(|r| r["name"] == "python")
        .expect("the conda package was read from the prefix.dev cache");
    assert_eq!(python["version"], "3.12.14");
    assert_eq!(python["latest"], "3.13.1");
    assert_eq!(python["behind"], 1);
    // `recent` dates the latest release; `current` is filtered to the installed version, so its
    // date is exact however far behind it is.
    assert!(
        python["latest_published"].as_str().unwrap().starts_with("2026-05-28"),
        "{python}"
    );
    assert!(
        python["published"].as_str().unwrap().starts_with("2024-01-02"),
        "{python}"
    );
}

#[test]
fn outdated_report_reads_both_indexes_from_the_cache() {
    let dir = workspace("with-pypi");
    // Recorded project documents: one PyPI project behind by two releases, one conda package
    // behind by one, both served from the cache so the run is offline.
    let cache = dir.path().join("cache").join("outdated");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(
        cache.join("pypi-urllib3.json"),
        serde_json::json!({
            "releases": {
                "2.8.0": [{"upload_time_iso_8601": "2026-09-15T19:29:34Z", "yanked": false}],
                "2.9.0": [{"upload_time_iso_8601": "2026-09-20T00:00:00Z", "yanked": false}],
                "3.0.0": [{"upload_time_iso_8601": "2026-09-22T00:00:00Z", "yanked": false}],
                "3.1.0rc1": [{"upload_time_iso_8601": "2026-09-23T00:00:00Z", "yanked": false}],
                "3.2.0": [{"upload_time_iso_8601": "2026-09-24T00:00:00Z", "yanked": true}],
            }
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        cache.join("conda-conda-forge-python.json"),
        serde_json::json!({
            "versions": ["3.12.14", "3.13.1"],
            "files": [{"version": "3.13.1", "attrs": {"timestamp": 1_780_000_000_000i64}}]
        })
        .to_string(),
    )
    .unwrap();

    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "160")
            .args([
                "-e",
                "web",
                "-p",
                "linux-64",
                "--report",
                "outdated",
                "--conda-index-kind",
                "anaconda",
            ])
            .args(args)
            .assert()
            .success()
    };
    let assert =
        run(&["--report-format", "json"]).stderr(predicate::str::contains("checked how far behind the packages are"));
    let report: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(report["report"], "outdated");
    let rows = report["outdated"].as_array().unwrap();
    let urllib3 = rows.iter().find(|r| r["name"] == "urllib3").unwrap();
    assert_eq!(urllib3["version"], "2.8.0");
    assert_eq!(
        urllib3["latest"], "3.0.0",
        "the prerelease and the yanked release do not count"
    );
    assert_eq!(urllib3["behind"], 2);
    assert_eq!(urllib3["step"], "major");
    let python = rows.iter().find(|r| r["name"] == "python").unwrap();
    assert_eq!(python["latest"], "3.13.1");
    assert_eq!(python["behind"], 1);
    assert_eq!(python["step"], "minor");
    // Everything the caches could not answer for is named rather than silently dropped.
    let unknown = report["summary"]["unknown"].as_array().unwrap();
    assert!(unknown.len() > 10, "{unknown:?}");
    assert!(unknown.iter().any(|n| n == "libzlib"));

    // The table sorts the furthest behind first and the CSV carries the raw fields.
    let table = String::from_utf8(run(&[]).get_output().stdout.clone()).unwrap();
    let first = table.lines().nth(2).unwrap();
    assert!(first.starts_with("urllib3"), "{table}");
    assert!(table.contains("Summary: 2 of 2 packages behind their index"), "{table}");
    let csv = String::from_utf8(run(&["--report-format", "csv"]).get_output().stdout.clone()).unwrap();
    assert!(csv.lines().next().unwrap().ends_with(",behind,step"));
    assert!(csv.lines().any(|l| l.contains(",urllib3,pypi,2.8.0,")));

    // --outdated-min filters by step, and only applies to this report.
    let json: Value = serde_json::from_slice(
        &run(&["--report-format", "json", "--outdated-min", "major"])
            .get_output()
            .stdout,
    )
    .unwrap();
    let names: Vec<&str> = json["outdated"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["urllib3"]);
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--report", "packages", "--outdated-min", "major"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("only applies to '--report outdated'"));
}

#[test]
fn python_report_names_what_blocks_the_next_interpreter() {
    let dir = workspace("with-pypi");
    // The fixture's wheels are open-ended; cap one of them so there is a ceiling to find.
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n")
        .replacen("  requires_python: '>=3.10'", "  requires_python: '>=3.10,<3.13'", 1);
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();

    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("COLUMNS", "160")
            .args(["-e", "web", "-p", "linux-64", "--report", "python"])
            .args(args)
            .assert()
            .success()
    };
    let report: Value = serde_json::from_slice(&run(&["--report-format", "json"]).get_output().stdout).unwrap();
    assert_eq!(report["report"], "python");
    assert_eq!(report["summary"]["interpreter"], "3.12");
    assert_eq!(report["summary"]["ceiling"], "3.12", "the capped wheel decides");
    let blocking = report["summary"]["blocking"].as_array().unwrap();
    assert_eq!(blocking.len(), 1, "{blocking:?}");
    // The lockfile parser normalizes the specifier, so match on its parts.
    assert!(
        blocking[0].as_str().unwrap().starts_with("urllib3 >=3.10"),
        "{blocking:?}"
    );
    assert!(blocking[0].as_str().unwrap().contains("<3.13"), "{blocking:?}");
    assert!(report["summary"]["unsatisfied"].as_array().unwrap().is_empty());
    // Every wheel has a row, with its specifier as written.
    let rows = report["python"].as_array().unwrap();
    assert!(rows.len() >= 6, "{rows:?}");
    assert_eq!(rows[0]["ceiling"], "3.12", "the ceiling comes first");
    assert!(
        rows.iter()
            .any(|r| r["name"] == "six" && r["requires_python"].as_str().unwrap().starts_with(">=2.7")),
        "{rows:?}"
    );

    let table = String::from_utf8(run(&[]).get_output().stdout.clone()).unwrap();
    let header = table.lines().next().unwrap();
    assert!(
        header.starts_with("Package") && header.contains("Requires-Python"),
        "{header}"
    );
    assert!(
        table.contains("Summary: interpreter 3.12, highest Python these packages allow: 3.12"),
        "{table}"
    );
    assert!(table.contains("Holding the ceiling (1):"), "{table}");

    let csv = String::from_utf8(run(&["--report-format", "csv"]).get_output().stdout.clone()).unwrap();
    assert!(csv.starts_with("environment,platform,package,kind,version,requires_python,satisfied,ceiling\n"));
    assert!(csv.lines().any(|l| l.contains(",urllib3,pypi,")));
}

#[test]
fn manifest_declarations_mark_direct_packages_and_the_root_edges() {
    let dir = workspace("with-pypi");
    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("COLUMNS", "200")
            .args(args)
            .assert()
            .success()
    };

    let output = dir.path().join("default.cdx.json");
    run(&["-p", "linux-64", "--output", output.to_str().unwrap()]);
    let document: Value = read_json(&output);
    let python = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "python")
        .unwrap();
    let properties: Vec<(&str, &str)> = python["properties"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["name"].as_str().unwrap(), p["value"].as_str().unwrap()))
        .collect();
    assert!(properties.contains(&("pixi:direct", "true")), "{properties:?}");
    assert!(properties.contains(&("pixi:declared-in", "default")), "{properties:?}");
    let libzlib = document["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "libzlib")
        .unwrap();
    assert!(
        !libzlib["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "pixi:direct"),
        "nothing declared libzlib"
    );

    let python_ref = python["bom-ref"].as_str().unwrap();
    let edges = document["dependencies"].as_array().unwrap();
    let root = edges.iter().find(|e| e["ref"] == "root").unwrap();
    let root_deps: Vec<&str> = root["dependsOn"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(root_deps.contains(&python_ref), "the workspace asked for python");
    // And it is a root edge although something else needs it too, which the old graph-root
    // heuristic could not say.
    assert!(
        edges.iter().any(|e| e["ref"] != "root"
            && e["dependsOn"]
                .as_array()
                .is_some_and(|d| d.iter().any(|r| r == python_ref))),
        "something depends on python"
    );

    // A feature's dependency belongs to the environments that include the feature.
    let web = dir.path().join("web.cdx.json");
    run(&["-e", "web", "-p", "linux-64", "--output", web.to_str().unwrap()]);
    let declared: Vec<String> = read_json(&web)["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| {
            let features = c["properties"]
                .as_array()?
                .iter()
                .find(|p| p["name"] == "pixi:declared-in")?["value"]
                .as_str()?;
            Some(format!("{}:{features}", c["name"].as_str()?))
        })
        .collect();
    assert_eq!(declared, ["python:default", "requests:web", "six:default"]);

    let table = String::from_utf8(
        run(&["-p", "linux-64", "--report", "packages", "--color", "never"])
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(table.lines().next().unwrap().contains("Declared"), "{table}");
    assert!(table.contains(", 2 declared by the workspace"), "{table}");
    assert!(table.contains("Declared but not in this environment: none"), "{table}");
}

#[test]
fn phantom_report_finds_undeclared_imports_and_unused_declarations() {
    let dir = workspace("with-pypi");
    // A source tree that imports one package the manifest never declared (urllib3 is only
    // there because requests needs it), one it did (six), and nothing else of interest.
    std::fs::create_dir_all(dir.path().join("src/app")).unwrap();
    std::fs::write(
        dir.path().join("src/app/__init__.py"),
        "\"\"\"App.\n\n    import notcode\n\"\"\"\nimport os\nimport urllib3\nfrom six import moves\nfrom . import other\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("src/app/other.py"), "import urllib3\n").unwrap();

    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("COLUMNS", "160")
            .args(["-e", "web", "-p", "linux-64", "--report", "phantom"])
            .args(args);
        command
    };

    let stdout = run(&["--report-format", "json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(report["report"], "phantom");
    let rows = report["phantom"].as_array().unwrap();
    let findings: Vec<(&str, &str)> = rows
        .iter()
        .map(|r| (r["finding"].as_str().unwrap(), r["name"].as_str().unwrap()))
        .collect();
    // requests is declared by the web feature and never imported; urllib3 is imported and
    // declared nowhere. The conda packages provide no module, so they are not judged.
    assert_eq!(findings, [("phantom", "urllib3"), ("unused", "requests")]);
    assert_eq!(rows[0]["modules"], serde_json::json!(["urllib3"]));
    assert_eq!(
        rows[0]["files"],
        serde_json::json!(["src/app/__init__.py", "src/app/other.py"]),
        "the importing files, so an editor can jump to them"
    );
    let summary = &report["summary"];
    assert_eq!(summary["phantom"], 1);
    assert_eq!(summary["unused"], 1);
    assert_eq!(summary["files"], 2);
    assert_eq!(summary["from_manifest"], true);
    assert_eq!(
        summary["from_environment"], false,
        "nothing is installed next to the fixture"
    );

    let table = String::from_utf8(run(&[]).assert().success().get_output().stdout.clone()).unwrap();
    assert!(table.lines().next().unwrap().starts_with("Finding"), "{table}");
    assert!(table.contains("Summary: 1 phantom, 0 undeclared, 1 unused"), "{table}");
    assert!(table.contains("Read 2 Python files importing"), "{table}");

    let csv = String::from_utf8(
        run(&["--report-format", "csv"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(csv.starts_with("environment,platform,finding,package,kind,version,modules,files\n"));
    assert!(csv.contains("web,linux-64,phantom,urllib3,pypi,"), "{csv}");

    // --assume-used silences the ones nothing imports by name; the phantom stays.
    let quiet = String::from_utf8(
        run(&["--assume-used", "requests*"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(quiet.contains("Summary: 1 phantom, 0 undeclared, 0 unused"), "{quiet}");

    // --fail-on-phantom gates on the phantom import alone.
    run(&["--fail-on-phantom"])
        .assert()
        .code(8)
        .stderr(predicate::str::contains("Imported but never declared: 1 package(s)"));
    run(&["--source", "docs", "--fail-on-phantom"]).assert().success();
}

#[test]
fn phantom_flags_need_the_phantom_report() {
    let dir = workspace("with-pypi");
    for flag in [
        vec!["--fail-on-phantom"],
        vec!["--assume-used", "x"],
        vec!["--source", "."],
    ] {
        pixi_sbom()
            .current_dir(dir.path())
            .args(["--report", "packages"])
            .args(&flag)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("only applies to '--report phantom'"));
    }
}

#[test]
fn fetch_licenses_reads_wheel_metadata_and_license_files() {
    // The with-pypi fixture with the six wheel pointed at the local copy; everything else offline.
    let dir = workspace("with-pypi");
    let wheel = tests_dir()
        .join("fixtures")
        .join("archives")
        .join("six-1.17.0-py2.py3-none-any.whl");
    let path = wheel.display().to_string().replace('\\', "/");
    let url = format!("file://{}{path}", if path.starts_with('/') { "" } else { "/" });
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n")
        .replace(
            "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
            &url,
        );
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--fetch-licenses",
            "--license-texts",
            "--output",
            "-",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "read PyPI license details from wheels fetched=1 failed=5 skipped=0",
        ));
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let six = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "six")
        .unwrap();
    assert_eq!(six["licenses"][0]["license"]["id"], "MIT", "License: MIT from METADATA");
    assert!(
        six["licenses"][0]["license"]["text"]["content"]
            .as_str()
            .unwrap()
            .contains("Benjamin Peterson")
    );
    assert_eq!(six["description"], "Python 2 and 3 compatibility utilities");
    let props = six["properties"].as_array().unwrap();
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:license-source" && p["value"] == "wheel")
    );
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:license-files-source" && p["value"] == "wheel")
    );
    // The other wheels were unreachable offline and simply have no license.
    let requests = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "requests")
        .unwrap();
    assert!(requests.get("licenses").is_none());
}

#[test]
fn license_policy_violations_exit_3_after_writing_the_document() {
    let dir = workspace("with-pypi");

    // ld_impl_linux-64 and readline are GPL-3.0-only in the fixture; python and libpython are Python-2.0.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args([
            "-p",
            "linux-64",
            "--deny-license",
            "GPL-3.0-only",
            "--deny-license",
            "Python-2.0",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("License policy violated by 4 package(s):"))
        .stderr(predicate::str::contains(
            "  ld_impl_linux-64 2.46.1: denied license (GPL-3.0-only)",
        ))
        .stderr(predicate::str::contains(
            "  readline 8.3: denied license (GPL-3.0-only)",
        ))
        .stderr(predicate::str::contains(
            "  python 3.12.14: denied license (Python-2.0)",
        ));
    assert!(
        dir.path().join("sbom.cdx.json").exists(),
        "the document is still written"
    );
    assert_valid(&cyclonedx_validator(), &read_json(&dir.path().join("sbom.cdx.json")));
    let _ = assert;

    // Allow-list: everything in the environment except the GPL linker is permissive.
    pixi_sbom()
        .current_dir(dir.path())
        .args([
            "-p",
            "linux-64",
            "--allow-license",
            "MIT",
            "--allow-license",
            "BSD-3-Clause",
            "--allow-license",
            "GPL-3.0-only",
            "--output",
            "-",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("not in the allowed licenses"))
        .stdout(predicate::str::contains("\"bomFormat\": \"CycloneDX\""));

    // A policy that everything satisfies exits 0.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--deny-license", "AGPL-3.0-only", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("checked the license policy violations=0"));

    // --ignore-license lets named packages through, records why in the document, and leaves
    // everything else to the policy.
    let exempt = |extra: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .args([
                "-p",
                "linux-64",
                "--deny-license",
                "GPL-3.0-only",
                "--ignore-license",
                "ld_impl_*:build-time only",
                "--ignore-license",
                "readline",
            ])
            .args(extra);
        command
    };
    let document: Value = serde_json::from_slice(
        &exempt(&["--output", "-"])
            .assert()
            .success()
            .stderr(predicate::str::contains(
                "ld_impl_linux-64 2.46.1: denied license (GPL-3.0-only) — build-time only",
            ))
            .stderr(predicate::str::contains("violations=0 exempt=2"))
            .get_output()
            .stdout,
    )
    .unwrap();
    let property = |name: &str| -> Option<String> {
        document["components"]
            .as_array()?
            .iter()
            .find(|c| c["name"] == name)?
            .get("properties")?
            .as_array()?
            .iter()
            .find(|p| p["name"] == "pixi:license-exempt")?
            .get("value")?
            .as_str()
            .map(str::to_string)
    };
    assert_eq!(property("ld_impl_linux-64").as_deref(), Some("build-time only"));
    assert_eq!(property("readline").as_deref(), Some("true"), "no justification given");
    assert_eq!(property("python"), None, "nothing exempted python");

    // The licenses report lists them, and a package nobody exempted still fails the policy.
    let table = String::from_utf8(
        exempt(&["--report", "licenses", "--color", "never"])
            .env("COLUMNS", "200")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        table.contains("Exempt from the policy (2): ld_impl_linux-64 (build-time only), readline"),
        "{table}"
    );
    pixi_sbom()
        .current_dir(dir.path())
        .args([
            "-p",
            "linux-64",
            "--deny-license",
            "GPL-3.0-only",
            "--ignore-license",
            "readline",
            "--output",
            "-",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("ld_impl_linux-64"));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--require-license", "--ignore-license", ":why"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--ignore-license"));
}

#[test]
fn require_license_flags_pypi_packages_without_one_and_batch_runs_label_violations() {
    let dir = workspace("with-pypi");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-e", "web", "-p", "linux-64", "--require-license", "--output", "-"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("  six 1.17.0: no license declared"))
        .stderr(predicate::str::contains("  requests"));

    // Two documents: violations are prefixed with the environment/platform.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-environments", "-p", "linux-64", "--deny-license", "GPL-3.0-only"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("[default/linux-64] ld_impl_linux-64"))
        .stderr(predicate::str::contains("[web/linux-64] ld_impl_linux-64"));

    // Works with --report too: the table prints and the exit code is still 3.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args([
            "-p",
            "linux-64",
            "--report",
            "licenses",
            "--deny-license",
            "GPL-3.0-only",
        ])
        .assert()
        .code(3);
    assert!(String::from_utf8_lossy(&assert.get_output().stdout).contains("Summary:"));
}

#[test]
fn bad_licensee_is_a_usage_error() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--allow-license", "not a license"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is not an SPDX license identifier"));
}

#[test]
fn embedded_sboms_attach_wheel_components_in_every_format() {
    // The with-pypi fixture with six pointed at the local wheel that carries PEP 770 fragments.
    let dir = workspace("with-pypi");
    let wheel = tests_dir()
        .join("fixtures")
        .join("archives")
        .join("six-1.17.0-py2.py3-none-any.sbom.whl");
    let path = wheel.display().to_string().replace('\\', "/");
    let url = format!("file://{}{path}", if path.starts_with('/') { "" } else { "/" });
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n")
        .replace(
            "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl",
            &url,
        );
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();
    let run = |extra: &[&str]| {
        let mut args = vec!["-e", "web", "-p", "linux-64", "--embedded-sboms", "--output", "-"];
        args.extend_from_slice(extra);
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(&args)
            .assert()
            .success()
            .stderr(predicate::str::contains(
                "attached embedded SBOM components files=2 unreadable=0 added=4 merged=0",
            ));
        serde_json::from_slice::<Value>(&assert.get_output().stdout).unwrap()
    };

    let doc = run(&[]);
    assert_valid(&cyclonedx_validator(), &doc);
    let components = doc["components"].as_array().unwrap();
    let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
    let pyo3 = by_name("pyo3");
    assert_eq!(pyo3["purl"], "pkg:cargo/pyo3@0.27.2");
    assert_eq!(pyo3["licenses"][0]["expression"], "MIT OR Apache-2.0");
    let props = pyo3["properties"].as_array().unwrap();
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:kind" && p["value"] == "embedded")
    );
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:embedded-sbom" && p["value"] == "six/six.cyclonedx.json")
    );
    let vendored_openssl = components
        .iter()
        .find(|c| c["purl"] == "pkg:generic/openssl@4.0.2")
        .unwrap();
    assert_eq!(
        vendored_openssl["hashes"][0]["content"],
        "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8"
    );
    assert!(
        by_name("openssl")["purl"].as_str().unwrap().starts_with("pkg:conda/"),
        "the conda openssl is untouched"
    );
    let deps = doc["dependencies"].as_array().unwrap();
    // six is the local wheel now, which claims no PyPI release (#333).
    let six_deps: Vec<_> = deps.iter().find(|d| d["ref"] == "pkg:generic/six@1.17.0").unwrap()["dependsOn"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap().split('?').next().unwrap().to_string())
        .collect();
    assert!(six_deps.contains(&"pkg:cargo/pyo3@0.27.2".to_string()), "{six_deps:?}");
    assert!(
        six_deps.contains(&"pkg:generic/openssl@4.0.2".to_string()),
        "{six_deps:?}"
    );
    assert!(
        six_deps.contains(&"pkg:conda/python@3.12.14".to_string()),
        "{six_deps:?}"
    );
    let pyo3_deps = deps.iter().find(|d| d["ref"] == "pkg:cargo/pyo3@0.27.2").unwrap()["dependsOn"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(pyo3_deps, 2, "libc and memoffset");

    let doc = run(&["--format", "spdx"]);
    assert_valid(&spdx_validator(), &doc);
    let libc = doc["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "libc")
        .unwrap();
    assert_eq!(libc["SPDXID"], "SPDXRef-Package-embedded-libc-0.2.177");
    assert_eq!(libc["licenseDeclared"], "MIT OR Apache-2.0");

    let doc = run(&["--format", "spdx", "--spec-version", "3.0"]);
    assert_valid(&spdx3_validator(), &doc);
    assert!(
        doc["@graph"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n["type"] == "software_Package" && n["software_packageUrl"] == "pkg:cargo/memoffset@0.9.1")
    );

    // The report shows the kind, and the policy sees the crates' licenses.
    pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--embedded-sboms",
            "--report",
            "packages",
            "--deny-license",
            "Apache-2.0",
        ])
        .assert()
        .code(3)
        .stdout(predicate::str::is_match(r"memoffset\s+0\.9\.1\s+embedded").unwrap())
        .stderr(predicate::str::contains("openssl 4.0.2: denied license (Apache-2.0)"));
}

#[test]
fn non_spdx_exception_clauses_stay_evaluable_expressions() {
    let dir = workspace("conda-only");
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n")
        .replace(
            "  license: Zlib\n  license_family: Other\n  run_exports:\n    weak:\n    - libzlib >=1.3.2,<2.0a0\n  size: 63713",
            "  license: LGPL-2.0-or-later AND LGPL-2.0-or-later WITH exceptions AND GPL-2.0-or-later\n  license_family: Other\n  run_exports:\n    weak:\n    - libzlib >=1.3.2,<2.0a0\n  size: 63713",
        );
    assert!(lock.contains("WITH exceptions"), "fixture edit applied");
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args([
            "-p",
            "linux-64",
            "--require-license",
            "--deny-license",
            "AGPL-3.0-only",
            "--output",
            "-",
        ])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let libzlib = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "libzlib")
        .unwrap();
    assert_eq!(
        libzlib["licenses"][0]["expression"],
        "LGPL-2.0-or-later AND LGPL-2.0-or-later WITH AdditionRef-exceptions AND GPL-2.0-or-later"
    );
    assert!(libzlib["properties"].as_array().unwrap().iter().any(|p| {
        p["name"] == "pixi:license-raw"
            && p["value"] == "LGPL-2.0-or-later AND LGPL-2.0-or-later WITH exceptions AND GPL-2.0-or-later"
    }));

    // Denying the LGPL part now works, because the expression is evaluable.
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--deny-license", "GPL-2.0-or-later", "--output", "-"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("libzlib 1.3.2: denied license"));
}

#[test]
fn spdx_format_writes_valid_spdx_document() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--format", "spdx", "-p", "osx-arm64"])
        .assert()
        .success();

    let doc = read_json(&dir.path().join("sbom.spdx.json"));
    assert_valid(&spdx_validator(), &doc);
    assert_eq!(doc["spdxVersion"], "SPDX-2.3");
    assert_eq!(doc["name"], "conda-only-default-osx-arm64");
    let packages = doc["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 3, "root + 2 packages");
    assert!(packages.iter().all(|p| p["downloadLocation"].as_str().is_some()));
    assert_eq!(
        packages[0]["sourceInfo"],
        "pixi workspace; lockfile pixi.lock; environment default; platform osx-arm64"
    );
    assert_eq!(packages[0]["licenseDeclared"], "MIT");
    assert_eq!(packages[0]["homepage"], "https://conda-only.example");
    assert_eq!(packages[0]["downloadLocation"], "https://github.com/example/conda-only");
    let creators = doc["creationInfo"]["creators"].as_array().unwrap();
    assert!(creators.contains(&Value::from("Person: Test Author (author@example.org)")));
    assert!(
        packages[1..]
            .iter()
            .all(|p| p["supplier"].as_str().unwrap().starts_with("Organization: conda-forge"))
    );
}

#[test]
fn explicit_lockfile_and_output_paths_are_honored() {
    let dir = workspace("with-pypi");
    let out = dir.path().join("reports").join("web.cdx.json");

    pixi_sbom()
        .args([
            "--lockfile",
            dir.path().join("pixi.lock").to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "-e",
            "web",
            "-p",
            "linux-64",
        ])
        .assert()
        .success();

    let doc = read_json(&out);
    assert_valid(&cyclonedx_validator(), &doc);
    let components = doc["components"].as_array().unwrap();
    assert!(components.iter().any(|c| c["name"] == "requests"));
    assert!(components.iter().any(|c| c["name"] == "python"));
    let props = doc["metadata"]["properties"].as_array().unwrap();
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:environment" && p["value"] == "web")
    );
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:lockfile" && p["value"] == "pixi.lock"),
        "lockfile is recorded by name, not by the absolute path it was read from"
    );
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(
        !text.contains(dir.path().to_str().unwrap()),
        "document must not contain the generating machine's paths"
    );
}

#[test]
fn pypi_environment_produces_valid_spdx() {
    let dir = workspace("with-pypi");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--format", "spdx", "-e", "web", "-p", "linux-64"])
        .assert()
        .success();

    let doc = read_json(&dir.path().join("sbom.spdx.json"));
    assert_valid(&spdx_validator(), &doc);
    let packages = doc["packages"].as_array().unwrap();
    let six = packages.iter().find(|p| p["name"] == "six").unwrap();
    assert_eq!(six["externalRefs"][0]["referenceLocator"], "pkg:pypi/six@1.17.0");
    let rels = doc["relationships"].as_array().unwrap();
    assert!(rels.iter().any(|r| r["relationshipType"] == "DEPENDS_ON"));
}

#[test]
fn source_packages_produce_valid_documents_in_both_formats() {
    let dir = workspace("source-packages");
    let cdx = dir.path().join("out.cdx.json");
    let spdx = dir.path().join("out.spdx.json");

    for (format, out) in [("cyclonedx", &cdx), ("spdx", &spdx)] {
        pixi_sbom()
            .current_dir(dir.path())
            .args(["--format", format, "-p", "linux-64", "--output", out.to_str().unwrap()])
            .assert()
            .success();
    }

    let cdx_doc = read_json(&cdx);
    assert_valid(&cyclonedx_validator(), &cdx_doc);
    let components = cdx_doc["components"].as_array().unwrap();
    let git = components.iter().find(|c| c["name"] == "pixi-tag-package").unwrap();
    assert_eq!(git["externalReferences"][0]["type"], "vcs");
    assert_eq!(
        git["externalReferences"][0]["url"],
        "git+https://github.com/example/pixi-package.git@def456789012345"
    );
    let partial = components.iter().find(|c| c["name"] == "my-partial-pkg").unwrap();
    assert!(partial.get("version").is_none());
    assert_eq!(partial["purl"], "pkg:conda/my-partial-pkg");

    let spdx_doc = read_json(&spdx);
    assert_valid(&spdx_validator(), &spdx_doc);
    let packages = spdx_doc["packages"].as_array().unwrap();
    let local = packages.iter().find(|p| p["name"] == "local-package").unwrap();
    assert_eq!(local["downloadLocation"], "NOASSERTION");
    assert_eq!(local["sourceInfo"], "built from source at ../local-package");
    let git = packages.iter().find(|p| p["name"] == "pixi-tag-package").unwrap();
    assert_eq!(
        git["downloadLocation"],
        "git+https://github.com/example/pixi-package.git@def456789012345"
    );
}

#[test]
fn all_environments_writes_one_file_per_environment_next_to_lockfile() {
    let dir = workspace("multi-env");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-environments", "-p", "linux-64"])
        .assert()
        .success()
        .stderr(predicate::str::contains("environment=default"))
        .stderr(predicate::str::contains("environment=alpha"))
        .stderr(predicate::str::contains("environment=zeta"));

    let validator = cyclonedx_validator();
    for (env, expected_packages) in [("default", 1), ("alpha", 2), ("zeta", 2)] {
        let doc = read_json(&dir.path().join(format!("sbom-{env}.cdx.json")));
        assert_valid(&validator, &doc);
        assert_eq!(doc["components"].as_array().unwrap().len(), expected_packages, "{env}");
        let props = doc["metadata"]["properties"].as_array().unwrap();
        assert!(
            props
                .iter()
                .any(|p| p["name"] == "pixi:environment" && p["value"] == env)
        );
    }
    assert!(
        !dir.path().join("sbom.cdx.json").exists(),
        "single-environment default name is not used"
    );
}

#[test]
fn all_environments_with_output_directory_and_spdx() {
    let dir = workspace("with-pypi");
    let out = dir.path().join("reports").join("nested");

    pixi_sbom()
        .current_dir(dir.path())
        .args([
            "--all-environments",
            "--format",
            "spdx",
            "-p",
            "linux-64",
            "--output",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let validator = spdx_validator();
    for env in ["default", "web"] {
        let doc = read_json(&out.join(format!("sbom-{env}.spdx.json")));
        assert_valid(&validator, &doc);
        assert_eq!(doc["name"], format!("with-pypi-{env}-linux-64"));
    }
}

#[test]
fn all_environments_conflicts_with_environment() {
    let dir = workspace("with-pypi");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--all-environments", "-e", "web"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn unknown_environment_is_reported() {
    let dir = workspace("with-pypi");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-e", "missing", "-p", "linux-64"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("environment 'missing' not found"))
        .stderr(predicate::str::contains("web"));
}

#[test]
fn unknown_platform_is_reported() {
    let dir = workspace("with-pypi");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "win-64"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("platform 'win-64' is not locked"))
        .stderr(predicate::str::contains("osx-arm64"));
}

#[test]
fn unwritable_output_is_reported() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--output", dir.path().to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot create"));
}

#[test]
fn the_document_records_what_the_run_could_not_ask() {
    let dir = workspace_with_vulnerable_urllib3();
    let run = |cache: &str| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join(cache))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args([
                "-e",
                "web",
                "-p",
                "linux-64",
                "--vulnerabilities",
                "osv",
                "--output",
                "-",
            ]);
        command
    };
    let properties = |doc: &Value| -> Vec<(String, String)> {
        doc["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["name"].as_str().unwrap().to_string(),
                    p["value"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let validator = cyclonedx_validator();

    // Warm cache: every purl is answered from disk, so nothing is missing and the document
    // says nothing about itself.
    let assert = run("cache").assert().success();
    let warm: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&validator, &warm);
    assert!(
        warm["vulnerabilities"].as_array().is_some_and(|v| !v.is_empty()),
        "the cache answers for the vulnerable urllib3"
    );
    let warm_properties = properties(&warm);
    assert!(
        warm_properties
            .iter()
            .all(|(name, _)| !name.starts_with("pixi:incomplete")),
        "{warm_properties:?}"
    );

    // Empty cache: the same lockfile and the same flags, but nothing could be asked. An empty
    // `vulnerabilities[]` now says which question went unanswered instead of reading as
    // "no known vulnerabilities".
    let assert = run("empty-cache").assert().success();
    let cold: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&validator, &cold);
    assert!(
        cold["vulnerabilities"].as_array().is_none_or(|v| v.is_empty()),
        "offline with nothing cached finds nothing"
    );
    let cold_properties = properties(&cold);
    let value = |name: &str| {
        cold_properties
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(value("pixi:incomplete").as_deref(), Some("osv"), "{cold_properties:?}");
    let detail = value("pixi:incomplete-detail").unwrap_or_default();
    assert!(detail.contains("purls unasked (offline, nothing cached)"), "{detail}");
    assert_ne!(
        properties(&warm),
        cold_properties,
        "the two documents differ in what they say about themselves"
    );
}

#[test]
fn the_log_can_be_json_for_a_collector_instead_of_prose_for_a_person() {
    let dir = workspace("with-pypi");
    let run = |args: &[&str], envs: &[(&str, &str)]| -> String {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["-p", "linux-64", "--output", "-"])
            .args(args);
        for (name, value) in envs {
            command.env(name, value);
        }
        String::from_utf8(command.assert().success().get_output().stderr.clone()).unwrap()
    };

    let log = run(&["--log-format", "json", "-v"], &[]);
    let lines: Vec<&str> = log.lines().filter(|line| !line.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "the run logs something at -v");
    for line in &lines {
        let event: Value = serde_json::from_str(line).unwrap_or_else(|err| panic!("not JSON: {line}\n{err}"));
        assert!(event["level"].is_string(), "{line}");
        assert!(
            event["target"].as_str().is_some_and(|t| t.starts_with("pixi_sbom")),
            "{line}"
        );
        assert!(event["fields"]["message"].is_string(), "{line}");
        // The timestamp the text renderer drops deliberately comes back: a collector needs it.
        assert!(event["timestamp"].is_string(), "{line}");
        // Nothing reading this is a terminal, so nothing is coloured.
        assert!(!line.contains('\u{1b}'), "escape codes in a JSON log: {line}");
    }

    // The fields stay fields rather than being folded into the message.
    let selected = lines
        .iter()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["fields"]["message"] == "selected lock environment")
        .expect("the run says which environment it read");
    assert_eq!(selected["fields"]["platform"], "linux-64");
    assert!(selected["fields"]["packages"].is_number());

    // PIXI_SBOM_LOG_FORMAT does the same, and a value that is not a format says so in the log
    // rather than refusing to run.
    let log = run(&[], &[("PIXI_SBOM_LOG_FORMAT", "json")]);
    assert!(
        log.lines().all(|line| serde_json::from_str::<Value>(line).is_ok()),
        "{log}"
    );
    let log = run(&[], &[("PIXI_SBOM_LOG_FORMAT", "jsonl")]);
    assert!(log.contains("not a log format"), "{log}");
    assert!(
        serde_json::from_str::<Value>(log.lines().next().unwrap()).is_err(),
        "an unusable value falls back to text: {log}"
    );

    // The default is unchanged: prose, and no timestamp column.
    let log = run(&[], &[]);
    assert!(
        serde_json::from_str::<Value>(log.lines().next().unwrap_or("")).is_err(),
        "{log}"
    );
}

#[test]
fn a_private_ca_bundle_is_checked_before_the_first_request() {
    let dir = workspace("with-pypi");

    // A path that is not there names the file and the flag that gave it, rather than coming
    // back as a handshake failure once the run is well under way.
    pixi_sbom()
        .current_dir(dir.path())
        .args([
            "-p",
            "linux-64",
            "--ca-bundle",
            "no-such-ca.pem",
            "--fetch-licenses",
            "--output",
            "-",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot read the CA bundle"))
        .stderr(predicate::str::contains("no-such-ca.pem"))
        .stderr(predicate::str::contains("pixi_sbom::http::ca_bundle"));

    // A file that is not a certificate is the other half of the same mistake: DER instead of
    // PEM, or a pasted fragment.
    let der = dir.path().join("cacert.der");
    std::fs::write(&der, [0x30u8, 0x82, 0x01, 0x0a]).unwrap();
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--output", "-"])
        .env("PIXI_SBOM_CA_BUNDLE", &der)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no certificate in the CA bundle"))
        .stderr(predicate::str::contains("openssl x509 -inform der"));

    // And the configuration block says which roots are in play, so --doctor answers "is it my
    // CA?" without anyone reading the source.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .env("SSL_CERT_FILE", "/etc/ssl/corp.pem")
        .args(["--doctor", "--color", "never"])
        .assert();
    let assert = assert.code(1);
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(
        text.contains("TLS roots  the CA bundle at /etc/ssl/corp.pem (SSL_CERT_FILE)"),
        "{text}"
    );
    // The bundle named there does not exist on the test machine, and --doctor is the one
    // command that reports that instead of refusing to run.
    assert!(text.contains("unusable: cannot read the CA bundle"), "{text}");

    // Without any of the three, the platform store is used and said so.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .env_remove("SSL_CERT_FILE")
        .args(["--doctor", "--color", "never"])
        .assert();
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    assert!(text.contains("TLS roots  the platform verifier"), "{text}");
}

#[test]
fn the_number_of_jobs_at_once_is_configurable_and_never_changes_the_document() {
    let dir = workspace("with-pypi");
    let run = |concurrency: Option<&str>| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .args(["-e", "web", "-p", "linux-64", "--fetch-licenses", "--output", "-"]);
        match concurrency {
            Some(value) => command.env("PIXI_SBOM_CONCURRENCY", value),
            None => command.env_remove("PIXI_SBOM_CONCURRENCY"),
        };
        command
    };

    // One job at a time and the default produce the same document, byte for byte: a scheduler
    // that could change the output would make the documents unreproducible.
    let default = run(None).assert().success().get_output().stdout.clone();
    let serial = run(Some("1")).assert().success().get_output().stdout.clone();
    let many = run(Some("16")).assert().success().get_output().stdout.clone();
    assert_eq!(default, serial, "one job at a time writes the same document");
    assert_eq!(default, many, "sixteen jobs at a time write the same document");
    assert!(!default.is_empty());

    // A value that is not a number is named and ignored rather than stopping the run.
    let assert = run(Some("plenty")).assert().success();
    let log = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(log.contains("not a positive number of requests"), "{log}");
    assert!(log.contains("value=\"plenty\""), "{log}");
    assert_eq!(assert.get_output().stdout, default, "and the document is unchanged");

    // The chosen limits are in the debug log, where a run that is slower than expected can be
    // checked against what it was allowed to do.
    let assert = run(Some("3")).args(["-v"]).assert().success();
    let log = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(log.contains("concurrency") && log.contains("network=3"), "{log}");
    assert!(
        log.contains("source=\"PIXI_SBOM_CONCURRENCY\""),
        "and which of the four sources chose it: {log}"
    );
    // The setting is requests only, and local work still follows the core count. Asserting on a
    // literal would only prove the machine's core count differs from the value asked for, which on
    // a three-core runner it does not: compare two runs instead, and the invariant holds anywhere.
    let cpu_of = |value: &str| {
        let assert = run(Some(value)).args(["-v"]).assert().success();
        let log = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
        let line = log
            .lines()
            .find(|line| line.contains("concurrency network="))
            .unwrap_or_default()
            .to_string();
        let cpu = line
            .split("cpu=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or_default()
            .to_string();
        assert!(!cpu.is_empty(), "{log}");
        cpu
    };
    assert_eq!(
        cpu_of("2"),
        cpu_of("16"),
        "threads for local work do not move with the number of requests"
    );
}

#[test]
fn a_batch_looks_each_package_up_once_however_many_documents_share_it() {
    let dir = workspace("multi-env");
    let out = dir.path().join("out");
    // Offline, with nothing cached, every request is refused and logged with its URL: the
    // count of those lines is the count of lookups the run would have made.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("empty-cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "--all-environments",
            "-p",
            "linux-64",
            "--fetch-licenses",
            "--output",
            out.to_str().unwrap(),
            "-v",
        ])
        .assert()
        .success();
    let log = String::from_utf8(assert.get_output().stderr.clone()).unwrap();

    // Three environments hold five package entries between them, and two distinct packages.
    assert!(
        log.contains("documents=3 packages=2 instead_of=5"),
        "the shared pass should say what it saved: {log}"
    );
    let asked: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("refusing the request"))
        .collect();
    assert_eq!(
        asked.len(),
        2,
        "each distinct package is asked about once, not once per document: {asked:#?}"
    );
    assert_eq!(
        asked.iter().filter(|line| line.contains("libzlib")).count(),
        1,
        "libzlib is in all three environments and is looked up once"
    );

    // And every document was still written.
    let written: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(written.len(), 3, "{written:?}");

    // A single-document run does not pay for the shared pass at all.
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("empty-cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "alpha",
            "-p",
            "linux-64",
            "--fetch-licenses",
            "--output",
            "-",
            "-v",
        ])
        .assert()
        .success();
    let log = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(!log.contains("looking every document's packages up at once"), "{log}");
}

#[test]
fn the_shared_lookups_do_not_change_what_any_document_says() {
    let dir = workspace("multi-env");
    let together = dir.path().join("together");
    let apart = dir.path().join("apart");
    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .args(["-p", "linux-64", "--fetch-licenses"])
            .args(args)
            .assert()
            .success();
    };

    // Every environment at once, which takes the shared path.
    run(&["--all-environments", "--output", together.to_str().unwrap()]);
    // The same environments one at a time, which does not.
    std::fs::create_dir_all(&apart).unwrap();
    for environment in ["default", "alpha", "zeta"] {
        run(&[
            "-e",
            environment,
            "--output",
            apart.join(format!("{environment}.cdx.json")).to_str().unwrap(),
        ]);
    }

    for environment in ["default", "alpha", "zeta"] {
        let batched = read_json(&together.join(format!("sbom-{environment}.cdx.json")));
        let alone = read_json(&apart.join(format!("{environment}.cdx.json")));
        assert_eq!(
            batched["components"], alone["components"],
            "{environment} must not depend on what else was built beside it"
        );
        assert_eq!(batched["dependencies"], alone["dependencies"], "{environment}");
        // The steps that could not finish are the same; only the counts differ, because the
        // batch looked every document's packages up at once and says so.
        let property = |doc: &Value, name: &str| {
            doc["metadata"]["properties"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == name)
                .map(|p| p["value"].as_str().unwrap().to_string())
        };
        assert_eq!(
            property(&batched, "pixi:incomplete"),
            property(&alone, "pixi:incomplete"),
            "{environment}"
        );
        assert!(
            property(&batched, "pixi:incomplete-detail")
                .unwrap_or_default()
                .contains("looked up once for every document in the run"),
            "{environment}: a batch says whose counts those are"
        );
    }
}

#[test]
fn a_document_or_report_written_to_stdout_is_the_same_bytes_as_to_a_file() {
    let dir = workspace("with-pypi");
    let file = dir.path().join("sbom.cdx.json");
    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .args(["-e", "web", "-p", "linux-64"])
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };

    // The two go through different writers — a file is buffered, stdout is buffered by hand
    // because Rust's own is line-buffered and the writers emit a line at a time.
    let piped = run(&["--output", "-"]);
    run(&["--output", file.to_str().unwrap()]);
    let written = std::fs::read(&file).unwrap();
    assert_eq!(piped, written, "the same document, whichever writer carries it");
    assert!(!piped.is_empty());

    // The JSON report is written the same way, straight out rather than assembled into a
    // string first, and has to survive the same comparison.
    let report = run(&["--report", "packages", "--report-format", "json"]);
    let value: Value = serde_json::from_slice(&report).unwrap_or_else(|err| panic!("not JSON: {err}"));
    assert!(value["packages"].as_array().is_some_and(|p| !p.is_empty()), "{value}");
    assert!(report.ends_with(b"\n"), "one trailing newline, as before");
}

#[test]
fn every_lockfile_format_version_we_support_produces_the_same_document() {
    // rattler has four parsers, not seven: v1-v3, v4-v5, v6 and v7. One fixture per parser,
    // each holding the same two conda packages and one wheel, so a difference in the output
    // is a difference in how that format was read rather than in what it described.
    //
    // v1 is there twice over: it is the oldest, and it is the only one that writes
    // dependencies as a map rather than a list.
    let versions = [("lock-v1", 1), ("lock-v3", 3), ("lock-v5", 5), ("lock-v6", 6)];
    let validator = cyclonedx_validator();

    for (fixture, version) in versions {
        let dir = workspace(fixture);
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .args(["-p", "linux-64", "--output", "-"])
            .assert()
            .success();
        let doc: Value = serde_json::from_slice(&assert.get_output().stdout)
            .unwrap_or_else(|err| panic!("v{version} did not produce JSON: {err}"));
        assert_valid(&validator, &doc);

        let components = doc["components"].as_array().unwrap();
        let by_name = |name: &str| {
            components
                .iter()
                .find(|c| c["name"] == name)
                .unwrap_or_else(|| panic!("v{version} lost {name}"))
        };
        assert_eq!(components.len(), 3, "v{version}");

        // A conda package keeps the identity that only the lockfile can give it. Before v6
        // these fields were written out; from v6 they are derived from the location, and the
        // document should not be able to tell.
        let zlib = by_name("zlib");
        let props: Vec<(&str, &str)> = zlib["properties"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| (p["name"].as_str().unwrap(), p["value"].as_str().unwrap()))
            .collect();
        assert!(props.contains(&("pixi:kind", "conda")), "v{version}: {props:?}");
        assert!(
            props.contains(&("pixi:channel", "conda-forge")),
            "v{version}: {props:?}"
        );
        assert!(props.contains(&("pixi:subdir", "linux-64")), "v{version}: {props:?}");
        assert_eq!(zlib["licenses"][0]["expression"], "Zlib", "v{version}");
        assert!(
            zlib["purl"].as_str().unwrap().starts_with("pkg:conda/zlib@1.3.2"),
            "v{version}: {}",
            zlib["purl"]
        );

        // v1 and v2 call it `pip`; v3 renamed it to `pypi`. Either way it is a PyPI package
        // here, or its identity would be wrong everywhere downstream.
        let six = by_name("six");
        assert_eq!(six["purl"], "pkg:pypi/six@1.17.0", "v{version}");

        // The dependency zlib declares on libzlib survives, whether the format wrote it as a
        // map (v1) or a list (everything after).
        let edges = doc["dependencies"].as_array().unwrap();
        let zlib_deps = edges
            .iter()
            .find(|e| e["ref"] == zlib["bom-ref"])
            .map(|e| e["dependsOn"].as_array().cloned().unwrap_or_default())
            .unwrap_or_default();
        assert!(
            zlib_deps.iter().any(|d| d.as_str().unwrap().contains("libzlib")),
            "v{version} lost the edge to libzlib: {zlib_deps:?}"
        );
    }
}

#[test]
fn a_format_older_than_multiple_environments_still_answers_every_environment() {
    // v1 to v3 predate the environments block entirely — rattler synthesizes a single
    // `default`. The flags that iterate environments and platforms have to cope with that
    // rather than finding nothing to do.
    for fixture in ["lock-v1", "lock-v3"] {
        let dir = workspace(fixture);
        let out = dir.path().join("out");
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .args([
                "--all-environments",
                "--all-platforms",
                "--output",
                out.to_str().unwrap(),
            ])
            .assert()
            .success();
        let written: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(written, vec!["sbom-default-linux-64.cdx.json".to_string()], "{fixture}");
    }
}

#[test]
fn a_lockfile_newer_than_we_understand_says_so_and_names_the_ceiling() {
    let dir = workspace("lock-v1");
    let lock = dir.path().join("pixi.lock");
    let text = std::fs::read_to_string(&lock)
        .unwrap()
        .replace("version: 1", "version: 8");
    std::fs::write(&lock, text).unwrap();

    pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["-p", "linux-64", "--output", "-"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("version 8"))
        .stderr(predicate::str::contains("up to"))
        // The help line says what to do about it, as every diagnostic here does.
        .stderr(predicate::str::contains("upgrade pixi-sbom"));
}

/// Every file under `root`, relative and sorted, so two runs can be compared.
fn tree(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, found: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, found);
            } else {
                found.push(path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut found = Vec::new();
    walk(root, root, &mut found);
    found
}

/// SECURITY.md states, as a property a reporter can hold us to, that a run writes the output
/// paths it was given and nothing else outside the cache. Nothing was checking it, and a stray
/// write — a temporary file left behind, a path built from a package name — is exactly the kind
/// of thing that would go unnoticed until someone ran this against a package they did not trust.
#[test]
fn a_run_writes_the_outputs_it_was_asked_for_and_nothing_else() {
    let dir = workspace("with-pypi");
    let before = tree(dir.path());
    assert_eq!(before, vec!["pixi.lock", "pixi.toml"]);

    let cache = tempfile::tempdir().unwrap();
    let out = dir.path().join("reports").join("web.cdx.json");
    pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_CACHE_DIR", cache.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["--output", out.to_str().unwrap(), "-e", "web", "-p", "linux-64"])
        .assert()
        .success();

    // The path the flag named, and nothing beside it: no temporary file left behind, no
    // directory built from a name that came out of the lockfile.
    assert_eq!(tree(dir.path()), vec!["pixi.lock", "pixi.toml", "reports/web.cdx.json"]);

    // And the case where the tool picks the names itself, which is where a name taken from
    // untrusted input would actually reach the filesystem.
    let many = workspace("conda-only");
    pixi_sbom()
        .current_dir(many.path())
        .env("PIXI_SBOM_CACHE_DIR", cache.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .arg("--all-platforms")
        .assert()
        .success();
    assert_eq!(
        tree(many.path()),
        vec![
            "pixi.lock",
            "pixi.toml",
            "sbom-linux-64.cdx.json",
            "sbom-osx-arm64.cdx.json",
        ]
    );
}

/// #215: pixi records a conda package's PyPI purl in the lockfile as a bare name, with no
/// version, and the mapping pass then skips the package because the lockfile already answered.
/// The answer it left behind could not be queried by anything. Checked end to end, because the
/// symptom was never in the lockfile reader alone — it was what came out the other end.
#[test]
fn a_bare_pypi_purl_in_the_lockfile_reaches_the_document_with_a_version() {
    let dir = workspace("lock-bare-purls");
    let out = dir.path().join("out.cdx.json");
    pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["-p", "linux-64", "--output", out.to_str().unwrap()])
        .assert()
        .success();

    let doc = read_json(&out);
    let component = |name: &str| {
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap()
            .clone()
    };
    let pixi_purl = |name: &str| {
        component(name)["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "pixi:purl")
            .map(|p| p["value"].as_str().unwrap().to_string())
    };

    assert_eq!(
        pixi_purl("zlib").as_deref(),
        Some("pkg:pypi/zlib@1.3.2?source=compressed-mapping"),
        "a name with no version is not an identity; the version was in the same lock entry"
    );
    assert_eq!(
        pixi_purl("libzlib").as_deref(),
        Some("pkg:pypi/libzlib@9.9.9"),
        "a purl the lockfile already made specific is left exactly as it was"
    );
}

/// The other half of #215: with the identity complete, the package is one the vulnerability
/// lookup will ask about. Offline with an empty cache, so what is asserted is which packages it
/// tried to query, not what any database said.
#[test]
fn a_completed_purl_makes_the_package_one_the_lookup_asks_about() {
    let dir = workspace("lock-bare-purls");
    let cache = tempfile::tempdir().unwrap();

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_CACHE_DIR", cache.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-p",
            "linux-64",
            "--vulnerabilities",
            "osv",
            "--report",
            "vulnerabilities",
        ])
        .assert()
        .success();
    let output = assert.get_output();
    let report = String::from_utf8(output.stdout.clone()).unwrap();
    let log = String::from_utf8(output.stderr.clone()).unwrap();

    assert!(
        log.contains("queried=2") && log.contains("without_identity=0"),
        "both packages were asked about: {log}"
    );
    assert!(
        log.contains("pkg:pypi/zlib@1.3.2"),
        "the completed purl is what went to the database, not the bare name: {log}"
    );
    assert!(
        report.contains("No queryable identity: none"),
        "and the report says nothing was skipped: {report}"
    );
}

/// `workspace_with_legacy_archive`, but with the archive copied into the workspace so a test can
/// take it away afterwards and see what still answers.
fn workspace_with_a_removable_archive() -> (tempfile::TempDir, PathBuf) {
    let dir = workspace("conda-only");
    let source = tests_dir()
        .join("fixtures")
        .join("archives")
        .join("zlib-1.3.2-h25fd6f3_3.tar.bz2");
    let archive = dir.path().join("zlib-1.3.2-h25fd6f3_3.tar.bz2");
    std::fs::copy(&source, &archive).unwrap();
    let path = archive.display().to_string().replace('\\', "/");
    let url = format!("file://{}{path}", if path.starts_with('/') { "" } else { "/" });
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock"))
        .unwrap()
        .replace("\r\n", "\n")
        .replace(
            "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.3.2-h25fd6f3_3.conda",
            &url,
        )
        .replace(
            &format!("- conda: {url}\n  sha256: 16080a1c7724f7d25727cdc23c7658e0cec2db52448c1dc0c33467ee2c6e1c62"),
            &format!("- conda: {url}\n  subdir: linux-64\n  sha256: d4b0036253168923ee9056a5198f1fc55c7e65cf8f826a4ba8e8afd94a72c97f"),
        )
        .replace("  size: 96132\n", "  size: 4762\n")
        // libzlib is pointed at a legacy archive the lockfile calls huge, so it is skipped for
        // its size rather than attempted and failed. That keeps the counts in these tests about
        // zlib, which is the package whose archive comes and goes.
        .replace(
            "https://conda.anaconda.org/conda-forge/linux-64/libzlib-1.3.2-h25fd6f3_3.conda",
            "file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.tar.bz2",
        )
        .replace(
            "- conda: file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.tar.bz2\n  sha256:",
            "- conda: file:///nonexistent/libzlib-1.3.2-h25fd6f3_3.tar.bz2\n  subdir: linux-64\n  sha256:",
        )
        .replace("  size: 63713\n", "  size: 40000000\n");
    std::fs::write(dir.path().join("pixi.lock"), lock).unwrap();
    (dir, archive)
}

/// #197: `--no-cache` is documented as "Neither read nor write any cache", and the conda archive
/// info cache was exempt from it — read and written unconditionally. Taking the archive away
/// after warming the cache is what tells the two apart: a run that still succeeds is reading the
/// cache, whatever the flag says.
#[test]
fn no_cache_does_not_read_the_conda_archive_cache() {
    let (dir, archive) = workspace_with_a_removable_archive();
    let sbom_cache = dir.path().join("sbom-cache");
    let run = |flags: &[&str]| {
        let mut cmd = pixi_sbom();
        cmd.current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", &sbom_cache)
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["-p", "linux-64", "--fetch-licenses", "--output", "-"])
            .args(flags);
        cmd.assert().success()
    };

    // Warm it from the archive, then take the archive away.
    run(&[]).stderr(predicate::str::contains("fetched=1 failed=0"));
    let key_dir = sbom_cache.join("conda-info");
    assert!(key_dir.is_dir(), "the info cache was written");
    std::fs::remove_file(&archive).unwrap();

    // With the cache allowed, the answer comes off disk and the missing archive does not matter.
    run(&[]).stderr(predicate::str::contains("fetched=0 failed=0"));

    // With --no-cache it must go to the archive, which is gone. Before this was fixed the run
    // reported fetched=0 failed=0 here: served entirely from a cache the flag said was off.
    run(&["--no-cache"]).stderr(predicate::str::contains("failed=1"));
}

/// The other half of the flag: `--no-cache` must not leave the cache behind either.
#[test]
fn no_cache_does_not_write_the_conda_archive_cache() {
    let (dir, _archive) = workspace_with_a_removable_archive();
    let sbom_cache = dir.path().join("sbom-cache");

    pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", &sbom_cache)
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["-p", "linux-64", "--fetch-licenses", "--no-cache", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("fetched=1 failed=0"));

    // The licenses were read, so the info was extracted somewhere — just not here.
    assert!(
        !sbom_cache.join("conda-info").exists(),
        "--no-cache wrote the cache it said it would not: {:?}",
        std::fs::read_dir(&sbom_cache).map(|d| d.filter_map(Result::ok).map(|e| e.path()).collect::<Vec<_>>())
    );

    // And nothing of ours is left in the temp directory either.
    let leftovers: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with("pixi-sbom-no-cache-"))
        .collect();
    assert!(leftovers.is_empty(), "scratch directories left behind: {leftovers:?}");
}

/// `--refresh` gained a value, and a value the flag does not accept is as good as no fix.
#[test]
fn refresh_accepts_the_conda_archive_cache_by_name() {
    pixi_sbom()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("conda-info"));

    let (dir, archive) = workspace_with_a_removable_archive();
    let sbom_cache = dir.path().join("sbom-cache");
    let run = |flags: &[&str]| {
        let mut cmd = pixi_sbom();
        cmd.current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", &sbom_cache)
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["-p", "linux-64", "--fetch-licenses", "--output", "-"])
            .args(flags);
        cmd.assert().success()
    };

    run(&[]).stderr(predicate::str::contains("fetched=1"));
    std::fs::remove_file(&archive).unwrap();
    // A refresh ignores what is cached and asks again — so the missing archive is a failure,
    // where an ordinary run would have answered from disk.
    run(&["--refresh", "conda-info"]).stderr(predicate::str::contains("failed=1"));
    // Refreshing a different cache leaves this one alone.
    run(&["--refresh", "osv"]).stderr(predicate::str::contains("failed=0"));
}

/// #227: `--name` became `--root-name` and `--outdated-only` became `--outdated-min`. The old
/// spellings are permanent hidden aliases rather than deprecations with an end date (#117), so
/// what needs pinning is that they keep working and that `--help` shows only one of each. A
/// removal later would be a major version with its own notice, not a quiet break.
#[test]
fn the_pre_1_0_flag_spellings_are_still_accepted() {
    // --help advertises the canonical name and not the alias.
    let help = String::from_utf8(pixi_sbom().arg("--help").assert().success().get_output().stdout.clone()).unwrap();
    for canonical in ["--root-name", "--outdated-min"] {
        assert!(help.contains(canonical), "{canonical} missing from --help");
    }
    // The aliases get no entry of their own, so there is one spelling to learn. Matched in
    // entry form — `--flag <VALUE>` at the start of its line — because both names are named in
    // the surrounding help *text* on purpose: someone who typed the old one and is now reading
    // --help should be told it still works.
    for (alias, value) in [("--name", "<NAME>"), ("--outdated-only", "<STEP>")] {
        let entry = format!("{alias} {value}");
        assert!(
            !help.lines().any(|line| line.trim().starts_with(&entry)),
            "{alias} should have no entry of its own:\n{help}"
        );
    }
    assert!(
        help.contains("`--outdated-only` is the pre-1.0 spelling"),
        "and the text should say the old spelling still works"
    );

    // --root-name / --name: the same document either way.
    let doc = |flag: &str| {
        let dir = workspace("conda-only");
        let prefix = dir.path().join("env");
        std::fs::create_dir_all(prefix.join("conda-meta")).unwrap();
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["--prefix", prefix.to_str().unwrap(), flag, "Named App", "--output", "-"])
            .assert()
            .success();
        let value: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
        value["metadata"]["component"]["name"].as_str().unwrap().to_string()
    };
    assert_eq!(doc("--root-name"), "Named App");
    assert_eq!(
        doc("--name"),
        "Named App",
        "the pre-1.0 spelling still names the root component"
    );

    // --outdated-min / --outdated-only: both reach the same validation, which is enough to show
    // the alias resolves to the same argument without needing the network.
    for flag in ["--outdated-min", "--outdated-only"] {
        pixi_sbom()
            .current_dir(workspace("conda-only").path())
            .args(["--report", "packages", flag, "major"])
            .assert()
            .code(2)
            .stderr(predicate::str::contains("only applies to '--report outdated'"));
    }
}

/// #118: findings used to reach CycloneDX only, and an SPDX run warned it was dropping them.
/// SPDX 3.0.1 has a security profile, so the same nine findings from the recorded OSV fixtures
/// now come out as `security_Vulnerability` elements with CVSS and KEV assessments hanging off
/// them, validated against the real 3.0.1 schema.
#[test]
fn vulnerabilities_are_recorded_in_spdx_3_via_the_security_profile() {
    let dir = workspace_with_vulnerable_urllib3();
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--spec-version",
            "3.0",
            "--vulnerabilities",
            "osv",
            "--output",
            "-",
        ])
        .assert()
        .success();
    // The 2.3-only warning must not fire for 3.0 any more.
    let log = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !log.contains("does not record vulnerabilities"),
        "3.0 records them now: {log}"
    );

    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx3_validator(), &doc);
    let graph = doc["@graph"].as_array().unwrap();
    let of_type = |kind: &str| -> Vec<&Value> { graph.iter().filter(|n| n["type"] == kind).collect() };

    // Nine findings, nine elements.
    let vulns = of_type("security_Vulnerability");
    assert_eq!(vulns.len(), 9, "one element per finding");
    assert!(
        vulns.iter().all(|v| v["name"].as_str().unwrap().starts_with("GHSA-")),
        "named by the advisory id"
    );

    // The CVE alias is findable as a cve external identifier, not only as free text.
    let regex = vulns.iter().find(|v| v["name"] == "GHSA-q2q7-5pp4-w6pg").unwrap();
    assert!(
        regex["externalIdentifier"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["externalIdentifierType"] == "cve" && e["identifier"] == "CVE-2021-33503"),
        "{regex}"
    );
    assert!(regex["security_publishedTime"].is_string(), "{regex}");

    // Each affected package points at the vulnerability, which is the direction a reader
    // follows from a component.
    let associations = graph
        .iter()
        .filter(|n| n["relationshipType"] == "hasAssociatedVulnerability")
        .count();
    assert_eq!(associations, 9, "one per affected package per finding");

    // CVSS assessments carry all three fields the schema requires together.
    let cvss = of_type("security_CvssV3VulnAssessmentRelationship");
    assert!(!cvss.is_empty(), "the fixtures carry CVSS v3 vectors");
    for a in &cvss {
        assert_eq!(a["relationshipType"], "hasAssessmentFor");
        assert!(a["security_score"].is_number(), "{a}");
        assert!(
            ["critical", "high", "medium", "low", "none"].contains(&a["security_severity"].as_str().unwrap()),
            "{a}"
        );
        assert!(
            a["security_vectorString"].as_str().unwrap().starts_with("CVSS:3"),
            "{a}"
        );
    }

    // The document declares the profile it is now using.
    let sbom = graph.iter().find(|n| n["type"] == "software_Sbom").unwrap();
    let profiles: Vec<&str> = sbom["profileConformance"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(profiles.contains(&"security"), "{profiles:?}");
}

/// A document with no findings must not claim the security profile, and SPDX 2.3 still says it
/// cannot carry them.
#[test]
fn without_findings_spdx_3_does_not_claim_the_security_profile() {
    let dir = workspace("conda-only");
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--spec-version",
            "3.0",
            "--output",
            "-",
        ])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx3_validator(), &doc);
    let graph = doc["@graph"].as_array().unwrap();
    assert!(
        graph.iter().all(|n| n["type"] != "security_Vulnerability"),
        "nothing to record"
    );
    let sbom = graph.iter().find(|n| n["type"] == "software_Sbom").unwrap();
    let profiles: Vec<&str> = sbom["profileConformance"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(profiles, ["core", "software", "simpleLicensing"]);
}

/// The two assessment kinds beyond CVSS: a KEV catalog entry and an accepted finding. Both are
/// separate SPDX classes with their own required fields, so they need their own coverage.
#[test]
fn kev_and_accepted_findings_become_spdx_3_assessment_relationships() {
    let dir = workspace_with_vulnerable_urllib3();
    let kev_dir = dir.path().join("cache").join("kev");
    std::fs::create_dir_all(&kev_dir).unwrap();
    std::fs::copy(
        tests_dir()
            .join("fixtures")
            .join("kev")
            .join("known_exploited_vulnerabilities.json"),
        kev_dir.join("known_exploited_vulnerabilities.json"),
    )
    .unwrap();

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--spec-version",
            "3.0",
            "--vulnerabilities",
            "osv",
            "--kev",
            "--ignore-vuln",
            "GHSA-q2q7-5pp4-w6pg:not_affected:code_not_reachable:the URL parser is never handed user input",
            "--output",
            "-",
        ])
        .assert()
        .success();
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_valid(&spdx3_validator(), &doc);
    let graph = doc["@graph"].as_array().unwrap();

    // KEV: catalogType, exploited and locator are required together by the schema.
    let kev: Vec<&Value> = graph
        .iter()
        .filter(|n| n["type"] == "security_ExploitCatalogVulnAssessmentRelationship")
        .collect();
    assert!(!kev.is_empty(), "the recorded catalog matches at least one finding");
    for entry in &kev {
        assert_eq!(entry["security_catalogType"], "kev");
        assert_eq!(entry["security_exploited"], true);
        assert!(
            entry["security_locator"].as_str().unwrap().contains("cisa.gov"),
            "{entry}"
        );
        assert_eq!(entry["relationshipType"], "hasAssessmentFor");
    }

    // The accepted finding becomes a VEX not-affected assessment carrying the operator's reason.
    let vex: Vec<&Value> = graph
        .iter()
        .filter(|n| n["type"] == "security_VexNotAffectedVulnAssessmentRelationship")
        .collect();
    assert_eq!(vex.len(), 1, "one --ignore-vuln, one assessment");
    assert_eq!(
        vex[0]["security_impactStatement"],
        "the URL parser is never handed user input"
    );
    assert_eq!(vex[0]["security_justificationType"], "vulnerableCodeNotInExecutePath");

    // Every timestamp we write is in the one shape SPDX 3 accepts: second precision, UTC, no
    // fractional part. The OSV records these came from carry nanoseconds.
    for node in graph {
        for field in ["security_publishedTime", "security_modifiedTime"] {
            if let Some(stamp) = node[field].as_str() {
                assert!(
                    stamp.len() == 20 && stamp.ends_with('Z') && !stamp.contains('.'),
                    "{field} = {stamp}"
                );
            }
        }
    }
}

/// A `pylock.toml` from examples/projects, read in place: `--output -` writes nothing beside it.
fn pylock_example(scenario: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/projects/pylock")
        .join(scenario)
        .join("pylock.toml")
}

#[test]
fn pylock_is_read_in_every_format_for_the_chosen_platform() {
    // #321: PEP 751 lockfiles, as uv (01-django) and pip (08-cli-tool) write them.
    let work = tempfile::tempdir().unwrap();
    let command = |lockfile: &Path, args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(work.path())
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("SOURCE_DATE_EPOCH", "1767225600")
            .arg("--lockfile")
            .arg(lockfile)
            .args(args);
        command
    };
    let run = |lockfile: &Path, args: &[&str]| command(lockfile, &[&["--output", "-"][..], args].concat());
    let doc = |lockfile: &Path, args: &[&str]| -> Value {
        let assert = run(lockfile, args).assert().success();
        serde_json::from_slice(&assert.get_output().stdout).unwrap()
    };
    let django = pylock_example("01-django");

    // Every format validates.
    let linux = doc(&django, &["-p", "linux-64"]);
    assert_valid(&cyclonedx_validator(), &linux);
    assert_valid(
        &cyclonedx_1_7_validator(),
        &doc(&django, &["-p", "linux-64", "--spec-version", "1.7"]),
    );
    assert_valid(
        &spdx_validator(),
        &doc(&django, &["-p", "linux-64", "--format", "spdx"]),
    );
    assert_valid(
        &spdx3_validator(),
        &doc(
            &django,
            &["-p", "linux-64", "--format", "spdx", "--spec-version", "3.0"],
        ),
    );

    // The project is named by the pyproject.toml beside the lockfile, and the input is recorded.
    assert_eq!(linux["metadata"]["component"]["name"], "django-example");
    let props = linux["metadata"]["properties"].as_array().unwrap();
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:lockfile" && p["value"] == "pylock.toml"),
        "{props:?}"
    );

    let components = |d: &Value| d["components"].as_array().unwrap().clone();
    let named = |d: &Value, name: &str| components(d).into_iter().find(|c| c["name"] == name);
    let property = |c: &Value, key: &str| {
        c["properties"]
            .as_array()
            .and_then(|ps| ps.iter().find(|p| p["name"] == key))
            .map(|p| p["value"].as_str().unwrap().to_string())
    };

    // Markers are evaluated for the platform: colorama is Windows-only.
    assert!(named(&linux, "colorama").is_none());
    let windows = doc(&django, &["-p", "win-64"]);
    let colorama = named(&windows, "colorama").expect("colorama on win-64");
    assert_eq!(
        property(&colorama, "pixi:marker").as_deref(),
        Some("sys_platform == 'win32'")
    );

    // The pinned, vulnerable release is there with its purl; git and local sources say where they came from.
    let django_pkg = named(&linux, "django").unwrap();
    assert_eq!(django_pkg["purl"], "pkg:pypi/django@3.2.12");
    let toolbar = named(&linux, "django-debug-toolbar").unwrap();
    assert!(
        property(&toolbar, "pixi:source-rev").is_some_and(|rev| rev.len() == 40),
        "{toolbar}"
    );
    let local = named(&linux, "internal-utils").unwrap();
    assert_eq!(property(&local, "pixi:editable").as_deref(), Some("true"));
    assert_eq!(
        property(&local, "pixi:direct-url").as_deref(),
        Some("libs/internal-utils")
    );

    // pip writes the project itself into the lockfile; it is the document's root, not a component.
    let cli = doc(&pylock_example("08-cli-tool"), &["-p", "linux-64"]);
    assert_eq!(cli["metadata"]["component"]["name"], "cli-tool-example");
    assert!(named(&cli, "cli-tool-example").is_none());
    assert!(named(&cli, "click").is_some());

    // Byte-identical when nothing changed.
    let once = run(&django, &["-p", "linux-64"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let twice = run(&django, &["-p", "linux-64"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(once, twice);

    // The reports run on it.
    for report in [
        &["--report", "packages"][..],
        &["--report", "licenses"],
        &["--vulnerabilities", "osv", "--report", "vulnerabilities"],
    ] {
        command(&django, &[&["-p", "linux-64"][..], report].concat())
            .assert()
            .success();
    }
    let before = work.path().join("before.cdx.json");
    std::fs::write(&before, serde_json::to_vec(&linux).unwrap()).unwrap();
    let diff = command(
        &django,
        &[
            "-p",
            "win-64",
            "--report",
            "diff",
            "--against",
            before.to_str().unwrap(),
        ],
    )
    .assert()
    .success();
    assert!(String::from_utf8_lossy(&diff.get_output().stdout).contains("colorama"));

    // A pylock.toml has no environments or platform list to choose among.
    for flag in [&["--all-platforms"][..], &["--all-environments"], &["-e", "dev"]] {
        run(&django, flag)
            .assert()
            .code(2)
            .stderr(predicate::str::contains("pylock.toml has none"));
    }
}

#[test]
fn uv_lock_is_found_by_the_upward_search_and_read_in_every_format() {
    // #322: uv.lock, with its graph walked for the platform; workspace members are first-party.
    let work = tempfile::tempdir().unwrap();
    let run = |dir: &Path, args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir)
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["--output", "-"])
            .args(args);
        command
    };
    let doc = |dir: &Path, args: &[&str]| -> Value {
        serde_json::from_slice(&run(dir, args).assert().success().get_output().stdout).unwrap()
    };
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects");
    let django = examples.join("uv/01-django");

    // No --lockfile: the upward search finds uv.lock beside the project.
    let linux = doc(&django, &["-p", "linux-64"]);
    assert_valid(&cyclonedx_validator(), &linux);
    assert_valid(
        &cyclonedx_1_7_validator(),
        &doc(&django, &["-p", "linux-64", "--spec-version", "1.7"]),
    );
    assert_valid(
        &spdx_validator(),
        &doc(&django, &["-p", "linux-64", "--format", "spdx"]),
    );
    assert_valid(
        &spdx3_validator(),
        &doc(
            &django,
            &["-p", "linux-64", "--format", "spdx", "--spec-version", "3.0"],
        ),
    );
    let props = linux["metadata"]["properties"].as_array().unwrap();
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:lockfile" && p["value"] == "uv.lock")
    );
    assert_eq!(linux["metadata"]["component"]["name"], "django-example");
    // A graph, unlike pylock.toml: django depends on what it brought.
    let deps = linux["dependencies"].as_array().unwrap();
    let django_ref = linux["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "django")
        .unwrap()["bom-ref"]
        .clone();
    let django_deps = deps.iter().find(|d| d["ref"] == django_ref).unwrap()["dependsOn"]
        .as_array()
        .unwrap();
    assert!(
        django_deps.iter().any(|d| d.as_str().unwrap().contains("sqlparse")),
        "{django_deps:?}"
    );

    // uv.lock and the pylock.toml uv exported from the same project describe the same packages
    // on every platform: two formats, one resolution. (The export leaves the version off a local
    // directory package, so versions are compared where both say one.)
    let versions = |d: &Value| -> std::collections::BTreeMap<String, String> {
        d["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["name"].as_str().unwrap().to_lowercase(),
                    c["version"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    };
    let set = |d: &Value| -> std::collections::BTreeSet<String> {
        versions(d)
            .into_iter()
            .map(|(name, version)| format!("{name}@{version}"))
            .collect()
    };
    for platform in ["linux-64", "osx-arm64", "win-64"] {
        for scenario in ["01-django", "06-deep-learning", "13-genai-llm"] {
            let from_uv = versions(&doc(&examples.join("uv").join(scenario), &["-p", platform]));
            let from_pylock = versions(&doc(&examples.join("pylock").join(scenario), &["-p", platform]));
            assert_eq!(
                from_uv.keys().collect::<Vec<_>>(),
                from_pylock.keys().collect::<Vec<_>>(),
                "{scenario} on {platform}"
            );
            for (name, version) in &from_pylock {
                if !version.is_empty() {
                    assert_eq!(&from_uv[name], version, "{name} in {scenario} on {platform}");
                }
            }
        }
    }

    // A workspace: the root member is the document, the other members are first-party components.
    let workspace = tests_dir().join("fixtures/uv-workspace");
    let ws = doc(&workspace, &["-p", "linux-64"]);
    assert_valid(&cyclonedx_validator(), &ws);
    assert_eq!(ws["metadata"]["component"]["name"], "acme-platform");
    let purls: Vec<&str> = ws["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["purl"].as_str().unwrap())
        .collect();
    assert!(purls.contains(&"pkg:generic/acme-cli@0.4.0"), "{purls:?}");
    assert!(purls.contains(&"pkg:generic/acme-core@0.4.0"), "{purls:?}");
    assert!(
        !purls.iter().any(|p| p.starts_with("pkg:pypi/acme")),
        "members are not PyPI releases"
    );
    assert!(!purls.iter().any(|p| p.contains("colorama")), "Windows-only");
    assert!(
        set(&doc(&workspace, &["-p", "win-64"]))
            .iter()
            .any(|p| p.starts_with("colorama@"))
    );

    // Flags that need a pixi workspace.
    run(&django, &["--all-platforms"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("uv.lock has none"));
}

#[test]
fn poetry_lock_is_read_in_every_format_with_its_sources() {
    // #324: poetry.lock 2.x. No download URLs in the lock, a second index, and the project's own
    // dependencies from the pyproject.toml beside it.
    let work = tempfile::tempdir().unwrap();
    let command = |dir: &Path, args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir)
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(args);
        command
    };
    let doc = |dir: &Path, args: &[&str]| -> Value {
        let mut all = vec!["--output", "-"];
        all.extend_from_slice(args);
        serde_json::from_slice(&command(dir, &all).assert().success().get_output().stdout).unwrap()
    };
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects");
    let django = examples.join("poetry/01-django");

    // Found by the upward search; every format validates, including components with no location.
    let linux = doc(&django, &["-p", "linux-64"]);
    assert_valid(&cyclonedx_validator(), &linux);
    assert_valid(
        &cyclonedx_1_7_validator(),
        &doc(&django, &["-p", "linux-64", "--spec-version", "1.7"]),
    );
    assert_valid(
        &spdx_validator(),
        &doc(&django, &["-p", "linux-64", "--format", "spdx"]),
    );
    assert_valid(
        &spdx3_validator(),
        &doc(
            &django,
            &["-p", "linux-64", "--format", "spdx", "--spec-version", "3.0"],
        ),
    );
    assert_eq!(linux["metadata"]["component"]["name"], "django-example");
    let components = linux["components"].as_array().unwrap();
    let named = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
    let property = |c: &Value, key: &str| {
        c["properties"]
            .as_array()
            .and_then(|ps| ps.iter().find(|p| p["name"] == key))
            .map(|p| p["value"].as_str().unwrap().to_string())
    };
    let django_pkg = named("django");
    assert_eq!(django_pkg["purl"], "pkg:pypi/django@3.2.12");
    assert!(
        django_pkg.get("externalReferences").is_none_or(|refs| !refs
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["type"] == "distribution")),
        "no URL to claim"
    );
    assert!(property(django_pkg, "pixi:file-name").is_some_and(|f| f.ends_with(".whl")));
    assert_eq!(
        property(django_pkg, "pixi:direct").as_deref(),
        Some("true"),
        "declared in pyproject.toml"
    );
    assert!(property(named("django-debug-toolbar"), "pixi:source-rev").is_some_and(|r| r.len() == 40));
    assert_eq!(
        property(named("internal-utils"), "pixi:editable").as_deref(),
        Some("true")
    );
    let spdx = doc(&django, &["-p", "linux-64", "--format", "spdx"]);
    let spdx_django = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "django")
        .unwrap();
    assert_eq!(spdx_django["downloadLocation"], "NOASSERTION");
    assert!(spdx_django.get("sourceInfo").is_none());

    // Poetry and uv resolved this scenario independently; they agree on what is installed.
    let names = |d: &Value| -> std::collections::BTreeSet<String> {
        d["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_lowercase())
            .collect()
    };
    for platform in ["linux-64", "win-64"] {
        assert_eq!(
            names(&doc(&django, &["-p", platform])),
            names(&doc(&examples.join("uv/01-django"), &["-p", platform])),
            "{platform}"
        );
    }

    // A package from a second index names that index, not PyPI.
    let sources = tests_dir().join("fixtures/poetry-sources");
    let ml = doc(&sources, &["-p", "linux-64"]);
    assert_valid(&cyclonedx_validator(), &ml);
    let torch = ml["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "torch")
        .unwrap();
    assert_eq!(torch["purl"], "pkg:pypi/torch@2.9.0%2Bcpu");
    assert_eq!(torch["supplier"]["name"], "download.pytorch.org");
    assert!(torch["hashes"].as_array().is_some_and(|h| !h.is_empty()));

    // Reports run on it.
    for report in [
        &["--report", "packages"][..],
        &["--report", "licenses"],
        &["--vulnerabilities", "osv", "--report", "vulnerabilities"],
    ] {
        command(&django, &[&["-p", "linux-64"][..], report].concat())
            .assert()
            .success();
    }

    // A lock-version 1 file is refused with the fix.
    let old = work.path().join("old");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(
        old.join("poetry.lock"),
        "[metadata]\nlock-version = \"1.1\"\npython-versions = \"^3.8\"\ncontent-hash = \"x\"\n",
    )
    .unwrap();
    command(&old, &["--output", "-"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("lock-version 1.1 is not supported"))
        .stderr(predicate::str::contains("poetry lock"));
}

#[test]
fn pdm_lock_is_read_in_every_format_with_extras_folded_in() {
    // #325: pdm.lock 4.x, as current PDM writes it for a project with groups, an extra, a git
    // dependency and an editable path.
    let work = tempfile::tempdir().unwrap();
    let command = |dir: &Path, args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir)
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(args);
        command
    };
    let doc = |dir: &Path, args: &[&str]| -> Value {
        let mut all = vec!["--output", "-"];
        all.extend_from_slice(args);
        serde_json::from_slice(&command(dir, &all).assert().success().get_output().stdout).unwrap()
    };
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects");
    let django = examples.join("pdm/01-django");

    let linux = doc(&django, &["-p", "linux-64"]);
    assert_valid(&cyclonedx_validator(), &linux);
    assert_valid(
        &cyclonedx_1_7_validator(),
        &doc(&django, &["-p", "linux-64", "--spec-version", "1.7"]),
    );
    assert_valid(
        &spdx_validator(),
        &doc(&django, &["-p", "linux-64", "--format", "spdx"]),
    );
    assert_valid(
        &spdx3_validator(),
        &doc(
            &django,
            &["-p", "linux-64", "--format", "spdx", "--spec-version", "3.0"],
        ),
    );
    let props = linux["metadata"]["properties"].as_array().unwrap();
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:lockfile" && p["value"] == "pdm.lock")
    );

    let components = linux["components"].as_array().unwrap();
    // django[argon2] is a second entry in the lock; it is one component, with argon2-cffi under it.
    assert_eq!(components.iter().filter(|c| c["name"] == "django").count(), 1);
    let django_ref = components.iter().find(|c| c["name"] == "django").unwrap()["bom-ref"].clone();
    let depends_on = linux["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["ref"] == django_ref)
        .unwrap()["dependsOn"]
        .clone();
    assert!(
        depends_on
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d.as_str().unwrap().contains("argon2-cffi")),
        "{depends_on}"
    );
    let property = |name: &str, key: &str| {
        components.iter().find(|c| c["name"] == name).unwrap()["properties"]
            .as_array()
            .and_then(|ps| ps.iter().find(|p| p["name"] == key))
            .map(|p| p["value"].as_str().unwrap().to_string())
    };
    assert!(property("django-debug-toolbar", "pixi:source-rev").is_some_and(|r| r.len() == 40));
    assert_eq!(
        property("internal-utils", "pixi:direct-url").as_deref(),
        Some("libs/internal-utils")
    );

    // PDM and uv resolved this scenario independently; they agree on what is installed.
    let names = |d: &Value| -> std::collections::BTreeSet<String> {
        d["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap().to_lowercase())
            .collect()
    };
    for platform in ["linux-64", "win-64"] {
        assert_eq!(
            names(&doc(&django, &["-p", platform])),
            names(&doc(&examples.join("uv/01-django"), &["-p", platform])),
            "{platform}"
        );
    }

    for report in [
        &["--report", "packages"][..],
        &["--report", "licenses"],
        &["--vulnerabilities", "osv", "--report", "vulnerabilities"],
    ] {
        command(&django, &[&["-p", "linux-64"][..], report].concat())
            .assert()
            .success();
    }

    let old = work.path().join("old");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("pdm.lock"), "[metadata]\nlock_version = \"3.0\"\n").unwrap();
    command(&old, &["--output", "-"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("lock_version 3.0 is not supported"));
}

#[test]
fn conda_lock_gives_the_same_conda_components_as_pixi_lock_and_one_document_per_platform() {
    // #326: conda-lock.yml (unified, version 1).
    let work = tempfile::tempdir().unwrap();
    let command = |dir: &Path, args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir)
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(args);
        command
    };
    let doc = |dir: &Path, args: &[&str]| -> Value {
        let mut all = vec!["--output", "-"];
        all.extend_from_slice(args);
        serde_json::from_slice(&command(dir, &all).assert().success().get_output().stdout).unwrap()
    };
    let component = |d: &Value, name: &str| -> Value {
        d["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name}"))
    };

    // The exact python archive tests/fixtures/with-pypi/pixi.lock pins, as conda-lock writes it.
    let same = work.path().join("same");
    std::fs::create_dir_all(&same).unwrap();
    std::fs::write(
        same.join("conda-lock.yml"),
        r#"version: 1
metadata:
  content_hash: {linux-64: x}
  channels: [{url: conda-forge, used_env_vars: []}]
  platforms: [linux-64]
  sources: [environment.yml]
package:
- name: python
  version: 3.12.14
  manager: conda
  platform: linux-64
  dependencies: {}
  url: https://conda.anaconda.org/conda-forge/linux-64/python-3.12.14-h5f976f7_3_cpython.conda
  hash: {md5: 98be3cf76eca2e8871f907a03aed3b84, sha256: 14c579b1016da04e4c9f1c5c857272d83ec447317d8c4074a07d59de3cef70ef}
  category: main
  optional: false
"#,
    )
    .unwrap();
    let from_conda_lock = component(
        &doc(&same, &["--lockfile", "conda-lock.yml", "-p", "linux-64"]),
        "python",
    );
    let from_pixi_lock = component(
        &doc(
            workspace("with-pypi").path(),
            &[
                "--lockfile",
                tests_dir().join("fixtures/with-pypi/pixi.lock").to_str().unwrap(),
                "-e",
                "web",
                "-p",
                "linux-64",
            ],
        ),
        "python",
    );
    for field in ["purl", "supplier", "hashes", "externalReferences"] {
        assert_eq!(from_conda_lock[field], from_pixi_lock[field], "{field}");
    }

    // A real conda-lock.yml with conda and pip packages on two platforms.
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/conda-lock/01-django");
    let linux = doc(&example, &["--lockfile", "conda-lock.yml", "-p", "linux-64"]);
    assert_valid(&cyclonedx_validator(), &linux);
    assert_valid(
        &cyclonedx_1_7_validator(),
        &doc(
            &example,
            &[
                "--lockfile",
                "conda-lock.yml",
                "-p",
                "linux-64",
                "--spec-version",
                "1.7",
            ],
        ),
    );
    assert_valid(
        &spdx_validator(),
        &doc(
            &example,
            &["--lockfile", "conda-lock.yml", "-p", "linux-64", "--format", "spdx"],
        ),
    );
    assert_valid(
        &spdx3_validator(),
        &doc(
            &example,
            &[
                "--lockfile",
                "conda-lock.yml",
                "-p",
                "linux-64",
                "--format",
                "spdx",
                "--spec-version",
                "3.0",
            ],
        ),
    );
    assert!(
        component(&linux, "django")["purl"]
            .as_str()
            .unwrap()
            .starts_with("pkg:conda/django@3.2.12")
    );
    assert_eq!(
        component(&linux, "django-environ")["purl"],
        "pkg:pypi/django-environ@0.9.0",
        "the pip section"
    );
    let mac = doc(&example, &["--lockfile", "conda-lock.yml", "-p", "osx-arm64"]);
    assert!(
        component(&mac, "python")["purl"]
            .as_str()
            .unwrap()
            .contains("subdir=osx-arm64")
    );

    // --all-platforms writes one document per locked platform.
    let out = work.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    command(
        &example,
        &[
            "--lockfile",
            "conda-lock.yml",
            "--all-platforms",
            "--output",
            out.to_str().unwrap(),
        ],
    )
    .assert()
    .success();
    let mut written: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    assert_eq!(written, ["sbom-linux-64.cdx.json", "sbom-osx-arm64.cdx.json"]);

    // Reports run; environments and unknown platforms are refused.
    for report in [&["--report", "packages"][..], &["--report", "licenses"]] {
        command(
            &example,
            &[&["--lockfile", "conda-lock.yml", "-p", "linux-64"][..], report].concat(),
        )
        .assert()
        .success();
    }
    command(
        &example,
        &["--lockfile", "conda-lock.yml", "--all-environments", "--output", "-"],
    )
    .assert()
    .code(2)
    .stderr(predicate::str::contains("conda-lock.yml has none"));
    command(
        &example,
        &["--lockfile", "conda-lock.yml", "-p", "win-64", "--output", "-"],
    )
    .assert()
    .code(1)
    .stderr(predicate::str::contains(
        "platform win-64 is not in this conda-lock.yml",
    ));
}

#[test]
fn explicit_spec_files_are_read_with_whatever_hashes_they_carry() {
    // #327: `conda list --explicit` output, recognised by its @EXPLICIT line.
    let work = tempfile::tempdir().unwrap();
    let command = |file: &Path, args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(work.path())
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .arg("--lockfile")
            .arg(file)
            .args(args);
        command
    };
    let doc = |file: &Path, args: &[&str]| -> Value {
        let mut all = vec!["--output", "-"];
        all.extend_from_slice(args);
        serde_json::from_slice(&command(file, &all).assert().success().get_output().stdout).unwrap()
    };
    let fixtures = tests_dir().join("fixtures/explicit");
    let by_purl = |d: &Value| -> std::collections::BTreeMap<String, Value> {
        d["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["purl"].as_str().unwrap().to_string(), c["hashes"].clone()))
            .collect()
    };
    let alg = |hashes: &Value| -> Vec<String> {
        hashes
            .as_array()
            .map(|h| h.iter().map(|x| x["alg"].as_str().unwrap().to_string()).collect())
            .unwrap_or_default()
    };

    let md5 = doc(&fixtures.join("md5.txt"), &[]);
    assert_valid(&cyclonedx_validator(), &md5);
    assert_valid(
        &cyclonedx_1_7_validator(),
        &doc(&fixtures.join("md5.txt"), &["--spec-version", "1.7"]),
    );
    assert_valid(
        &spdx_validator(),
        &doc(&fixtures.join("md5.txt"), &["--format", "spdx"]),
    );
    assert_valid(
        &spdx3_validator(),
        &doc(
            &fixtures.join("md5.txt"),
            &["--format", "spdx", "--spec-version", "3.0"],
        ),
    );
    let props = md5["metadata"]["properties"].as_array().unwrap();
    assert!(
        props
            .iter()
            .any(|p| p["name"] == "pixi:platform" && p["value"] == "linux-64"),
        "from the # platform: comment"
    );

    // The same 65 packages whichever hashes the file carries.
    let (with_md5, with_sha, without) = (
        by_purl(&md5),
        by_purl(&doc(&fixtures.join("sha256.txt"), &[])),
        by_purl(&doc(&fixtures.join("no-hashes.txt"), &[])),
    );
    assert_eq!(with_md5.len(), 65);
    assert_eq!(with_md5.keys().collect::<Vec<_>>(), with_sha.keys().collect::<Vec<_>>());
    assert_eq!(with_md5.keys().collect::<Vec<_>>(), without.keys().collect::<Vec<_>>());
    assert!(with_md5.values().all(|h| alg(h) == ["MD5"]));
    assert!(with_sha.values().all(|h| alg(h) == ["SHA-256"]));
    assert!(without.values().all(|h| alg(h).is_empty()));

    // The format has no graph: every package hangs off the root and nothing else.
    let deps = md5["dependencies"].as_array().unwrap();
    assert!(
        deps.iter()
            .filter(|d| d["ref"] != "root")
            .all(|d| d["dependsOn"].as_array().is_none_or(|a| a.is_empty()))
    );

    // The conda-lock.yml it was rendered from gives the same conda components.
    let lock = doc(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/conda-lock/01-django/conda-lock.yml"),
        &["-p", "linux-64"],
    );
    let conda_from_lock: std::collections::BTreeSet<String> = by_purl(&lock)
        .into_keys()
        .filter(|p| p.starts_with("pkg:conda/"))
        .collect();
    let conda_from_explicit: std::collections::BTreeSet<String> = with_md5.into_keys().collect();
    assert_eq!(conda_from_explicit, conda_from_lock);

    // A platform the file is not for, and a file that is not explicit after all.
    command(&fixtures.join("md5.txt"), &["-p", "win-64", "--output", "-"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("is for linux-64, not win-64"));
    let unpinned = work.path().join("environment.txt");
    std::fs::write(&unpinned, "@EXPLICIT\nnumpy=2.0\n").unwrap();
    command(&unpinned, &["--output", "-"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("line 2"))
        .stderr(predicate::str::contains("is not a package URL"));
    command(&fixtures.join("md5.txt"), &["--all-platforms", "--output", "-"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("an explicit spec file has none"));
}

#[test]
fn the_manifest_beside_a_non_pixi_lockfile_says_what_the_project_declared() {
    // #328: pyproject.toml beside uv.lock / poetry.lock, environment.yml beside conda-lock.yml.
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("app.py"), "import django\nimport sqlparse\n").unwrap();
    let command = |dir: &Path, args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(dir)
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .args(["-p", "linux-64"])
            .args(args);
        command
    };
    let stdout = |dir: &Path, args: &[&str]| {
        String::from_utf8(command(dir, args).assert().success().get_output().stdout.clone()).unwrap()
    };
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects");

    for reader in ["uv", "poetry"] {
        let project = examples.join(reader).join("01-django");
        // The packages report: the features that declared each package, and the count.
        let table = stdout(&project, &["--report", "packages"]);
        assert!(
            table.contains("27 packages, 12 declared by the workspace"),
            "{reader}: {table}"
        );
        for (name, feature) in [
            ("django ", "default"),
            ("django-storages", "s3"),
            ("pytest-django", "test"),
            ("django-debug-toolbar", "dev"),
        ] {
            let row = table
                .lines()
                .find(|l| l.starts_with(name))
                .unwrap_or_else(|| panic!("{reader}: {name}"));
            assert!(row.contains(feature), "{reader}: {row}");
        }
        assert!(
            table
                .lines()
                .find(|l| l.starts_with("asgiref"))
                .unwrap()
                .contains(" - "),
            "transitive"
        );

        // The phantom report reads the same declarations: django and sqlparse are imported.
        let phantom = stdout(
            &project,
            &["--report", "phantom", "--source", work.path().to_str().unwrap()],
        );
        assert!(
            phantom.contains("Summary: 0 phantom, 0 undeclared, 10 unused"),
            "{reader}: {phantom}"
        );

        // The root depends on exactly what was declared.
        let doc: Value = serde_json::from_str(&stdout(&project, &["--output", "-"])).unwrap();
        let root = doc["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["ref"] == "root")
            .unwrap();
        assert_eq!(root["dependsOn"].as_array().unwrap().len(), 12, "{reader}");
    }

    // environment.yml beside conda-lock.yml: its conda specs and its pip list.
    let conda = examples.join("conda-lock/01-django");
    let table = stdout(&conda, &["--lockfile", "conda-lock.yml", "--report", "packages"]);
    assert!(table.contains("66 packages, 9 declared by the workspace"), "{table}");
    assert!(
        table
            .lines()
            .find(|l| l.starts_with("django-environ"))
            .unwrap()
            .contains("default"),
        "from the pip: list"
    );

    // A pixi workspace keeps its rule: declared packages plus what nothing depends on.
    let pixi = workspace("with-pypi");
    let doc: Value = serde_json::from_str(&stdout(pixi.path(), &["-e", "web", "--output", "-"])).unwrap();
    let root = doc["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["ref"] == "root")
        .unwrap();
    let direct = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| {
            c["properties"]
                .as_array()
                .is_some_and(|ps| ps.iter().any(|p| p["name"] == "pixi:direct"))
        })
        .count();
    assert!(root["dependsOn"].as_array().unwrap().len() >= direct);
}

#[test]
fn python_extras_say_what_was_asked_for_and_what_came_with_it() {
    // #330: `pixi:python-extras` on a package installed with extras, `pixi:via-extra` on what an
    // extra alone brought in, from uv.lock, poetry.lock, pdm.lock and pixi.lock.
    let work = tempfile::tempdir().unwrap();
    let run = |dir: &Path, args: &[&str]| {
        let output = pixi_sbom()
            .current_dir(dir)
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .args(["-p", "linux-64"])
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(output).unwrap()
    };
    let properties = |dir: &Path| -> std::collections::BTreeMap<String, (Option<String>, Option<String>)> {
        let doc: Value = serde_json::from_str(&run(dir, &["--output", "-"])).unwrap();
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                let get = |key: &str| {
                    c["properties"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .find(|p| p["name"] == key)
                        .map(|p| p["value"].as_str().unwrap().to_string())
                };
                (
                    c["name"].as_str().unwrap().to_string(),
                    (get("pixi:python-extras"), get("pixi:via-extra")),
                )
            })
            .collect()
    };
    let some = |s: &str| Some(s.to_string());
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects");

    for reader in ["uv", "poetry", "pdm"] {
        let found = properties(&examples.join(reader).join("01-django"));
        assert_eq!(found["django"].0, some("argon2"), "{reader}");
        assert_eq!(found["django-storages"].0, some("s3"), "{reader}");
        for name in ["argon2-cffi", "argon2-cffi-bindings", "cffi", "pycparser"] {
            assert_eq!(found[name].1, some("django[argon2]"), "{reader}: {name}");
        }
        assert_eq!(found["sqlparse"], (None, None), "{reader}: needed anyway");
        if reader != "pdm" {
            // pdm.lock does not say which of the project's groups are extras.
            assert_eq!(found["django-storages"].1, some("django-example[s3]"), "{reader}");
        }
    }

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pypi-extras");
    let found = properties(&fixture);
    assert_eq!(found["requests"].0, some("socks"), "from the manifest's extras = [...]");
    assert_eq!(found["pysocks"].1, some("requests[socks]"));
    assert_eq!(found["urllib3"], (None, None));

    let explained = run(&fixture, &["--explain", "pysocks", "--explain", "requests"]);
    assert!(
        explained
            .lines()
            .any(|l| l.contains("brought in by") && l.contains("requests[socks]")),
        "{explained}"
    );
    assert!(
        explained
            .lines()
            .any(|l| l.contains("installed with extras") && l.contains("socks")),
        "{explained}"
    );
    let uv = run(&examples.join("uv/01-django"), &["--explain", "cffi"]);
    assert!(
        !uv.contains("none was read"),
        "the pyproject.toml beside uv.lock was read: {uv}"
    );
}

#[test]
fn dependency_groups_and_extras_set_the_scope_in_every_format() {
    // #331: what only a dependency group needs is development, what only an extra needs is
    // optional, and the rest, shared ones included, is required; each format says so its way.
    let work = tempfile::tempdir().unwrap();
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/uv/01-django");
    let document = |args: &[&str]| -> Value {
        let output = pixi_sbom()
            .current_dir(&project)
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["-p", "linux-64", "--output", "-"])
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice(&output).unwrap()
    };

    let cdx = document(&[]);
    assert_valid(&cyclonedx_validator(), &cdx);
    let scope = |name: &str| {
        cdx["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))["scope"]
            .clone()
    };
    for name in ["django", "sqlparse", "asgiref", "argon2-cffi"] {
        assert_eq!(scope(name), "required", "{name}");
    }
    for name in [
        "pytest",
        "pluggy",
        "django-debug-toolbar",
        "django-storages",
        "factory-boy",
    ] {
        assert_eq!(scope(name), "optional", "{name}");
    }

    let spdx = document(&["--format", "spdx"]);
    assert_valid(&spdx_validator(), &spdx);
    let names: std::collections::BTreeMap<&str, &str> = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["SPDXID"].as_str().unwrap(), p["name"].as_str().unwrap()))
        .collect();
    let edges: Vec<(&str, &str, &str)> = spdx["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["relationshipType"] != "DESCRIBES")
        .map(|r| {
            (
                names[r["spdxElementId"].as_str().unwrap()],
                r["relationshipType"].as_str().unwrap(),
                names[r["relatedSpdxElement"].as_str().unwrap()],
            )
        })
        .collect();
    assert!(edges.contains(&("pytest-django", "DEV_DEPENDENCY_OF", "django-example")));
    assert!(edges.contains(&("django-storages", "OPTIONAL_DEPENDENCY_OF", "django-example")));
    assert!(edges.contains(&("django-example", "DEPENDS_ON", "django")));
    assert!(
        edges.contains(&("pytest-django", "DEPENDS_ON", "pytest")),
        "inside the group the edge is plain"
    );

    let spdx3 = document(&["--format", "spdx", "--spec-version", "3.0"]);
    assert_valid(&spdx3_validator(), &spdx3);
    let scoped: Vec<&Value> = spdx3["@graph"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["type"] == "LifecycleScopedRelationship")
        .collect();
    assert_eq!(scoped.len(), 1, "{scoped:?}");
    assert_eq!(scoped[0]["scope"], "development");
    assert_eq!(scoped[0]["to"].as_array().unwrap().len(), 3);

    // pixi.lock: an environment is already a selection of features, so no scope is written.
    let multi = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi-env/pixi.lock");
    let pixi = document(&["--lockfile", multi.to_str().unwrap(), "--environment", "alpha"]);
    assert!(
        pixi["components"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c.get("scope").is_none())
    );
}

#[test]
fn prefix_reads_venvs_and_plain_site_packages() {
    // #323: a venv (POSIX and Windows layouts) and a plain site-packages are environments too.
    let work = tempfile::tempdir().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let run = |args: &[&str]| {
        let mut command = pixi_sbom();
        command
            .current_dir(work.path())
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(args);
        command
    };
    for (dir, platform, python, count) in [
        ("venv-posix", "linux-64", "3.12.7", 6),
        ("venv-windows", "win-64", "3.13.5", 2),
        ("site-packages", "osx-arm64", "3.11", 3), // numpy, six and the interpreter
    ] {
        let prefix = fixtures.join(dir);
        let output = run(&["--prefix", prefix.to_str().unwrap(), "--output", "-"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let doc: Value = serde_json::from_slice(&output).unwrap();
        assert_valid(&cyclonedx_validator(), &doc);
        assert_eq!(doc["components"].as_array().unwrap().len(), count, "{dir}");
        let property = |name: &str| {
            doc["metadata"]["properties"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == name)
                .map(|p| p["value"].as_str().unwrap().to_string())
        };
        assert_eq!(property("pixi:platform").as_deref(), Some(platform), "{dir}");
        assert_eq!(property("pixi:python-version").as_deref(), Some(python), "{dir}");

        let output = run(&[
            "--prefix",
            prefix.to_str().unwrap(),
            "--format",
            "spdx",
            "--output",
            "-",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
        let spdx: Value = serde_json::from_slice(&output).unwrap();
        assert_valid(&spdx_validator(), &spdx);
    }

    // The drift check: a venv against the lockfile environment it was meant to match.
    let venv = fixtures.join("venv-posix");
    let lockfile = fixtures.join("with-pypi/pixi.lock");
    let output = run(&["--prefix", venv.to_str().unwrap(), "-p", "linux-64", "-e", "web"])
        .args(["--report", "diff", "--report-format", "json", "--against"])
        .arg(&lockfile)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    let changed = &report["version_changed"][0];
    assert_eq!(changed["name"], "urllib3");
    assert_eq!(changed["old_version"], "2.8.0");
    assert_eq!(changed["new_version"], "2.7.0");
    let pip: Vec<&str> = report["pip_installed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(pip, ["pip"]);

    // --environment with --prefix means the lockfile side, so it needs --against.
    run(&["--prefix", venv.to_str().unwrap(), "-e", "web"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("names the lockfile side of '--against'"));
    run(&["--prefix", fixtures.join("explicit").to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is not an environment"))
        .stderr(predicate::str::contains("found"));
}

#[test]
fn installs_from_outside_an_index_do_not_claim_a_pypi_release() {
    // #333: a git checkout, a local directory and an editable install, per PEP 610.
    let work = tempfile::tempdir().unwrap();
    let venv = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/venv-sources");
    let output = pixi_sbom()
        .current_dir(work.path())
        .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["--prefix", venv.to_str().unwrap(), "--output", "-"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let doc: Value = serde_json::from_slice(&output).unwrap();
    assert_valid(&cyclonedx_validator(), &doc);
    let component = |name: &str| {
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("{name}"))
            .clone()
    };
    let property = |c: &Value, key: &str| {
        c["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == key)
            .map(|p| p["value"].as_str().unwrap().to_string())
    };
    assert_eq!(
        component("requests")["purl"],
        "pkg:pypi/requests@2.34.2",
        "from an index: unchanged"
    );
    let git = component("acme_tools");
    assert_eq!(
        git["purl"],
        "pkg:github/acme/acme-tools@4f2c9e1b7d3a5c8e0f6b2d4a1c3e5f7091a2b3c4"
    );
    assert_eq!(
        property(&git, "pixi:source-rev").as_deref(),
        Some("4f2c9e1b7d3a5c8e0f6b2d4a1c3e5f7091a2b3c4")
    );
    let local = component("internal_lib");
    assert_eq!(local["purl"], "pkg:generic/internal_lib@1.0.0");
    // A local directory outside the venv's project says only where it is on that machine.
    assert_eq!(property(&local, "pixi:direct-url"), None);
    assert_eq!(property(&local, "pixi:editable"), None);
    let editable = component("myapp");
    assert_eq!(editable["purl"], "pkg:generic/myapp@2.1.0");
    assert_eq!(property(&editable, "pixi:editable").as_deref(), Some("true"));
}

#[test]
fn what_was_requested_by_name_is_direct_in_an_installed_environment() {
    // #332: a REQUESTED dist-info is what the user asked for; the rest came along with it.
    let work = tempfile::tempdir().unwrap();
    let venv = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/venv-posix");
    let run = |args: &[&str]| {
        let output = pixi_sbom()
            .current_dir(work.path())
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("COLUMNS", "200")
            .args(["--prefix", venv.to_str().unwrap()])
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        String::from_utf8(output).unwrap()
    };
    let table = run(&["--report", "packages"]);
    assert!(
        table.contains("6 packages, 1 requested by name when installed"),
        "{table}"
    );
    let row = table.lines().find(|l| l.starts_with("requests ")).unwrap();
    assert!(row.contains("requested"), "{row}");
    let row = table.lines().find(|l| l.starts_with("urllib3 ")).unwrap();
    assert!(!row.contains("requested"), "came along: {row}");

    let doc: Value = serde_json::from_str(&run(&["--output", "-"])).unwrap();
    let root = doc["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["ref"] == doc["metadata"]["component"]["bom-ref"])
        .unwrap();
    assert_eq!(root["dependsOn"], serde_json::json!(["pkg:pypi/requests@2.34.2"]));
}

#[test]
fn infer_extras_is_opt_in_and_labelled() {
    // #334: off by default; with the flag, the inference is marked as such.
    let work = tempfile::tempdir().unwrap();
    let venv = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/venv-extras");
    let requests = |args: &[&str]| -> Value {
        let output = pixi_sbom()
            .current_dir(work.path())
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["--prefix", venv.to_str().unwrap(), "--output", "-"])
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let doc: Value = serde_json::from_slice(&output).unwrap();
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "requests")
            .unwrap()
            .clone()
    };
    let names = |c: &Value| -> Vec<String> {
        c["properties"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(
        !names(&requests(&[])).iter().any(|n| n.contains("extras")),
        "off by default"
    );
    let inferred = requests(&["--infer-extras"]);
    for key in [
        "pixi:python-extras",
        "pixi:python-extras-inferred",
        "pixi:python-extras-evidence",
    ] {
        assert!(names(&inferred).iter().any(|n| n == key), "{key}");
    }

    // The configuration file can turn it on, and the flag needs --prefix.
    std::fs::write(work.path().join("pixi-sbom.toml"), "infer-extras = true\n").unwrap();
    assert!(names(&requests(&[])).iter().any(|n| n == "pixi:python-extras-inferred"));
    pixi_sbom()
        .current_dir(work.path())
        .args(["--infer-extras", "--no-config"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--prefix"));
}

#[test]
fn a_scan_reads_every_kind_of_lockfile_once_per_project() {
    // #339: a monorepo of pixi, uv and Poetry projects; one directory has pixi.lock and uv.lock.
    let tree = tempfile::tempdir().unwrap();
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects");
    let place = |dir: &str, from: &Path, files: &[&str]| {
        let target = tree.path().join(dir);
        std::fs::create_dir_all(&target).unwrap();
        for file in files {
            std::fs::copy(from.join(file), target.join(file)).unwrap();
        }
    };
    place(
        "services/pixi-app",
        &tests_dir().join("fixtures/conda-only"),
        &["pixi.toml", "pixi.lock"],
    );
    place(
        "services/uv-app",
        &examples.join("uv/01-django"),
        &["pyproject.toml", "uv.lock"],
    );
    place(
        "libs/poetry-lib",
        &examples.join("poetry/01-django"),
        &["pyproject.toml", "poetry.lock"],
    );
    place(
        "both",
        &tests_dir().join("fixtures/conda-only"),
        &["pixi.toml", "pixi.lock"],
    );
    place("both", &examples.join("uv/01-django"), &["uv.lock"]);

    let assert = pixi_sbom()
        .current_dir(tree.path())
        .env("PIXI_CACHE_DIR", tree.path().join(".empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", tree.path().join(".cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["-p", "linux-64", "--scan", "."])
        .assert()
        .success();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("several lockfiles in one directory") && stderr.contains("chosen=pixi.lock"),
        "{stderr}"
    );
    for (dir, lockfile) in [
        ("services/pixi-app", "pixi.lock"),
        ("services/uv-app", "uv.lock"),
        ("libs/poetry-lib", "poetry.lock"),
        ("both", "pixi.lock"),
    ] {
        let doc = read_json(&tree.path().join(dir).join("sbom.cdx.json"));
        let recorded = doc["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "pixi:lockfile")
            .map(|p| p["value"].as_str().unwrap().to_string());
        assert_eq!(recorded.as_deref(), Some(lockfile), "{dir}");
    }
}

#[test]
fn a_venv_is_checked_against_its_uv_lock_or_pylock() {
    // #340: --against reads uv.lock and pylock.toml like --lockfile does.
    let work = tempfile::tempdir().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    // The venv-posix fixture without the pip that `python -m venv` seeds: what `uv sync` leaves.
    let venv = work.path().join("venv");
    let copy = |from: &Path, to: &Path| {
        for entry in walkdir(from) {
            let target = to.join(entry.strip_prefix(from).unwrap());
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::copy(&entry, &target).unwrap();
        }
    };
    copy(&fixtures.join("venv-posix"), &venv);
    std::fs::remove_dir_all(venv.join("lib/python3.12/site-packages/pip-25.2.dist-info")).unwrap();
    let check = |against: &str| {
        let mut command = pixi_sbom();
        command
            .current_dir(work.path())
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args([
                "--prefix",
                venv.to_str().unwrap(),
                "--report",
                "diff",
                "--fail-on-diff",
                "any",
                "--against",
            ])
            .arg(fixtures.join("uv-drift").join(against));
        command
    };
    for against in ["uv.lock", "pylock.toml"] {
        let assert = check(against).assert().success();
        let out = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        assert!(out.contains("No changes against"), "{against}: {out}");
    }

    // Someone ran `pip install six` in the venv.
    let six = venv.join("lib/python3.12/site-packages/six-1.17.0.dist-info");
    std::fs::create_dir_all(&six).unwrap();
    std::fs::write(
        six.join("METADATA"),
        "Metadata-Version: 2.1\nName: six\nVersion: 1.17.0\n",
    )
    .unwrap();
    std::fs::write(six.join("INSTALLER"), "pip\n").unwrap();
    for against in ["uv.lock", "pylock.toml"] {
        check(against)
            .assert()
            .code(6)
            .stderr(predicate::str::contains("pip installed (1)"));
    }

    // A conda prefix against uv.lock compares the PyPI packages and counts the conda ones out.
    let output = pixi_sbom()
        .current_dir(work.path())
        .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "--prefix",
            fixtures.join("prefix").to_str().unwrap(),
            "--report",
            "diff",
        ])
        .args(["--report-format", "json", "--against"])
        .arg(fixtures.join("uv-drift/uv.lock"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["out_of_scope"], 3, "{report}");
    assert!(
        report["removed"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["kind"] == "pypi")
    );
}

/// Every file under `dir`.
fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(walkdir(&path));
        } else {
            files.push(path);
        }
    }
    files
}

#[test]
fn a_rerun_that_would_change_only_the_timestamp_leaves_the_file_alone() {
    // #342: what lets a pre-commit hook pass until the SBOM really changes.
    let dir = workspace("conda-only");
    let run = |epoch: &str| {
        let output = pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("SOURCE_DATE_EPOCH", epoch)
            .args(["-p", "linux-64"])
            .assert()
            .success()
            .get_output()
            .stderr
            .clone();
        String::from_utf8(output).unwrap()
    };
    assert!(run("1700000000").contains("wrote SBOM"));
    let first = std::fs::read(dir.path().join("sbom.cdx.json")).unwrap();
    let again = run("1800000000");
    assert!(again.contains("left as it was"), "{again}");
    assert_eq!(
        std::fs::read(dir.path().join("sbom.cdx.json")).unwrap(),
        first,
        "byte for byte, old timestamp kept"
    );

    // A real change is written, with the new timestamp.
    let lock = std::fs::read_to_string(dir.path().join("pixi.toml")).unwrap();
    std::fs::write(
        dir.path().join("pixi.toml"),
        lock.replacen("name = \"", "name = \"renamed-", 1),
    )
    .unwrap();
    assert!(run("1800000000").contains("wrote SBOM"));
    assert_ne!(std::fs::read(dir.path().join("sbom.cdx.json")).unwrap(), first);
}

#[test]
fn the_without_pixi_page_runs_and_shows_the_tested_matrix() {
    // #345: every `pixi-sbom` line in the page's shell blocks runs as written, in a project that
    // has each file it names, and its table is the one tests/matrix.rs produces.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs/without-pixi.md")).unwrap();
    let project = tempfile::tempdir().unwrap();
    let examples = root.join("examples/projects");
    for (from, files) in [
        ("uv/01-django", &["pyproject.toml", "uv.lock"][..]),
        ("pylock/01-django", &["pylock.toml"]),
        ("poetry/01-django", &["poetry.lock"]),
        ("pdm/01-django", &["pdm.lock"]),
        ("conda-lock/01-django", &["conda-lock.yml", "environment.yml"]),
        ("conda-explicit/01-django", &["explicit-linux-64.txt"]),
    ] {
        for file in files {
            std::fs::copy(examples.join(from).join(file), project.path().join(file)).unwrap();
        }
    }
    let venv = root.join("tests/fixtures/venv-posix");
    for entry in walkdir(&venv) {
        let target = project.path().join(".venv").join(entry.strip_prefix(&venv).unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(&entry, &target).unwrap();
    }

    let mut ran = 0;
    let mut in_shell = false;
    for line in page.lines() {
        if line.starts_with("```") {
            in_shell = line == "```sh";
            continue;
        }
        let Some(command) = line.strip_prefix("pixi-sbom ").filter(|_| in_shell) else {
            continue;
        };
        let args: Vec<&str> = command.split('#').next().unwrap().split_whitespace().collect();
        pixi_sbom()
            .current_dir(project.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("PIXI_CACHE_DIR", project.path().join(".empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", project.path().join(".cache"))
            .args(&args)
            .assert()
            .success();
        ran += 1;
    }
    assert!(ran >= 8, "the page's examples were found and run ({ran})");

    let snapshot =
        std::fs::read_to_string(root.join("tests/snapshots/matrix__every_report_and_gate_on_every_input.snap"))
            .unwrap();
    let grid: Vec<&str> = snapshot.lines().filter(|l| l.starts_with('|')).collect();
    assert!(grid.len() > 10, "the snapshot has the grid");
    for row in grid {
        assert!(
            page.lines().any(|line| line == row),
            "docs/without-pixi.md is behind tests/matrix.rs; copy the grid from the snapshot. Missing: {row}"
        );
    }
}

#[test]
fn what_each_common_setup_writes_is_read() {
    // #389: the "Getting a lockfile" table in docs/without-pixi.md, one real tool output per row
    // (tests/fixtures/lockfile-routes/README.md says how each was made).
    let routes = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lockfile-routes");
    for (file, platform, expect) in [
        ("pylock.pip-tools.toml", "linux-64", "requests"),
        ("requirements.txt", "osx-arm64", "requests"),
        ("pylock.pipenv.toml", "linux-64", "requests"),
        ("pylock.pip.toml", "osx-arm64", "requests"),
        ("explicit-micromamba.txt", "osx-arm64", "requests"),
        ("explicit-conda.txt", "osx-arm64", "requests"),
        ("conda-lock.yml", "linux-64", "requests"),
        ("conda-linux-64.lock", "linux-64", "requests"),
    ] {
        let work = tempfile::tempdir().unwrap();
        let output = pixi_sbom()
            .current_dir(work.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .args(["--lockfile", routes.join(file).to_str().unwrap(), "-p", platform])
            .args(["--report", "packages", "--report-format", "json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let report: Value = serde_json::from_slice(&output).unwrap();
        let names: Vec<&str> = report["packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&expect), "{file}: {names:?}");
    }
}

#[test]
fn an_unlocked_input_is_pointed_to_the_command_that_locks_it() {
    // #394: given (or found) something that declares rather than locks, say what locks it.
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, text: &str| std::fs::write(dir.path().join(name), text).unwrap();
    write("pixi.toml", "[workspace]\nname = \"w\"\n");
    write("Pipfile", "[packages]\nrequests = \"*\"\n");
    write("environment.yml", "name: app\ndependencies:\n  - python=3.12\n");
    write(
        "export.yml",
        "name: app\ndependencies:\n  - python=3.12.1=h1_0\nprefix: /opt/conda/envs/app\n",
    );
    write("requirements.txt", "django>=5.2\n");
    std::fs::create_dir_all(dir.path().join("poetry")).unwrap();
    std::fs::write(
        dir.path().join("poetry/pyproject.toml"),
        "[project]\nname = \"p\"\n[tool.poetry]\n",
    )
    .unwrap();
    for (file, code, command) in [
        ("poetry/pyproject.toml", "pixi_sbom::input::not_a_lock", "poetry lock"),
        ("pixi.toml", "pixi_sbom::input::not_a_lock", "pixi lock"),
        ("Pipfile", "pixi_sbom::input::not_a_lock", "pipenv requirements"),
        (
            "environment.yml",
            "pixi_sbom::input::not_a_lock",
            "conda-lock -f environment.yml",
        ),
        (
            "export.yml",
            "pixi_sbom::input::not_a_lock",
            "conda list --explicit --md5",
        ),
        (
            "requirements.txt",
            "pixi_sbom::requirements::not_pinned",
            "uv pip compile requirements.txt",
        ),
    ] {
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .args(["--lockfile", file])
            .assert()
            .failure();
        let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
        assert!(stderr.contains(code), "{file}: {stderr}");
        assert!(stderr.contains(command), "{file}: {stderr}");
    }

    // The upward search: no lockfile anywhere, but a Poetry manifest one level up.
    let nested = dir.path().join("poetry/src");
    std::fs::create_dir_all(&nested).unwrap();
    let assert = pixi_sbom().current_dir(&nested).assert().failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("pixi_sbom::discover::not_found"), "{stderr}");
    assert!(
        stderr.contains("is a Poetry project's manifest: run `poetry lock` beside it"),
        "{stderr}"
    );
}

#[test]
fn the_quality_report_grades_a_complete_and_a_sparse_document() {
    // #336: a pixi.lock document and a document syft wrote, graded the same way; the gate is
    // exit 10, named in the gate summary, and the document is written first.
    let work = tempfile::tempdir().unwrap();
    let run = |dir: &Path, args: &[&str]| {
        pixi_sbom()
            .current_dir(dir)
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("NO_COLOR", "1")
            .env("COLUMNS", "160")
            .args(args)
            .output()
            .unwrap()
    };
    let complete = workspace("with-pypi");
    let output = run(complete.path(), &["-e", "web", "-p", "linux-64", "--report", "quality"]);
    assert!(output.status.success());
    insta::assert_snapshot!("quality_complete", String::from_utf8(output.stdout).unwrap());

    let syft = tests_dir().join("fixtures/syft/app.cdx.json");
    let output = run(
        work.path(),
        &["--from-sbom", syft.to_str().unwrap(), "--report", "quality"],
    );
    assert!(output.status.success());
    insta::assert_snapshot!("quality_sparse", String::from_utf8(output.stdout).unwrap());

    let output = run(
        work.path(),
        &[
            "--from-sbom",
            syft.to_str().unwrap(),
            "--report",
            "quality",
            "--report-format",
            "json",
        ],
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["report"], "quality");
    assert_eq!(
        report["summary"]["overall"], 62,
        "syft's authors are suppliers, its CPEs identifiers"
    );
    let rows = report["quality"].as_array().unwrap();
    assert_eq!(rows.len(), 11);
    // The same tool's SPDX: `supplier: Person: ...` and `cpe23Type` references are read too.
    let spdx = tests_dir().join("fixtures/syft/app.spdx.json");
    let output = run(
        work.path(),
        &[
            "--from-sbom",
            spdx.to_str().unwrap(),
            "--report",
            "quality",
            "--report-format",
            "json",
        ],
    );
    let spdx: Value = serde_json::from_slice(&output.stdout).unwrap();
    let element = |name: &str| {
        spdx["quality"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["element"] == name)
            .unwrap()
            .clone()
    };
    assert!(
        element("supplier")["score"].as_u64().unwrap() > 0,
        "{}",
        element("supplier")
    );
    assert!(
        element("unique identifier")["detail"]
            .as_str()
            .unwrap()
            .contains("a purl or a CPE"),
        "{}",
        element("unique identifier")
    );

    // Read and written again, the CPEs stay CPEs and the suppliers suppliers.
    let syft = tests_dir().join("fixtures/syft/app.cdx.json");
    let output = run(work.path(), &["--from-sbom", syft.to_str().unwrap(), "--output", "-"]);
    let written: Value = serde_json::from_slice(&output.stdout).unwrap();
    let components = written["components"].as_array().unwrap();
    assert_eq!(components.iter().filter(|c| c["cpe"].is_string()).count(), 15);
    assert_eq!(components.iter().filter(|c| c["supplier"].is_object()).count(), 9);
    assert!(
        !components
            .iter()
            .flat_map(|c| c["properties"].as_array().into_iter().flatten())
            .any(|p| p["name"] == "cpe"),
        "the CPE is a field, never a property"
    );
    let informational: Vec<&Value> = rows
        .iter()
        .filter(|r| r["informational"] == true)
        .map(|r| &r["element"])
        .collect();
    assert_eq!(
        informational,
        ["scanner identity", "PyPI identity"],
        "shown, not scored: the overall score above is unchanged"
    );

    let document = work.path().join("out.cdx.json");
    let output = run(
        work.path(),
        &[
            "--from-sbom",
            syft.to_str().unwrap(),
            "--min-quality",
            "80",
            "--output",
            document.to_str().unwrap(),
        ],
    );
    assert_eq!(output.status.code(), Some(10));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("SBOM quality below 80"), "{stderr}");
    assert!(stderr.contains("Gate failed: quality (1). Exiting 10."), "{stderr}");
    assert!(document.is_file(), "the document is written before the gate fails");
    let output = run(
        complete.path(),
        &["-e", "web", "-p", "linux-64", "--min-quality", "80", "--output", "-"],
    );
    assert!(output.status.success(), "86 passes 80");
}

/// Every pixi example, every environment its manifest declares, on both locked platforms: one
/// document each, valid CycloneDX, and the PyPI packages pixi put on top of the conda ones.
#[test]
fn every_pixi_example_reads_in_every_environment() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/pixi");
    let work = tempfile::tempdir().unwrap();
    let mut projects: Vec<PathBuf> = std::fs::read_dir(&examples)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("pixi.lock").is_file())
        .collect();
    projects.sort();
    assert_eq!(projects.len(), 14, "one per scenario");
    for project in &projects {
        let manifest: toml::Table = std::fs::read_to_string(project.join("pixi.toml"))
            .unwrap()
            .parse()
            .unwrap();
        let environments = 1 + manifest
            .get("environments")
            .and_then(|e| e.as_table())
            .map_or(0, |e| e.len());
        for platform in ["linux-64", "osx-arm64"] {
            let out = work.path().join(project.file_name().unwrap()).join(platform);
            pixi_sbom()
                .current_dir(project)
                .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
                .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
                .env("PIXI_SBOM_OFFLINE", "1")
                .args(["--all-environments", "-p", platform, "--output"])
                .arg(&out)
                .assert()
                .success();
            let written = std::fs::read_dir(&out).unwrap().count();
            assert_eq!(written, environments, "{}: {platform}", project.display());
        }
    }

    // The Django project: a conda Django, a PyPI package conda-forge lacks, an editable local
    // package, and in the `dev` environment a git checkout.
    let django = examples.join("01-django");
    let document = |environment: &str| -> Value {
        let output = pixi_sbom()
            .current_dir(&django)
            .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["-e", environment, "-p", "linux-64", "--output", "-"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice(&output).unwrap()
    };
    let purls = |doc: &Value| -> Vec<String> {
        doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| c["purl"].as_str().map(str::to_string))
            .collect()
    };
    let default = document("default");
    assert_valid(&cyclonedx_validator(), &default);
    let found = purls(&default);
    assert!(
        found.iter().any(|p| p.starts_with("pkg:conda/django@3.2.12")),
        "{found:?}"
    );
    assert!(found.iter().any(|p| p == "pkg:pypi/django-environ@0.9.0"), "{found:?}");
    assert!(
        default["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "internal-utils"),
        "the editable local package"
    );
    let dev = document("dev");
    assert!(
        dev["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "django-debug-toolbar"),
        "the git checkout, only in dev"
    );
    assert!(
        !default["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "django-debug-toolbar")
    );
}

/// Every pinned requirements example, both files, read for the interpreter and platform it was
/// compiled for: uv's command says so in its header, pip-compile's header names the Python.
#[test]
fn every_requirements_example_reads_for_what_it_was_compiled_for() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/requirements");
    let work = tempfile::tempdir().unwrap();
    let mut projects: Vec<PathBuf> = std::fs::read_dir(&examples)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("requirements.txt").is_file())
        .collect();
    projects.sort();
    assert_eq!(projects.len(), 14, "one per scenario");
    for project in &projects {
        let first = std::fs::read_to_string(project.join("requirements.txt")).unwrap();
        let by_uv = first.contains("uv pip compile");
        let python = if by_uv {
            let at = first.find("--python-version ").unwrap() + "--python-version ".len();
            first[at..].split_whitespace().next().unwrap().to_string()
        } else {
            let at = first.find("pip-compile with Python ").unwrap() + "pip-compile with Python ".len();
            first[at..].split_whitespace().next().unwrap().to_string()
        };
        for file in ["requirements.txt", "requirements-dev.txt"] {
            let assert = pixi_sbom()
                .current_dir(project)
                .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
                .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
                .env("PIXI_SBOM_OFFLINE", "1")
                .args(["--lockfile", file, "--output", "-"])
                .assert()
                .success()
                .stderr(predicate::str::contains(format!("python={python}")));
            if by_uv {
                // Compiled for manylinux x86_64, whatever machine reads it.
                assert.stderr(predicate::str::contains("platform=linux-64"));
            }
        }
    }
}

/// The unpinned requirements projects: each one is refused, naming the first line that is not
/// one version, and writes nothing.
#[test]
fn every_unpinned_requirements_example_is_refused_by_line() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/requirements-unpinned");
    let cases = [
        ("01-loose-ranges", 3, "Django>=4.2,<5"),
        ("02-bare-names", 1, "flask"),
        ("03-one-loose-line", 55, "rich>=14"),
        ("04-editable-and-git", 6, "-e ./libs/internal-utils"),
        ("05-wildcard-pins", 2, "Django==4.2.*"),
    ];
    let listed = std::fs::read_dir(&examples)
        .unwrap()
        .filter(|e| e.as_ref().unwrap().path().is_dir())
        .count();
    assert_eq!(listed, cases.len(), "every project has a case here");
    let work = tempfile::tempdir().unwrap();
    for (project, line, text) in cases {
        let out = work.path().join(format!("{project}.cdx.json"));
        pixi_sbom()
            .current_dir(examples.join(project))
            .env("PIXI_SBOM_OFFLINE", "1")
            .args(["--lockfile", "requirements.txt", "--output"])
            .arg(&out)
            .assert()
            .code(1)
            .stderr(predicate::str::contains("pixi_sbom::requirements::not_pinned"))
            .stderr(predicate::str::contains(format!(
                "line {line} of requirements.txt is not pinned to one version: {text}"
            )));
        assert!(!out.exists(), "{project}: nothing written");
    }
}

/// Every example a scan discovers reads: 14 scenarios for each of the six readers whose lockfile
/// has a fixed name (explicit specs and requirements files are only read through --lockfile). A
/// reader that cannot read a file its own tool wrote fails here rather than on a user's scan.
#[test]
fn the_whole_examples_tree_scans_clean() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects");
    let work = tempfile::tempdir().unwrap();
    let output = pixi_sbom()
        .current_dir(work.path())
        .env("PIXI_CACHE_DIR", work.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args([
            "-p",
            "linux-64",
            "--report",
            "packages",
            "--report-format",
            "json",
            "--scan",
        ])
        .arg(&examples)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    assert_eq!(
        text.matches("\"report\": \"packages\"").count(),
        84,
        "one report per lockfile"
    );
}

/// The what's-new page has a section for every release since 1.0, and none for a release that
/// does not exist: a release that ships without one fails the next build, which is how it gets
/// written while the release is still fresh.
#[test]
fn the_whats_new_page_covers_every_release_since_1_0() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let version_of = |line: &str, prefix: &str| -> Option<(u32, u32, u32)> {
        let rest = line.strip_prefix(prefix)?;
        let version = rest.split_whitespace().next()?;
        if version.contains('-') {
            return None; // a release candidate
        }
        let mut parts = version.split('.').map(|p| p.parse::<u32>());
        Some((parts.next()?.ok()?, parts.next()?.ok()?, parts.next()?.ok()?))
    };
    let changelog = std::fs::read_to_string(root.join("CHANGELOG.md")).unwrap();
    let released: std::collections::BTreeSet<(u32, u32, u32)> = changelog
        .lines()
        .filter_map(|l| version_of(l, "## "))
        .filter(|v| *v > (1, 0, 0))
        .collect();
    let page = std::fs::read_to_string(root.join("docs/whats-new.md")).unwrap();
    let covered: std::collections::BTreeSet<(u32, u32, u32)> =
        page.lines().filter_map(|l| version_of(l, "## ")).collect();
    let missing: Vec<_> = released.difference(&covered).collect();
    let invented: Vec<_> = covered.difference(&released).collect();
    assert!(missing.is_empty(), "docs/whats-new.md has no section for {missing:?}");
    assert!(
        invented.is_empty(),
        "docs/whats-new.md describes releases that do not exist: {invented:?}"
    );
    assert!(released.contains(&(1, 8, 1)), "the changelog was read");

    // Notes for the next release collect under one `## Unreleased`, above every release, and the
    // release workflow refuses to tag without them and renames them in the release commit.
    let unreleased: Vec<usize> = page
        .lines()
        .enumerate()
        .filter(|(_, l)| l.trim_end() == "## Unreleased")
        .map(|(i, _)| i)
        .collect();
    assert!(
        unreleased.len() <= 1,
        "docs/whats-new.md has {} '## Unreleased' sections",
        unreleased.len()
    );
    if let Some(&at) = unreleased.first() {
        let first_release = page.lines().position(|l| version_of(l, "## ").is_some()).unwrap();
        assert!(
            at < first_release,
            "'## Unreleased' in docs/whats-new.md is below a release's section"
        );
    }
    let release = std::fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();
    for step in [
        "scripts/whats_new.py check",
        "pixi run whats-new release",
        "pixi.toml docs/whats-new.md",
    ] {
        assert!(release.contains(step), "release.yml no longer runs `{step}`");
    }
}

/// Every `pixi sbom` line on the examples tour runs as written, in order, against a copy of
/// `examples/projects`. A plain line succeeds; `# exit N` exits with N; `# needs the network`
/// cannot be judged offline, so it is held to what offline can check: the flags parse and every
/// example it names exists.
#[test]
fn the_examples_tour_runs_as_written() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs/try-the-examples.md")).unwrap();
    let work = tempfile::tempdir().unwrap();
    let examples = root.join("examples/projects");
    for file in walkdir(&examples) {
        let target = work
            .path()
            .join("examples/projects")
            .join(file.strip_prefix(&examples).unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(&file, &target).unwrap();
    }

    let (mut ran, mut online) = (0, 0);
    let mut in_shell = false;
    for line in page.lines() {
        if line.starts_with("```") {
            in_shell = line == "```sh";
            continue;
        }
        let Some(command) = line.strip_prefix("pixi sbom ").filter(|_| in_shell) else {
            continue;
        };
        let (args, comment) = command.split_once('#').unwrap_or((command, ""));
        let args: Vec<&str> = args.split_whitespace().collect();
        let comment = comment.trim();
        for path in args.iter().filter(|a| a.starts_with("examples/")) {
            assert!(work.path().join(path).exists(), "{line}: {path} does not exist");
        }
        let assert = pixi_sbom()
            .current_dir(work.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("PIXI_CACHE_DIR", work.path().join(".empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", work.path().join(".cache"))
            .args(&args)
            .assert();
        let code = assert.get_output().status.code();
        match comment {
            "needs the network" => {
                assert_ne!(code, Some(2), "{line}: a usage error");
                online += 1;
            }
            "" => assert_eq!(
                code,
                Some(0),
                "{line}: {}",
                String::from_utf8_lossy(&assert.get_output().stderr)
            ),
            other => {
                let expected: i32 = other
                    .strip_prefix("exit ")
                    .and_then(|n| n.parse().ok())
                    .unwrap_or_else(|| panic!("{line}: an annotation this test does not know: {other}"));
                assert_eq!(code, Some(expected), "{line}");
            }
        }
        ran += 1;
    }
    assert!(ran >= 20, "the page's commands were found and run ({ran})");
    assert!(online >= 5, "and the ones that need the network are marked ({online})");
    // What the tour wrote is there for the next section to use.
    for written in ["sboms", "app.cdx.json", "vendor.spdx.json"] {
        assert!(work.path().join(written).exists(), "{written}");
    }
    assert_eq!(
        std::fs::read_dir(work.path().join("sboms")).unwrap().count(),
        4,
        "one per environment"
    );
}

/// Every recording tape has its GIF beside it, writes to that GIF, and the GIF is shown somewhere
/// with a description: a clip recorded and never placed, or placed without alt text, fails here.
#[test]
fn every_recording_is_recorded_named_and_shown() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let assets = root.join("docs/assets");
    let docs: String = ["README.md", "docs/cli.md", "docs/index.md"]
        .iter()
        .map(|f| std::fs::read_to_string(root.join(f)).unwrap())
        .collect();
    let mut tapes = 0;
    for entry in std::fs::read_dir(&assets).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".tape").filter(|s| !s.starts_with('_')) else {
            continue;
        };
        tapes += 1;
        let gif = format!("{stem}.gif");
        assert!(
            assets.join(&gif).is_file(),
            "{name} has no {gif}: run `pixi run demo {stem}`"
        );
        let tape = std::fs::read_to_string(&path).unwrap();
        assert!(
            tape.contains(&format!("Output \"docs/assets/{gif}\"")),
            "{name} writes somewhere other than docs/assets/{gif}"
        );
        let shown = docs
            .lines()
            .find(|line| line.contains(&format!("assets/{gif}")))
            .unwrap_or_else(|| panic!("{gif} is not shown in the README or the docs"));
        assert!(
            shown.contains("alt=\"") && !shown.contains("alt=\"\""),
            "{gif} has no alt text: {shown}"
        );
    }
    assert!(tapes >= 12, "the tapes were found ({tapes})");
}

/// A shell line as the field manual writes it: leading `VAR=value` assignments, then words, quotes
/// honoured, and nothing after a pipe or a redirect (those belong to the shell, not to the tool).
fn shell_words(line: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                started = true;
            }
            (None, '|' | '>') if !started => break,
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (None, c) => {
                word.push(c);
                started = true;
            }
        }
    }
    if started {
        words.push(word);
    }
    let mut env = Vec::new();
    while let Some((key, value)) = words.first().and_then(|w| w.split_once('=')).filter(|(k, _)| {
        !k.is_empty()
            && k.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }) {
        env.push((key.to_string(), value.to_string()));
        words.remove(0);
    }
    (env, words)
}

#[test]
fn shell_words_split_like_the_shell_the_manual_is_written_for() {
    let (env, words) =
        shell_words(r#"PIXI_SBOM_OFFLINE=1 pixi sbom --ignore-vuln "CVE-1:not reachable" --output - | grep x > y"#);
    assert_eq!(env, [("PIXI_SBOM_OFFLINE".to_string(), "1".to_string())]);
    assert_eq!(
        words,
        ["pixi", "sbom", "--ignore-vuln", "CVE-1:not reachable", "--output", "-"]
    );
}

/// Every `pixi sbom` line in the field manual runs as written, page by page in the order the
/// navigation lists them, in one project that has what the playbooks name: a pixi workspace,
/// a vendor's CycloneDX, SPDX and OpenVEX documents, and a pinned requirements.txt. A plain line
/// succeeds; `# exit N` exits N; `# needs the network` is held offline to parsing and to the
/// files it names existing.
#[test]
fn the_field_manual_runs_as_written() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let work = tempfile::tempdir().unwrap();
    let project = root.join("examples/projects/pixi/01-django");
    for file in walkdir(&project) {
        let target = work.path().join(file.strip_prefix(&project).unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(&file, &target).unwrap();
    }
    for (from, to) in [
        ("tests/fixtures/syft/app.cdx.json", "vendor.cdx.json"),
        ("tests/fixtures/syft/app.spdx.json", "vendor.spdx.json"),
        ("tests/fixtures/vex-in/vendor.openvex.json", "vendor.openvex.json"),
        (
            "examples/projects/requirements/01-django/requirements.txt",
            "requirements.txt",
        ),
    ] {
        std::fs::copy(root.join(from), work.path().join(to)).unwrap();
    }

    let nav = std::fs::read_to_string(root.join("mkdocs.yml")).unwrap();
    let pages: Vec<&str> = nav
        .lines()
        .filter_map(|line| line.trim().split_once(": field-manual/").map(|(_, page)| page))
        .collect();
    assert!(pages.len() >= 8, "the field manual is in the navigation: {pages:?}");
    let (mut ran, mut online) = (0, 0);
    for page in pages {
        let text = std::fs::read_to_string(root.join("docs/field-manual").join(page)).unwrap();
        let mut in_shell = false;
        for line in text.lines() {
            if line.starts_with("```") {
                in_shell = line == "```sh";
                continue;
            }
            if !in_shell || !line.contains("pixi sbom ") {
                continue;
            }
            let (command, comment) = line.split_once(" # ").unwrap_or((line, ""));
            let (env, words) = shell_words(command);
            let Some(args) = words.strip_prefix(&["pixi".to_string(), "sbom".to_string()]) else {
                continue;
            };
            let mut cmd = pixi_sbom();
            cmd.current_dir(work.path())
                .env("PIXI_SBOM_OFFLINE", "1")
                .env("PIXI_CACHE_DIR", work.path().join(".empty-pkgs-cache"))
                .env("PIXI_SBOM_CACHE_DIR", work.path().join(".cache"))
                .args(args);
            for (key, value) in &env {
                cmd.env(key, value);
            }
            let output = cmd.output().unwrap();
            let code = output.status.code();
            let stderr = String::from_utf8_lossy(&output.stderr);
            match comment.trim() {
                "needs the network" => {
                    assert_ne!(code, Some(2), "{page}: {line}: a usage error\n{stderr}");
                    assert!(
                        !stderr.contains("No such file"),
                        "{page}: {line}: a file it names is missing\n{stderr}"
                    );
                    online += 1;
                }
                "" => assert_eq!(code, Some(0), "{page}: {line}\n{stderr}"),
                other => {
                    let expected: i32 = other
                        .strip_prefix("exit ")
                        .and_then(|n| n.parse().ok())
                        .unwrap_or_else(|| panic!("{page}: {line}: an annotation this test does not know: {other}"));
                    assert_eq!(code, Some(expected), "{page}: {line}\n{stderr}");
                }
            }
            ran += 1;
        }
    }
    assert!(ran >= 25, "the playbooks' commands were found and run ({ran})");
    assert!(online >= 10, "and the ones that need the network are marked ({online})");
}

/// The training lab runs as written, offline, from the cache it ships with: every `pixi sbom` line
/// in order, `# exit N` honoured, and every line of each expected-output block found in what the
/// command before it printed. A release that changes what a learner sees fails here rather than in
/// a classroom.
#[test]
fn the_training_lab_runs_as_written_and_shows_what_it_says() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs/lab.md")).unwrap();
    let work = tempfile::tempdir().unwrap();
    let examples = root.join("examples");
    for file in walkdir(&examples) {
        let target = work.path().join("examples").join(file.strip_prefix(&examples).unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(&file, &target).unwrap();
    }
    let cache = work.path().join("examples/lab-cache");

    // The page says when its answers were recorded, and the cache says the same.
    let recorded = |text: &str, marker: &str| {
        let at = text.find(marker).unwrap_or_else(|| panic!("no '{marker}'")) + marker.len();
        text[at..at + 10].to_string()
    };
    let readme = std::fs::read_to_string(cache.join("README.md")).unwrap();
    assert_eq!(
        recorded(&page, "recorded into `examples/lab-cache/` on "),
        recorded(&readme, "commands were run on "),
        "docs/lab.md and examples/lab-cache disagree about when the cache was recorded: run `pixi run lab-cache`"
    );

    let (mut ran, mut checked) = (0, 0);
    let mut block: Option<&str> = None;
    let mut last = String::new();
    for line in page.lines() {
        if let Some(fence) = line.strip_prefix("```") {
            block = match block {
                Some(_) => None,
                None => Some(fence),
            };
            continue;
        }
        match block {
            Some("sh") if line.starts_with("pixi sbom ") => {
                let (command, comment) = line.split_once(" # ").unwrap_or((line, ""));
                let (_, words) = shell_words(command);
                let output = pixi_sbom()
                    .current_dir(work.path())
                    .env("PIXI_SBOM_OFFLINE", "1")
                    .env("PIXI_SBOM_CACHE_DIR", &cache)
                    .env("PIXI_CACHE_DIR", work.path().join(".empty-pkgs-cache"))
                    .env("COLUMNS", "120")
                    .args(&words[2..])
                    .output()
                    .unwrap();
                last = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let expected = comment
                    .trim()
                    .strip_prefix("exit ")
                    .map_or(0, |n| n.parse::<i32>().unwrap());
                assert_eq!(output.status.code(), Some(expected), "{line}\n{last}");
                ran += 1;
            }
            Some("text") if !line.trim().is_empty() => {
                assert!(
                    last.contains(line.trim()),
                    "docs/lab.md expects `{}` from the command before it, which printed:\n{last}",
                    line.trim()
                );
                checked += 1;
            }
            _ => {}
        }
    }
    assert!(ran >= 14, "the lab's commands were found and run ({ran})");
    assert!(checked >= 12, "and its expected outputs checked ({checked})");
}

/// The public talk's demo slides show commands and what they print. Every command in the demo script runs offline
/// against the lab cache as written, and every output line on a demo slide is in what its command printed.
#[test]
fn the_talk_demo_runs_as_written_and_its_slides_show_what_it_prints() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let talk = root.join("docs/presentations/talk");
    let script = std::fs::read_to_string(talk.join("demo-script.md")).unwrap();
    let work = tempfile::tempdir().unwrap();
    let examples = root.join("examples");
    for file in walkdir(&examples) {
        let target = work.path().join("examples").join(file.strip_prefix(&examples).unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(&file, &target).unwrap();
    }
    let cache = work.path().join("examples/lab-cache");

    let mut printed = std::collections::HashMap::new();
    let mut in_console = false;
    for line in script.lines() {
        if let Some(fence) = line.strip_prefix("```") {
            in_console = !in_console && fence == "console";
            continue;
        }
        if !in_console || !line.starts_with("pixi sbom ") {
            continue;
        }
        let (command, comment) = line.split_once(" # ").unwrap_or((line, ""));
        let (_, words) = shell_words(command);
        let output = pixi_sbom()
            .current_dir(work.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("PIXI_SBOM_CACHE_DIR", &cache)
            .env("PIXI_CACHE_DIR", work.path().join(".empty-pkgs-cache"))
            .env("COLUMNS", "120")
            .args(&words[2..])
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let expected = comment
            .trim()
            .strip_prefix("exit ")
            .map_or(0, |n| n.parse::<i32>().unwrap());
        assert_eq!(output.status.code(), Some(expected), "{line}\n{text}");
        printed.insert(command.trim().to_string(), text);
    }
    assert!(
        printed.len() >= 8,
        "the demo script's commands were found and run ({})",
        printed.len()
    );

    let (mut commands, mut checked) = (0, 0);
    for slide in ["demo-read", "demo-gate", "demo-vendor"] {
        let html = std::fs::read_to_string(talk.join(format!("slides/{slide}.html"))).unwrap();
        let mut last: Option<&String> = None;
        for p in html.split("<p ").skip(1) {
            let (style, rest) = p.split_once('>').unwrap();
            let text = rest.split("</p>").next().unwrap().replace("&amp;", "&");
            if !style.contains("JetBrains Mono") {
                continue;
            }
            if let Some(command) = text.strip_prefix("$ ") {
                let found = printed.get(command);
                assert!(
                    found.is_some(),
                    "slide {slide} shows `{command}`, which the demo script never runs"
                );
                last = found;
                commands += 1;
            } else if style.contains("#F7F8F6") {
                let output = last.unwrap_or_else(|| panic!("slide {slide} shows `{text}` before any command"));
                assert!(
                    output.contains(&text),
                    "slide {slide} shows `{text}`, but its command printed:\n{output}"
                );
                checked += 1;
            }
        }
    }
    assert_eq!(
        (commands, checked),
        (7, 6),
        "every command and output line on the demo slides was checked"
    );
}

/// `PIXI_SBOM_COMPLETE=<shell> pixi-sbom` prints the line a shell's startup file sources, for
/// every shell offered, and registers it for `pixi-sbom`, called by name on PATH.
#[test]
fn every_shell_gets_a_completion_registration_for_pixi_sbom() {
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = pixi_sbom().env("PIXI_SBOM_COMPLETE", shell).output().unwrap();
        let script = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{shell}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(script.contains("pixi-sbom"), "{shell} registers pixi-sbom:\n{script}");
        assert!(
            script.contains("PIXI_SBOM_COMPLETE"),
            "{shell} calls back with our variable:\n{script}"
        );
        assert!(
            !script.contains("/pixi-sbom"),
            "{shell} calls the binary by name, not by path:\n{script}"
        );
    }
}

/// What a shell gets back when it asks: flags, the values a flag takes, and file paths. Asked the
/// way fish asks, the simplest of the protocols, in a copy of a pixi example.
#[test]
fn completion_offers_flags_values_and_paths() {
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("pixi.lock"), "").unwrap();
    let complete = |words: &[&str]| {
        let output = pixi_sbom()
            .current_dir(work.path())
            .env("PIXI_SBOM_COMPLETE", "fish")
            .arg("--")
            .arg("pixi-sbom")
            .args(words)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{words:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|line| line.split('\t').next().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(complete(&["--form"]), ["--format"]);
    assert_eq!(complete(&["--format", ""]), ["cyclonedx", "github", "spdx"]);
    // Alphabetical, not the order the flags are declared in (#481).
    assert_eq!(
        complete(&["--fail-on-"]),
        [
            "--fail-on-diff",
            "--fail-on-epss",
            "--fail-on-kev",
            "--fail-on-phantom",
            "--fail-on-scorecard",
            "--fail-on-severity",
            "--fail-on-yanked"
        ]
    );
    let reports = complete(&["--report", ""]);
    for kind in ["packages", "licenses", "vulnerabilities", "quality"] {
        assert!(reports.iter().any(|r| r == kind), "--report offers {kind}: {reports:?}");
    }
    assert_eq!(complete(&["--lockfile", "pixi."]), ["pixi.lock"]);
    // Nothing is written while completing: no SBOM, no cache.
    let left: Vec<_> = std::fs::read_dir(work.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, ["pixi.lock"]);
}

/// Only a shell's name asks for completion. A stray value left in an environment, or clap's
/// default `COMPLETE` variable that other tools share, leaves the run as it was.
#[test]
fn a_stray_completion_variable_does_not_change_a_run() {
    for (variable, value) in [
        ("PIXI_SBOM_COMPLETE", "1"),
        ("PIXI_SBOM_COMPLETE", "true"),
        ("COMPLETE", "zsh"),
    ] {
        pixi_sbom()
            .env(variable, value)
            .arg("--version")
            .assert()
            .success()
            .stdout(predicates::str::starts_with("pixi-sbom "));
    }
}

/// Every `bom-ref` in a CycloneDX document, and every SPDXID in an SPDX 2.3 one, is unique. Both
/// specifications require it and neither schema can say so.
fn assert_unique_ids(doc: &Value) {
    let mut ids: Vec<&str> = Vec::new();
    if let Some(components) = doc["components"].as_array() {
        ids.extend(components.iter().filter_map(|c| c["bom-ref"].as_str()));
        ids.extend(doc["metadata"]["component"]["bom-ref"].as_str());
    }
    if let Some(packages) = doc["packages"].as_array() {
        ids.extend(packages.iter().filter_map(|p| p["SPDXID"].as_str()));
    }
    assert!(!ids.is_empty(), "the document has ids to check");
    let mut seen = std::collections::HashSet::new();
    let duplicates: Vec<&&str> = ids.iter().filter(|id| !seen.insert(**id)).collect();
    assert!(duplicates.is_empty(), "duplicate ids: {duplicates:?}");
}

/// conda-forge's Python ships `lib/python3.1 -> python3.11`. A pip-installed package is listed
/// once, and the documents stay valid: every id unique, in CycloneDX and SPDX.
#[cfg(unix)]
#[test]
fn a_symlinked_python_directory_lists_each_package_once() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("env");
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prefix");
    for file in walkdir(&fixture) {
        let target = prefix.join(file.strip_prefix(&fixture).unwrap());
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(&file, &target).unwrap();
    }
    std::os::unix::fs::symlink("python3.12", prefix.join("lib/python3.1")).unwrap();
    for (format, validator) in [("cyclonedx", cyclonedx_validator()), ("spdx", spdx_validator())] {
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("sbom-cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .arg("--prefix")
            .arg(&prefix)
            .args(["-p", "linux-64", "--format", format, "--output", "-"])
            .assert()
            .success();
        let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
        assert_valid(&validator, &doc);
        assert_unique_ids(&doc);
        let names: Vec<&str> = doc[if format == "cyclonedx" {
            "components"
        } else {
            "packages"
        }]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
        assert_eq!(names.iter().filter(|n| **n == "six").count(), 1, "{format}: {names:?}");
    }
}

/// A channel's native conda package carries a CPE from the curated table in every format, and
/// every document stays valid against its schema. A package missing from the table has none.
#[test]
fn native_conda_packages_carry_a_cpe_in_every_format() {
    let work = tempfile::tempdir().unwrap();
    let lockfile = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/projects/pixi/01-django/pixi.lock");
    let run = |args: &[&str]| -> Value {
        let assert = pixi_sbom()
            .current_dir(work.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .arg("--lockfile")
            .arg(&lockfile)
            .args(["-p", "linux-64", "--output", "-"])
            .args(args)
            .assert()
            .success();
        serde_json::from_slice(&assert.get_output().stdout).unwrap()
    };
    let libtiff = "cpe:2.3:a:libtiff:libtiff:4.5.1:*:*:*:*:*:*:*";
    for (version, validator) in [("1.6", cyclonedx_validator()), ("1.7", cyclonedx_1_7_validator())] {
        let doc = run(&["--spec-version", version]);
        assert_valid(&validator, &doc);
        let cpe = |name: &str| {
            doc["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
                .map(|c| c["cpe"].clone())
                .unwrap()
        };
        assert_eq!(cpe("libtiff"), libtiff, "CycloneDX {version}");
        assert_eq!(
            cpe("tzdata"),
            Value::Null,
            "CycloneDX {version}: not in the table, no CPE"
        );
        assert_eq!(
            cpe("django"),
            Value::Null,
            "CycloneDX {version}: a PyPI identity, no CPE"
        );
    }
    let spdx = run(&["--format", "spdx"]);
    assert_valid(&spdx_validator(), &spdx);
    let refs: Vec<&Value> = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["name"] == "libtiff")
        .flat_map(|p| p["externalRefs"].as_array().unwrap())
        .filter(|r| r["referenceType"] == "cpe23Type")
        .collect();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0]["referenceCategory"], "SECURITY");
    assert_eq!(refs[0]["referenceLocator"], libtiff);
    let spdx3 = run(&["--format", "spdx", "--spec-version", "3.0"]);
    assert_valid(&spdx3_validator(), &spdx3);
    let text = spdx3.to_string();
    assert!(
        text.contains(&format!(r#""externalIdentifierType":"cpe23","identifier":"{libtiff}""#)),
        "SPDX 3: a cpe23 external identifier"
    );
}

/// The same installed environment at two paths gives the same document, apart from when it was
/// written and its serial number: nothing in it says where on the machine the environment, or
/// the package cache it was extracted from, lives.
#[test]
fn an_installed_environment_documents_the_same_wherever_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prefix");
    let describe = |at: &Path| -> Value {
        for file in walkdir(&fixture) {
            let target = at.join(file.strip_prefix(&fixture).unwrap());
            std::fs::create_dir_all(target.parent().unwrap()).unwrap();
            std::fs::copy(&file, &target).unwrap();
        }
        let assert = pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("sbom-cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .arg("--prefix")
            .arg(at)
            .args(["-p", "linux-64", "--output", "-"])
            .assert()
            .success();
        let mut doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
        let text = doc.to_string();
        assert!(
            !text.contains(&*at.to_string_lossy()),
            "the document names its path:\n{text}"
        );
        assert!(
            !text.contains("/opt/pkgs"),
            "the document names the package cache's path"
        );
        doc["metadata"]["timestamp"] = Value::Null;
        doc["serialNumber"] = Value::Null;
        doc
    };
    let first = describe(&dir.path().join("one/env"));
    let second = describe(&dir.path().join("another/place/env"));
    assert_eq!(first, second);
    let python = first["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "python")
        .unwrap();
    let extracted = python["properties"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "pixi:extracted-package-dir")
        .unwrap();
    assert_eq!(
        extracted["value"], "python-3.12.14-h5f976f7_3_cpython",
        "the cache entry's name"
    );
}

/// The pixi-sbom column of the lockfile table on docs/syft.md: each row's package and hash counts
/// are what pixi-sbom writes for that lockfile, offline, for linux-64.
#[test]
fn the_syft_page_counts_are_what_pixi_sbom_writes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let page = std::fs::read_to_string(root.join("docs/syft.md")).unwrap();
    let work = tempfile::tempdir().unwrap();
    let mut checked = 0;
    for line in page.lines().filter(|l| l.starts_with("| `examples/")) {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        let lockfile = cells[0].trim_matches('`');
        let (packages, hashed): (usize, usize) = (cells[2].parse().unwrap(), cells[3].parse().unwrap());
        let assert = pixi_sbom()
            .current_dir(work.path())
            .env("PIXI_SBOM_OFFLINE", "1")
            .env("PIXI_SBOM_CACHE_DIR", work.path().join("cache"))
            .arg("--lockfile")
            .arg(root.join(lockfile))
            .args(["-p", "linux-64", "--output", "-"])
            .assert()
            .success();
        let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
        let components = doc["components"].as_array().unwrap();
        assert_eq!(components.len(), packages, "{lockfile}: packages");
        assert_eq!(
            components.iter().filter(|c| c["hashes"].is_array()).count(),
            hashed,
            "{lockfile}: hashes"
        );
        checked += 1;
    }
    assert_eq!(checked, 3, "the table's rows were found");
}

/// `--verify-files` and `--report files` (#455): an altered file and a missing one are found,
/// recorded on the package and end the run with 11; an unaltered environment passes.
#[test]
fn verify_files_finds_altered_and_missing_files_and_exits_11() {
    use sha2::{Digest, Sha256};
    let hex = |bytes: &[u8]| -> String { Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect() };
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("env");
    copy_dir(&tests_dir().join("fixtures").join("prefix"), &prefix);
    std::fs::write(prefix.join("lib").join("libz.so.1"), b"zlib").unwrap();
    std::fs::write(prefix.join("lib").join("zlib.h"), b"header").unwrap();
    let record_path = prefix.join("conda-meta").join("libzlib-1.3.2-h25fd6f3_3.json");
    let mut record: Value = serde_json::from_str(&std::fs::read_to_string(&record_path).unwrap()).unwrap();
    record["paths_data"] = serde_json::json!({"paths": [
        {"_path": "lib/libz.so.1", "path_type": "hardlink", "sha256": hex(b"zlib")},
        {"_path": "lib/zlib.h", "path_type": "hardlink", "sha256": hex(b"header")},
    ]});
    std::fs::write(&record_path, record.to_string()).unwrap();
    let run = |args: &[&str]| {
        pixi_sbom()
            .arg("--prefix")
            .arg(&prefix)
            .args(["--primary-purl", "conda"])
            .args(args)
            .assert()
    };

    let clean = run(&["--report", "files"]).success();
    let out = String::from_utf8(clean.get_output().stdout.clone()).unwrap();
    assert!(
        out.contains("Files: 2 checked in 1 conda packages; 0 modified, 0 missing"),
        "{out}"
    );

    std::fs::write(prefix.join("lib").join("zlib.h"), b"tampered").unwrap();
    std::fs::remove_file(prefix.join("lib").join("libz.so.1")).unwrap();
    let report = run(&["--report", "files", "--report-format", "json"]).code(11);
    let json: Value = serde_json::from_slice(&report.get_output().stdout).unwrap();
    assert_eq!(json["summary"]["modified"], 1);
    assert_eq!(json["summary"]["missing"], 1);
    let states: Vec<(&str, &str)> = json["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["state"].as_str().unwrap(), r["path"].as_str().unwrap()))
        .collect();
    assert_eq!(states, [("modified", "lib/zlib.h"), ("missing", "lib/libz.so.1")]);

    let document = run(&["--verify-files", "--output", "-"])
        .code(11)
        .stderr(predicate::str::contains("modified: lib/zlib.h (libzlib)"))
        .stderr(predicate::str::contains("installed files"));
    let doc: Value = serde_json::from_slice(&document.get_output().stdout).unwrap();
    let zlib = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "libzlib")
        .unwrap();
    let property = |name: &str| {
        zlib["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == name)
            .map(|p| p["value"].as_str().unwrap().to_string())
    };
    assert_eq!(property("pixi:verified-files").as_deref(), Some("2"));
    assert_eq!(property("pixi:modified-files").as_deref(), Some("lib/zlib.h"));
    assert_eq!(property("pixi:missing-files").as_deref(), Some("lib/libz.so.1"));

    let workspace = workspace("conda-python");
    pixi_sbom()
        .args(["--report", "files"])
        .current_dir(workspace.path())
        .assert()
        .code(2)
        .stderr(predicate::str::contains("'--report files' needs '--prefix <DIR>'"));
}

/// `--format github` (#456): a dependency submission snapshot naming the run from the variables
/// Actions sets, with a conda package submitted by its PyPI identity; without them, a warning.
#[test]
fn format_github_writes_a_dependency_submission_snapshot() {
    let dir = workspace("conda-python");
    let assert = pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--pypi-mapping-file"])
        .arg(mapping_file())
        .args(["--primary-purl", "conda", "--format", "github", "--output", "-"])
        .env("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
        .env("GITHUB_REF", "refs/heads/main")
        .env("GITHUB_RUN_ID", "7")
        .assert()
        .success()
        .stderr(predicate::str::contains("GITHUB_SHA").not());
    let doc: Value = serde_json::from_slice(&assert.get_output().stdout).unwrap();
    assert_eq!(doc["sha"], "0123456789abcdef0123456789abcdef01234567");
    assert_eq!(doc["ref"], "refs/heads/main");
    assert_eq!(doc["job"]["id"], "7");
    assert_eq!(doc["detector"]["name"], "pixi-sbom");
    let manifest = doc["manifests"].as_object().unwrap().values().next().unwrap();
    assert_eq!(manifest["file"]["source_location"], "pixi.lock");
    let resolved = manifest["resolved"].as_object().unwrap();
    assert_eq!(resolved["pkg:pypi/numpy@2.3.1"]["package_url"], "pkg:pypi/numpy@2.3.1");
    assert!(resolved.keys().any(|k| k.starts_with("pkg:conda/python@")));

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--format", "github", "--output", "-"])
        .env_remove("GITHUB_SHA")
        .env_remove("GITHUB_REF")
        .assert()
        .success()
        .stderr(predicate::str::contains("GITHUB_SHA or GITHUB_REF is not set"));
    pixi_sbom()
        .current_dir(dir.path())
        .args([
            "-p",
            "linux-64",
            "--format",
            "github",
            "--spec-version",
            "1.6",
            "--output",
            "-",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("is not a version of '--format github'"));
    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--format", "github"])
        .env("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
        .env("GITHUB_REF", "refs/heads/main")
        .assert()
        .success();
    assert!(dir.path().join("sbom.github.json").is_file(), "the default file name");
}

/// `--help` draws each section as a rule set apart by blank lines (#482), and piped it has no colour.
#[test]
fn help_sections_are_rules_set_apart_by_blank_lines() {
    for flag in ["-h", "--help"] {
        let assert = pixi_sbom().arg(flag).assert().success();
        let help = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
        assert!(!help.contains('\u{1b}'), "{flag}: no colour when piped");
        for section in [
            "GENERAL",
            "INPUT",
            "ENVIRONMENT AND PLATFORM",
            "VULNERABILITIES",
            "DIAGNOSTICS",
        ] {
            assert!(
                help.contains(&format!("\n\n\n── {section} ─")),
                "{flag}: {section}\n{help}"
            );
        }
        assert!(!help.contains("\nOptions:") && !help.contains("\nInput:"), "{flag}");
        assert!(help.contains("Documentation: https://millsks.github.io/pixi-sbom/"));
    }
}

/// Run in the workspace with a relative `--prefix .pixi/envs/default`, as the docs show it, an
/// editable install inside the workspace is `./libs/...`, and the document names no machine path.
#[test]
fn a_relative_prefix_makes_a_local_direct_url_relative_to_the_workspace() {
    let dir = tempfile::tempdir().unwrap();
    // Canonical, so macOS's /var is /private/var as the run sees it; without Windows's `\\?\` prefix,
    // which no file URL pip writes carries.
    let canonical = dir.path().canonicalize().unwrap().display().to_string();
    let workspace = PathBuf::from(canonical.trim_start_matches(r"\\?\")).join("app");
    let env = workspace.join(".pixi").join("envs").join("default");
    copy_dir(&tests_dir().join("fixtures").join("venv-sources"), &env);
    let source = workspace.join("libs").join("myapp");
    let url = format!(
        "file:///{}",
        source.display().to_string().replace('\\', "/").trim_start_matches('/')
    );
    std::fs::write(
        env.join("lib/python3.12/site-packages/myapp-2.1.0.dist-info/direct_url.json"),
        serde_json::json!({"url": url, "dir_info": {"editable": true}}).to_string(),
    )
    .unwrap();
    let assert = pixi_sbom()
        .current_dir(&workspace)
        .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_OFFLINE", "1")
        .args(["--prefix", ".pixi/envs/default", "--output", "-"])
        .assert()
        .success();
    let text = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let workspace_text = workspace.display().to_string().replace('\\', "/");
    assert!(!text.contains(&workspace_text), "no machine path:\n{text}");
    let doc: Value = serde_json::from_str(&text).unwrap();
    let myapp = doc["components"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "myapp")
        .unwrap();
    let direct = myapp["properties"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "pixi:direct-url")
        .map(|p| p["value"].as_str().unwrap().to_string());
    assert_eq!(direct.as_deref(), Some("./libs/myapp"));
}

/// An installed R environment (#436): a CRAN package gets a `pkg:cran` purl beside its conda one,
/// named and versioned as its DESCRIPTION says; R itself does not; and `--vulnerabilities osv`
/// finds the CRAN advisory through it.
#[test]
fn r_packages_on_cran_get_a_cran_purl_that_osv_answers() {
    let dir = tempfile::tempdir().unwrap();
    let prefix = dir.path().join("env");
    std::fs::create_dir_all(prefix.join("conda-meta")).unwrap();
    let records = [
        (
            "r-commonmark",
            "1.8.0",
            "r43h0_0",
            "commonmark",
            "Package: commonmark\nVersion: 1.8.0\nRepository: CRAN\n",
        ),
        (
            "r-rcpp",
            "1.0.13_1",
            "r43h0_0",
            "Rcpp",
            "Package: Rcpp\nVersion: 1.0.13-1\nRepository: CRAN\n",
        ),
        (
            "r-base",
            "4.3.3",
            "h0_0",
            "stats",
            "Package: stats\nVersion: 4.3.3\nPriority: base\n",
        ),
    ];
    for (name, version, build, library, description) in records {
        let record = serde_json::json!({
            "name": name, "version": version, "build": build, "build_number": 0,
            "channel": "https://conda.anaconda.org/conda-forge", "subdir": "linux-64",
            "fn": format!("{name}-{version}-{build}.conda"),
            "files": [format!("lib/R/library/{library}/DESCRIPTION")],
        });
        std::fs::write(
            prefix.join("conda-meta").join(format!("{name}-{version}-{build}.json")),
            record.to_string(),
        )
        .unwrap();
        let lib = prefix.join("lib/R/library").join(library);
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(lib.join("DESCRIPTION"), description).unwrap();
    }
    let osv = tests_dir().join("fixtures").join("osv-cran");
    for sub in ["queries", "vulns"] {
        let target = dir.path().join("cache").join("osv").join(sub);
        std::fs::create_dir_all(&target).unwrap();
        for entry in std::fs::read_dir(osv.join(sub)).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
        }
    }
    let run = |args: &[&str]| {
        pixi_sbom()
            .current_dir(dir.path())
            .env("PIXI_CACHE_DIR", dir.path().join("empty-pkgs-cache"))
            .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
            .env("PIXI_SBOM_OFFLINE", "1")
            .arg("--prefix")
            .arg(&prefix)
            .args(["-p", "linux-64", "--primary-purl", "conda"])
            .args(args)
            .assert()
            .success()
    };
    let cdx: Value = serde_json::from_slice(&run(&["--output", "-"]).get_output().stdout).unwrap();
    assert_valid(&cyclonedx_validator(), &cdx);
    let purls = |name: &str| -> Vec<String> {
        let component = cdx["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        component["properties"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["name"] == "pixi:purl")
            .map(|p| p["value"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(purls("r-commonmark"), ["pkg:cran/commonmark@1.8.0"]);
    assert_eq!(
        purls("r-rcpp"),
        ["pkg:cran/Rcpp@1.0.13-1"],
        "CRAN's spelling and version"
    );
    assert!(purls("r-base").is_empty(), "R itself is not a CRAN package");

    let spdx: Value = serde_json::from_slice(&run(&["--format", "spdx", "--output", "-"]).get_output().stdout).unwrap();
    assert_valid(&spdx_validator(), &spdx);
    let rcpp = spdx["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "r-rcpp")
        .unwrap();
    assert!(
        rcpp["externalRefs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["referenceLocator"] == "pkg:cran/Rcpp@1.0.13-1")
    );

    let report = run(&[
        "--vulnerabilities",
        "osv",
        "--report",
        "vulnerabilities",
        "--report-format",
        "json",
    ]);
    let findings: Value = serde_json::from_slice(&report.get_output().stdout).unwrap();
    let ids: Vec<(&str, &str)> = findings["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| (f["id"].as_str().unwrap(), f["package"].as_str().unwrap()))
        .collect();
    assert_eq!(ids, [("RSEC-2023-8", "r-commonmark")]);
}
