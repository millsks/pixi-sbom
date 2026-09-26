//! End-to-end tests that drive the `pixi-sbom` binary and validate what it writes
//! against the official CycloneDX 1.6 and SPDX 2.3 JSON schemas.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use jsonschema::{Registry, Validator};
use predicates::prelude::*;
use serde_json::Value;

fn pixi_sbom() -> Command {
    Command::cargo_bin("pixi-sbom").expect("binary builds")
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
    assert!(text.contains("socks-proxy: no"), "{text}");
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
        .stderr(predicate::str::contains("no pixi.lock found"))
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
    assert!(scan.contains("every pixi.lock under this directory"), "{scan}");
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

    // With no network flag there is nothing to probe, and it says what to add.
    let text = String::from_utf8(run(&[], &[]).assert().success().get_output().stdout.clone()).unwrap();
    assert!(text.contains("No upstream is in play"), "{text}");

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
    // Offline, nothing was spent waiting, and the line says so rather than leaving it out.
    assert!(table.contains("of which 0.00 s waiting on the network"), "{table}");

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

    // SPDX has no place for them: the document is written and a warning says so.
    run(&["--format", "spdx"])
        .success()
        .stderr(predicate::str::contains("SPDX documents do not record vulnerabilities"));
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
        "GHSA-2xpw-w6gg-jr37:not_affected:streaming API unused",
        "--ignore-vuln",
        "GHSA-38jv-5279-wg99",
        "--ignore-vuln",
        "CVE-2025-66418",
        "--ignore-vuln",
        "GHSA-q2q7-5pp4-w6pg:false_positive:wrong package",
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
    // The file decides the format and the filter; the policy it enables trips (exit 3).
    let assert = run(&[])
        .code(3)
        .stderr(predicate::str::contains("applied the configuration file"))
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
    let assert = run(&["--format", "spdx", "--name", "My App", "--root-version", "1.2.3"]);
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
        .stderr(predicate::str::contains("not a conda environment"));
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
            .args(["-e", "web", "-p", "linux-64", "--report", "outdated"])
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

    // --outdated-only filters by step, and only applies to this report.
    let json: Value = serde_json::from_slice(
        &run(&["--report-format", "json", "--outdated-only", "major"])
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
        .args(["--report", "packages", "--outdated-only", "major"])
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
    let six_deps: Vec<_> = deps.iter().find(|d| d["ref"] == "pkg:pypi/six@1.17.0").unwrap()["dependsOn"]
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
