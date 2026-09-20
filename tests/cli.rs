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
        .stdout(predicate::str::contains("--all-platforms"));
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
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
        .args(["-e", "web", "-p", "linux-64", "--pypi-licenses", "--output", "-"])
        .assert()
        .success()
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
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
        .args([
            "-e",
            "web",
            "-p",
            "linux-64",
            "--format",
            "spdx",
            "--pypi-licenses",
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
fn pypi_licenses_never_fail_the_run_when_the_index_is_unreachable() {
    let dir = workspace("with-pypi");

    let assert = pixi_sbom()
        .current_dir(dir.path())
        .env("PIXI_SBOM_CACHE_DIR", dir.path().join("cache"))
        .env("PIXI_SBOM_PYPI_URL", "http://127.0.0.1:9/pypi")
        .args(["-e", "web", "-p", "linux-64", "--pypi-licenses", "--output", "-"])
        .assert()
        .success()
        .stderr(predicate::str::contains("PyPI index unreachable"))
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
fn spec_version_conflicts_with_spdx() {
    let dir = workspace("conda-only");

    pixi_sbom()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--format", "spdx", "--spec-version", "1.7"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with '--format spdx'"));
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
        "environment,platform,name,version,kind,license,spdx,license_family,license_source,license_files,purl"
    );
    assert!(
        csv.contains("default,linux-64,zlib,1.3.2,conda,Zlib,true,Other,lockfile,license.txt,pkg:conda/zlib@1.3.2")
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
    let lock = std::fs::read_to_string(dir.path().join("pixi.lock")).unwrap();
    let url = format!("file://{}", archive.display());
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
