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
        .stdout(predicate::str::contains("--platform"));
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
