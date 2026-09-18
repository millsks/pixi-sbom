//! End-to-end tests that drive the `pixi-sbom` binary.

use assert_cmd::Command;
use predicates::prelude::*;

fn pixi_sbom() -> Command {
    Command::cargo_bin("pixi-sbom").expect("binary builds")
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
fn lockfile_is_discovered_from_nested_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("pixi.lock"), "version: 6\n").unwrap();
    let nested = dir.path().join("src").join("deep");
    std::fs::create_dir_all(&nested).unwrap();

    pixi_sbom()
        .current_dir(&nested)
        .arg("-v")
        .assert()
        .success()
        .stderr(predicate::str::contains("sbom.cdx.json"));
}

#[test]
fn spdx_format_picks_spdx_default_output() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("pixi.lock"), "version: 6\n").unwrap();

    pixi_sbom()
        .current_dir(dir.path())
        .args(["--format", "spdx", "-v"])
        .assert()
        .success()
        .stderr(predicate::str::contains("sbom.spdx.json"));
}
