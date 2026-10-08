//! `docs/stability.md` is a promise, so it is checked against the code rather than maintained by
//! hand and hoped over.
//!
//! Each test extracts a list from the page and compares it to what the binary, `action.yml` or the
//! config parser actually has. Both directions matter: a flag added without a line on the page
//! fails, and so does a line on the page for something that does not exist. Before 1.0 that second
//! direction is the one that rots — a page listing a flag nobody can type is worse than no page.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use assert_cmd::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

/// Read a repository file with line endings normalised. Git checks these out with CRLF on
/// Windows, and every scan below anchors on `\n` — `action.find("\ninputs:\n")` silently found
/// nothing there, so the test passed vacuously on Linux and failed on Windows.
fn read(relative: &str) -> String {
    std::fs::read_to_string(repo().join(relative))
        .unwrap_or_else(|err| panic!("{relative}: {err}"))
        .replace("\r\n", "\n")
}

fn page() -> String {
    read("docs/stability.md")
}

/// The section of the page under `heading`, up to the next heading of the same level or higher.
fn section(text: &str, heading: &str) -> String {
    let start = text.find(heading).unwrap_or_else(|| panic!("no section {heading:?}"));
    let level = heading.chars().take_while(|c| *c == '#').count();
    let rest = &text[start + heading.len()..];
    let end = rest
        .match_indices('\n')
        .filter(|(_, _)| true)
        .find_map(|(i, _)| {
            let line = rest[i + 1..].lines().next()?;
            let hashes = line.chars().take_while(|c| *c == '#').count();
            (hashes > 0 && hashes <= level).then_some(i)
        })
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// Every `` `token` `` in `text` that starts with `prefix`.
fn quoted(text: &str, prefix: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for piece in text.split('`').skip(1).step_by(2) {
        if piece.starts_with(prefix) {
            found.insert(piece.to_string());
        }
    }
    found
}

/// Compare a list the code defines against the list the page promises, both ways.
///
/// The direction people think of is "something new is undocumented". The direction that breaks a
/// contract is the other one: the page still promising something that has been removed. A reader
/// trusting this page would write it into their CI and find out from a failure.
fn assert_same(kind: &str, real: &BTreeSet<String>, listed: &BTreeSet<String>) {
    assert!(!real.is_empty(), "found no {kind} at all; the extraction is broken");
    let missing: Vec<&String> = real.difference(listed).collect();
    let extra: Vec<&String> = listed.difference(real).collect();
    assert!(
        missing.is_empty(),
        "these {kind} exist but docs/stability.md does not list them: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "docs/stability.md promises these {kind} but they no longer exist: {extra:?}"
    );
}

fn help() -> String {
    let output = Command::cargo_bin("pixi-sbom")
        .expect("binary builds")
        .arg("--help")
        .output()
        .expect("--help runs");
    String::from_utf8(output.stdout).expect("help is utf-8")
}

/// The flags clap actually defines: the ones that begin an entry in `--help`, which excludes
/// aliases (hidden) and mentions of a flag inside another flag's help text.
fn defined_flags() -> BTreeSet<String> {
    let mut flags = BTreeSet::new();
    for line in help().lines() {
        let trimmed = line.trim_start();
        if line.len() == trimmed.len() || !trimmed.starts_with('-') {
            continue;
        }
        // `-e, --environment <ENVIRONMENT>` or `--all-platforms`
        for token in trimmed.split_whitespace() {
            if let Some(name) = token.strip_prefix("--") {
                let name: String = name
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                    .collect();
                if !name.is_empty() {
                    flags.insert(format!("--{name}"));
                }
                break;
            }
        }
    }
    flags
}

#[test]
fn the_page_lists_every_flag_and_only_flags_that_exist() {
    // Up to the alias subsection: that subsection names the canonical flags too, so including it
    // would let a flag listed only there pass as documented.
    let whole = section(&page(), "## Command-line flags");
    let table = whole.split("###").next().unwrap();
    let listed = quoted(table, "--");
    let defined = defined_flags();

    assert_same("flags", &defined, &listed);
    assert_eq!(defined.len(), 69, "the count in the page's prose needs updating too");
}

#[test]
fn every_alias_the_page_promises_is_actually_accepted() {
    let aliases = quoted(&section(&page(), "### Spellings that answer to an older name"), "--");
    assert!(!aliases.is_empty(), "the alias table should not be empty");
    for alias in &aliases {
        // A flag clap does not know is a usage error naming it; anything else means it resolved.
        let output = Command::cargo_bin("pixi-sbom")
            .unwrap()
            .args([alias.as_str(), "--help"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument") && !stderr.contains("unrecognized"),
            "{alias} is promised on the stability page but not accepted: {stderr}"
        );
    }
}

#[test]
fn the_page_lists_every_action_input_and_output() {
    let action = read("action.yml");
    // `inputs:` and `outputs:` are top-level, and their keys are indented two spaces.
    let keys = |block: &str| -> BTreeSet<String> {
        let start = match action.find(block) {
            Some(i) => i + block.len(),
            None => return BTreeSet::new(),
        };
        let mut found = BTreeSet::new();
        for line in action[start..].lines() {
            if !line.starts_with("  ") && !line.trim().is_empty() {
                break; // next top-level key
            }
            if let Some(name) = line.strip_prefix("  ")
                && !name.starts_with(' ')
                && !name.starts_with('#')
                && let Some(name) = name.split(':').next()
            {
                let name = name.trim();
                if !name.is_empty() {
                    found.insert(name.to_string());
                }
            }
        }
        found
    };
    let section = section(&page(), "## The GitHub Action");
    for (block, label, bold) in [
        ("\ninputs:\n", "action inputs", "**Inputs:**"),
        ("\noutputs:\n", "action outputs", "**Outputs:**"),
    ] {
        let start = section.find(bold).unwrap_or_else(|| panic!("no {bold} paragraph"));
        let paragraph = section[start..].split("\n\n").next().unwrap();
        assert_same(label, &keys(block), &quoted(paragraph, ""));
    }
}

#[test]
fn the_page_lists_every_configuration_key_and_spells_them_as_the_parser_wants() {
    // Derived from the parser's own rejection message rather than from the struct's field names.
    // The struct is `rename_all = "kebab-case"`, so its Rust identifiers are snake_case while the
    // accepted TOML keys are kebab — and comparing the page against the field names let the page
    // document 29 keys in a casing the parser rejects, with the test agreeing because both sides
    // were wrong the same way. Asking the binary cannot go wrong that way.
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/conda-only/pixi.lock"),
        dir.path().join("pixi.lock"),
    )
    .unwrap();
    std::fs::write(dir.path().join("pixi-sbom.toml"), "definitely-not-a-key = true\n").unwrap();
    let output = Command::cargo_bin("pixi-sbom")
        .unwrap()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--output", "-"])
        .output()
        .unwrap();
    let complaint = String::from_utf8_lossy(&output.stderr);
    let expected = complaint
        .split("expected one of ")
        .nth(1)
        .unwrap_or_else(|| panic!("no key list in: {complaint}"));
    let real: BTreeSet<String> = expected
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .filter(|key| key.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        .collect();

    // The section's prose backticks filenames and the `--flag` a key is named after, neither of
    // which is a key.
    let listed: BTreeSet<String> = quoted(&section(&page(), "## Configuration keys"), "")
        .into_iter()
        .filter(|token| !token.contains('.') && !token.contains('[') && !token.starts_with('-'))
        .collect();
    assert_same("config keys", &real, &listed);

    // And every key the page lists is actually accepted, not merely spelled the way the parser
    // lists it. One file with all of them: `deny_unknown_fields` rejects the first bad one.
    let all: String = listed
        .iter()
        .map(|key| match key.as_str() {
            // A value of the right shape for each; the point is the key, not the value.
            "exclude" | "include" | "exclude-kind" | "allow-license" | "deny-license" | "ignore-vuln"
            | "ignore-license" | "fail-on-diff" | "source" | "assume-used" => format!("{key} = []\n"),
            "scorecard-min" | "fail-on-scorecard" => format!("{key} = 5.0\n"),
            "format" | "spec-version" | "pypi-mapping" | "pypi-mapping-file" | "primary-purl" | "vulnerabilities"
            | "fail-on-severity" => format!("{key} = \"\"\n"),
            _ => format!("{key} = false\n"),
        })
        .collect();
    std::fs::write(dir.path().join("pixi-sbom.toml"), &all).unwrap();
    let output = Command::cargo_bin("pixi-sbom")
        .unwrap()
        .current_dir(dir.path())
        .args(["-p", "linux-64", "--output", "-"])
        .output()
        .unwrap();
    let complaint = String::from_utf8_lossy(&output.stderr);
    assert!(
        !complaint.contains("unknown field"),
        "a key the page promises is not accepted:\n{complaint}\n\nconfig was:\n{all}"
    );
}

#[test]
fn the_page_lists_every_exit_code_the_code_defines() {
    // Every `const *_EXIT_CODE` in the sources, plus the ones clap and success own.
    let mut defined: BTreeSet<i32> = BTreeSet::from([0, 2]);
    for file in ["src/main.rs", "src/policy.rs", "src/vulnpolicy.rs", "src/diff.rs"] {
        let text = read(file);
        for line in text.lines() {
            if line.contains("EXIT_CODE: i32 = ")
                && let Some(value) = line.split('=').nth(1)
                && let Ok(code) = value.trim().trim_end_matches(';').parse::<i32>()
            {
                defined.insert(code);
            }
        }
    }
    assert_eq!(
        defined,
        BTreeSet::from([0, 1, 2, 3, 4, 6, 7, 8, 9]),
        "the set of exit codes changed; docs/stability.md and this test both need a decision"
    );

    let section = section(&page(), "## Exit codes");
    for code in &defined {
        assert!(
            section.contains(&format!("| {code} |")),
            "exit code {code} is not in the page's table"
        );
    }
    // The hole is deliberate, and the page has to keep saying so.
    assert!(!section.contains("| 5 |"), "5 has never been assigned");
    assert!(
        section.contains("**5 is deliberately unused.**"),
        "the page must explain the gap rather than leave a reader guessing"
    );
}

#[test]
fn the_page_lists_every_pixi_property_the_code_emits() {
    let mut emitted = BTreeSet::new();
    for entry in walk(&repo().join("src")) {
        let text = std::fs::read_to_string(&entry)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        let mut rest = text.as_str();
        while let Some(i) = rest.find("\"pixi:") {
            rest = &rest[i + 1..];
            if let Some(end) = rest.find('"') {
                let name = &rest[..end];
                let is_name = name.len() > "pixi:".len()
                    && name["pixi:".len()..]
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
                if is_name {
                    emitted.insert(name.to_string());
                }
            }
        }
    }
    assert!(emitted.len() > 40, "expected the whole property surface");

    // The scorecard checks are a documented family, not individual names, on both sides.
    let family = |set: BTreeSet<String>| -> BTreeSet<String> {
        set.into_iter()
            .filter(|name| !name.starts_with("pixi:scorecard-check-"))
            .collect()
    };
    let listed = family(quoted(&section(&page(), "## `pixi:*` names in a document"), "pixi:"));
    assert_same("pixi:* names", &family(emitted), &listed);
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            found.push(path);
        }
    }
    found
}

#[test]
fn the_page_lists_every_environment_variable_the_code_reads() {
    let mut read = BTreeSet::new();
    for entry in walk(&repo().join("src")) {
        let text = std::fs::read_to_string(&entry)
            .unwrap_or_default()
            .replace("\r\n", "\n");
        let mut rest = text.as_str();
        while let Some(i) = rest.find("\"PIXI_SBOM_") {
            rest = &rest[i + 1..];
            if let Some(end) = rest.find('"') {
                let name = &rest[..end];
                if name
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                {
                    read.insert(name.to_string());
                }
            }
        }
    }
    // Test-only plumbing is not part of the surface and is not promised.
    read.retain(|name| !name.starts_with("PIXI_SBOM_TEST_"));
    assert!(read.len() > 8, "expected the whole environment surface");

    let listed = quoted(&section(&page(), "## Environment variables"), "PIXI_SBOM_");
    assert_same("environment variables", &read, &listed);
}

/// The help output itself, snapshotted. The list tests above catch a flag appearing or vanishing;
/// this catches the quieter changes they cannot see — a value name, a possible value, a default, a
/// short flag. Those are part of the contract too: `--format cyclonedx` has to keep being spelled
/// that way, not just `--format` keep existing.
///
/// A diff here is not automatically a bug. Reworded help text is free to change (the page says so),
/// so accept the new snapshot for wording. A changed value name, possible value, default or short
/// flag is a contract change and needs a major version.
#[test]
fn the_help_surface_is_pinned() {
    let help = help();
    // Only the lines that define the surface, so rewording a description does not churn the
    // snapshot: flag entries, and the value/default lines under them.
    let surface: Vec<&str> = help
        .lines()
        .map(str::trim_end)
        .filter(|line| {
            let t = line.trim_start();
            (line.len() != t.len() && t.starts_with('-'))
                || t.starts_with("[default:")
                || t.starts_with("[possible values:")
                || t.starts_with("- ")
        })
        .collect();
    insta::assert_snapshot!(surface.join("\n"));
}
