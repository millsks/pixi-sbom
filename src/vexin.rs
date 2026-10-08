//! `--vex-in`: somebody else's VEX applied to the findings before the gate runs. A vendor that
//! ships an SBOM often ships a VEX saying which of its findings do not affect the product; this
//! reads it (CycloneDX, standalone or as `vulnerabilities[].analysis` inside an SBOM, or OpenVEX)
//! and marks the findings it covers, the way `--ignore-vuln` does.
//!
//! A statement matches a finding by vulnerability id or alias, and by the purl of the package it
//! names (a statement naming no product covers every package). `not_affected`, `false_positive`
//! and `resolved` clear the finding from the gate; `exploitable` and `in_triage` are recorded and
//! never clear it. A later file wins over an earlier one, and `--ignore-vuln` wins over both.

use std::collections::HashMap;
use std::path::Path;

use serde_json::Value;

use crate::model::{Analysis, Sbom, Vulnerability};
use crate::vulnpolicy::{JUSTIFICATIONS, RESPONSES, STATES};

/// Why a `--vex-in` file could not be read.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum VexInError {
    #[error("cannot read the VEX {path}: {source}")]
    #[diagnostic(code(pixi_sbom::vex_in::read), help("check the path given to --vex-in"))]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse the VEX {path}: {source}")]
    #[diagnostic(
        code(pixi_sbom::vex_in::parse),
        help(
            "--vex-in reads JSON: a CycloneDX document (a VEX or an SBOM with vulnerabilities) or an OpenVEX document"
        )
    )]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("{path} is neither a CycloneDX document nor OpenVEX")]
    #[diagnostic(
        code(pixi_sbom::vex_in::format),
        help(
            "a CycloneDX VEX has \"bomFormat\": \"CycloneDX\" and a `vulnerabilities` array; an OpenVEX document has an \
             openvex.dev `@context` and a `statements` array. SPDX and CSAF VEX are not read"
        )
    )]
    Format { path: String },
}

/// One statement: which vulnerability, for which packages, and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The vulnerability id and its aliases, as the statement gives them.
    pub ids: Vec<String>,
    /// The purls (or references) of the packages it covers; empty means every package.
    pub products: Vec<String>,
    /// The analysis it gives, with `source` set to the file.
    pub analysis: Analysis,
}

impl Statement {
    /// `CVE-2021-33503 for pkg:pypi/urllib3@1.26.4 (vendor.vex.json)`, for the log.
    pub fn describe(&self) -> String {
        let id = self.ids.first().map(String::as_str).unwrap_or("?");
        let source = self.analysis.source.as_deref().unwrap_or("?");
        if self.products.is_empty() {
            format!("{id} ({source})")
        } else {
            format!("{id} for {} ({source})", self.products.join(", "))
        }
    }

    fn names(&self, vuln: &Vulnerability) -> bool {
        std::iter::once(&vuln.id)
            .chain(&vuln.aliases)
            .any(|name| self.ids.iter().any(|id| id.eq_ignore_ascii_case(name)))
    }

    fn covers(&self, purl: &str) -> bool {
        self.products.is_empty() || self.products.iter().any(|product| same_package(product, purl))
    }
}

/// Read every statement in `path`.
pub fn load(path: &Path) -> Result<Vec<Statement>, VexInError> {
    let display = path.display().to_string();
    let text = std::fs::read_to_string(path).map_err(|source| VexInError::Read {
        path: display.clone(),
        source,
    })?;
    let document: Value = serde_json::from_str(&text).map_err(|source| VexInError::Parse {
        path: display.clone(),
        source,
    })?;
    // The file name, not the whole path: it is what a reader of the report recognises.
    let source = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or(display.clone());
    if document["bomFormat"] == "CycloneDX" {
        Ok(cyclonedx(&document, &source))
    } else if document["statements"].is_array() {
        Ok(openvex(&document, &source))
    } else {
        Err(VexInError::Format { path: display })
    }
}

fn known(list: &[&'static str], word: &str) -> Option<&'static str> {
    list.iter().find(|w| **w == word).copied()
}

fn text(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// CycloneDX: every vulnerability with an `analysis`, its `affects[].ref` resolved through the
/// document's components when it is an SBOM, or read as a BOM-Link's fragment otherwise.
fn cyclonedx(document: &Value, source: &str) -> Vec<Statement> {
    let mut purls: HashMap<&str, &str> = HashMap::new();
    let mut stack: Vec<&Value> = document["components"].as_array().into_iter().flatten().collect();
    stack.extend(
        document["metadata"]["component"]
            .as_object()
            .map(|_| &document["metadata"]["component"]),
    );
    while let Some(component) = stack.pop() {
        if let (Some(reference), Some(purl)) = (component["bom-ref"].as_str(), component["purl"].as_str()) {
            purls.insert(reference, purl);
        }
        stack.extend(component["components"].as_array().into_iter().flatten());
    }
    let mut statements = Vec::new();
    for vuln in document["vulnerabilities"].as_array().into_iter().flatten() {
        let analysis = &vuln["analysis"];
        let Some(id) = text(&vuln["id"]) else { continue };
        let Some(state) = analysis["state"].as_str() else {
            continue;
        };
        let Some(state) = known(&STATES, state) else {
            tracing::warn!(
                id,
                state,
                source,
                "skipping a VEX statement with an unknown analysis state"
            );
            continue;
        };
        let mut ids = vec![id];
        ids.extend(
            vuln["references"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| text(&r["id"])),
        );
        let products = vuln["affects"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a["ref"].as_str())
            .map(|reference| {
                let local = reference.rsplit_once('#').map_or(reference, |(_, fragment)| fragment);
                purls
                    .get(reference)
                    .or_else(|| purls.get(local))
                    .copied()
                    .unwrap_or(local)
                    .to_string()
            })
            .collect();
        statements.push(Statement {
            ids,
            products,
            analysis: Analysis {
                state,
                justification: analysis["justification"]
                    .as_str()
                    .and_then(|j| known(&JUSTIFICATIONS, j))
                    .filter(|_| state == "not_affected"),
                response: analysis["response"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r.as_str().and_then(|r| known(&RESPONSES, r)))
                    .collect(),
                detail: text(&analysis["detail"]),
                source: Some(source.to_string()),
            },
        });
    }
    statements
}

/// OpenVEX: each statement's status and justification mapped onto the CycloneDX vocabulary
/// the rest of the program speaks; a product's subcomponents, when it lists any, are the
/// packages the statement is about.
fn openvex(document: &Value, source: &str) -> Vec<Statement> {
    let mut statements = Vec::new();
    for statement in document["statements"].as_array().into_iter().flatten() {
        let vulnerability = &statement["vulnerability"];
        // OpenVEX 0.0.x gave the vulnerability as a bare string.
        let Some(id) = text(vulnerability).or_else(|| text(&vulnerability["name"])) else {
            continue;
        };
        let mut ids = vec![id];
        ids.extend(
            vulnerability["aliases"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(text),
        );
        let status = statement["status"].as_str().unwrap_or_default();
        let Some(state) = (match status {
            "not_affected" => Some("not_affected"),
            "fixed" => Some("resolved"),
            "affected" => Some("exploitable"),
            "under_investigation" => Some("in_triage"),
            _ => None,
        }) else {
            tracing::warn!(
                id = ids[0],
                status,
                source,
                "skipping an OpenVEX statement with an unknown status"
            );
            continue;
        };
        let justification = match statement["justification"].as_str().unwrap_or_default() {
            "component_not_present" | "vulnerable_code_not_present" => Some("code_not_present"),
            "vulnerable_code_not_in_execute_path" => Some("code_not_reachable"),
            "vulnerable_code_cannot_be_controlled_by_adversary" => Some("protected_at_runtime"),
            "inline_mitigations_already_exist" => Some("protected_by_mitigating_control"),
            _ => None,
        }
        .filter(|_| state == "not_affected");
        let identity = |product: &Value| {
            text(&product["identifiers"]["purl"])
                .or_else(|| text(&product["@id"]))
                .or_else(|| text(product))
        };
        let mut products = Vec::new();
        for product in statement["products"].as_array().into_iter().flatten() {
            let subcomponents: Vec<String> = product["subcomponents"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(identity)
                .collect();
            if subcomponents.is_empty() {
                products.extend(identity(product));
            } else {
                products.extend(subcomponents);
            }
        }
        let detail = ["impact_statement", "status_notes", "action_statement"]
            .iter()
            .find_map(|field| text(&statement[*field]));
        statements.push(Statement {
            ids,
            products,
            analysis: Analysis {
                state,
                justification,
                response: Vec::new(),
                detail,
                source: Some(source.to_string()),
            },
        });
    }
    statements
}

/// `pkg:type/namespace/name` (lower-cased, a PyPI name normalised) and the version, from a purl;
/// `None` for something that is not one.
fn package_key(purl: &str) -> Option<(String, Option<String>)> {
    let rest = purl.strip_prefix("pkg:")?;
    let rest = rest.split(['?', '#']).next()?;
    let (path, version) = match rest.rsplit_once('@') {
        Some((path, version)) => (path, Some(version.to_string())),
        None => (rest, None),
    };
    let (kind, name) = path.split_once('/')?;
    let kind = kind.to_ascii_lowercase();
    let name = if kind == "pypi" {
        crate::purl::normalize_pypi_name(name)
    } else {
        name.to_ascii_lowercase()
    };
    Some((format!("pkg:{kind}/{name}"), version))
}

/// Whether a statement's product names the package with purl (or id) `purl`: the same package,
/// and the same version when the product gives one.
fn same_package(product: &str, purl: &str) -> bool {
    match (package_key(product), package_key(purl)) {
        (Some((product, version)), Some((package, package_version))) => {
            product == package && version.is_none_or(|v| package_version.is_some_and(|p| p == v))
        }
        _ => product == purl,
    }
}

/// Apply `statements` to the findings in `sbom`: a statement applies to a finding it names when
/// it covers every package the finding affects. Returns, per statement, whether it applied to
/// anything here; one that named a finding but covered only some of its packages is logged.
pub fn apply(sbom: &mut Sbom, statements: &[Statement]) -> Vec<bool> {
    let mut applied = vec![false; statements.len()];
    for vuln in &mut sbom.vulnerabilities {
        for (i, statement) in statements.iter().enumerate() {
            if !statement.names(vuln) {
                continue;
            }
            let covered = vuln.affects.iter().filter(|a| statement.covers(&a.purl)).count();
            if covered == 0 {
                continue;
            }
            if covered < vuln.affects.len() {
                tracing::warn!(
                    id = %vuln.id,
                    statement = statement.describe(),
                    covered,
                    affected = vuln.affects.len(),
                    "a VEX statement covers only some of the packages a finding affects; the finding is left as it was"
                );
                continue;
            }
            // Later statements (and later files) win.
            vuln.analysis = Some(statement.analysis.clone());
            applied[i] = true;
        }
    }
    applied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use crate::model::{Affected, Severity};

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/vex-in")
            .join(name)
    }

    fn finding(id: &str, aliases: &[&str], purls: &[&str]) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            source: "OSV".into(),
            url: String::new(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            summary: None,
            details: None,
            severity: Severity::High,
            ratings: vec![],
            cwes: vec![],
            references: vec![],
            published: None,
            modified: None,
            affects: purls
                .iter()
                .map(|p| Affected {
                    package_id: p.to_string(),
                    purl: p.to_string(),
                    fixed_version: None,
                })
                .collect(),
            analysis: None,
            kev: None,
            epss: None,
        }
    }

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        let bad_json = serde_json::from_str::<Value>("{").expect_err("truncated JSON");
        for err in [
            VexInError::Read {
                path: "vendor.vex.json".into(),
                source: std::io::Error::from(std::io::ErrorKind::NotFound),
            },
            VexInError::Parse {
                path: "vendor.vex.json".into(),
                source: bad_json,
            },
            VexInError::Format {
                path: "vendor.vex.json".into(),
            },
        ] {
            crate::assert_actionable(&err);
        }
    }

    #[test]
    fn openvex_statements_map_onto_cyclonedx_states() {
        let statements = load(&fixture("vendor.openvex.json")).unwrap();
        assert_eq!(statements.len(), 3);
        let first = &statements[0];
        assert_eq!(first.ids, ["CVE-2021-33503", "GHSA-q2q7-5pp4-w6pg"]);
        assert_eq!(
            first.products,
            ["pkg:pypi/urllib3@1.26.4"],
            "the subcomponent, not the product"
        );
        assert_eq!(first.analysis.state, "not_affected");
        assert_eq!(first.analysis.justification, Some("code_not_reachable"));
        assert_eq!(first.analysis.source.as_deref(), Some("vendor.openvex.json"));
        assert!(first.analysis.detail.as_deref().unwrap().contains("never parses"));
        assert_eq!(statements[1].analysis.state, "in_triage");
        assert_eq!(statements[1].products, ["pkg:pypi/requests"]);
        assert_eq!(statements[2].analysis.state, "resolved");
        assert_eq!(statements[2].analysis.justification, None);
    }

    #[test]
    fn cyclonedx_statements_resolve_their_references() {
        let statements = load(&fixture("vendor.cdx.json")).unwrap();
        assert_eq!(
            statements.len(),
            2,
            "the vulnerability without an analysis is not a statement"
        );
        assert_eq!(statements[0].ids, ["GHSA-q2q7-5pp4-w6pg", "CVE-2021-33503"]);
        assert_eq!(
            statements[0].products,
            ["pkg:pypi/urllib3@1.26.4"],
            "through the component"
        );
        assert_eq!(statements[0].analysis.state, "not_affected");
        assert_eq!(statements[0].analysis.justification, Some("requires_configuration"));
        assert_eq!(statements[0].analysis.response, ["will_not_fix"]);
        // A BOM-Link into another document: its fragment.
        assert_eq!(statements[1].products, ["pkg:pypi/idna@3.7"]);
        assert_eq!(statements[1].analysis.state, "exploitable");
    }

    #[test]
    fn unreadable_and_foreign_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            load(&dir.path().join("missing.json")),
            Err(VexInError::Read { .. })
        ));
        let path = dir.path().join("x.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(matches!(load(&path), Err(VexInError::Parse { .. })));
        std::fs::write(&path, r#"{"spdxVersion":"SPDX-2.3"}"#).unwrap();
        assert!(matches!(load(&path), Err(VexInError::Format { .. })));
        // Unknown states and statuses are skipped, not guessed at.
        std::fs::write(
            &path,
            r#"{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"fine"}}]}"#,
        )
        .unwrap();
        assert!(load(&path).unwrap().is_empty());
        std::fs::write(
            &path,
            r#"{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":"CVE-1","status":"maybe"}]}"#,
        )
        .unwrap();
        assert!(load(&path).unwrap().is_empty());
    }

    #[test]
    fn purls_match_by_package_and_by_version_when_given() {
        assert!(same_package("pkg:pypi/urllib3@1.26.4", "pkg:pypi/urllib3@1.26.4"));
        assert!(same_package("pkg:pypi/urllib3", "pkg:pypi/urllib3@2.0.0"));
        assert!(same_package(
            "pkg:pypi/Typing_Extensions@4.0",
            "pkg:pypi/typing-extensions@4.0?x=y"
        ));
        assert!(!same_package("pkg:pypi/urllib3@1.26.5", "pkg:pypi/urllib3@1.26.4"));
        assert!(!same_package("pkg:pypi/urllib3", "pkg:conda/urllib3@1.26.4"));
        assert!(same_package("my-ref", "my-ref"));
        assert!(!same_package("pkg:pypi/urllib3@1", "my-ref"));
    }

    #[test]
    fn statements_apply_when_they_cover_every_affected_package() {
        let statements = load(&fixture("vendor.openvex.json")).unwrap();
        let mut sbom = sample_sbom();
        sbom.vulnerabilities = vec![
            finding("GHSA-q2q7-5pp4-w6pg", &["CVE-2021-33503"], &["pkg:pypi/urllib3@1.26.4"]),
            finding(
                "GHSA-j8r2-6x86-q33q",
                &["CVE-2023-32681"],
                &["pkg:pypi/requests@2.31.0"],
            ),
            finding(
                "GHSA-split",
                &["CVE-2099-0002"],
                &["pkg:pypi/six@1.17.0", "pkg:pypi/idna@3.7"],
            ),
        ];
        let applied = apply(&mut sbom, &statements);
        assert_eq!(
            applied,
            [true, true, false],
            "the third covers only six of the split finding"
        );
        assert!(!sbom.vulnerabilities[0].is_open(), "not_affected clears it");
        assert!(sbom.vulnerabilities[1].is_open(), "in_triage is recorded, not cleared");
        assert_eq!(sbom.vulnerabilities[1].analysis.as_ref().unwrap().state, "in_triage");
        assert!(sbom.vulnerabilities[2].analysis.is_none());
        assert!(
            statements[0]
                .describe()
                .contains("for pkg:pypi/urllib3@1.26.4 (vendor.openvex.json)")
        );

        // A statement for another version of the package does not apply.
        let mut other = sample_sbom();
        other.vulnerabilities = vec![finding(
            "GHSA-q2q7-5pp4-w6pg",
            &["CVE-2021-33503"],
            &["pkg:pypi/urllib3@1.26.5"],
        )];
        assert_eq!(apply(&mut other, &statements[..1]), [false]);
    }
}
