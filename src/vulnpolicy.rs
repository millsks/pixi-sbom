//! The vulnerability gate: `--fail-on-severity` fails the run after writing the document when
//! any finding at or above a severity remains, and `--ignore-vuln` accepts findings deliberately
//! (they stay in the document with a VEX-style analysis block and are excluded from the gate).

use crate::model::{Analysis, Sbom, Severity, Vulnerability};

/// Exit code when the gate trips. Distinct from the license policy's 3.
pub const GATE_EXIT_CODE: i32 = 4;

/// Analysis state recorded when `--ignore-vuln` gives none.
pub const DEFAULT_STATE: &str = "not_affected";

/// The CycloneDX impact-analysis states `--ignore-vuln` accepts.
const STATES: [&str; 6] = [
    "resolved",
    "resolved_with_pedigree",
    "exploitable",
    "in_triage",
    "false_positive",
    "not_affected",
];

/// One `--ignore-vuln` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignore {
    /// The advisory id or alias to ignore (`GHSA-...`, `CVE-...`).
    pub id: String,
    /// Analysis state, one of the CycloneDX states.
    pub state: &'static str,
    /// Free-text justification, when given.
    pub detail: Option<String>,
}

impl Ignore {
    /// Parse `ID`, `ID:detail` or `ID:state:detail`; the second segment is a state only when it
    /// names one, otherwise it is the detail.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (id, rest) = match text.split_once(':') {
            Some((id, rest)) => (id.trim(), Some(rest.trim())),
            None => (text, None),
        };
        if id.is_empty() {
            return Err(format!("'{text}' has no vulnerability id"));
        }
        let (state, detail) = match rest {
            None | Some("") => (DEFAULT_STATE, None),
            Some(rest) => match rest.split_once(':') {
                Some((state, detail)) if STATES.contains(&state.trim()) => {
                    let state = STATES
                        .iter()
                        .find(|s| **s == state.trim())
                        .copied()
                        .unwrap_or(DEFAULT_STATE);
                    (state, Some(detail.trim()).filter(|d| !d.is_empty()).map(str::to_string))
                }
                _ => match STATES.iter().find(|s| **s == rest) {
                    Some(state) => (*state, None),
                    None => (DEFAULT_STATE, Some(rest.to_string())),
                },
            },
        };
        Ok(Self {
            id: id.to_string(),
            state,
            detail,
        })
    }

    /// Whether this entry names `vuln` by id or alias (case-insensitively).
    fn matches(&self, vuln: &Vulnerability) -> bool {
        std::iter::once(&vuln.id)
            .chain(&vuln.aliases)
            .any(|name| name.eq_ignore_ascii_case(&self.id))
    }
}

/// A finding that trips the gate.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub id: String,
    pub severity: Severity,
    /// Whether it is in CISA's KEV catalog.
    pub known_exploited: bool,
    /// `name version` of each affected package.
    pub packages: Vec<String>,
}

impl std::fmt::Display for Hit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}{}): {}",
            self.id,
            self.severity.name(),
            if self.known_exploited { ", known exploited" } else { "" },
            self.packages.join(", ")
        )
    }
}

/// Mark every finding an `--ignore-vuln` entry names with its analysis; entries that match
/// nothing are logged so a typo does not pass silently. Returns how many findings were marked.
pub fn apply_ignores(sbom: &mut Sbom, ignores: &[Ignore]) -> usize {
    let mut marked = 0;
    for ignore in ignores {
        let mut any = false;
        for vuln in sbom.vulnerabilities.iter_mut().filter(|v| ignore.matches(v)) {
            vuln.analysis = Some(Analysis {
                state: ignore.state,
                detail: ignore.detail.clone(),
            });
            marked += 1;
            any = true;
        }
        if !any {
            tracing::debug!(id = %ignore.id, "--ignore-vuln names no finding in this document");
        }
    }
    marked
}

/// The open findings that trip the gate: at or above `threshold` when one is given, or known
/// exploited when `kev` is set. Worst first.
pub fn check(sbom: &Sbom, threshold: Option<Severity>, kev: bool) -> Vec<Hit> {
    sbom.vulnerabilities
        .iter()
        .filter(|v| v.analysis.is_none())
        .filter(|v| threshold.is_some_and(|t| v.severity >= t) || (kev && v.kev.is_some()))
        .map(|v| Hit {
            id: v.id.clone(),
            severity: v.severity,
            known_exploited: v.kev.is_some(),
            packages: v
                .affects
                .iter()
                .map(|a| {
                    let package = sbom.packages.iter().find(|p| p.id == a.package_id);
                    match package {
                        Some(p) => format!("{} {}", p.name, p.version.as_deref().unwrap_or("-")),
                        None => a.package_id.clone(),
                    }
                })
                .collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use crate::model::{Affected, Vulnerability};

    fn finding(id: &str, aliases: &[&str], severity: Severity) -> Vulnerability {
        Vulnerability {
            id: id.into(),
            source: "OSV".into(),
            url: format!("https://osv.dev/vulnerability/{id}"),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
            summary: None,
            details: None,
            severity,
            ratings: vec![],
            cwes: vec![],
            references: vec![],
            published: None,
            modified: None,
            affects: vec![Affected {
                package_id: "pkg:pypi/six@1.17.0".into(),
                purl: "pkg:pypi/six@1.17.0".into(),
                fixed_version: None,
            }],
            analysis: None,
            kev: None,
        }
    }

    #[test]
    fn ignore_syntax() {
        assert_eq!(
            Ignore::parse("GHSA-1").unwrap(),
            Ignore {
                id: "GHSA-1".into(),
                state: "not_affected",
                detail: None
            }
        );
        assert_eq!(
            Ignore::parse("GHSA-1:only used at build time").unwrap(),
            Ignore {
                id: "GHSA-1".into(),
                state: "not_affected",
                detail: Some("only used at build time".into())
            }
        );
        assert_eq!(
            Ignore::parse("CVE-1:false_positive:wrong package").unwrap(),
            Ignore {
                id: "CVE-1".into(),
                state: "false_positive",
                detail: Some("wrong package".into())
            }
        );
        assert_eq!(Ignore::parse("CVE-1:in_triage").unwrap().state, "in_triage");
        assert_eq!(Ignore::parse("CVE-1:in_triage:").unwrap().detail, None);
        // A detail that contains a colon but no state keeps the whole text.
        assert_eq!(
            Ignore::parse("CVE-1:see ticket: ABC-12").unwrap().detail.as_deref(),
            Some("see ticket: ABC-12")
        );
        assert!(Ignore::parse(":x").is_err());
        assert!(Ignore::parse("  ").is_err());
    }

    #[test]
    fn ignores_match_ids_and_aliases_and_leave_the_gate() {
        let mut sbom = sample_sbom();
        sbom.vulnerabilities = vec![
            finding("GHSA-a", &["CVE-1"], Severity::Critical),
            finding("GHSA-b", &[], Severity::High),
            finding("GHSA-c", &[], Severity::Medium),
            finding("GHSA-d", &[], Severity::Unknown),
        ];
        let ignores = [
            Ignore::parse("cve-1:not reachable").unwrap(),
            Ignore::parse("GHSA-zzz").unwrap(),
        ];
        assert_eq!(apply_ignores(&mut sbom, &ignores), 1);
        assert_eq!(
            sbom.vulnerabilities[0].analysis,
            Some(Analysis {
                state: "not_affected",
                detail: Some("not reachable".into())
            })
        );
        assert_eq!(sbom.vulnerabilities[1].analysis, None);

        let hits = check(&sbom, Some(Severity::High), false);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].to_string(), "GHSA-b (high): six 1.17.0");
        assert_eq!(
            check(&sbom, Some(Severity::Low), false).len(),
            2,
            "unknown severity never trips the gate"
        );
        assert!(check(&sbom, Some(Severity::Critical), false).is_empty());

        // The KEV gate is independent of severity and also respects ignores.
        sbom.vulnerabilities[2].kev = Some(crate::model::Kev {
            cve_id: "CVE-2".into(),
            name: None,
            date_added: None,
            due_date: None,
            ransomware: true,
            required_action: None,
        });
        sbom.vulnerabilities[0].kev = sbom.vulnerabilities[2].kev.clone();
        let hits = check(&sbom, None, true);
        assert_eq!(hits.len(), 1, "GHSA-a is ignored, GHSA-c is known exploited");
        assert_eq!(hits[0].to_string(), "GHSA-c (medium, known exploited): six 1.17.0");
        assert_eq!(check(&sbom, Some(Severity::High), true).len(), 2);
    }
}
