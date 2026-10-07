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

/// The CycloneDX impact-analysis justifications `--ignore-vuln` accepts after `not_affected`.
pub const JUSTIFICATIONS: [&str; 9] = [
    "code_not_present",
    "code_not_reachable",
    "requires_configuration",
    "requires_dependency",
    "requires_environment",
    "protected_by_compiler",
    "protected_at_runtime",
    "protected_at_perimeter",
    "protected_by_mitigating_control",
];

/// One `--ignore-vuln` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ignore {
    /// The advisory id or alias to ignore (`GHSA-...`, `CVE-...`).
    pub id: String,
    /// Analysis state, one of the CycloneDX states.
    pub state: &'static str,
    /// Machine-readable reason, one of [`JUSTIFICATIONS`]; only with `not_affected`.
    pub justification: Option<&'static str>,
    /// Free-text justification, when given.
    pub detail: Option<String>,
}

impl Ignore {
    /// Parse `ID`, `ID:detail`, `ID:state:detail` or `ID:state:justification:detail`; a segment is
    /// a state or a justification only when it names one, otherwise it is the detail.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (id, rest) = match text.split_once(':') {
            Some((id, rest)) => (id.trim(), Some(rest.trim())),
            None => (text, None),
        };
        if id.is_empty() {
            return Err(format!("'{text}' has no vulnerability id"));
        }
        let known = |list: &[&'static str], word: &str| list.iter().find(|w| **w == word.trim()).copied();
        let trimmed = |text: &str| Some(text.trim()).filter(|t| !t.is_empty()).map(str::to_string);
        let (state, justification, detail) = match rest {
            None | Some("") => (DEFAULT_STATE, None, None),
            Some(rest) => match rest.split_once(':') {
                // Only after an explicit state may the next segment be a justification.
                Some((state, after)) if known(&STATES, state).is_some() => {
                    let state = known(&STATES, state).unwrap_or(DEFAULT_STATE);
                    let (head, tail) = after.split_once(':').unwrap_or((after, ""));
                    match known(&JUSTIFICATIONS, head) {
                        Some(justification) => (state, Some(justification), trimmed(tail)),
                        None => (state, None, trimmed(after)),
                    }
                }
                _ => match known(&STATES, rest) {
                    Some(state) => (state, None, None),
                    None => (DEFAULT_STATE, None, Some(rest.to_string())),
                },
            },
        };
        if let Some(justification) = justification
            && state != "not_affected"
        {
            return Err(format!(
                "'{text}': a justification ('{justification}') only applies to the not_affected state, not {state}"
            ));
        }
        Ok(Self {
            id: id.to_string(),
            state,
            justification,
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
                justification: ignore.justification,
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
                justification: None,
                detail: None
            }
        );
        assert_eq!(
            Ignore::parse("GHSA-1:only used at build time").unwrap(),
            Ignore {
                id: "GHSA-1".into(),
                state: "not_affected",
                justification: None,
                detail: Some("only used at build time".into())
            }
        );
        assert_eq!(
            Ignore::parse("CVE-1:false_positive:wrong package").unwrap(),
            Ignore {
                id: "CVE-1".into(),
                state: "false_positive",
                justification: None,
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
    fn ignore_justification_follows_an_explicit_state() {
        assert_eq!(
            Ignore::parse("CVE-1:not_affected:code_not_reachable:only the docs build imports it").unwrap(),
            Ignore {
                id: "CVE-1".into(),
                state: "not_affected",
                justification: Some("code_not_reachable"),
                detail: Some("only the docs build imports it".into())
            }
        );
        let bare = Ignore::parse("CVE-1:not_affected:protected_at_perimeter").unwrap();
        assert_eq!(bare.justification, Some("protected_at_perimeter"));
        assert_eq!(bare.detail, None);
        // Colons inside the text survive, with or without a justification before it.
        assert_eq!(
            Ignore::parse("CVE-1:not_affected:some text with: colons").unwrap(),
            Ignore {
                id: "CVE-1".into(),
                state: "not_affected",
                justification: None,
                detail: Some("some text with: colons".into())
            }
        );
        assert_eq!(
            Ignore::parse("CVE-1:not_affected:code_not_present:see: ABC-12")
                .unwrap()
                .detail
                .as_deref(),
            Some("see: ABC-12")
        );
        // Without an explicit state, a justification word is part of the text, as it always was.
        let implicit = Ignore::parse("CVE-1:code_not_reachable:text").unwrap();
        assert_eq!(implicit.justification, None);
        assert_eq!(implicit.detail.as_deref(), Some("code_not_reachable:text"));
        // An unknown word in that position stays part of the detail.
        let unknown = Ignore::parse("CVE-1:not_affected:not_a_reason:text").unwrap();
        assert_eq!(unknown.justification, None);
        assert_eq!(unknown.detail.as_deref(), Some("not_a_reason:text"));
        // A justification only explains not_affected.
        let err = Ignore::parse("CVE-1:exploitable:code_not_present:text").unwrap_err();
        assert!(err.contains("only applies to the not_affected state"), "{err}");
    }

    #[test]
    fn apply_ignores_carries_the_justification() {
        let mut sbom = sample_sbom();
        sbom.vulnerabilities = vec![finding("GHSA-a", &[], Severity::High)];
        let ignores = [Ignore::parse("GHSA-a:not_affected:requires_configuration:off by default").unwrap()];
        apply_ignores(&mut sbom, &ignores);
        assert_eq!(
            sbom.vulnerabilities[0].analysis.as_ref().and_then(|a| a.justification),
            Some("requires_configuration")
        );
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
                justification: None,
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
