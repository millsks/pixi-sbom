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

/// The CycloneDX impact-analysis responses `--ignore-vuln` accepts after a state.
pub const RESPONSES: [&str; 5] = [
    "can_not_fix",
    "will_not_fix",
    "update",
    "rollback",
    "workaround_available",
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
    /// What is being done about it, from [`RESPONSES`]; empty when not given.
    pub response: Vec<&'static str>,
    /// Free-text justification, when given.
    pub detail: Option<String>,
}

impl Ignore {
    /// Parse `ID`, `ID:detail` or `ID:state[:justification][:response,...][:detail]`; a segment is
    /// a state, a justification or a response list only when it names known values, otherwise it
    /// starts the detail.
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
        let (state, justification, response, detail) = match rest {
            None | Some("") => (DEFAULT_STATE, None, Vec::new(), None),
            Some(rest) => match rest.split_once(':') {
                // Only after an explicit state may a justification or a response follow.
                Some((state, mut after)) if known(&STATES, state).is_some() => {
                    let state = known(&STATES, state).unwrap_or(DEFAULT_STATE);
                    let (head, tail) = after.split_once(':').unwrap_or((after, ""));
                    let justification = known(&JUSTIFICATIONS, head);
                    if justification.is_some() {
                        after = tail;
                    }
                    let (head, tail) = after.split_once(':').unwrap_or((after, ""));
                    let response: Option<Vec<&'static str>> =
                        head.split(',').map(|word| known(&RESPONSES, word)).collect();
                    let mut response = response.unwrap_or_default();
                    if !response.is_empty() {
                        after = tail;
                        let mut seen = std::collections::HashSet::new();
                        response.retain(|r| seen.insert(*r));
                    }
                    (state, justification, response, trimmed(after))
                }
                _ => match known(&STATES, rest) {
                    Some(state) => (state, None, Vec::new(), None),
                    None => (DEFAULT_STATE, None, Vec::new(), Some(rest.to_string())),
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
            response,
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
    /// Its EPSS score, with `--epss`.
    pub epss: Option<f64>,
    /// `name version` of each affected package.
    pub packages: Vec<String>,
}

impl std::fmt::Display for Hit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}{}{}): {}",
            self.id,
            self.severity.name(),
            if self.known_exploited { ", known exploited" } else { "" },
            self.epss.map(|p| format!(", EPSS {p:.3}")).unwrap_or_default(),
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
                response: ignore.response.clone(),
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

/// What trips the vulnerability gate; a finding trips it by meeting any one of these.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Rule {
    /// `--fail-on-severity`: at or above this severity.
    pub severity: Option<Severity>,
    /// `--fail-on-kev`: in CISA's KEV catalog.
    pub kev: bool,
    /// `--fail-on-epss`: an EPSS score at or above this probability.
    pub epss: Option<f64>,
}

impl Rule {
    /// Whether any part of the gate is set.
    pub fn is_set(&self) -> bool {
        self.severity.is_some() || self.kev || self.epss.is_some()
    }

    fn trips(&self, vuln: &Vulnerability) -> bool {
        self.severity.is_some_and(|t| vuln.severity >= t)
            || (self.kev && vuln.kev.is_some())
            || self
                .epss
                .is_some_and(|t| vuln.epss.as_ref().is_some_and(|e| e.score >= t))
    }
}

impl std::fmt::Display for Rule {
    /// The rule as the gate's message says it: `at or above high or known exploited`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if let Some(severity) = self.severity {
            parts.push(format!("at or above {}", severity.name()));
        }
        if self.kev {
            parts.push("known exploited".to_string());
        }
        if let Some(threshold) = self.epss {
            parts.push(format!("with an EPSS score of {threshold} or more"));
        }
        f.write_str(&parts.join(" or "))
    }
}

/// The open findings that trip the gate's `rule`. Worst first.
pub fn check(sbom: &Sbom, rule: &Rule) -> Vec<Hit> {
    sbom.vulnerabilities
        .iter()
        .filter(|v| v.analysis.is_none())
        .filter(|v| rule.trips(v))
        .map(|v| Hit {
            id: v.id.clone(),
            severity: v.severity,
            known_exploited: v.kev.is_some(),
            epss: v.epss.as_ref().map(|e| e.score),
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
            epss: None,
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
                response: vec![],
                detail: None
            }
        );
        assert_eq!(
            Ignore::parse("GHSA-1:only used at build time").unwrap(),
            Ignore {
                id: "GHSA-1".into(),
                state: "not_affected",
                justification: None,
                response: vec![],
                detail: Some("only used at build time".into())
            }
        );
        assert_eq!(
            Ignore::parse("CVE-1:false_positive:wrong package").unwrap(),
            Ignore {
                id: "CVE-1".into(),
                state: "false_positive",
                justification: None,
                response: vec![],
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
                response: vec![],
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
                response: vec![],
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
    fn ignore_response_follows_a_state_or_a_justification() {
        let entry = Ignore::parse("CVE-1:exploitable:update:fixed in 2.3, rolling out").unwrap();
        assert_eq!(entry.state, "exploitable");
        assert_eq!(entry.response, ["update"]);
        assert_eq!(entry.detail.as_deref(), Some("fixed in 2.3, rolling out"));
        // A list, de-duplicated, in the order given; spaces around the commas are fine.
        let entry = Ignore::parse("CVE-1:in_triage:will_not_fix, workaround_available,will_not_fix").unwrap();
        assert_eq!(entry.response, ["will_not_fix", "workaround_available"]);
        assert_eq!(entry.detail, None);
        // Both segments, justification first.
        assert_eq!(
            Ignore::parse("CVE-1:not_affected:protected_at_perimeter:can_not_fix:the WAF blocks it").unwrap(),
            Ignore {
                id: "CVE-1".into(),
                state: "not_affected",
                justification: Some("protected_at_perimeter"),
                response: vec!["can_not_fix"],
                detail: Some("the WAF blocks it".into())
            }
        );
        // A list with any unknown word is text, so an existing detail keeps its meaning.
        let entry = Ignore::parse("CVE-1:exploitable:update,later:text").unwrap();
        assert!(entry.response.is_empty());
        assert_eq!(entry.detail.as_deref(), Some("update,later:text"));
        // Without an explicit state a response word is text, as it always was.
        let entry = Ignore::parse("CVE-1:update:text").unwrap();
        assert!(entry.response.is_empty());
        assert_eq!(entry.detail.as_deref(), Some("update:text"));
    }

    #[test]
    fn apply_ignores_carries_the_justification() {
        let mut sbom = sample_sbom();
        sbom.vulnerabilities = vec![finding("GHSA-a", &[], Severity::High)];
        let ignores =
            [Ignore::parse("GHSA-a:not_affected:requires_configuration:will_not_fix:off by default").unwrap()];
        apply_ignores(&mut sbom, &ignores);
        let analysis = sbom.vulnerabilities[0].analysis.as_ref().unwrap();
        assert_eq!(analysis.justification, Some("requires_configuration"));
        assert_eq!(analysis.response, ["will_not_fix"]);
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
                response: vec![],
                detail: Some("not reachable".into())
            })
        );
        assert_eq!(sbom.vulnerabilities[1].analysis, None);

        let severity = |s: Severity| Rule {
            severity: Some(s),
            ..Rule::default()
        };
        let hits = check(&sbom, &severity(Severity::High));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].to_string(), "GHSA-b (high): six 1.17.0");
        assert_eq!(
            check(&sbom, &severity(Severity::Low)).len(),
            2,
            "unknown severity never trips the gate"
        );
        assert!(check(&sbom, &severity(Severity::Critical)).is_empty());

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
        let kev = Rule {
            kev: true,
            ..Rule::default()
        };
        let hits = check(&sbom, &kev);
        assert_eq!(hits.len(), 1, "GHSA-a is ignored, GHSA-c is known exploited");
        assert_eq!(hits[0].to_string(), "GHSA-c (medium, known exploited): six 1.17.0");
        let both = Rule {
            severity: Some(Severity::High),
            kev: true,
            epss: None,
        };
        assert_eq!(check(&sbom, &both).len(), 2);
        assert_eq!(both.to_string(), "at or above high or known exploited");

        // The EPSS gate: at or above the threshold, unscored findings never, ignores respected.
        let score = |p: f64| {
            Some(crate::model::Epss {
                cve_id: "CVE-1".into(),
                score: p,
                percentile: 0.5,
                date: None,
            })
        };
        sbom.vulnerabilities[0].epss = score(0.9);
        sbom.vulnerabilities[1].epss = score(0.1);
        let epss = |t: f64| Rule {
            epss: Some(t),
            ..Rule::default()
        };
        let hits = check(&sbom, &epss(0.1));
        assert_eq!(hits.len(), 1, "GHSA-a is ignored and GHSA-c has no score");
        assert_eq!(hits[0].to_string(), "GHSA-b (high, EPSS 0.100): six 1.17.0");
        assert!(check(&sbom, &epss(0.11)).is_empty());
        assert_eq!(epss(0.1).to_string(), "with an EPSS score of 0.1 or more");
        assert!(epss(0.5).is_set() && kev.is_set() && !Rule::default().is_set());
    }
}
