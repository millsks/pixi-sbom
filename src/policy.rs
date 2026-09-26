//! License policy: allow-list, deny-list and "every package must have a license".
//!
//! Each package's declared license is parsed as an SPDX expression and evaluated against
//! the policy with the expression's `AND` / `OR` structure respected: `MIT OR GPL-3.0-only`
//! passes a policy that denies GPL because MIT is an option; `MIT AND GPL-3.0-only` does not.
//! Identifiers are compared by base id, `-or-later` flag and exception, so the deprecated
//! `GPL-3.0` and the current `GPL-3.0-only` mean the same thing, and an `-or-later`
//! requirement is satisfied by any allowed later version of the same family.

use std::fmt;

use miette::Diagnostic;
use spdx::{LicenseItem, LicenseReq, ParseMode};
use thiserror::Error;

use crate::license::{self, License};
use crate::model::Sbom;

/// Exit code of a run whose documents were written but whose policy was violated.
pub const VIOLATION_EXIT_CODE: i32 = 3;

/// The `pixi:*` property recording that a package was let through the policy deliberately,
/// with the justification when one was given.
pub const EXEMPT_PROPERTY: &str = "pixi:license-exempt";

/// One package (or pattern of packages) the policy does not apply to, and why.
#[derive(Debug, Clone)]
pub struct Exemption {
    /// Name or shell-style pattern, as `--exclude` spells it.
    pub pattern: crate::filter::Glob,
    /// Free text, for the report and the document.
    pub justification: Option<String>,
}

impl Exemption {
    /// Parse `PACKAGE` or `PACKAGE:justification`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (pattern, justification) = match text.split_once(':') {
            Some((pattern, rest)) => (pattern.trim(), Some(rest.trim()).filter(|r| !r.is_empty())),
            None => (text, None),
        };
        if pattern.is_empty() {
            return Err(format!("'{text}' names no package"));
        }
        Ok(Self {
            pattern: crate::filter::Glob::parse(pattern)?,
            justification: justification.map(str::to_string),
        })
    }
}

/// A package the policy would have failed, let through by an exemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exempt {
    pub violation: Violation,
    pub justification: Option<String>,
}

impl fmt::Display for Exempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.violation)?;
        match &self.justification {
            Some(justification) => write!(f, " — {justification}"),
            None => Ok(()),
        }
    }
}

/// What a policy check found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Packages that fail the policy and are not exempt.
    pub violations: Vec<Violation>,
    /// Packages that would have failed and were let through.
    pub exempt: Vec<Exempt>,
}

/// A licensee given on the command line could not be parsed.
#[derive(Debug, Error, Diagnostic)]
#[error("'{text}' is not an SPDX license identifier: {reason}")]
#[diagnostic(
    code(pixi_sbom::policy::licensee),
    help("use an identifier from the SPDX license list, e.g. MIT, Apache-2.0, GPL-3.0-or-later, or a LicenseRef-")
)]
pub struct LicenseeError {
    /// What was given.
    pub text: String,
    /// Why it was rejected.
    pub reason: String,
}

/// A single license identifier in comparable form.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Lic {
    /// `GPL-3.0`, `MIT`, `LicenseRef-Proprietary`.
    base: String,
    /// The requirement or licensee accepts later versions.
    or_later: bool,
    /// Exception name, e.g. `Classpath-exception-2.0`.
    addition: Option<String>,
}

impl Lic {
    fn from_req(req: &LicenseReq) -> Self {
        let (name, mut or_later) = match &req.license {
            LicenseItem::Spdx { id, or_later } => (id.name.to_string(), *or_later),
            LicenseItem::Other(lic) => (
                match &lic.doc_ref {
                    Some(doc) => format!("DocumentRef-{doc}:LicenseRef-{}", lic.lic_ref),
                    None => format!("LicenseRef-{}", lic.lic_ref),
                },
                false,
            ),
        };
        let mut base = name;
        if let Some(stripped) = base.strip_suffix("-or-later") {
            base = stripped.to_string();
            or_later = true;
        } else if let Some(stripped) = base.strip_suffix("-only") {
            base = stripped.to_string();
        } else if let Some(stripped) = base.strip_suffix('+') {
            base = stripped.to_string();
            or_later = true;
        }
        let addition = req.addition.as_ref().map(|a| match a {
            spdx::AdditionItem::Spdx(id) => id.name.to_string(),
            spdx::AdditionItem::Other(add) => match &add.doc_ref {
                Some(doc) => format!("DocumentRef-{doc}:AdditionRef-{}", add.add_ref),
                None => format!("AdditionRef-{}", add.add_ref),
            },
        });
        Self {
            base,
            or_later,
            addition,
        }
    }

    /// `("GPL", "3.0")` for `GPL-3.0`; `None` when the id has no trailing version.
    fn family_version(&self) -> Option<(&str, Vec<u32>)> {
        let (family, version) = self.base.rsplit_once('-')?;
        let parts: Option<Vec<u32>> = version.split('.').map(|p| p.parse().ok()).collect();
        parts.filter(|p| !p.is_empty()).map(|v| (family, v))
    }

    /// Whether accepting this license satisfies `req`.
    fn satisfies(&self, req: &Lic) -> bool {
        if self.addition != req.addition {
            return false;
        }
        if self.base == req.base {
            return true;
        }
        if !req.or_later {
            return false;
        }
        match (self.family_version(), req.family_version()) {
            (Some((fa, va)), Some((fb, vb))) => fa == fb && va > vb,
            _ => false,
        }
    }
}

impl fmt::Display for Lic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)?;
        if self.or_later {
            write!(f, "-or-later")?;
        }
        if let Some(addition) = &self.addition {
            write!(f, " WITH {addition}")?;
        }
        Ok(())
    }
}

/// The policy to enforce.
#[derive(Debug, Default)]
pub struct Policy {
    allow: Vec<Lic>,
    deny: Vec<Lic>,
    require_license: bool,
    /// Packages the policy deliberately does not apply to.
    exemptions: Vec<Exemption>,
}

/// Why a package violates the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// The expression cannot be satisfied without a denied license.
    Denied,
    /// The expression cannot be satisfied with allowed licenses only.
    NotAllowed,
    /// The package declares no license.
    Missing,
    /// The declared license is not an SPDX expression, so it cannot be evaluated.
    NotSpdx,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Reason::Denied => "denied license",
            Reason::NotAllowed => "not in the allowed licenses",
            Reason::Missing => "no license declared",
            Reason::NotSpdx => "license is not an SPDX expression",
        })
    }
}

/// One package that violates the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub package: String,
    pub version: Option<String>,
    pub license: Option<String>,
    pub reason: Reason,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.package)?;
        if let Some(version) = &self.version {
            write!(f, " {version}")?;
        }
        write!(f, ": {}", self.reason)?;
        if let Some(license) = &self.license {
            write!(f, " ({license})")?;
        }
        Ok(())
    }
}

impl Policy {
    /// Build a policy from the command-line lists; `None` when nothing was asked for.
    pub fn new(
        allow: &[String],
        deny: &[String],
        require_license: bool,
        exemptions: Vec<Exemption>,
    ) -> Result<Option<Self>, LicenseeError> {
        if allow.is_empty() && deny.is_empty() && !require_license {
            return Ok(None);
        }
        Ok(Some(Self {
            allow: allow.iter().map(|a| parse_licensee(a)).collect::<Result<_, _>>()?,
            deny: deny.iter().map(|d| parse_licensee(d)).collect::<Result<_, _>>()?,
            require_license,
            exemptions,
        }))
    }

    /// The exemption that covers a package, if any.
    fn exemption(&self, package: &str) -> Option<&Exemption> {
        self.exemptions.iter().find(|e| e.pattern.matches(package))
    }

    /// Whether the policy restricts which licenses are acceptable (as opposed to only
    /// requiring one).
    fn restricts(&self) -> bool {
        !self.allow.is_empty() || !self.deny.is_empty()
    }

    /// Every package in `sbom` that violates the policy, in document order.
    pub fn check(&self, sbom: &Sbom) -> Outcome {
        let mut outcome = Outcome::default();
        for package in &sbom.packages {
            let violation = |reason, license: Option<String>| Violation {
                package: package.name.clone(),
                version: package.version.clone(),
                license,
                reason,
            };
            // A package the policy does not apply to is recorded, not failed.
            let mut record = |reason, license: Option<String>| match self.exemption(&package.name) {
                Some(exemption) => outcome.exempt.push(Exempt {
                    violation: violation(reason, license),
                    justification: exemption.justification.clone(),
                }),
                None => outcome.violations.push(violation(reason, license)),
            };
            let Some(raw) = package.license.as_deref() else {
                if self.require_license {
                    record(Reason::Missing, None);
                }
                continue;
            };
            let expression = match license::normalize(raw) {
                License::Expression(expression) => expression,
                License::Text(text) => {
                    if self.require_license {
                        let detail = license::rejection_reason(raw)
                            .map(|why| format!("{text} ({why})"))
                            .unwrap_or(text);
                        record(Reason::NotSpdx, Some(detail));
                    }
                    continue;
                }
            };
            if !self.restricts() {
                continue;
            }
            if let Some(reason) = self.evaluate(&expression) {
                record(reason, Some(expression));
            }
        }
        outcome
    }

    /// `None` when `expression` is acceptable, otherwise why not.
    fn evaluate(&self, expression: &str) -> Option<Reason> {
        let mode = ParseMode {
            allow_deprecated: true,
            ..ParseMode::STRICT
        };
        let Ok(parsed) = spdx::Expression::parse_mode(expression, mode) else {
            // normalize() only returns expressions this parser accepts; be safe anyway.
            return Some(Reason::NotSpdx);
        };
        let denied = |req: &LicenseReq| {
            let lic = Lic::from_req(req);
            self.deny.iter().any(|d| d.satisfies(&lic))
        };
        let allowed = |req: &LicenseReq| {
            let lic = Lic::from_req(req);
            self.allow.is_empty() || self.allow.iter().any(|a| a.satisfies(&lic))
        };
        if !self.deny.is_empty() && !parsed.evaluate(|req| !denied(req)) {
            return Some(Reason::Denied);
        }
        if !self.allow.is_empty() && !parsed.evaluate(|req| allowed(req) && !denied(req)) {
            return Some(Reason::NotAllowed);
        }
        None
    }
}

fn parse_licensee(text: &str) -> Result<Lic, LicenseeError> {
    let text = text.trim();
    // A licensee cannot carry the `+` shorthand; spell it out the way the license list does.
    let spelled = match text.strip_suffix('+') {
        Some(base) if !base.contains(' ') => format!("{base}-or-later"),
        _ => text.to_string(),
    };
    spdx::Licensee::parse_mode(&spelled, ParseMode::LAX)
        .map(|licensee| Lic::from_req(&licensee.into_req()))
        .map_err(|err| LicenseeError {
            text: text.to_string(),
            reason: err.reason.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        crate::assert_actionable(&LicenseeError {
            text: "MIT-ish".to_string(),
            reason: "unknown identifier".to_string(),
        });
    }
    use crate::format::testing::sample_sbom;

    fn policy(allow: &[&str], deny: &[&str], require: bool) -> Policy {
        let allow: Vec<String> = allow.iter().map(|s| s.to_string()).collect();
        let deny: Vec<String> = deny.iter().map(|s| s.to_string()).collect();
        Policy::new(&allow, &deny, require, Vec::new()).unwrap().unwrap()
    }

    fn reason(p: &Policy, expression: &str) -> Option<Reason> {
        p.evaluate(expression)
    }

    #[test]
    fn an_exempt_package_is_recorded_instead_of_failed() {
        let mut sbom = sample_sbom();
        // libzlib is Zlib, mylib is Proprietary: two different ways to fail one policy.
        let deny = Policy::new(
            &[],
            &["Zlib".into()],
            true,
            vec![
                Exemption::parse("libz*:vendored, reviewed 2026-01").unwrap(),
                Exemption::parse("mylib").unwrap(),
            ],
        )
        .unwrap()
        .unwrap();
        sbom.packages.iter_mut().find(|p| p.name == "mylib").unwrap().license = None;

        let outcome = deny.check(&sbom);
        // six declares no license and is nobody's exemption.
        let failed: Vec<&str> = outcome.violations.iter().map(|v| v.package.as_str()).collect();
        assert_eq!(failed, ["six"], "{outcome:?}");
        let exempt: Vec<(&str, Option<&str>)> = outcome
            .exempt
            .iter()
            .map(|e| (e.violation.package.as_str(), e.justification.as_deref()))
            .collect();
        assert_eq!(
            exempt,
            [("libzlib", Some("vendored, reviewed 2026-01")), ("mylib", None)]
        );
        assert_eq!(outcome.exempt[0].violation.reason, Reason::Denied);
        assert_eq!(outcome.exempt[1].violation.reason, Reason::Missing);
        assert!(
            outcome.exempt[0].to_string().contains("vendored, reviewed 2026-01"),
            "{}",
            outcome.exempt[0]
        );

        // Without the exemptions the same policy fails both.
        let strict = Policy::new(&[], &["Zlib".into()], true, Vec::new()).unwrap().unwrap();
        assert_eq!(strict.check(&sbom).violations.len(), 3);
    }

    #[test]
    fn an_exemption_needs_a_package_and_takes_a_justification() {
        assert_eq!(Exemption::parse("six").unwrap().justification, None);
        assert_eq!(
            Exemption::parse(" six : because ").unwrap().justification.as_deref(),
            Some("because")
        );
        assert_eq!(Exemption::parse("six:").unwrap().justification, None);
        assert!(Exemption::parse(":why").is_err());
        assert!(Exemption::parse("  ").is_err());
    }

    #[test]
    fn no_flags_means_no_policy_and_bad_licensees_are_errors() {
        assert!(Policy::new(&[], &[], false, Vec::new()).unwrap().is_none());
        assert!(Policy::new(&[], &[], true, Vec::new()).unwrap().is_some());
        let err = Policy::new(&["not a license!!".into()], &[], false, Vec::new()).unwrap_err();
        assert!(err.text.contains("not a license"));
        assert!(
            Policy::new(&["mit".into()], &[], false, Vec::new()).is_ok(),
            "lax parsing accepts lower case"
        );
    }

    #[test]
    fn deny_respects_or_and_and() {
        let p = policy(&[], &["GPL-3.0-only"], false);
        assert_eq!(reason(&p, "MIT OR GPL-3.0-only"), None, "MIT is an option");
        assert_eq!(reason(&p, "MIT AND GPL-3.0-only"), Some(Reason::Denied));
        assert_eq!(reason(&p, "GPL-3.0-only"), Some(Reason::Denied));
        assert_eq!(reason(&p, "GPL-3.0"), Some(Reason::Denied), "deprecated spelling");
        assert_eq!(reason(&p, "GPL-2.0-only"), None);
        assert_eq!(
            reason(&p, "GPL-2.0-or-later"),
            Some(Reason::Denied),
            "3.0 is a later version"
        );
        assert_eq!(reason(&p, "LGPL-3.0-only"), None, "different family");
    }

    #[test]
    fn allow_list_requires_a_satisfiable_choice() {
        let p = policy(&["MIT", "Apache-2.0", "GPL-3.0-or-later"], &[], false);
        assert_eq!(reason(&p, "MIT"), None);
        assert_eq!(reason(&p, "MIT OR GPL-2.0-only"), None);
        assert_eq!(reason(&p, "BSD-3-Clause"), Some(Reason::NotAllowed));
        assert_eq!(reason(&p, "MIT AND BSD-3-Clause"), Some(Reason::NotAllowed));
        assert_eq!(reason(&p, "GPL-3.0-only"), None, "allowed base matches");
        assert_eq!(
            reason(&p, "GPL-2.0-or-later"),
            None,
            "an allowed later version satisfies or-later"
        );
        assert_eq!(reason(&p, "GPL-2.0-only"), Some(Reason::NotAllowed));
        assert_eq!(
            reason(&p, "GPL-3.0-only WITH Classpath-exception-2.0"),
            Some(Reason::NotAllowed),
            "exceptions must match"
        );
        let with = policy(&["GPL-2.0-only WITH Classpath-exception-2.0"], &[], false);
        assert_eq!(reason(&with, "GPL-2.0-only WITH Classpath-exception-2.0"), None);
        assert_eq!(reason(&with, "GPL-2.0-only"), Some(Reason::NotAllowed));
    }

    #[test]
    fn deny_wins_over_allow_and_license_refs_match_exactly() {
        let p = policy(&["MIT", "GPL-3.0-only"], &["GPL-3.0-only"], false);
        assert_eq!(reason(&p, "GPL-3.0-only"), Some(Reason::Denied));
        assert_eq!(reason(&p, "MIT"), None);
        let refs = policy(&[], &["LicenseRef-Proprietary"], false);
        assert_eq!(reason(&refs, "LicenseRef-Proprietary"), Some(Reason::Denied));
        assert_eq!(reason(&refs, "LicenseRef-Other"), None);
    }

    #[test]
    fn lic_display_and_version_parsing() {
        let l = parse_licensee("GPL-2.0+").unwrap();
        assert_eq!(l.to_string(), "GPL-2.0-or-later");
        assert_eq!(
            parse_licensee("LGPL-2.1").unwrap().family_version().unwrap().1,
            vec![2, 1]
        );
        assert_eq!(parse_licensee("MIT").unwrap().family_version(), None);
        assert_eq!(
            parse_licensee("Apache-2.0 WITH LLVM-exception").unwrap().to_string(),
            "Apache-2.0 WITH LLVM-exception"
        );
    }

    #[test]
    fn check_reports_packages_in_document_order() {
        let sbom = sample_sbom();
        // libzlib: Zlib; zlib: MIT/Apache-2.0; mylib: Proprietary (text); six: none.
        let deny = policy(&[], &["Zlib"], false);
        let v = deny.check(&sbom).violations;
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].package, "libzlib");
        assert_eq!(v[0].reason, Reason::Denied);
        assert_eq!(v[0].to_string(), "libzlib 1.3.1: denied license (Zlib)");

        let allow = policy(&["Zlib", "MIT"], &[], false);
        let v = allow.check(&sbom).violations;
        assert_eq!(
            v.len(),
            0,
            "MIT satisfies MIT OR Apache-2.0; text and missing are not violations"
        );

        let require = policy(&[], &[], true);
        let v = require.check(&sbom).violations;
        let names: Vec<_> = v.iter().map(|v| (v.package.as_str(), v.reason.clone())).collect();
        assert_eq!(names, [("mylib", Reason::NotSpdx), ("six", Reason::Missing)]);
        assert_eq!(v[1].to_string(), "six 1.17.0: no license declared");
        assert_eq!(
            v[0].to_string(),
            "mylib: license is not an SPDX expression (Proprietary (unknown term: 'Proprietary'))"
        );
    }
}
