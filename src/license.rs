//! Normalizes package license strings into SPDX expressions where possible.

use spdx::ParseMode;
use spdx::expression::{ExprNode, Operator};

/// Outcome of interpreting a package's declared license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum License {
    /// A valid SPDX license expression.
    Expression(String),
    /// Free text that is not an SPDX expression (e.g. `Proprietary`, `PSF`).
    Text(String),
}

/// Interpret a raw license string.
///
/// Strict SPDX (plus deprecated identifiers, which conda-forge still uses widely) is
/// kept verbatim. Common non-conforming spellings such as `MIT/Apache-2.0` or lower-case
/// identifiers are parsed leniently and rewritten canonically. Anything else is text.
pub fn normalize(raw: &str) -> License {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return License::Text(String::new());
    }
    let strict_with_deprecated = ParseMode {
        allow_deprecated: true,
        ..ParseMode::STRICT
    };
    if spdx::Expression::parse_mode(trimmed, strict_with_deprecated).is_ok() {
        return License::Expression(trimmed.to_string());
    }
    if let Ok(expr) = spdx::Expression::parse_mode(trimmed, ParseMode::LAX) {
        return License::Expression(canonical(&expr));
    }
    // conda-forge spells several toolchain licenses with a non-SPDX exception clause
    // (`LGPL-2.0-or-later WITH exceptions`). Turn such clauses into AdditionRef- additions,
    // which SPDX allows and the policy compares as opaque strings, so the expression stays
    // evaluable instead of collapsing into free text.
    let rewritten = rewrite_unknown_exceptions(trimmed);
    if rewritten != trimmed
        && let Ok(expr) = spdx::Expression::parse_mode(&rewritten, ParseMode::LAX)
    {
        tracing::debug!(raw = trimmed, "rewrote a non-SPDX exception clause");
        return License::Expression(canonical(&expr));
    }
    License::Text(trimmed.to_string())
}

/// Why `raw` is not an SPDX expression, for a human: the parser's reason and the offending
/// span, e.g. `unknown license 'PSF' at 1..4`. `None` when it is a valid expression.
pub fn rejection_reason(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some("empty".into());
    }
    if matches!(normalize(trimmed), License::Expression(_)) {
        return None;
    }
    let err = spdx::Expression::parse_mode(trimmed, ParseMode::LAX).err()?;
    let offending = trimmed.get(err.span.clone()).unwrap_or("").trim();
    let reason = err.reason.to_string();
    Some(if offending.is_empty() {
        reason
    } else {
        format!("{reason}: '{offending}'")
    })
}

/// Whether [`normalize`] only succeeds on `raw` by rewriting a non-SPDX exception clause, so
/// callers can preserve the original spelling next to the normalized expression.
pub fn is_rewritten(raw: &str) -> bool {
    let trimmed = raw.trim();
    let strict_with_deprecated = ParseMode {
        allow_deprecated: true,
        ..ParseMode::STRICT
    };
    spdx::Expression::parse_mode(trimmed, strict_with_deprecated).is_err()
        && spdx::Expression::parse_mode(trimmed, ParseMode::LAX).is_err()
        && matches!(normalize(trimmed), License::Expression(_))
}

/// Replace `WITH <word>` where `<word>` is not an SPDX exception (nor already a reference)
/// by `WITH AdditionRef-<word>`.
fn rewrite_unknown_exceptions(text: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut out: Vec<String> = Vec::with_capacity(words.len());
    let mut i = 0;
    while i < words.len() {
        let word = words[i];
        out.push(word.to_string());
        if word.eq_ignore_ascii_case("WITH")
            && let Some(next) = words.get(i + 1)
        {
            let bare = next.trim_end_matches(')');
            let parens = &next[bare.len()..];
            let known = spdx::exception_id(bare).is_some()
                || bare.starts_with("AdditionRef-")
                || bare.starts_with("DocumentRef-");
            if !known && bare.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
                out.push(format!("AdditionRef-{bare}{parens}"));
            } else {
                out.push(next.to_string());
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    out.join(" ")
}

/// Whether a (normalized) SPDX expression is a single license identifier with no operators,
/// e.g. `MIT` or `GPL-2.0-or-later WITH Classpath-exception-2.0` but not `MIT OR Apache-2.0`.
/// CycloneDX can attach a license text to a single identifier but not to a compound expression.
pub fn is_single_id(expression: &str) -> bool {
    let strict_with_deprecated = ParseMode {
        allow_deprecated: true,
        ..ParseMode::STRICT
    };
    spdx::Expression::parse_mode(expression, strict_with_deprecated)
        .map(|expr| expr.iter().all(|node| matches!(node, ExprNode::Req(_))) && expr.iter().count() == 1)
        .unwrap_or(false)
}

/// Rebuild an infix expression from the parser's postfix node list.
fn canonical(expr: &spdx::Expression) -> String {
    let mut stack: Vec<(String, Option<Operator>)> = Vec::new();
    for node in expr.iter() {
        match node {
            ExprNode::Req(req) => stack.push((req.req.to_string(), None)),
            ExprNode::Op(op) => {
                let (rhs, rhs_op) = stack.pop().expect("valid postfix expression");
                let (lhs, lhs_op) = stack.pop().expect("valid postfix expression");
                let text = format!(
                    "{} {} {}",
                    group(lhs, lhs_op, *op),
                    keyword(*op),
                    group(rhs, rhs_op, *op)
                );
                stack.push((text, Some(*op)));
            }
        }
    }
    stack.pop().map(|(text, _)| text).unwrap_or_default()
}

fn keyword(op: Operator) -> &'static str {
    match op {
        Operator::And => "AND",
        Operator::Or => "OR",
    }
}

/// Parenthesize an `OR` sub-expression that sits under an `AND`.
fn group(text: String, inner: Option<Operator>, outer: Operator) -> String {
    match (inner, outer) {
        (Some(Operator::Or), Operator::And) => format!("({text})"),
        _ => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_spdx_is_kept_verbatim() {
        assert_eq!(normalize("MIT"), License::Expression("MIT".into()));
        assert_eq!(
            normalize(" Apache-2.0 OR MIT "),
            License::Expression("Apache-2.0 OR MIT".into())
        );
        assert_eq!(
            normalize("GPL-2.0-or-later WITH Classpath-exception-2.0"),
            License::Expression("GPL-2.0-or-later WITH Classpath-exception-2.0".into())
        );
        assert_eq!(
            normalize("LicenseRef-Proprietary"),
            License::Expression("LicenseRef-Proprietary".into())
        );
    }

    #[test]
    fn deprecated_ids_are_kept_verbatim() {
        assert_eq!(normalize("GPL-3.0"), License::Expression("GPL-3.0".into()));
        assert_eq!(normalize("LGPL-2.1"), License::Expression("LGPL-2.1".into()));
    }

    #[test]
    fn lax_spellings_are_canonicalized() {
        assert_eq!(
            normalize("MIT/Apache-2.0"),
            License::Expression("MIT OR Apache-2.0".into())
        );
        assert_eq!(normalize("mit"), License::Expression("MIT".into()));
        assert_eq!(
            normalize("MIT AND BSD-3-Clause/Apache-2.0"),
            License::Expression("MIT AND BSD-3-Clause OR Apache-2.0".into()),
            "AND binds tighter than OR"
        );
        assert_eq!(
            normalize("MIT AND (BSD-3-Clause/Apache-2.0)"),
            License::Expression("MIT AND (BSD-3-Clause OR Apache-2.0)".into())
        );
        assert_eq!(
            normalize("(MIT OR Apache-2.0) AND Zlib"),
            License::Expression("(MIT OR Apache-2.0) AND Zlib".into())
        );
    }

    #[test]
    fn single_ids_are_recognized() {
        assert!(is_single_id("MIT"));
        assert!(is_single_id("GPL-3.0"));
        assert!(is_single_id("GPL-2.0-or-later WITH Classpath-exception-2.0"));
        assert!(is_single_id("LicenseRef-Proprietary"));
        assert!(!is_single_id("MIT OR Apache-2.0"));
        assert!(!is_single_id("MIT AND Zlib"));
        assert!(!is_single_id("Proprietary"));
    }

    #[test]
    fn non_spdx_exception_clauses_become_addition_refs() {
        assert_eq!(
            normalize("LGPL-2.0-or-later AND LGPL-2.0-or-later WITH exceptions AND GPL-2.0-or-later"),
            License::Expression(
                "LGPL-2.0-or-later AND LGPL-2.0-or-later WITH AdditionRef-exceptions AND GPL-2.0-or-later".into()
            )
        );
        assert_eq!(
            normalize("GPL-2.0-only WITH Classpath-exception-2.0"),
            License::Expression("GPL-2.0-only WITH Classpath-exception-2.0".into()),
            "real exceptions are left alone"
        );
        assert_eq!(
            normalize("(MIT WITH weird) OR Zlib"),
            License::Expression("MIT WITH AdditionRef-weird OR Zlib".into())
        );
        assert_eq!(
            normalize("GPL WITH nothing else"),
            License::Text("GPL WITH nothing else".into())
        );
        assert_eq!(
            rewrite_unknown_exceptions("X WITH AdditionRef-already"),
            "X WITH AdditionRef-already"
        );
        assert!(is_rewritten("LGPL-2.0-or-later WITH exceptions"));
        assert!(!is_rewritten("MIT"));
        assert!(!is_rewritten("MIT/Apache-2.0"), "lax canonicalization is not a rewrite");
        assert!(!is_rewritten("Proprietary"));
    }

    #[test]
    fn rejection_reasons_name_the_offending_token() {
        assert_eq!(rejection_reason("MIT"), None);
        assert_eq!(
            rejection_reason("MIT/Apache-2.0"),
            None,
            "lax spellings are expressions"
        );
        assert_eq!(rejection_reason("LGPL-2.0-or-later WITH exceptions"), None, "rewritten");
        let reason = rejection_reason("Proprietary").unwrap();
        assert!(reason.contains("Proprietary"), "{reason}");
        let reason = rejection_reason("MIT AND (Zlib").unwrap();
        assert!(!reason.is_empty());
        assert_eq!(rejection_reason("  "), Some("empty".into()));
    }

    #[test]
    fn unknown_text_is_passed_through_as_text() {
        assert_eq!(normalize("Proprietary"), License::Text("Proprietary".into()));
        assert_eq!(normalize("PSF"), License::Text("PSF".into()));
        assert_eq!(normalize("   "), License::Text(String::new()));
    }
}
