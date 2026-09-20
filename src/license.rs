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
    match spdx::Expression::parse_mode(trimmed, ParseMode::LAX) {
        Ok(expr) => License::Expression(canonical(&expr)),
        Err(_) => License::Text(trimmed.to_string()),
    }
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
    fn unknown_text_is_passed_through_as_text() {
        assert_eq!(normalize("Proprietary"), License::Text("Proprietary".into()));
        assert_eq!(normalize("PSF"), License::Text("PSF".into()));
        assert_eq!(normalize("   "), License::Text(String::new()));
    }
}
