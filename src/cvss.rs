//! CVSS v3.0 / v3.1 base scores from vector strings, for advisories that give a vector but no
//! qualitative severity.

/// Base score of a `CVSS:3.x/...` vector, or `None` when the vector is not CVSS v3 or is
/// missing a base metric.
pub fn v3_base_score(vector: &str) -> Option<f64> {
    let mut parts = vector.split('/');
    let version = parts.next()?;
    if version != "CVSS:3.0" && version != "CVSS:3.1" {
        return None;
    }
    let mut av = None;
    let mut ac = None;
    let mut pr = None;
    let mut ui = None;
    let mut scope_changed = None;
    let mut c = None;
    let mut i = None;
    let mut a = None;
    for part in parts {
        let (metric, value) = part.split_once(':')?;
        match metric {
            "AV" => {
                av = Some(match value {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.2,
                    _ => return None,
                })
            }
            "AC" => {
                ac = Some(match value {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return None,
                })
            }
            "PR" => pr = Some(value.to_string()),
            "UI" => {
                ui = Some(match value {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return None,
                })
            }
            "S" => {
                scope_changed = Some(match value {
                    "U" => false,
                    "C" => true,
                    _ => return None,
                })
            }
            "C" => c = Some(cia(value)?),
            "I" => i = Some(cia(value)?),
            "A" => a = Some(cia(value)?),
            // Temporal and environmental metrics do not change the base score.
            _ => {}
        }
    }
    let scope_changed = scope_changed?;
    let pr = match (pr?.as_str(), scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let iss = 1.0 - (1.0 - c?) * (1.0 - i?) * (1.0 - a?);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av? * ac? * pr * ui?;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if scope_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(roundup(raw))
}

fn cia(value: &str) -> Option<f64> {
    Some(match value {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    })
}

/// CVSS v3.1 "round up to one decimal" (Appendix A), done on integers to avoid float drift.
fn roundup(value: f64) -> f64 {
    let int_input = (value * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_match_the_first_org_calculator() {
        // Examples from the CVSS v3.1 specification and well-known advisories.
        assert_eq!(v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), Some(7.5));
        assert_eq!(v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some(9.8));
        assert_eq!(v3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), Some(10.0));
        assert_eq!(v3_base_score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"), Some(1.8));
        assert_eq!(v3_base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N"), Some(6.4));
        assert_eq!(v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), Some(0.0));
        // Temporal metrics are ignored.
        assert_eq!(
            v3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P/RL:O/RC:C"),
            Some(7.5)
        );
    }

    #[test]
    fn other_versions_and_broken_vectors_are_none() {
        assert_eq!(v3_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"), None);
        assert_eq!(v3_base_score("CVSS:3.1/AV:N/AC:L"), None);
        assert_eq!(v3_base_score("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"), None);
        assert_eq!(v3_base_score("nonsense"), None);
    }
}
