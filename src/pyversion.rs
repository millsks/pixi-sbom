//! What each package says about the Python it runs on, and which of them stand between the
//! environment and the next interpreter.
//!
//! The facts are already in the document: `pixi:requires-python` on every PyPI package (from
//! the lockfile or the wheel's `dist-info`) and the environment's own `python` package. This
//! reads the PEP 440 specifier well enough to answer two questions: does the environment's
//! interpreter satisfy it, and what is the highest Python minor version it still allows.

use crate::model::{PackageKind, Sbom};

/// The property every PyPI package carries when it names a Python requirement.
pub const REQUIRES_PYTHON_PROPERTY: &str = "pixi:requires-python";

/// A `MAJOR.MINOR` Python version, which is the granularity every interesting question is
/// asked at: nobody is blocked from 3.14 by a patch release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PyVersion {
    pub major: u32,
    pub minor: u32,
}

impl std::fmt::Display for PyVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl PyVersion {
    /// Parse the leading `MAJOR.MINOR` of a version string; the rest is ignored.
    pub fn parse(version: &str) -> Option<Self> {
        let mut parts = version
            .trim()
            .trim_start_matches(['=', '>', '<', '~', '!', ' '])
            .split('.');
        let major = digits(parts.next()?)?;
        // `3` alone means the whole 3.x series, whose lowest member is 3.0.
        let minor = parts.next().and_then(digits).unwrap_or(0);
        Some(Self { major, minor })
    }

    /// The next minor version, for turning an exclusive bound into an inclusive one.
    fn previous_minor(self) -> Option<Self> {
        self.minor.checked_sub(1).map(|minor| Self {
            major: self.major,
            minor,
        })
    }
}

fn digits(text: &str) -> Option<u32> {
    let digits: String = text.trim().chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// What one package's `Requires-Python` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The specifier as written.
    pub specifier: String,
    /// The lowest version it admits, when it names one.
    pub lowest: Option<PyVersion>,
    /// The highest minor version it admits, when it has an upper bound.
    pub highest: Option<PyVersion>,
    /// Minor versions it excludes outright (`!=3.9.*`).
    pub excluded: Vec<PyVersion>,
}

impl Requirement {
    /// Parse a PEP 440 specifier set (`>=3.9`, `>=3.8,<3.13`, `>=2.7,!=3.0.*`).
    pub fn parse(specifier: &str) -> Self {
        let mut requirement = Self {
            specifier: specifier.trim().to_string(),
            lowest: None,
            highest: None,
            excluded: Vec::new(),
        };
        for clause in specifier.split(',') {
            let clause = clause.trim();
            let (operator, version) = split_operator(clause);
            let Some(version) = PyVersion::parse(version) else {
                continue;
            };
            match operator {
                ">=" | ">" | "==" | "~=" => {
                    // `>3.8` admits 3.9 upward, but at this granularity the distinction only
                    // matters for the lowest bound, which is not what blocks an upgrade.
                    requirement.lowest = Some(requirement.lowest.map_or(version, |l: PyVersion| l.max(version)));
                    if operator == "==" {
                        requirement.highest = Some(version);
                    }
                }
                "<=" => requirement.highest = Some(requirement.highest.map_or(version, |h: PyVersion| h.min(version))),
                "<" => {
                    // `<3.13` admits up to 3.12; `<4` admits the whole 3.x series, which this
                    // granularity cannot express, so it is not a ceiling worth reporting.
                    if let Some(highest) = version.previous_minor() {
                        requirement.highest = Some(requirement.highest.map_or(highest, |h: PyVersion| h.min(highest)));
                    }
                }
                "!=" => requirement.excluded.push(version),
                _ => {}
            }
        }
        requirement
    }

    /// Whether `version` satisfies this requirement at `MAJOR.MINOR` granularity.
    pub fn allows(&self, version: PyVersion) -> bool {
        self.lowest.is_none_or(|lowest| version >= lowest)
            && self.highest.is_none_or(|highest| version <= highest)
            && !self.excluded.contains(&version)
    }
}

fn split_operator(clause: &str) -> (&str, &str) {
    for operator in [">=", "<=", "==", "!=", "~=", ">", "<"] {
        if let Some(rest) = clause.strip_prefix(operator) {
            return (operator, rest);
        }
    }
    ("", clause)
}

/// One package's answer, as the report prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub kind: &'static str,
    pub version: String,
    /// The specifier as written, when the package names one.
    pub requires: Option<String>,
    /// Whether the environment's interpreter satisfies it.
    pub satisfied: bool,
    /// The highest minor version the package still allows, when it has a ceiling.
    pub ceiling: Option<PyVersion>,
}

/// The environment's own interpreter, from its `python` package.
pub fn interpreter(sbom: &Sbom) -> Option<PyVersion> {
    sbom.packages
        .iter()
        .find(|p| p.name == "python" && p.kind != PackageKind::Pypi)
        .and_then(|p| p.version.as_deref())
        .and_then(PyVersion::parse)
}

/// One row per package that says something about Python: every PyPI package, and any conda
/// package that depends on a specific interpreter.
pub fn rows(sbom: &Sbom) -> Vec<Row> {
    let interpreter = interpreter(sbom);
    let mut rows: Vec<Row> = sbom
        .packages
        .iter()
        .filter(|p| p.kind == PackageKind::Pypi)
        .map(|package| {
            let requires = package.properties.get(REQUIRES_PYTHON_PROPERTY).cloned();
            let requirement = requires.as_deref().map(Requirement::parse);
            Row {
                name: package.name.clone(),
                kind: package.kind.name(),
                version: package.version.clone().unwrap_or_else(|| "-".into()),
                satisfied: match (&requirement, interpreter) {
                    (Some(requirement), Some(interpreter)) => requirement.allows(interpreter),
                    _ => true,
                },
                ceiling: requirement.as_ref().and_then(|r| r.highest),
                requires,
            }
        })
        .collect();
    // Lowest ceiling first, then the unbounded ones by name: what blocks an upgrade comes up
    // the screen first.
    rows.sort_by(|a, b| match (a.ceiling, b.ceiling) {
        (Some(a_ceiling), Some(b_ceiling)) => a_ceiling.cmp(&b_ceiling).then_with(|| a.name.cmp(&b.name)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.name.cmp(&b.name),
    });
    rows
}

/// What the summary says about the environment as a whole.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// The environment's interpreter, when it has one.
    pub interpreter: Option<String>,
    /// The lowest ceiling among the packages: the highest Python this environment can move to
    /// without dropping something.
    pub ceiling: Option<String>,
    /// The packages that impose that ceiling.
    pub blocking: Vec<String>,
    /// Packages whose requirement the current interpreter does not satisfy.
    pub unsatisfied: Vec<String>,
    /// Packages that say nothing about Python.
    pub unconstrained: usize,
}

/// Reduce the rows into the summary.
pub fn summarize(sbom: &Sbom, rows: &[Row]) -> Summary {
    let ceiling = rows.iter().filter_map(|row| row.ceiling).min();
    Summary {
        interpreter: interpreter(sbom).map(|v| v.to_string()),
        ceiling: ceiling.map(|v| v.to_string()),
        blocking: rows
            .iter()
            .filter(|row| row.ceiling == ceiling && ceiling.is_some())
            .map(|row| format!("{} {}", row.name, row.requires.clone().unwrap_or_default()))
            .collect(),
        unsatisfied: rows
            .iter()
            .filter(|row| !row.satisfied)
            .map(|row| format!("{} {}", row.name, row.requires.clone().unwrap_or_default()))
            .collect(),
        unconstrained: rows.iter().filter(|row| row.requires.is_none()).count(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    fn version(major: u32, minor: u32) -> PyVersion {
        PyVersion { major, minor }
    }

    #[test]
    fn versions_parse_to_major_and_minor() {
        assert_eq!(PyVersion::parse("3.12.14"), Some(version(3, 12)));
        assert_eq!(PyVersion::parse("3.9"), Some(version(3, 9)));
        assert_eq!(PyVersion::parse("3"), Some(version(3, 0)));
        assert_eq!(PyVersion::parse("3.13.0rc1"), Some(version(3, 13)));
        assert_eq!(PyVersion::parse("3.*"), Some(version(3, 0)));
        assert_eq!(PyVersion::parse("not a version"), None);
        assert_eq!(version(3, 9).to_string(), "3.9");
    }

    #[test]
    fn specifiers_give_a_floor_a_ceiling_and_exclusions() {
        let open = Requirement::parse(">=3.9");
        assert_eq!(open.lowest, Some(version(3, 9)));
        assert_eq!(open.highest, None);
        assert!(open.allows(version(3, 14)));
        assert!(!open.allows(version(3, 8)));

        let bounded = Requirement::parse(">=3.8,<3.13");
        assert_eq!(
            bounded.highest,
            Some(version(3, 12)),
            "an exclusive bound is one minor lower"
        );
        assert!(bounded.allows(version(3, 12)));
        assert!(!bounded.allows(version(3, 13)));

        // `<4` bounds the major, which says nothing about how high within 3.x you may go.
        assert_eq!(Requirement::parse(">=3.7,<4").highest, None);

        let excluded = Requirement::parse(">=2.7,!=3.0.*,!=3.1.*,!=3.2.*");
        assert_eq!(excluded.excluded, [version(3, 0), version(3, 1), version(3, 2)]);
        assert!(excluded.allows(version(3, 12)));
        assert!(!excluded.allows(version(3, 1)));

        assert_eq!(Requirement::parse("<=3.11").highest, Some(version(3, 11)));
        assert_eq!(Requirement::parse("==3.10").highest, Some(version(3, 10)));
        // The tightest of several bounds wins.
        let several = Requirement::parse(">=3.8,<3.13,<=3.10");
        assert_eq!(several.highest, Some(version(3, 10)));
        assert_eq!(several.lowest, Some(version(3, 8)));
        // Nonsense is ignored rather than guessed at.
        let empty = Requirement::parse("");
        assert_eq!(empty.lowest, None);
        assert!(empty.allows(version(3, 14)));
    }

    /// The sample with an interpreter and three wheels: one unbounded, one that blocks the
    /// next upgrade, one that the interpreter already fails.
    fn constrained_sbom() -> Sbom {
        let mut sbom = sample_sbom();
        let template = sbom
            .packages
            .iter()
            .find(|p| p.kind == PackageKind::Pypi)
            .unwrap()
            .clone();
        sbom.packages.retain(|p| p.kind != PackageKind::Pypi);
        let python = sbom.packages.iter_mut().find(|p| p.name == "libzlib").unwrap();
        python.name = "python".into();
        python.version = Some("3.12.14".into());
        for (name, requires) in [
            ("open-wheel", Some(">=3.9")),
            ("ceiling-wheel", Some(">=3.8,<3.13")),
            ("too-new-wheel", Some(">=3.13")),
            ("silent-wheel", None),
        ] {
            let mut package = template.clone();
            package.id = format!("pkg:pypi/{name}@1.0");
            package.name = name.into();
            package.version = Some("1.0".into());
            package.properties.remove(REQUIRES_PYTHON_PROPERTY);
            if let Some(requires) = requires {
                package
                    .properties
                    .insert(REQUIRES_PYTHON_PROPERTY.into(), requires.into());
            }
            sbom.packages.push(package);
        }
        sbom
    }

    #[test]
    fn rows_name_the_ceiling_and_the_packages_that_impose_it() {
        let sbom = constrained_sbom();
        assert_eq!(interpreter(&sbom), Some(version(3, 12)));
        let rows = rows(&sbom);
        assert_eq!(rows.len(), 4, "one row per wheel");
        assert_eq!(rows[0].name, "ceiling-wheel", "the lowest ceiling comes first");
        assert_eq!(rows[0].ceiling, Some(version(3, 12)));
        assert!(rows[0].satisfied);
        let too_new = rows.iter().find(|r| r.name == "too-new-wheel").unwrap();
        assert!(!too_new.satisfied, "3.12 does not satisfy >=3.13");
        let silent = rows.iter().find(|r| r.name == "silent-wheel").unwrap();
        assert_eq!(silent.requires, None);
        assert!(silent.satisfied, "saying nothing constrains nothing");

        let summary = summarize(&sbom, &rows);
        assert_eq!(summary.interpreter.as_deref(), Some("3.12"));
        assert_eq!(summary.ceiling.as_deref(), Some("3.12"));
        assert_eq!(summary.blocking, ["ceiling-wheel >=3.8,<3.13"]);
        assert_eq!(summary.unsatisfied, ["too-new-wheel >=3.13"]);
        assert_eq!(summary.unconstrained, 1);
    }

    #[test]
    fn an_environment_without_an_interpreter_or_ceilings() {
        let mut sbom = sample_sbom();
        sbom.packages.retain(|p| p.kind == PackageKind::Pypi);
        for package in &mut sbom.packages {
            package
                .properties
                .insert(REQUIRES_PYTHON_PROPERTY.into(), ">=3.9".into());
        }
        assert_eq!(interpreter(&sbom), None);
        let rows = rows(&sbom);
        assert!(rows.iter().all(|r| r.satisfied), "nothing to check against");
        let summary = summarize(&sbom, &rows);
        assert_eq!(summary.interpreter, None);
        assert_eq!(summary.ceiling, None);
        assert!(summary.blocking.is_empty());
    }
}
