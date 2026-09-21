//! `--include` / `--exclude` / `--exclude-kind`: drop packages from the model before anything
//! is enriched or written, then re-close the dependency graph so that what only the dropped
//! packages needed goes with them. The document records what was left out.

use std::collections::{BTreeSet, HashSet};

use crate::model::{PackageKind, Sbom};

/// A shell-style pattern over package names: `*` matches any run of characters, `?` one.
/// Matching is case-insensitive and treats `-` and `_` alike, as package names do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    pattern: Vec<char>,
    text: String,
}

impl Glob {
    /// Parse a pattern. Empty patterns are rejected.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("empty pattern".into());
        }
        Ok(Self {
            pattern: normalize(text).chars().collect(),
            text: text.to_string(),
        })
    }

    /// Whether `name` matches.
    pub fn matches(&self, name: &str) -> bool {
        let name: Vec<char> = normalize(name).chars().collect();
        glob_match(&self.pattern, &name)
    }
}

impl std::fmt::Display for Glob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

fn normalize(name: &str) -> String {
    name.to_ascii_lowercase().replace('_', "-")
}

/// Iterative wildcard matching with backtracking on the last `*`.
fn glob_match(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some((p, t));
            p += 1;
        } else if let Some((sp, st)) = star {
            p = sp + 1;
            t = st + 1;
            star = Some((sp, st + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

/// What to drop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// When non-empty, only packages matching one of these are kept.
    pub include: Vec<Glob>,
    /// Packages matching one of these are dropped.
    pub exclude: Vec<Glob>,
    /// Packages of these kinds are dropped.
    pub exclude_kinds: Vec<PackageKind>,
    /// Keep packages that only the dropped ones needed.
    pub keep_orphans: bool,
}

/// What a filter did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Names of the packages the filter matched, sorted.
    pub excluded: Vec<String>,
    /// Names of the packages dropped because only excluded packages needed them, sorted.
    pub orphans: Vec<String>,
}

impl Filter {
    /// Whether anything is filtered at all.
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty() && self.exclude_kinds.is_empty()
    }

    fn matches(&self, name: &str, kind: PackageKind) -> bool {
        if self.exclude_kinds.contains(&kind) || self.exclude.iter().any(|g| g.matches(name)) {
            return true;
        }
        !self.include.is_empty() && !self.include.iter().any(|g| g.matches(name))
    }

    /// Drop the matching packages from `sbom`, re-close the graph, and record the omission in
    /// `sbom.excluded`.
    pub fn apply(&self, sbom: &mut Sbom) -> Outcome {
        let mut outcome = Outcome::default();
        if self.is_empty() {
            return outcome;
        }
        let excluded: HashSet<String> = sbom
            .packages
            .iter()
            .filter(|p| self.matches(&p.name, p.kind))
            .map(|p| p.id.clone())
            .collect();
        outcome.excluded = names(sbom, &excluded);

        // The graph's roots are the packages nothing depends on; after dropping the excluded
        // ones, everything the remaining roots reach stays and the rest were only there for
        // the excluded packages.
        let mut drop = excluded.clone();
        if !self.keep_orphans {
            // Roots are judged on the original graph: a package that only excluded packages
            // depended on is not promoted to a root by their removal.
            let depended_on: HashSet<&str> = sbom
                .packages
                .iter()
                .flat_map(|p| p.dependencies.iter().map(String::as_str))
                .collect();
            let mut reachable: HashSet<String> = HashSet::new();
            let mut stack: Vec<&str> = sbom
                .packages
                .iter()
                .filter(|p| !excluded.contains(&p.id) && !depended_on.contains(p.id.as_str()))
                .map(|p| p.id.as_str())
                .collect();
            while let Some(id) = stack.pop() {
                if !reachable.insert(id.to_string()) {
                    continue;
                }
                if let Some(package) = sbom.packages.iter().find(|p| p.id == id) {
                    stack.extend(
                        package
                            .dependencies
                            .iter()
                            .map(String::as_str)
                            .filter(|d| !excluded.contains(*d)),
                    );
                }
            }
            let orphans: HashSet<String> = sbom
                .packages
                .iter()
                .filter(|p| !excluded.contains(&p.id) && !reachable.contains(&p.id))
                .map(|p| p.id.clone())
                .collect();
            outcome.orphans = names(sbom, &orphans);
            drop.extend(orphans);
        }

        sbom.packages.retain(|p| !drop.contains(&p.id));
        for package in &mut sbom.packages {
            package.dependencies.retain(|d| !drop.contains(d));
        }
        sbom.excluded = outcome.excluded.iter().chain(&outcome.orphans).cloned().collect();
        sbom.excluded.sort();
        sbom.excluded.dedup();
        outcome
    }
}

fn names(sbom: &Sbom, ids: &HashSet<String>) -> Vec<String> {
    sbom.packages
        .iter()
        .filter(|p| ids.contains(&p.id))
        .map(|p| p.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    #[test]
    fn globs_match_like_a_shell_and_ignore_case_and_separators() {
        let g = Glob::parse("pre-commit*").unwrap();
        assert!(g.matches("pre-commit"));
        assert!(g.matches("pre_commit_hooks"));
        assert!(g.matches("Pre-Commit"));
        assert!(!g.matches("precommit"));
        assert!(Glob::parse("py?").unwrap().matches("pyx"));
        assert!(!Glob::parse("py?").unwrap().matches("pyxy"));
        assert!(Glob::parse("*").unwrap().matches("anything"));
        assert!(Glob::parse("*-dev").unwrap().matches("libfoo-dev"));
        assert!(Glob::parse("a*b*c").unwrap().matches("axxbyyc"));
        assert!(!Glob::parse("a*b*c").unwrap().matches("axxbyy"));
        assert!(Glob::parse("  ").is_err());
    }

    #[test]
    fn excluding_a_root_drops_what_only_it_needed() {
        // sample graph: mylib -> zlib -> libzlib; six alone. Roots: mylib, six.
        let mut sbom = sample_sbom();
        let filter = Filter {
            exclude: vec![Glob::parse("mylib").unwrap()],
            ..Filter::default()
        };
        let outcome = filter.apply(&mut sbom);
        assert_eq!(outcome.excluded, ["mylib"]);
        assert_eq!(outcome.orphans, ["libzlib", "zlib"], "only mylib needed them");
        let names: Vec<&str> = sbom.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["six"]);
        assert_eq!(sbom.excluded, ["libzlib", "mylib", "zlib"]);

        // Excluding a leaf keeps everything else and prunes the edge to it.
        let mut sbom = sample_sbom();
        let filter = Filter {
            exclude: vec![Glob::parse("libzlib").unwrap()],
            ..Filter::default()
        };
        let outcome = filter.apply(&mut sbom);
        assert_eq!(outcome.orphans, Vec::<String>::new());
        let names: Vec<&str> = sbom.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["zlib", "mylib", "six"]);
        let zlib = sbom.packages.iter().find(|p| p.name == "zlib").unwrap();
        assert!(zlib.dependencies.is_empty());
    }

    #[test]
    fn orphans_go_unless_kept() {
        // Make libzlib depend on six as well; exclude both roots that reach libzlib.
        let mut sbom = sample_sbom();
        let libzlib = sbom.packages.iter().position(|p| p.name == "libzlib").unwrap();
        sbom.packages[libzlib].dependencies = vec!["pkg:pypi/six@1.17.0".into()];
        let filter = Filter {
            exclude: vec![Glob::parse("zlib").unwrap(), Glob::parse("mylib").unwrap()],
            ..Filter::default()
        };
        let mut dropped = sbom.clone();
        let outcome = filter.apply(&mut dropped);
        assert_eq!(outcome.excluded, ["mylib", "zlib"]);
        assert_eq!(
            outcome.orphans,
            ["libzlib", "six"],
            "six was only reachable through libzlib"
        );
        assert!(dropped.packages.is_empty());
        assert_eq!(dropped.excluded, ["libzlib", "mylib", "six", "zlib"]);

        let keep = Filter {
            keep_orphans: true,
            ..filter
        };
        let mut kept = sbom.clone();
        let outcome = keep.apply(&mut kept);
        assert_eq!(outcome.orphans, Vec::<String>::new());
        let names: Vec<&str> = kept.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["libzlib", "six"]);
        assert_eq!(kept.excluded, ["mylib", "zlib"]);
    }

    #[test]
    fn include_and_kind_filters() {
        let mut sbom = sample_sbom();
        let filter = Filter {
            include: vec![Glob::parse("*zlib").unwrap()],
            keep_orphans: true,
            ..Filter::default()
        };
        filter.apply(&mut sbom);
        let names: Vec<&str> = sbom.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["libzlib", "zlib"]);

        // Excluding every root empties the document unless orphans are kept.
        let mut sbom = sample_sbom();
        let filter = Filter {
            exclude_kinds: vec![PackageKind::Pypi, PackageKind::CondaSource],
            ..Filter::default()
        };
        let outcome = filter.apply(&mut sbom);
        assert_eq!(outcome.excluded, ["mylib", "six"]);
        assert_eq!(outcome.orphans, ["libzlib", "zlib"]);
        assert!(sbom.packages.is_empty());
        let mut sbom = sample_sbom();
        let filter = Filter {
            keep_orphans: true,
            ..filter
        };
        filter.apply(&mut sbom);
        assert_eq!(sbom.packages.len(), 2);
        assert_eq!(Filter::default().apply(&mut sample_sbom()), Outcome::default());
    }
}
