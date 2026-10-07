//! Which packages the project needs to run, and which only for development or an optional
//! extra, so the writers can say so in each format's own field: CycloneDX `scope`, SPDX 2.3
//! `DEV_DEPENDENCY_OF` / `OPTIONAL_DEPENDENCY_OF`, SPDX 3 `LifecycleScopedRelationship`.
//!
//! Only an input that distinguishes the two gets scopes: a manifest beside a non-pixi lockfile
//! with dependency groups or extras, or a conda-lock file with categories besides `main`. A
//! `pixi.lock` environment is already one selection of features, so it gets none.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::model::Package;

/// What a package is in the document for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Reachable from what the project needs at run time.
    Required,
    /// Reachable only through one of the project's extras.
    Optional,
    /// Reachable only through a dependency group (development, tests, docs).
    Development,
}

impl Scope {
    /// The CycloneDX `component.scope` value.
    pub fn cyclonedx(self) -> &'static str {
        match self {
            Scope::Required => "required",
            Scope::Optional | Scope::Development => "optional",
        }
    }

    /// The conda-lock `category` a package was locked under: `main` is what the environment
    /// needs, `dev` is development, any other category an optional extra.
    pub fn from_category(category: &str) -> Self {
        match category {
            "main" => Scope::Required,
            "dev" => Scope::Development,
            _ => Scope::Optional,
        }
    }
}

/// The scope of every package reachable from the roots: required from `required`, then
/// optional from `optional`, then development from `development`, each claiming only what the
/// ones before it have not. A package reachable from none of them gets no scope.
pub fn assign(
    packages: &[Package],
    required: &BTreeSet<String>,
    optional: &BTreeSet<String>,
    development: &BTreeSet<String>,
) -> BTreeMap<String, Scope> {
    let edges: BTreeMap<&str, &[String]> = packages
        .iter()
        .map(|p| (p.id.as_str(), p.dependencies.as_slice()))
        .collect();
    let mut scopes: BTreeMap<String, Scope> = BTreeMap::new();
    for (roots, scope) in [
        (required, Scope::Required),
        (optional, Scope::Optional),
        (development, Scope::Development),
    ] {
        let mut queue: VecDeque<&str> = roots.iter().map(String::as_str).collect();
        while let Some(id) = queue.pop_front() {
            if scopes.contains_key(id) || !edges.contains_key(id) {
                continue;
            }
            scopes.insert(id.to_string(), scope);
            queue.extend(edges[id].iter().map(String::as_str));
        }
    }
    scopes
}

/// The scope an edge into `to` crosses into, when it leaves what `from` was there for:
/// `from` is `None` for the root, which is required. `None` when the edge stays in one scope
/// or leads into what is required anyway.
pub fn crossing(scopes: &BTreeMap<String, Scope>, from: Option<&str>, to: &str) -> Option<Scope> {
    let target = *scopes.get(to)?;
    let source = match from {
        None => Scope::Required,
        Some(from) => *scopes.get(from)?,
    };
    (target != Scope::Required && target != source).then_some(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(id: &str, deps: &[&str]) -> Package {
        let mut p = crate::format::testing::sample_sbom().packages.remove(0);
        p.id = id.into();
        p.dependencies = deps.iter().map(|d| d.to_string()).collect();
        p
    }

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn required_wins_then_optional_then_development() {
        // django -> sqlparse ; pytest -> pluggy, sqlparse ; storages -> boto3 ; mypy -> boto3
        let packages = vec![
            package("django", &["sqlparse"]),
            package("sqlparse", &[]),
            package("pytest", &["pluggy", "sqlparse"]),
            package("pluggy", &[]),
            package("storages", &["boto3"]),
            package("boto3", &[]),
            package("mypy", &["boto3"]),
            package("stray", &[]),
        ];
        let scopes = assign(
            &packages,
            &set(&["django"]),
            &set(&["storages"]),
            &set(&["pytest", "mypy"]),
        );
        assert_eq!(scopes["django"], Scope::Required);
        assert_eq!(scopes["sqlparse"], Scope::Required, "shared with a group, so required");
        assert_eq!(scopes["pytest"], Scope::Development);
        assert_eq!(scopes["pluggy"], Scope::Development);
        assert_eq!(scopes["storages"], Scope::Optional);
        assert_eq!(scopes["boto3"], Scope::Optional, "an extra claims it before a group");
        assert_eq!(scopes["mypy"], Scope::Development);
        assert!(!scopes.contains_key("stray"), "reachable from nothing declared");
        assert!(
            assign(&packages, &set(&["missing"]), &set(&[]), &set(&[])).is_empty(),
            "a root with no package"
        );

        assert_eq!(crossing(&scopes, None, "pytest"), Some(Scope::Development));
        assert_eq!(crossing(&scopes, None, "django"), None);
        assert_eq!(crossing(&scopes, Some("pytest"), "pluggy"), None, "inside the group");
        assert_eq!(crossing(&scopes, Some("pytest"), "sqlparse"), None, "required anyway");
        assert_eq!(crossing(&scopes, Some("mypy"), "boto3"), Some(Scope::Optional));
        assert_eq!(crossing(&scopes, Some("stray"), "pytest"), None, "an unscoped source");
    }

    #[test]
    fn format_values_and_conda_lock_categories() {
        assert_eq!(Scope::Required.cyclonedx(), "required");
        assert_eq!(Scope::Optional.cyclonedx(), "optional");
        assert_eq!(Scope::Development.cyclonedx(), "optional");
        assert_eq!(Scope::from_category("main"), Scope::Required);
        assert_eq!(Scope::from_category("dev"), Scope::Development);
        assert_eq!(Scope::from_category("docs"), Scope::Optional);
    }
}
