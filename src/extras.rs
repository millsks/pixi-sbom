//! Python extras: which extras a package was installed with, and which packages are in the
//! document only because something asked for an extra.
//!
//! Each reader knows its format's way of saying so and hands over the same three facts: the
//! extras requested of each package, the dependency edges that exist only because of an extra
//! (labelled `requests[socks]`), and the packages the project's own extras bring in directly. This
//! module turns them into two properties:
//!
//! - `pixi:python-extras` on a package installed with extras: `socks,security`.
//! - `pixi:via-extra` on a package that nothing but an extra brings in: `requests[socks]`. A
//!   package an extra-only package depends on is there only because of that extra too, so the
//!   label is carried down the graph until a package is reached that is needed anyway.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::model::Package;

/// The extras a package was installed with.
pub const PYTHON_EXTRAS_PROPERTY: &str = "pixi:python-extras";
/// The extras that brought a package in, as `package[extra]`.
pub const VIA_EXTRA_PROPERTY: &str = "pixi:via-extra";

/// What a reader learned about extras, by package id.
#[derive(Debug, Default)]
pub struct Extras {
    /// The extras each package was asked for, by whatever depends on it.
    pub requested: BTreeMap<String, BTreeSet<String>>,
    /// Edges `(from, to)` that exist only because of an extra of `from`, with that extra's label.
    pub gated: BTreeMap<(String, String), BTreeSet<String>>,
    /// Packages the project's own extras bring in directly, with the label (`project[s3]`).
    pub project: BTreeMap<String, BTreeSet<String>>,
    /// Edges that exist only for an extra nobody asked for: the lockfile lists them, but they do
    /// not make their target needed, and they bring nothing in by themselves.
    pub unrequested: BTreeSet<(String, String)>,
    /// The packages needed whatever extras are chosen. `None` means every package nothing depends
    /// on and that no project extra brings in, which is right for a lockfile that records no root.
    pub roots: Option<BTreeSet<String>>,
}

impl Extras {
    /// Record that `to` was asked for with `extras`.
    pub fn request(&mut self, to: &str, extras: impl IntoIterator<Item = String>) {
        let wanted: BTreeSet<String> = extras.into_iter().filter(|e| !e.is_empty()).collect();
        if !wanted.is_empty() {
            self.requested.entry(to.to_string()).or_default().extend(wanted);
        }
    }

    /// Record an edge that exists only because `from`'s `extra` was asked for.
    pub fn gate(&mut self, from: &str, from_name: &str, extra: &str, to: &str) {
        self.gated
            .entry((from.to_string(), to.to_string()))
            .or_default()
            .insert(format!("{from_name}[{extra}]"));
    }

    /// Write the properties onto `packages`.
    pub fn apply(&self, packages: &mut [Package]) {
        let ids: BTreeSet<&str> = packages.iter().map(|p| p.id.as_str()).collect();
        let edges: BTreeMap<&str, Vec<&str>> = packages
            .iter()
            .map(|p| (p.id.as_str(), p.dependencies.iter().map(String::as_str).collect()))
            .collect();
        let gated = |from: &str, to: &str| {
            let edge = (from.to_string(), to.to_string());
            self.gated.contains_key(&edge) || self.unrequested.contains(&edge)
        };

        // What is needed whatever extras are chosen: everything reachable from the roots along
        // edges no extra gates.
        let roots: BTreeSet<&str> = match &self.roots {
            Some(roots) => roots.iter().map(String::as_str).filter(|id| ids.contains(id)).collect(),
            None => {
                let depended_on: BTreeSet<&str> = edges.values().flatten().copied().collect();
                ids.iter()
                    .copied()
                    .filter(|id| !depended_on.contains(id) && !self.project.contains_key(*id))
                    .collect()
            }
        };
        let mut needed: BTreeSet<&str> = BTreeSet::new();
        let mut queue: VecDeque<&str> = roots.into_iter().collect();
        while let Some(id) = queue.pop_front() {
            if !needed.insert(id) {
                continue;
            }
            for &to in edges.get(id).into_iter().flatten() {
                if !gated(id, to) {
                    queue.push_back(to);
                }
            }
        }

        // Everything else is there because of an extra: label it, and carry the label down.
        let mut labels: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        let mut queue: VecDeque<&str> = VecDeque::new();
        for (id, project) in &self.project {
            if ids.contains(id.as_str()) && !needed.contains(id.as_str()) {
                labels.entry(id.as_str()).or_default().extend(project.iter().cloned());
                queue.push_back(id.as_str());
            }
        }
        for ((from, to), via) in &self.gated {
            if ids.contains(to.as_str()) && !needed.contains(to.as_str()) && ids.contains(from.as_str()) {
                labels.entry(to.as_str()).or_default().extend(via.iter().cloned());
                queue.push_back(to.as_str());
            }
        }
        while let Some(id) = queue.pop_front() {
            let carried = labels.get(id).cloned().unwrap_or_default();
            for &to in edges.get(id).into_iter().flatten() {
                if needed.contains(to) {
                    continue;
                }
                let entry = labels.entry(to).or_default();
                let before = entry.len();
                entry.extend(carried.iter().cloned());
                if entry.len() != before {
                    queue.push_back(to);
                }
            }
        }

        // Owned, so the ids borrowed from `packages` above are let go before it is written to.
        let labels: BTreeMap<String, BTreeSet<String>> =
            labels.into_iter().map(|(id, via)| (id.to_string(), via)).collect();
        for package in packages.iter_mut() {
            if let Some(extras) = self.requested.get(&package.id) {
                package.properties.insert(
                    PYTHON_EXTRAS_PROPERTY.into(),
                    extras.iter().cloned().collect::<Vec<_>>().join(","),
                );
            }
            if let Some(via) = labels.get(&package.id).filter(|v| !v.is_empty()) {
                package.properties.insert(
                    VIA_EXTRA_PROPERTY.into(),
                    via.iter().cloned().collect::<Vec<_>>().join(","),
                );
            }
        }
    }
}

/// The extra a PEP 751 dependency group stands for once [`pep751_marker`] has rewritten it.
pub const GROUP_EXTRA_PREFIX: &str = "dependency-group-";

/// A PEP 751 marker in the PEP 508 form the marker parser knows: `'s3' in extras` becomes
/// `extra == 's3'`, and `'dev' in dependency_groups` becomes `extra == 'dependency-group-dev'`
/// (`not in` likewise, with `!=`). Anything else is left as written.
pub fn pep751_marker(marker: &str) -> String {
    let mut out = String::with_capacity(marker.len());
    let mut rest = marker;
    loop {
        let quote = rest.find(['\'', '"']);
        let Some(start) = quote else {
            out.push_str(rest);
            return out;
        };
        let q = rest[start..].chars().next().unwrap_or('\'');
        let Some(len) = rest[start + 1..].find(q) else {
            out.push_str(rest);
            return out;
        };
        let value = &rest[start + 1..start + 1 + len];
        let after = &rest[start + len + 2..];
        let words: Vec<&str> = after.split_whitespace().take(3).collect();
        let (negated, set) = match words.as_slice() {
            ["not", "in", set, ..] => (true, *set),
            ["in", set, ..] => (false, *set),
            _ => (false, ""),
        };
        let set_name = set.trim_end_matches(')');
        let prefix = match set_name {
            "extras" => Some(""),
            "dependency_groups" => Some(GROUP_EXTRA_PREFIX),
            _ => None,
        };
        out.push_str(&rest[..start]);
        match prefix {
            Some(prefix) => {
                let op = if negated { "!=" } else { "==" };
                out.push_str(&format!("extra {op} '{prefix}{value}'"));
                // Skip past the set's name, keeping any closing parenthesis.
                let at = after.find(set_name).map_or(after.len(), |i| i + set_name.len());
                rest = &after[at..];
            }
            None => {
                out.push_str(&rest[start..start + len + 2]);
                rest = after;
            }
        }
    }
}

/// The extras a marker gates on: `socks` in `extra == "socks" and python_version < "3.12"`.
pub fn gating_extras(marker: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = marker;
    while let Some(at) = rest.find("extra") {
        rest = &rest[at + "extra".len()..];
        let after = rest.trim_start();
        let Some(after) = after.strip_prefix("==") else {
            continue;
        };
        let after = after.trim_start();
        let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            continue;
        };
        if let Some(end) = after[1..].find(quote) {
            out.push(after[1..1 + end].to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::PackageKind;

    fn package(id: &str, deps: &[&str]) -> Package {
        let mut p = crate::format::testing::sample_sbom().packages.remove(0);
        p.id = id.into();
        p.name = id.into();
        p.kind = PackageKind::Pypi;
        p.properties.clear();
        p.dependencies = deps.iter().map(|d| d.to_string()).collect();
        p
    }

    fn props(packages: &[Package], id: &str, key: &str) -> Option<String> {
        packages
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.properties.get(key).cloned())
    }

    #[test]
    fn a_package_only_an_extra_needs_is_labelled_and_so_is_what_it_brings() {
        // app -> requests -[socks]-> pysocks -> win-inet ; requests -> urllib3 ; app -> urllib3
        let mut packages = vec![
            package("app", &["requests", "urllib3"]),
            package("requests", &["pysocks", "urllib3"]),
            package("pysocks", &["win-inet"]),
            package("win-inet", &[]),
            package("urllib3", &[]),
        ];
        let mut extras = Extras::default();
        extras.request("requests", ["socks".to_string()]);
        extras.gate("requests", "requests", "socks", "pysocks");
        extras.apply(&mut packages);
        assert_eq!(
            props(&packages, "requests", PYTHON_EXTRAS_PROPERTY).as_deref(),
            Some("socks")
        );
        assert_eq!(
            props(&packages, "pysocks", VIA_EXTRA_PROPERTY).as_deref(),
            Some("requests[socks]")
        );
        assert_eq!(
            props(&packages, "win-inet", VIA_EXTRA_PROPERTY).as_deref(),
            Some("requests[socks]"),
            "carried down"
        );
        assert_eq!(props(&packages, "urllib3", VIA_EXTRA_PROPERTY), None, "needed anyway");
        assert_eq!(props(&packages, "app", VIA_EXTRA_PROPERTY), None);
    }

    #[test]
    fn a_package_also_needed_without_the_extra_is_not_labelled() {
        let mut packages = vec![package("a", &["b", "c"]), package("b", &["c"]), package("c", &[])];
        let mut extras = Extras::default();
        extras.gate("b", "b", "x", "c");
        extras.apply(&mut packages);
        assert_eq!(props(&packages, "c", VIA_EXTRA_PROPERTY), None, "a needs c directly");
    }

    #[test]
    fn the_projects_own_extras_and_explicit_roots() {
        let mut packages = vec![
            package("django", &[]),
            package("storages", &["boto3"]),
            package("boto3", &[]),
        ];
        let mut extras = Extras::default();
        extras
            .project
            .entry("storages".into())
            .or_default()
            .insert("app[s3]".into());
        extras.roots = Some(["django".to_string()].into());
        extras.apply(&mut packages);
        assert_eq!(
            props(&packages, "storages", VIA_EXTRA_PROPERTY).as_deref(),
            Some("app[s3]")
        );
        assert_eq!(
            props(&packages, "boto3", VIA_EXTRA_PROPERTY).as_deref(),
            Some("app[s3]")
        );
        assert_eq!(props(&packages, "django", VIA_EXTRA_PROPERTY), None);
    }

    #[test]
    fn pep_751_markers_are_rewritten_for_the_parser() {
        assert_eq!(pep751_marker("'s3' in extras"), "extra == 's3'");
        assert_eq!(
            pep751_marker("(\"dev\" in dependency_groups) and sys_platform == 'linux'"),
            "(extra == 'dependency-group-dev') and sys_platform == 'linux'"
        );
        assert_eq!(
            pep751_marker("'a' not in extras or 'b' in extras"),
            "extra != 'a' or extra == 'b'"
        );
        assert_eq!(pep751_marker("sys_platform == 'win32'"), "sys_platform == 'win32'");
        assert_eq!(pep751_marker("'unterminated"), "'unterminated");
        for marker in [
            "'s3' in extras and python_version >= '3.12'",
            "'dev' in dependency_groups",
        ] {
            use std::str::FromStr;
            assert!(
                pep508_rs::MarkerTree::from_str(&pep751_marker(marker)).is_ok(),
                "{marker}"
            );
        }
    }

    #[test]
    fn markers_name_the_extras_they_gate_on() {
        assert_eq!(gating_extras("extra == \"socks\""), ["socks"]);
        assert_eq!(
            gating_extras("python_version < '3.12' and extra == 'argon2'"),
            ["argon2"]
        );
        assert_eq!(gating_extras("extra == 'a' or extra=='b'"), ["a", "b"]);
        assert!(gating_extras("sys_platform == 'win32'").is_empty());
        assert!(gating_extras("extras_require == 'x' and extra").is_empty());
        assert!(
            gating_extras("extra != 'x'").is_empty(),
            "a negated extra gates nothing in"
        );
    }
}
