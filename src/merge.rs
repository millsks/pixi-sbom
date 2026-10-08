//! Several SBOMs as one document: `--from-sbom` given more than once, or `--scan --merge`. A
//! consumer that takes one document per product gets the per-project documents of a monorepo,
//! or an application and the SBOMs of the vendor components it ships, without another tool.
//!
//! Packages are the same package when their purls are; the first input's copy is kept, the
//! others add their extra purls and the properties it lacks, and a disagreement about the
//! license or a hash is logged and recorded on the package (`pixi:merge-conflict`) rather than
//! settled silently. Each input's root becomes a package of its own that depends on what that
//! input's root depended on, and the merged root depends on each of them, so every input's graph
//! survives. Every package names the inputs it came from (`pixi:source-document`).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::fromsbom::SOURCE_DOCUMENT_PROPERTY;
use crate::model::{Incomplete, Package, PackageKind, Root, Sbom};

/// Where a package's disagreement between inputs is recorded.
pub const CONFLICT_PROPERTY: &str = "pixi:merge-conflict";

/// One document to merge, with the name provenance gives it.
#[derive(Debug, Clone)]
pub struct Input {
    /// What `pixi:source-document` says for its packages: the document's identity, its
    /// lockfile, or its file name.
    pub name: String,
    pub sbom: Sbom,
}

/// The package an input's root becomes, depending on what the root depended on.
fn root_package(input: &Input, top_level: Vec<String>) -> Package {
    let root = &input.sbom.root;
    let version = root.version.clone();
    let purl = version
        .as_deref()
        .and_then(|v| crate::purl::generic(&root.name, v).ok())
        .unwrap_or_else(|| format!("pkg:generic/{}", root.name));
    let mut properties = BTreeMap::new();
    properties.insert(SOURCE_DOCUMENT_PROPERTY.to_string(), input.name.clone());
    Package {
        id: purl.clone(),
        name: root.name.clone(),
        version,
        kind: PackageKind::External,
        purl,
        supplier: None,
        extra_purls: Vec::new(),
        purls_from_lock: false,
        location: String::new(),
        sha256: None,
        md5: None,
        license: root.license.clone(),
        license_files: Vec::new(),
        description: None,
        homepage: root.homepage.clone(),
        repository: root.repository.clone(),
        documentation: None,
        yanked: None,
        properties,
        dependencies: top_level,
    }
}

/// Whether `purl` names a package the way two documents can agree on.
fn is_purl(purl: &str) -> bool {
    purl.starts_with("pkg:")
}

/// What two copies of one package disagree about, as `license: MIT (a.json) vs Apache-2.0 (b.json)`.
fn conflicts(kept: &Package, kept_from: &str, other: &Package, other_from: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut check = |field: &str, a: &Option<String>, b: &Option<String>| {
        if let (Some(a), Some(b)) = (a, b)
            && !a.eq_ignore_ascii_case(b)
        {
            found.push(format!("{field}: {a} ({kept_from}) vs {b} ({other_from})"));
        }
    };
    check("license", &kept.license, &other.license);
    check("sha256", &kept.sha256, &other.sha256);
    check("md5", &kept.md5, &other.md5);
    found
}

/// Merge `inputs` into one document under `root`.
pub fn merge(inputs: &[Input], root: Root) -> Sbom {
    let mut packages: Vec<Package> = Vec::new();
    let mut by_purl: HashMap<String, usize> = HashMap::new();
    let mut by_id: HashMap<String, usize> = HashMap::new();
    let mut sources: Vec<BTreeSet<String>> = Vec::new();
    let mut kept_from: Vec<String> = Vec::new();

    for (n, input) in inputs.iter().enumerate() {
        // This input's ids, as the merged document spells them.
        let mut ids: HashMap<String, String> = HashMap::new();
        let top_level: Vec<String> = crate::format::top_level_ids(&input.sbom)
            .into_iter()
            .map(str::to_string)
            .collect();
        for package in &input.sbom.packages {
            if is_purl(&package.purl)
                && let Some(&at) = by_purl.get(&package.purl)
            {
                let kept = &mut packages[at];
                ids.insert(package.id.clone(), kept.id.clone());
                for conflict in conflicts(kept, &kept_from[at], package, &input.name) {
                    tracing::warn!(package = %kept.name, conflict, "the merged documents disagree; keeping the first");
                    let entry = kept.properties.entry(CONFLICT_PROPERTY.to_string()).or_default();
                    if !entry.is_empty() {
                        entry.push_str("; ");
                    }
                    entry.push_str(&conflict);
                }
                for purl in &package.extra_purls {
                    if !kept.extra_purls.contains(purl) {
                        kept.extra_purls.push(purl.clone());
                    }
                }
                for (key, value) in &package.properties {
                    kept.properties.entry(key.clone()).or_insert_with(|| value.clone());
                }
                kept.license = kept.license.take().or_else(|| package.license.clone());
                kept.sha256 = kept.sha256.take().or_else(|| package.sha256.clone());
                kept.md5 = kept.md5.take().or_else(|| package.md5.clone());
                kept.supplier = kept.supplier.take().or_else(|| package.supplier.clone());
                kept.repository = kept.repository.take().or_else(|| package.repository.clone());
                kept.homepage = kept.homepage.take().or_else(|| package.homepage.clone());
                sources[at].insert(input.name.clone());
                continue;
            }
            // A new package; an id another input already used is made unique, since two
            // documents' `SPDXRef-Package-1` are not the same package.
            let mut id = package.id.clone();
            if by_id.contains_key(&id) {
                id = format!("{id}#{}", n + 1);
            }
            ids.insert(package.id.clone(), id.clone());
            let mut copy = package.clone();
            copy.id = id.clone();
            by_id.insert(id, packages.len());
            if is_purl(&package.purl) {
                by_purl.insert(package.purl.clone(), packages.len());
            }
            sources.push(BTreeSet::from([input.name.clone()]));
            kept_from.push(input.name.clone());
            packages.push(copy);
        }
        // Edges, in the merged ids; a package two inputs share keeps both inputs' edges.
        for package in &input.sbom.packages {
            let Some(&at) = ids.get(&package.id).and_then(|id| by_id.get(id)) else {
                continue;
            };
            for dependency in &package.dependencies {
                let target = ids.get(dependency).cloned().unwrap_or_else(|| dependency.clone());
                if !packages[at].dependencies.contains(&target) {
                    packages[at].dependencies.push(target);
                }
            }
        }
        let mut root_package = root_package(input, top_level.iter().filter_map(|id| ids.get(id).cloned()).collect());
        if by_id.contains_key(&root_package.id) {
            root_package.id = format!("{}#{}", root_package.id, n + 1);
        }
        by_id.insert(root_package.id.clone(), packages.len());
        sources.push(BTreeSet::from([input.name.clone()]));
        kept_from.push(input.name.clone());
        packages.push(root_package);
    }
    for (package, from) in packages.iter_mut().zip(&sources) {
        // What a workspace declared hangs off that workspace's root package now, not the
        // merged root.
        package.properties.remove(crate::manifest::DIRECT_PROPERTY);
        package.properties.insert(
            SOURCE_DOCUMENT_PROPERTY.to_string(),
            from.iter().cloned().collect::<Vec<_>>().join(", "),
        );
    }
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let same = |field: fn(&Sbom) -> &str| {
        let first = inputs.first().map(|i| field(&i.sbom)).unwrap_or_default();
        inputs
            .iter()
            .all(|i| field(&i.sbom) == first)
            .then(|| first.to_string())
    };
    let mut incomplete = Incomplete::default();
    for input in inputs {
        for note in &input.sbom.incomplete.steps {
            incomplete.note(format!("{}: {note}", input.name));
        }
        incomplete.stale.extend(input.sbom.incomplete.stale.iter().cloned());
    }
    let interpreter = inputs.first().and_then(|i| i.sbom.interpreter.clone());
    Sbom {
        root,
        environment: same(|s| &s.environment).unwrap_or_else(|| "merged".to_string()),
        platform: same(|s| &s.platform).unwrap_or_default(),
        lockfile: String::new(),
        prefix: None,
        document: Some(inputs.iter().map(|i| i.name.as_str()).collect::<Vec<_>>().join(", ")),
        packages,
        vulnerabilities: Vec::new(),
        excluded: inputs.iter().flat_map(|i| i.sbom.excluded.iter().cloned()).collect(),
        declared_missing: Vec::new(),
        incomplete,
        lifecycles: inputs
            .iter()
            .flat_map(|i| i.sbom.lifecycles.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        declared_roots: false,
        scopes: inputs
            .iter()
            .flat_map(|i| i.sbom.scopes.iter().map(|(k, v)| (k.clone(), *v)))
            .collect(),
        interpreter: interpreter.filter(|first| inputs.iter().all(|i| i.sbom.interpreter.as_ref() == Some(first))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    fn input(name: &str, sbom: Sbom) -> Input {
        Input {
            name: name.to_string(),
            sbom,
        }
    }

    fn named<'a>(sbom: &'a Sbom, name: &str) -> Vec<&'a Package> {
        sbom.packages.iter().filter(|p| p.name == name).collect()
    }

    #[test]
    fn one_document_merged_with_itself_keeps_one_copy_and_both_roots() {
        let a = sample_sbom();
        let mut b = sample_sbom();
        b.root.name = "other".into();
        let merged = merge(
            &[input("a.json", a.clone()), input("b.json", b)],
            Root {
                name: "product".into(),
                ..Root::default()
            },
        );
        assert_eq!(merged.root.name, "product");
        // Every package once, plus the two input roots.
        assert_eq!(merged.packages.len(), a.packages.len() + 2);
        let six = named(&merged, "six")[0];
        assert_eq!(six.properties[SOURCE_DOCUMENT_PROPERTY], "a.json, b.json");
        assert!(!six.properties.contains_key(CONFLICT_PROPERTY));
        // The input roots are what the merged root depends on, and each keeps its edges.
        let top: Vec<&str> = crate::format::top_level_ids(&merged);
        let demo = named(&merged, &a.root.name)[0];
        let other = named(&merged, "other")[0];
        assert_eq!(top.len(), 2, "{top:?}");
        assert!(top.contains(&demo.id.as_str()) && top.contains(&other.id.as_str()));
        assert_eq!(demo.kind, PackageKind::External);
        assert_eq!(demo.properties[SOURCE_DOCUMENT_PROPERTY], "a.json");
        assert!(!demo.dependencies.is_empty());
        assert_eq!(demo.dependencies.len(), other.dependencies.len());
        // Every edge points at a package that exists.
        let ids: BTreeSet<&str> = merged.packages.iter().map(|p| p.id.as_str()).collect();
        for package in &merged.packages {
            for dependency in &package.dependencies {
                assert!(ids.contains(dependency.as_str()), "{} -> {dependency}", package.id);
            }
        }
        assert_eq!(merged.document.as_deref(), Some("a.json, b.json"));
        assert_eq!(merged.environment, a.environment, "the inputs agree");
    }

    #[test]
    fn a_conflict_keeps_the_first_and_is_recorded() {
        let mut a = sample_sbom();
        a.packages.iter_mut().find(|p| p.name == "six").unwrap().license = Some("MIT".into());
        let mut b = a.clone();
        let six = b.packages.iter_mut().find(|p| p.name == "six").unwrap();
        six.license = Some("GPL-3.0-only".into());
        six.extra_purls.push("pkg:conda/conda-forge/six@1.17.0".into());
        b.environment = "other".into();
        let merged = merge(&[input("a.json", a.clone()), input("b.json", b)], Root::default());
        let six = named(&merged, "six")[0];
        let original = a.packages.iter().find(|p| p.name == "six").unwrap();
        assert_eq!(six.license, original.license, "the first input's license is kept");
        let conflict = &six.properties[CONFLICT_PROPERTY];
        assert_eq!(conflict, "license: MIT (a.json) vs GPL-3.0-only (b.json)");
        assert!(conflict.ends_with("vs GPL-3.0-only (b.json)"), "{conflict}");
        assert!(
            six.extra_purls
                .contains(&"pkg:conda/conda-forge/six@1.17.0".to_string())
        );
        assert_eq!(merged.environment, "merged", "the inputs disagree");
    }

    #[test]
    fn colliding_ids_without_a_shared_purl_stay_apart() {
        let mut a = sample_sbom();
        let mut b = sample_sbom();
        for package in a.packages.iter_mut().chain(b.packages.iter_mut()) {
            package.purl = String::new();
        }
        b.root.name = "other".into();
        let merged = merge(&[input("a.json", a.clone()), input("b.json", b)], Root::default());
        assert_eq!(merged.packages.len(), 2 * a.packages.len() + 2);
        let ids: BTreeSet<&str> = merged.packages.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids.len(), merged.packages.len(), "every id unique");
        for package in &merged.packages {
            for dependency in &package.dependencies {
                assert!(ids.contains(dependency.as_str()), "{} -> {dependency}", package.id);
            }
        }
    }
}
