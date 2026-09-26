//! Enriching once for a run that writes many documents.
//!
//! `--all-environments --all-platforms` on this repository writes fifteen documents holding
//! 853 package entries between them, but only 289 distinct packages: every shared package was
//! looked up once per document it appears in. The download cache meant the repeats were cheap,
//! but they were still serial — each document drained its own small pool of fetches before the
//! next document started filling one.
//!
//! So the lookups happen once, up front, over the union of every document's packages, in a
//! single pool. What that pass learned is then copied into each document. What it learned is
//! worked out by diffing the packages before and after, rather than by listing the fields each
//! enrichment step writes: a step added later is carried across without anyone remembering to
//! come back here.

use std::collections::BTreeMap;

use crate::model::{Incomplete, LicenseFile, Package, Sbom, Yanked};

/// What enrichment added to one package: only the fields that changed, so applying it to a
/// document cannot overwrite what that document's own environment said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Learned {
    license: Option<String>,
    license_files: Option<Vec<LicenseFile>>,
    description: Option<String>,
    homepage: Option<String>,
    repository: Option<String>,
    documentation: Option<String>,
    yanked: Option<Yanked>,
    extra_purls: Option<Vec<String>>,
    /// Properties the pass added or changed. Keys it left alone are absent, which is what
    /// keeps a per-environment fact like `pixi:direct` out of the shared answer.
    properties: BTreeMap<String, String>,
}

impl Learned {
    /// Everything enrichment did to one package, as the difference between the two.
    fn between(before: &Package, after: &Package) -> Self {
        let changed =
            |before: &Option<String>, after: &Option<String>| (before != after).then(|| after.clone()).flatten();
        Self {
            license: changed(&before.license, &after.license),
            license_files: (before.license_files != after.license_files).then(|| after.license_files.clone()),
            description: changed(&before.description, &after.description),
            homepage: changed(&before.homepage, &after.homepage),
            repository: changed(&before.repository, &after.repository),
            documentation: changed(&before.documentation, &after.documentation),
            yanked: (before.yanked != after.yanked).then(|| after.yanked.clone()).flatten(),
            extra_purls: (before.extra_purls != after.extra_purls).then(|| after.extra_purls.clone()),
            properties: after
                .properties
                .iter()
                .filter(|(key, value)| before.properties.get(*key) != Some(value))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        }
    }

    /// Whether the pass learned anything at all about this package.
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Put what was learned into `package`, leaving every field the pass did not touch as the
    /// document's own model built it.
    fn apply(&self, package: &mut Package) {
        if let Some(license) = &self.license {
            package.license = Some(license.clone());
        }
        if let Some(files) = &self.license_files {
            package.license_files = files.clone();
        }
        for (field, value) in [
            (&mut package.description, &self.description),
            (&mut package.homepage, &self.homepage),
            (&mut package.repository, &self.repository),
            (&mut package.documentation, &self.documentation),
        ] {
            if let Some(value) = value {
                *field = Some(value.clone());
            }
        }
        if let Some(yanked) = &self.yanked {
            package.yanked = Some(yanked.clone());
        }
        if let Some(purls) = &self.extra_purls {
            package.extra_purls = purls.clone();
        }
        for (key, value) in &self.properties {
            package.properties.insert(key.clone(), value.clone());
        }
    }
}

/// What one shared enrichment pass learned, ready to be copied into each document.
#[derive(Debug, Clone, Default)]
pub struct Shared {
    learned: BTreeMap<String, Learned>,
    /// What the shared pass could not finish, which is true of every document built from it.
    pub incomplete: Incomplete,
}

impl Shared {
    /// The difference the enrichment pass made, package by package.
    ///
    /// `before` is the union as the model built it and `after` is the same union once the
    /// lookups have run; they are matched by package id.
    pub fn between(before: &Sbom, after: &Sbom) -> Self {
        let was: BTreeMap<&str, &Package> = before.packages.iter().map(|p| (p.id.as_str(), p)).collect();
        let learned = after
            .packages
            .iter()
            .filter_map(|package| {
                let learned = Learned::between(was.get(package.id.as_str())?, package);
                (!learned.is_empty()).then(|| (package.id.clone(), learned))
            })
            .collect();
        Self {
            learned,
            incomplete: after.incomplete.clone(),
        }
    }

    /// How many packages the pass learned something about.
    pub fn len(&self) -> usize {
        self.learned.len()
    }

    /// Whether the pass learned nothing, in which case applying it is a no-op.
    pub fn is_empty(&self) -> bool {
        self.learned.is_empty()
    }

    /// Copy what was learned into `sbom`, and carry over what the pass could not finish.
    /// Returns how many of the document's packages were filled in.
    pub fn apply(&self, sbom: &mut Sbom) -> usize {
        let mut filled = 0;
        for package in &mut sbom.packages {
            if let Some(learned) = self.learned.get(&package.id) {
                learned.apply(package);
                filled += 1;
            }
        }
        // The counts belong to the shared pass, which looked at every document's packages at
        // once, so they are not this document's own numbers and must not read as if they
        // were: a one-package document saying "2 of 2 failed" would be a lie about itself.
        for step in &self.incomplete.steps {
            sbom.incomplete
                .note(format!("{step} (looked up once for every document in the run)"));
        }
        filled
    }
}

/// One package per distinct id across every document, so the lookups run over each exactly
/// once. The packages keep the fields the model gave them; the per-environment ones
/// (`pixi:direct` and its neighbours) come along but are never copied back out, because only
/// what the pass *changes* is.
pub fn union(documents: &[Sbom]) -> Sbom {
    let mut union = documents.first().cloned().unwrap_or_else(|| Sbom {
        root: crate::model::Root::default(),
        environment: String::new(),
        platform: String::new(),
        lockfile: String::new(),
        prefix: None,
        document: None,
        packages: Vec::new(),
        vulnerabilities: Vec::new(),
        excluded: Vec::new(),
        declared_missing: Vec::new(),
        incomplete: Incomplete::default(),
    });
    union.environment = "<every environment>".to_string();
    union.platform = "<every platform>".to_string();
    union.vulnerabilities.clear();
    union.incomplete = Incomplete::default();

    let mut seen: BTreeMap<String, Package> = BTreeMap::new();
    for document in documents {
        for package in &document.packages {
            seen.entry(package.id.clone()).or_insert_with(|| package.clone());
        }
    }
    union.packages = seen.into_values().collect();
    // The graph is per environment and the shared pass does not look at it; dropping the edges
    // keeps a package from claiming a dependency another environment gave it.
    for package in &mut union.packages {
        package.dependencies.clear();
    }
    union.packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    union
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PackageKind, Root};

    fn package(id: &str, name: &str) -> Package {
        Package {
            id: id.to_string(),
            name: name.to_string(),
            version: Some("1.0.0".into()),
            kind: PackageKind::CondaBinary,
            purl: id.to_string(),
            supplier: None,
            extra_purls: Vec::new(),
            purls_from_lock: false,
            location: format!("https://example.invalid/{name}.conda"),
            sha256: None,
            md5: None,
            license: None,
            license_files: Vec::new(),
            description: None,
            homepage: None,
            repository: None,
            documentation: None,
            yanked: None,
            properties: BTreeMap::new(),
            dependencies: Vec::new(),
        }
    }

    fn sbom(environment: &str, packages: Vec<Package>) -> Sbom {
        Sbom {
            root: Root::default(),
            environment: environment.to_string(),
            platform: "linux-64".into(),
            lockfile: "pixi.lock".into(),
            prefix: None,
            document: None,
            packages,
            vulnerabilities: Vec::new(),
            excluded: Vec::new(),
            declared_missing: Vec::new(),
            incomplete: Incomplete::default(),
        }
    }

    #[test]
    fn the_union_holds_each_package_once_however_many_documents_share_it() {
        let shared = package("pkg:conda/zlib@1.3", "zlib");
        let one = sbom("default", vec![shared.clone(), package("pkg:conda/only-a@1", "only-a")]);
        let two = sbom("docs", vec![shared.clone(), package("pkg:conda/only-b@1", "only-b")]);

        let all = union(&[one, two]);
        let names: Vec<&str> = all.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["only-a", "only-b", "zlib"],
            "each one once, in a stable order"
        );
        assert_eq!(all.environment, "<every environment>");
        assert!(all.vulnerabilities.is_empty());
        assert!(union(&[]).packages.is_empty(), "no documents, nothing to look up");
    }

    #[test]
    fn a_documents_own_facts_survive_what_the_shared_pass_learned() {
        let mut before = package("pkg:conda/zlib@1.3", "zlib");
        before.properties.insert("pixi:channel".into(), "conda-forge".into());
        let mut after = before.clone();
        after.license = Some("Zlib".into());
        after.description = Some("a compression library".into());
        after
            .properties
            .insert("pixi:license-source".into(), "conda-archive".into());

        let shared = Shared::between(&sbom("<all>", vec![before]), &sbom("<all>", vec![after]));
        assert_eq!(shared.len(), 1);
        assert!(!shared.is_empty());

        // The document's copy carries a fact of its own that the shared pass never saw.
        let mut mine = package("pkg:conda/zlib@1.3", "zlib");
        mine.properties.insert("pixi:channel".into(), "conda-forge".into());
        mine.properties.insert("pixi:direct".into(), "true".into());
        mine.dependencies = vec!["pkg:conda/libzlib@1.3".into()];
        let mut document = sbom("default", vec![mine, package("pkg:conda/other@1", "other")]);

        assert_eq!(shared.apply(&mut document), 1, "only the package it knows about");
        let zlib = &document.packages[0];
        assert_eq!(zlib.license.as_deref(), Some("Zlib"));
        assert_eq!(zlib.description.as_deref(), Some("a compression library"));
        assert_eq!(
            zlib.properties.get("pixi:license-source").map(String::as_str),
            Some("conda-archive")
        );
        assert_eq!(
            zlib.properties.get("pixi:direct").map(String::as_str),
            Some("true"),
            "the environment's own fact is not overwritten by a pass that never saw it"
        );
        assert_eq!(
            zlib.dependencies,
            vec!["pkg:conda/libzlib@1.3".to_string()],
            "nor its edges"
        );
        assert_eq!(
            document.packages[1].license, None,
            "a package the pass did not reach is untouched"
        );
    }

    #[test]
    fn what_the_shared_pass_could_not_finish_is_carried_into_every_document() {
        let before = sbom("<all>", vec![package("pkg:conda/zlib@1.3", "zlib")]);
        let mut after = before.clone();
        after.incomplete.note_failures("conda-archives", 3, 12, "archive reads");

        let shared = Shared::between(&before, &after);
        assert!(shared.is_empty(), "nothing was learned about any package");

        let mut document = sbom("default", vec![package("pkg:conda/zlib@1.3", "zlib")]);
        shared.apply(&mut document);
        assert_eq!(
            document.incomplete.steps,
            vec![
                "conda-archives: 3 of 12 archive reads failed (looked up once for every document in the run)"
                    .to_string()
            ],
            "a document whose licenses are missing says so, and says whose counts those are"
        );
    }
}
