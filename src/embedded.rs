//! PEP 770: SBOMs embedded in wheels (`*.dist-info/sboms/*`).
//!
//! Build backends such as maturin record what they compiled into a wheel, typically the Rust
//! crates, as a CycloneDX document in the wheel's `sboms/` directory; some projects add
//! hand-written SPDX fragments for vendored libraries. Those components are otherwise
//! invisible to a lockfile-based SBOM. With `--embedded-sboms` they are parsed out of the
//! wheels [`crate::wheel`] has read, added as packages of kind [`PackageKind::Embedded`], and
//! wired into the dependency graph under the wheel that carries them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use serde::Deserialize;

use crate::model::{Package, PackageKind, Sbom};
use crate::wheel;

/// Property naming the wheel and file a component came from.
pub const SOURCE_PROPERTY: &str = "pixi:embedded-sbom";

/// Counts from one pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Embedded SBOM files parsed.
    pub files: usize,
    /// Files that were neither CycloneDX nor SPDX 2.x JSON.
    pub unreadable: usize,
    /// Components added to the document.
    pub added: usize,
    /// Components that were already present (same purl) and only gained an edge.
    pub merged: usize,
}

/// One component read from a fragment, before it is placed in the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// The fragment's own reference for this component (`bom-ref` / `SPDXID`).
    pub reference: String,
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub license: Option<String>,
    pub description: Option<String>,
    pub sha256: Option<String>,
    pub location: Option<String>,
    /// References of the components this one depends on.
    pub depends_on: Vec<String>,
}

/// A parsed fragment: its components and the references of its top level (what the wheel
/// itself depends on).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fragment {
    pub components: Vec<Component>,
    pub top_level: Vec<String>,
}

// ---- CycloneDX 1.4 – 1.7 -------------------------------------------------------------------

#[derive(Deserialize)]
struct Cdx {
    #[serde(rename = "bomFormat")]
    bom_format: String,
    #[serde(default)]
    metadata: Option<CdxMetadata>,
    #[serde(default)]
    components: Vec<CdxComponent>,
    #[serde(default)]
    dependencies: Vec<CdxDependency>,
}

#[derive(Deserialize)]
struct CdxMetadata {
    component: Option<CdxComponent>,
}

#[derive(Deserialize)]
struct CdxComponent {
    #[serde(rename = "bom-ref")]
    bom_ref: Option<String>,
    name: String,
    version: Option<String>,
    purl: Option<String>,
    description: Option<String>,
    #[serde(default)]
    licenses: Vec<serde_json::Value>,
    #[serde(default)]
    hashes: Vec<CdxHash>,
    #[serde(default, rename = "externalReferences")]
    external_references: Vec<CdxExternalReference>,
}

#[derive(Deserialize)]
struct CdxHash {
    alg: String,
    content: String,
}

#[derive(Deserialize)]
struct CdxExternalReference {
    #[serde(rename = "type")]
    kind: String,
    url: String,
}

#[derive(Deserialize)]
struct CdxDependency {
    #[serde(rename = "ref")]
    reference: String,
    #[serde(default, rename = "dependsOn")]
    depends_on: Vec<String>,
}

fn cdx_license(licenses: &[serde_json::Value]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for entry in licenses {
        if let Some(expression) = entry.get("expression").and_then(|v| v.as_str()) {
            parts.push(expression.to_string());
        } else if let Some(license) = entry.get("license") {
            if let Some(id) = license.get("id").and_then(|v| v.as_str()) {
                parts.push(id.to_string());
            } else if let Some(name) = license.get("name").and_then(|v| v.as_str()) {
                parts.push(name.to_string());
            }
        }
    }
    match parts.len() {
        0 => None,
        1 => parts.pop(),
        _ => Some(parts.join(" AND ")),
    }
}

fn parse_cyclonedx(text: &str) -> Option<Fragment> {
    let doc: Cdx = serde_json::from_str(text).ok()?;
    if doc.bom_format != "CycloneDX" {
        return None;
    }
    let deps: HashMap<&str, &Vec<String>> = doc
        .dependencies
        .iter()
        .map(|d| (d.reference.as_str(), &d.depends_on))
        .collect();
    let mut fragment = Fragment::default();
    for (i, c) in doc.components.iter().enumerate() {
        let reference = c
            .bom_ref
            .clone()
            .or_else(|| c.purl.clone())
            .unwrap_or_else(|| format!("component-{i}"));
        fragment.components.push(Component {
            depends_on: deps.get(reference.as_str()).map(|d| (*d).clone()).unwrap_or_default(),
            reference,
            name: c.name.clone(),
            version: c.version.clone(),
            purl: c.purl.clone(),
            license: cdx_license(&c.licenses),
            description: c.description.clone(),
            sha256: c
                .hashes
                .iter()
                .find(|h| h.alg.eq_ignore_ascii_case("SHA-256"))
                .map(|h| h.content.to_lowercase()),
            location: c
                .external_references
                .iter()
                .find(|r| r.kind == "distribution" || r.kind == "vcs")
                .map(|r| r.url.clone()),
        });
    }
    // The top level is what the fragment's own root depends on; without a root or a graph,
    // every component that nothing else depends on.
    let root_ref = doc.metadata.and_then(|m| m.component).and_then(|c| c.bom_ref);
    let known: BTreeSet<&str> = fragment.components.iter().map(|c| c.reference.as_str()).collect();
    fragment.top_level = match root_ref.as_deref().and_then(|r| deps.get(r)) {
        Some(direct) => direct.iter().filter(|d| known.contains(d.as_str())).cloned().collect(),
        None => {
            let depended: BTreeSet<&str> = fragment
                .components
                .iter()
                .flat_map(|c| c.depends_on.iter().map(String::as_str))
                .collect();
            fragment
                .components
                .iter()
                .filter(|c| !depended.contains(c.reference.as_str()))
                .map(|c| c.reference.clone())
                .collect()
        }
    };
    Some(fragment)
}

// ---- SPDX 2.x ------------------------------------------------------------------------------

#[derive(Deserialize)]
struct Spdx {
    #[serde(rename = "spdxVersion")]
    spdx_version: String,
    #[serde(default)]
    packages: Vec<SpdxPackage>,
    #[serde(default)]
    relationships: Vec<SpdxRelationship>,
}

#[derive(Deserialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "versionInfo")]
    version_info: Option<String>,
    #[serde(rename = "downloadLocation")]
    download_location: Option<String>,
    #[serde(rename = "licenseDeclared")]
    license_declared: Option<String>,
    #[serde(rename = "licenseConcluded")]
    license_concluded: Option<String>,
    summary: Option<String>,
    #[serde(default)]
    checksums: Vec<SpdxChecksum>,
    #[serde(default, rename = "externalRefs")]
    external_refs: Vec<SpdxExternalRef>,
}

#[derive(Deserialize)]
struct SpdxChecksum {
    algorithm: String,
    #[serde(rename = "checksumValue")]
    checksum_value: String,
}

#[derive(Deserialize)]
struct SpdxExternalRef {
    #[serde(rename = "referenceType")]
    reference_type: String,
    #[serde(rename = "referenceLocator")]
    reference_locator: String,
}

#[derive(Deserialize)]
struct SpdxRelationship {
    #[serde(rename = "spdxElementId")]
    element: String,
    #[serde(rename = "relationshipType")]
    kind: String,
    #[serde(rename = "relatedSpdxElement")]
    related: String,
}

fn parse_spdx(text: &str) -> Option<Fragment> {
    let doc: Spdx = serde_json::from_str(text).ok()?;
    if !doc.spdx_version.starts_with("SPDX-2") {
        return None;
    }
    let mut depends: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut described: Vec<String> = Vec::new();
    for r in &doc.relationships {
        match r.kind.as_str() {
            "DEPENDS_ON" => depends.entry(r.element.as_str()).or_default().push(r.related.clone()),
            "DEPENDENCY_OF" => depends.entry(r.related.as_str()).or_default().push(r.element.clone()),
            "DESCRIBES" => described.push(r.related.clone()),
            _ => {}
        }
    }
    let mut fragment = Fragment::default();
    for p in &doc.packages {
        let noassertion = |v: &Option<String>| v.clone().filter(|s| s != "NOASSERTION" && s != "NONE");
        fragment.components.push(Component {
            reference: p.spdx_id.clone(),
            name: p.name.clone(),
            version: p.version_info.clone(),
            purl: p
                .external_refs
                .iter()
                .find(|r| r.reference_type == "purl")
                .map(|r| r.reference_locator.clone()),
            license: noassertion(&p.license_declared).or_else(|| noassertion(&p.license_concluded)),
            description: p.summary.clone(),
            sha256: p
                .checksums
                .iter()
                .find(|c| c.algorithm.eq_ignore_ascii_case("SHA256"))
                .map(|c| c.checksum_value.to_lowercase()),
            location: noassertion(&p.download_location),
            depends_on: depends.get(p.spdx_id.as_str()).cloned().unwrap_or_default(),
        });
    }
    let known: BTreeSet<&str> = fragment.components.iter().map(|c| c.reference.as_str()).collect();
    let described: Vec<String> = described.into_iter().filter(|d| known.contains(d.as_str())).collect();
    fragment.top_level = if described.is_empty() {
        let depended: BTreeSet<&str> = fragment
            .components
            .iter()
            .flat_map(|c| c.depends_on.iter().map(String::as_str))
            .collect();
        fragment
            .components
            .iter()
            .filter(|c| !depended.contains(c.reference.as_str()))
            .map(|c| c.reference.clone())
            .collect()
    } else {
        described
    };
    Some(fragment)
}

/// Parse an embedded SBOM file of either family; `None` when it is neither.
pub fn parse(text: &str) -> Option<Fragment> {
    parse_cyclonedx(text).or_else(|| parse_spdx(text))
}

// ---- Attaching to the document -------------------------------------------------------------

/// Read the embedded SBOMs of every wheel already cached under `cache_dir` and attach their
/// components to the document under the wheel that carries them.
pub fn enrich(sbom: &mut Sbom, cache_dir: &Path) -> Outcome {
    let mut outcome = Outcome::default();
    let wheels: Vec<(usize, String, String)> = sbom
        .packages
        .iter()
        .enumerate()
        .filter(|(_, p)| p.kind == PackageKind::Pypi && p.location.ends_with(".whl"))
        .map(|(i, p)| (i, p.name.clone(), wheel::cache_key(p)))
        .collect();
    let mut by_id: HashMap<String, usize> = sbom
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.id.clone(), i))
        .collect();

    for (wheel_index, wheel_name, key) in wheels {
        for (file, text) in wheel::cached_sboms(cache_dir, &key) {
            let Some(fragment) = parse(&text) else {
                tracing::warn!(wheel = %wheel_name, %file, "embedded SBOM is neither CycloneDX nor SPDX 2.x JSON; skipped");
                outcome.unreadable += 1;
                continue;
            };
            outcome.files += 1;
            let source = format!("{wheel_name}/{file}");
            // Reference -> document id, in fragment order, so edges can be resolved afterwards.
            let mut ids: HashMap<String, String> = HashMap::new();
            for component in &fragment.components {
                let id = document_id(component, &sbom.packages[wheel_index].purl);
                ids.insert(component.reference.clone(), id.clone());
                if let Some(&existing) = by_id.get(&id) {
                    outcome.merged += 1;
                    let package = &mut sbom.packages[existing];
                    // A later fragment may know more about the same component.
                    package.license = package.license.take().or_else(|| component.license.clone());
                    package.description = package.description.take().or_else(|| component.description.clone());
                    package.sha256 = package.sha256.take().or_else(|| component.sha256.clone());
                    if package.location.is_empty() {
                        package.location = component.location.clone().unwrap_or_default();
                    }
                    package
                        .properties
                        .entry(SOURCE_PROPERTY.to_string())
                        .and_modify(|v| {
                            if !v.split(';').any(|s| s == source) {
                                v.push(';');
                                v.push_str(&source);
                            }
                        })
                        .or_insert_with(|| source.clone());
                    continue;
                }
                let package = to_package(component, id.clone(), &source);
                by_id.insert(id, sbom.packages.len());
                sbom.packages.push(package);
                outcome.added += 1;
            }
            // Edges within the fragment, then from the wheel to the fragment's top level.
            for component in &fragment.components {
                let Some(&index) = ids.get(&component.reference).and_then(|id| by_id.get(id)) else {
                    continue;
                };
                let self_id = sbom.packages[index].id.clone();
                let mut deps: Vec<String> = component
                    .depends_on
                    .iter()
                    .filter_map(|r| ids.get(r).cloned())
                    .filter(|d| d != &self_id)
                    .collect();
                let package = &mut sbom.packages[index];
                deps.extend(package.dependencies.iter().cloned());
                deps.sort();
                deps.dedup();
                package.dependencies = deps;
            }
            let top: Vec<String> = fragment.top_level.iter().filter_map(|r| ids.get(r).cloned()).collect();
            let package = &mut sbom.packages[wheel_index];
            package.dependencies.extend(top);
            package.dependencies.sort();
            package.dependencies.dedup();
        }
    }
    outcome
}

/// The document id for an embedded component: its purl, else a purl-shaped id under the wheel.
fn document_id(component: &Component, wheel_purl: &str) -> String {
    match &component.purl {
        Some(purl) => purl.clone(),
        None => format!(
            "{wheel_purl}#{}",
            match &component.version {
                Some(v) => format!("{}@{v}", component.name),
                None => component.name.clone(),
            }
        ),
    }
}

fn to_package(component: &Component, id: String, source: &str) -> Package {
    let purl = component.purl.clone().unwrap_or_else(|| id.clone());
    Package {
        id,
        name: component.name.clone(),
        version: component.version.clone(),
        kind: PackageKind::Embedded,
        purl,
        supplier: None,
        extra_purls: Vec::new(),
        purls_from_lock: true,
        location: component.location.clone().unwrap_or_default(),
        sha256: component.sha256.clone(),
        md5: None,
        license: component.license.clone(),
        license_files: Vec::new(),
        description: component.description.clone(),
        homepage: None,
        repository: None,
        documentation: None,
        properties: BTreeMap::from([(SOURCE_PROPERTY.to_string(), source.to_string())]),
        dependencies: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    const CDX: &str = r#"{"bomFormat":"CycloneDX","specVersion":"1.5",
        "metadata":{"component":{"type":"library","bom-ref":"root","name":"w","version":"1"}},
        "components":[
          {"type":"library","bom-ref":"a","name":"alpha","version":"1.0","purl":"pkg:cargo/alpha@1.0","licenses":[{"expression":"MIT"}],"hashes":[{"alg":"SHA-256","content":"AB"}]},
          {"type":"library","bom-ref":"b","name":"beta","version":"2.0","purl":"pkg:cargo/beta@2.0","licenses":[{"license":{"id":"Apache-2.0"}},{"license":{"name":"Custom"}}],"externalReferences":[{"type":"vcs","url":"https://example/beta"}]},
          {"type":"library","name":"gamma","version":"3.0"}
        ],
        "dependencies":[{"ref":"root","dependsOn":["a"]},{"ref":"a","dependsOn":["b"]},{"ref":"b","dependsOn":[]}]}"#;

    #[test]
    fn parses_cyclonedx_components_licenses_and_graph() {
        let f = parse(CDX).unwrap();
        assert_eq!(f.components.len(), 3);
        assert_eq!(f.components[0].license.as_deref(), Some("MIT"));
        assert_eq!(f.components[0].sha256.as_deref(), Some("ab"));
        assert_eq!(f.components[0].depends_on, ["b"]);
        assert_eq!(f.components[1].license.as_deref(), Some("Apache-2.0 AND Custom"));
        assert_eq!(f.components[1].location.as_deref(), Some("https://example/beta"));
        assert_eq!(f.components[2].reference, "component-2", "no bom-ref, no purl");
        assert_eq!(f.top_level, ["a"], "what the root depends on");
    }

    #[test]
    fn cyclonedx_without_a_root_uses_undepended_components_as_top_level() {
        let text = r#"{"bomFormat":"CycloneDX","components":[
            {"type":"library","bom-ref":"a","name":"a","purl":"pkg:cargo/a@1"},
            {"type":"library","bom-ref":"b","name":"b","purl":"pkg:cargo/b@1"}],
            "dependencies":[{"ref":"a","dependsOn":["b"]}]}"#;
        assert_eq!(parse(text).unwrap().top_level, ["a"]);
    }

    #[test]
    fn parses_spdx_packages_and_describes() {
        let text = r#"{"spdxVersion":"SPDX-2.3","packages":[
            {"SPDXID":"SPDXRef-x","name":"x","versionInfo":"1","downloadLocation":"NOASSERTION","licenseDeclared":"NOASSERTION","licenseConcluded":"MIT",
             "checksums":[{"algorithm":"SHA256","checksumValue":"CD"}],"externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:generic/x@1"}]},
            {"SPDXID":"SPDXRef-y","name":"y"}],
            "relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-x"},
                             {"spdxElementId":"SPDXRef-y","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-x"}]}"#;
        let f = parse(text).unwrap();
        assert_eq!(f.components[0].purl.as_deref(), Some("pkg:generic/x@1"));
        assert_eq!(
            f.components[0].license.as_deref(),
            Some("MIT"),
            "concluded when declared is NOASSERTION"
        );
        assert_eq!(f.components[0].location, None);
        assert_eq!(f.components[0].sha256.as_deref(), Some("cd"));
        assert_eq!(f.components[0].depends_on, ["SPDXRef-y"], "DEPENDENCY_OF is reversed");
        assert_eq!(f.top_level, ["SPDXRef-x"]);
    }

    #[test]
    fn unknown_documents_are_rejected() {
        assert!(parse("not json").is_none());
        assert!(parse(r#"{"bomFormat":"Other"}"#).is_none());
        assert!(parse(r#"{"spdxVersion":"SPDX-3.0"}"#).is_none());
        assert!(parse(r#"{"hello":"world"}"#).is_none());
    }

    #[test]
    fn enrich_attaches_components_under_the_wheel_and_merges_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sample_sbom();
        // six is the wheel; give it a key and cached sboms.
        sbom.packages[3].sha256 = Some("s".repeat(64));
        let key = wheel::cache_key(&sbom.packages[3]);
        let sboms = dir.path().join("wheel-info").join(&key).join("sboms");
        std::fs::create_dir_all(&sboms).unwrap();
        std::fs::write(sboms.join("six.cyclonedx.json"), CDX).unwrap();
        std::fs::write(sboms.join("junk.json"), "{}").unwrap();
        // A second fragment declares alpha again: it must merge, not duplicate.
        std::fs::write(
            sboms.join("again.spdx.json"),
            r#"{"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-a","name":"alpha","versionInfo":"1.0",
                "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:cargo/alpha@1.0"}]}]}"#,
        )
        .unwrap();

        let outcome = enrich(&mut sbom, dir.path());
        assert_eq!(
            outcome,
            Outcome {
                files: 2,
                unreadable: 1,
                added: 3,
                merged: 1
            }
        );
        let find = |name: &str| sbom.packages.iter().find(|p| p.name == name).unwrap();
        let six = find("six");
        assert_eq!(
            six.dependencies,
            ["pkg:cargo/alpha@1.0"],
            "wheel depends on the fragment's top level"
        );
        let alpha = find("alpha");
        assert_eq!(alpha.kind, PackageKind::Embedded);
        assert_eq!(alpha.dependencies, ["pkg:cargo/beta@2.0"]);
        assert_eq!(
            alpha.properties[SOURCE_PROPERTY],
            "six/again.spdx.json;six/six.cyclonedx.json"
        );
        assert_eq!(alpha.license.as_deref(), Some("MIT"));
        let gamma = find("gamma");
        assert_eq!(gamma.id, "pkg:pypi/six@1.17.0#gamma@3.0", "no purl: id under the wheel");
        assert_eq!(gamma.purl, gamma.id);
        assert!(gamma.purls_from_lock);
        let ids: BTreeSet<&str> = sbom.packages.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids.len(), sbom.packages.len(), "ids stay unique");

        // Running again changes nothing.
        let before = sbom.packages.len();
        let outcome = enrich(&mut sbom, dir.path());
        assert_eq!(outcome.added, 0);
        assert_eq!(sbom.packages.len(), before);
    }
}
