//! SPDX 3.0.1 JSON-LD serializer.
//!
//! SPDX 3 is a graph of typed elements rather than a document with sections. The output is a
//! JSON-LD object whose `@graph` holds: a `CreationInfo` blank node shared by every element,
//! the pixi-sbom `Tool` and `SoftwareAgent`, `Person` elements for the workspace authors,
//! `Organization` elements for the suppliers, an `SpdxDocument` whose root is a
//! `software_Sbom`, whose root in turn is the workspace `software_Package`, one
//! `software_Package` per locked package, `simplelicensing_LicenseExpression` /
//! `simplelicensing_SimpleLicensingText` elements for the licenses, and `Relationship`
//! elements (`dependsOn`, `hasDeclaredLicense`). Every element uses the same node struct with
//! only the fields of its class set.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use super::spdx::{assign_ids, id_fragment, kind_name};
use super::{WriteContext, top_level_ids};
use crate::license::{self, License};
use crate::model::Sbom;

const CONTEXT: &str = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld";
const SPEC_VERSION: &str = "3.0.1";
const CREATION_INFO_ID: &str = "_:creationinfo";

/// The whole document.
#[derive(Debug, Serialize)]
pub(crate) struct Document {
    #[serde(rename = "@context")]
    context: &'static str,
    #[serde(rename = "@graph")]
    graph: Vec<Node>,
}

/// One JSON-LD element; each class sets only its own fields.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    #[serde(rename = "@id", skip_serializing_if = "Option::is_none")]
    blank_id: Option<String>,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    spdx_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creation_info: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,

    // CreationInfo
    #[serde(skip_serializing_if = "Option::is_none")]
    spec_version: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_by: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_using: Option<Vec<String>>,

    // ElementCollection / SpdxDocument / software_Sbom
    #[serde(skip_serializing_if = "Option::is_none")]
    profile_conformance: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_element: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    element: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_license: Option<String>,
    #[serde(rename = "software_sbomType", skip_serializing_if = "Option::is_none")]
    sbom_type: Option<Vec<&'static str>>,

    // software_Package
    #[serde(rename = "software_packageVersion", skip_serializing_if = "Option::is_none")]
    package_version: Option<String>,
    #[serde(rename = "software_downloadLocation", skip_serializing_if = "Option::is_none")]
    download_location: Option<String>,
    #[serde(rename = "software_homePage", skip_serializing_if = "Option::is_none")]
    home_page: Option<String>,
    #[serde(rename = "software_packageUrl", skip_serializing_if = "Option::is_none")]
    package_url: Option<String>,
    #[serde(rename = "software_primaryPurpose", skip_serializing_if = "Option::is_none")]
    primary_purpose: Option<&'static str>,
    #[serde(rename = "software_sourceInfo", skip_serializing_if = "Option::is_none")]
    source_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplied_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_identifier: Option<Vec<ExternalIdentifier>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified_using: Option<Vec<Hash>>,

    // Relationship
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relationship_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<Vec<String>>,

    // simplelicensing_LicenseExpression / SimpleLicensingText
    #[serde(
        rename = "simplelicensing_licenseExpression",
        skip_serializing_if = "Option::is_none"
    )]
    license_expression: Option<String>,
    #[serde(rename = "simplelicensing_licenseText", skip_serializing_if = "Option::is_none")]
    license_text: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalIdentifier {
    #[serde(rename = "type")]
    kind: &'static str,
    external_identifier_type: &'static str,
    identifier: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Hash {
    #[serde(rename = "type")]
    kind: &'static str,
    algorithm: &'static str,
    hash_value: String,
}

/// Mints element IRIs under the document namespace and keeps the graph in insertion order.
struct Builder {
    namespace: String,
    graph: Vec<Node>,
    /// License expression or text -> element IRI, so identical licenses share one element.
    licenses: BTreeMap<String, String>,
    /// Supplier name -> Organization IRI.
    suppliers: BTreeMap<String, String>,
}

impl Builder {
    fn iri(&self, fragment: &str) -> String {
        format!("{}#{}", self.namespace, fragment)
    }

    fn element(&mut self, kind: &'static str, fragment: &str) -> (String, Node) {
        let spdx_id = self.iri(fragment);
        let node = Node {
            kind,
            spdx_id: Some(spdx_id.clone()),
            creation_info: Some(CREATION_INFO_ID),
            ..Node::default()
        };
        (spdx_id, node)
    }

    fn push(&mut self, node: Node) -> String {
        let id = node.spdx_id.clone().expect("elements have ids");
        self.graph.push(node);
        id
    }

    /// The license element for `raw`, created on first use: an expression for SPDX text,
    /// a licensing-text element otherwise (with the file text when one is known).
    fn license(&mut self, raw: &str, file_text: Option<&str>) -> Option<String> {
        let (key, node) = match license::normalize(raw) {
            License::Expression(expression) => {
                let (_, mut node) = self.element(
                    "simplelicensing_LicenseExpression",
                    &format!("license-{}", id_fragment(&expression)),
                );
                node.license_expression = Some(expression.clone());
                (expression, node)
            }
            License::Text(text) if text.is_empty() => return None,
            License::Text(text) => {
                let (_, mut node) = self.element(
                    "simplelicensing_SimpleLicensingText",
                    &format!("license-text-{}", id_fragment(&text)),
                );
                node.name = Some(text.clone());
                node.license_text = Some(file_text.map(str::to_string).unwrap_or_else(|| text.clone()));
                (text, node)
            }
        };
        if let Some(id) = self.licenses.get(&key) {
            return Some(id.clone());
        }
        let id = self.push(node);
        self.licenses.insert(key, id.clone());
        Some(id)
    }

    fn supplier(&mut self, name: &str, url: Option<&str>) -> String {
        if let Some(id) = self.suppliers.get(name) {
            return id.clone();
        }
        let (_, mut node) = self.element("Organization", &format!("supplier-{}", id_fragment(name)));
        node.name = Some(name.to_string());
        node.external_identifier = url.map(|url| {
            vec![ExternalIdentifier {
                kind: "ExternalIdentifier",
                external_identifier_type: "urlScheme",
                identifier: url.to_string(),
            }]
        });
        let id = self.push(node);
        self.suppliers.insert(name.to_string(), id.clone());
        id
    }

    fn relationship(&mut self, fragment: &str, from: &str, kind: &'static str, to: Vec<String>) -> String {
        let (_, mut node) = self.element("Relationship", fragment);
        node.from = Some(from.to_string());
        node.relationship_type = Some(kind);
        node.to = Some(to);
        self.push(node)
    }
}

/// Build the SPDX 3.0.1 document for `sbom`.
pub(crate) fn document(sbom: &Sbom, ctx: &WriteContext) -> Document {
    let name = format!("{}-{}-{}", sbom.root.name, sbom.environment, sbom.platform);
    let mut b = Builder {
        namespace: format!(
            "https://spdx.org/spdxdocs/pixi-sbom/{}/{}",
            id_fragment(&name),
            ctx.uuid
        ),
        graph: Vec::new(),
        licenses: BTreeMap::new(),
        suppliers: BTreeMap::new(),
    };
    let created = ctx.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Agents and the tool, referenced by the creation info.
    let (agent_id, mut agent) = b.element("SoftwareAgent", "agent-pixi-sbom");
    agent.name = Some(format!("pixi-sbom {}", ctx.tool_version));
    b.push(agent);
    let (tool_id, mut tool) = b.element("Tool", "tool-pixi-sbom");
    tool.name = Some("pixi-sbom".into());
    tool.description = Some(format!(
        "pixi-sbom {} ({})",
        ctx.tool_version,
        env!("CARGO_PKG_REPOSITORY")
    ));
    b.push(tool);
    let mut created_by = vec![agent_id];
    for (i, author) in sbom.root.authors.iter().enumerate() {
        let (_, mut person) = b.element("Person", &format!("author-{i}"));
        person.name = Some(author.name.clone());
        person.external_identifier = author.email.as_ref().map(|email| {
            vec![ExternalIdentifier {
                kind: "ExternalIdentifier",
                external_identifier_type: "email",
                identifier: email.clone(),
            }]
        });
        created_by.push(b.push(person));
    }
    b.graph.insert(
        0,
        Node {
            blank_id: Some(CREATION_INFO_ID.into()),
            kind: "CreationInfo",
            spec_version: Some(SPEC_VERSION),
            created: Some(created),
            created_by: Some(created_by),
            created_using: Some(vec![tool_id]),
            comment: Some(format!(
                "Generated from the pixi {} (environment {}, platform {}) before any build",
                sbom.input_description(),
                sbom.environment,
                sbom.platform
            )),
            ..Node::default()
        },
    );

    // Packages.
    let ids = assign_ids(&sbom.packages);
    let iri_of: HashMap<&str, String> = ids
        .iter()
        .map(|(k, v)| (*k, b.iri(&v.replace("SPDXRef-", ""))))
        .collect();
    let mut elements: Vec<String> = Vec::new();
    let mut relationships: Vec<(String, &'static str, Vec<String>, String)> = Vec::new();

    let (root_id, mut root) = b.element("software_Package", "package-root");
    root.name = Some(sbom.root.name.clone());
    root.package_version = sbom.root.version.clone();
    root.primary_purpose = Some("application");
    root.home_page = sbom.root.homepage.clone();
    root.download_location = sbom.root.repository.clone();
    root.source_info = Some(format!(
        "pixi workspace; {}; environment {}; platform {}",
        sbom.input_description(),
        sbom.environment,
        sbom.platform
    ));
    root.comment = super::spdx::excluded_comment(sbom);
    if let Some(license) = sbom.root.license.as_deref().and_then(|raw| b.license(raw, None)) {
        relationships.push((
            root_id.clone(),
            "hasDeclaredLicense",
            vec![license],
            "root-license".into(),
        ));
    }
    b.push(root);
    elements.push(root_id.clone());

    for package in &sbom.packages {
        let iri = iri_of[package.id.as_str()].clone();
        let fragment = iri.rsplit('#').next().unwrap_or_default().to_string();
        let (_, mut node) = b.element("software_Package", &fragment);
        node.name = Some(package.name.clone());
        node.package_version = package.version.clone();
        node.primary_purpose = Some("library");
        node.summary = package.description.clone();
        node.home_page = package.homepage.clone();
        node.package_url = Some(package.purl.clone());
        let is_url = package.location.contains("://");
        node.download_location = is_url.then(|| package.location.clone());
        node.source_info = (!is_url).then(|| format!("built from source at {}", package.location));
        node.supplied_by = package.supplier.as_ref().map(|s| b.supplier(&s.name, s.url.as_deref()));
        let mut identifiers: Vec<ExternalIdentifier> = package
            .extra_purls
            .iter()
            .map(|purl| ExternalIdentifier {
                kind: "ExternalIdentifier",
                external_identifier_type: "packageUrl",
                identifier: purl.clone(),
            })
            .collect();
        if let Some(url) = &package.repository {
            identifiers.push(ExternalIdentifier {
                kind: "ExternalIdentifier",
                external_identifier_type: "urlScheme",
                identifier: url.clone(),
            });
        }
        node.external_identifier = (!identifiers.is_empty()).then_some(identifiers);
        let mut hashes = Vec::new();
        if let Some(sha256) = &package.sha256 {
            hashes.push(Hash {
                kind: "Hash",
                algorithm: "sha256",
                hash_value: sha256.clone(),
            });
        }
        if let Some(md5) = &package.md5 {
            hashes.push(Hash {
                kind: "Hash",
                algorithm: "md5",
                hash_value: md5.clone(),
            });
        }
        node.verified_using = (!hashes.is_empty()).then_some(hashes);
        let mut comment: Vec<String> = package.properties.iter().map(|(k, v)| format!("{k}={v}")).collect();
        comment.push(format!("pixi:kind={}", kind_name(package.kind)));
        if !package.license_files.is_empty() {
            comment.push(format!(
                "pixi:license-files={}",
                package
                    .license_files
                    .iter()
                    .map(|f| f.name.as_str())
                    .collect::<Vec<_>>()
                    .join(";")
            ));
        }
        node.comment = Some(comment.join("\n"));
        let file_text = package.license_files.iter().find_map(|f| f.text.as_deref());
        if let Some(license) = package.license.as_deref().and_then(|raw| b.license(raw, file_text)) {
            relationships.push((
                iri.clone(),
                "hasDeclaredLicense",
                vec![license],
                format!("{fragment}-license"),
            ));
        }
        if !package.dependencies.is_empty() {
            relationships.push((
                iri.clone(),
                "dependsOn",
                package
                    .dependencies
                    .iter()
                    .map(|dep| iri_of[dep.as_str()].clone())
                    .collect(),
                format!("{fragment}-depends"),
            ));
        }
        b.push(node);
        elements.push(iri);
    }
    let top: Vec<String> = top_level_ids(sbom).into_iter().map(|id| iri_of[id].clone()).collect();
    if !top.is_empty() {
        relationships.push((root_id.clone(), "dependsOn", top, "root-depends".into()));
    }
    for (from, kind, to, fragment) in relationships {
        let id = b.relationship(&format!("relationship-{fragment}"), &from, kind, to);
        elements.push(id);
    }
    let license_ids: Vec<String> = b.licenses.values().cloned().collect();
    elements.extend(license_ids);

    // The SBOM and the document that carries it.
    let (sbom_id, mut bom) = b.element("software_Sbom", "sbom");
    bom.name = Some(name.clone());
    bom.sbom_type = Some(vec!["build"]);
    bom.root_element = Some(vec![root_id]);
    bom.element = Some(elements);
    bom.profile_conformance = Some(vec!["core", "software", "simpleLicensing"]);
    b.push(bom);

    let data_license = b.license("CC0-1.0", None);
    let (_, mut doc) = b.element("SpdxDocument", "document");
    doc.name = Some(name);
    doc.root_element = Some(vec![sbom_id.clone()]);
    doc.element = Some(vec![sbom_id]);
    doc.data_license = data_license;
    doc.profile_conformance = Some(vec!["core", "software", "simpleLicensing"]);
    b.push(doc);

    Document {
        context: CONTEXT,
        graph: b.graph,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::{fixed_context, sample_sbom};

    fn json() -> serde_json::Value {
        serde_json::to_value(document(&sample_sbom(), &fixed_context())).unwrap()
    }

    fn nodes(doc: &serde_json::Value, kind: &str) -> Vec<serde_json::Value> {
        doc["@graph"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["type"] == kind)
            .cloned()
            .collect()
    }

    #[test]
    fn snapshot() {
        insta::assert_json_snapshot!(json());
    }

    #[test]
    fn graph_has_context_creation_info_and_document_roots() {
        let doc = json();
        assert_eq!(doc["@context"], CONTEXT);
        let ci = &doc["@graph"][0];
        assert_eq!(ci["type"], "CreationInfo");
        assert_eq!(ci["@id"], "_:creationinfo");
        assert_eq!(ci["specVersion"], "3.0.1");
        assert_eq!(ci["created"], "2026-09-18T12:00:00Z");
        assert_eq!(ci["createdBy"].as_array().unwrap().len(), 3, "agent + two authors");
        assert_eq!(
            ci["createdUsing"][0].as_str().unwrap().rsplit('#').next().unwrap(),
            "tool-pixi-sbom"
        );

        let document = &nodes(&doc, "SpdxDocument")[0];
        let sbom = &nodes(&doc, "software_Sbom")[0];
        assert_eq!(document["rootElement"][0], sbom["spdxId"]);
        assert_eq!(sbom["software_sbomType"][0], "build");
        assert!(sbom["rootElement"][0].as_str().unwrap().ends_with("#package-root"));
        assert!(document["dataLicense"].as_str().unwrap().ends_with("#license-CC0-1.0"));
        assert!(
            doc["@graph"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|n| n["type"] != "CreationInfo")
                .all(|n| n["creationInfo"] == "_:creationinfo" && n["spdxId"].as_str().is_some())
        );
    }

    #[test]
    fn packages_carry_purls_hashes_suppliers_and_metadata() {
        let doc = json();
        let packages = nodes(&doc, "software_Package");
        let by_name = |name: &str| packages.iter().find(|p| p["name"] == name).unwrap().clone();
        let libzlib = by_name("libzlib");
        assert!(
            libzlib["spdxId"]
                .as_str()
                .unwrap()
                .ends_with("#Package-conda-libzlib-1.3.1")
        );
        assert_eq!(libzlib["software_packageVersion"], "1.3.1");
        assert_eq!(libzlib["software_primaryPurpose"], "library");
        assert!(
            libzlib["software_packageUrl"]
                .as_str()
                .unwrap()
                .starts_with("pkg:conda/libzlib@1.3.1")
        );
        assert_eq!(libzlib["verifiedUsing"][0]["algorithm"], "sha256");
        assert_eq!(libzlib["verifiedUsing"][1]["algorithm"], "md5");
        assert_eq!(libzlib["summary"], "zlib data compression library");
        assert_eq!(libzlib["software_homePage"], "https://zlib.net");
        assert!(
            libzlib["comment"]
                .as_str()
                .unwrap()
                .contains("pixi:license-files=LICENSE.txt")
        );
        let suppliers = nodes(&doc, "Organization");
        assert_eq!(suppliers.len(), 2, "conda-forge and pypi.org, deduplicated");
        assert_eq!(
            libzlib["suppliedBy"],
            suppliers.iter().find(|s| s["name"] == "conda-forge").unwrap()["spdxId"]
        );
        let zlib = by_name("zlib");
        assert_eq!(zlib["externalIdentifier"][0]["externalIdentifierType"], "packageUrl");
        assert_eq!(zlib["externalIdentifier"][0]["identifier"], "pkg:pypi/zlib@1.3.1");
        let mylib = by_name("mylib");
        assert!(mylib.get("software_downloadLocation").is_none());
        assert_eq!(mylib["software_sourceInfo"], "built from source at ./packages/mylib");
        let root = by_name("demo");
        assert_eq!(root["software_primaryPurpose"], "application");
        assert_eq!(root["software_downloadLocation"], "https://github.com/example/demo");
    }

    #[test]
    fn licenses_are_shared_elements_linked_by_relationships() {
        let doc = json();
        let expressions = nodes(&doc, "simplelicensing_LicenseExpression");
        let mut exprs: Vec<_> = expressions
            .iter()
            .map(|n| n["simplelicensing_licenseExpression"].as_str().unwrap())
            .collect();
        exprs.sort();
        assert_eq!(exprs, ["Apache-2.0", "CC0-1.0", "MIT OR Apache-2.0", "Zlib"]);
        let texts = nodes(&doc, "simplelicensing_SimpleLicensingText");
        assert_eq!(texts.len(), 1);
        assert_eq!(texts[0]["name"], "Proprietary");
        assert_eq!(
            texts[0]["simplelicensing_licenseText"], "all rights reserved",
            "file text wins"
        );

        let rels = nodes(&doc, "Relationship");
        let declared: Vec<_> = rels
            .iter()
            .filter(|r| r["relationshipType"] == "hasDeclaredLicense")
            .collect();
        assert_eq!(declared.len(), 4, "root, libzlib, zlib, mylib; six has none");
        let depends: Vec<_> = rels.iter().filter(|r| r["relationshipType"] == "dependsOn").collect();
        assert_eq!(depends.len(), 3, "zlib, mylib, root");
        let root_dep = depends
            .iter()
            .find(|r| r["from"].as_str().unwrap().ends_with("#package-root"))
            .unwrap();
        assert_eq!(root_dep["to"].as_array().unwrap().len(), 2);

        // Every referenced id is an element in the graph.
        let ids: std::collections::HashSet<&str> = doc["@graph"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|n| n["spdxId"].as_str())
            .collect();
        for r in &rels {
            assert!(ids.contains(r["from"].as_str().unwrap()));
            for t in r["to"].as_array().unwrap() {
                assert!(ids.contains(t.as_str().unwrap()), "{t}");
            }
        }
        let sbom = &nodes(&doc, "software_Sbom")[0];
        for e in sbom["element"].as_array().unwrap() {
            assert!(ids.contains(e.as_str().unwrap()), "{e}");
        }
    }

    #[test]
    fn empty_license_text_is_skipped_and_no_authors_means_agent_only() {
        let mut sbom = sample_sbom();
        sbom.root.authors.clear();
        sbom.root.license = Some("   ".into());
        let doc = serde_json::to_value(document(&sbom, &fixed_context())).unwrap();
        assert_eq!(doc["@graph"][0]["createdBy"].as_array().unwrap().len(), 1);
        assert!(nodes(&doc, "Person").is_empty());
        let rels = nodes(&doc, "Relationship");
        assert!(!rels.iter().any(|r| {
            r["relationshipType"] == "hasDeclaredLicense" && r["from"].as_str().unwrap().ends_with("#package-root")
        }));
    }
}
