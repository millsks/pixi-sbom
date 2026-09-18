//! CycloneDX 1.6 JSON serializer.

use serde::Serialize;

use super::{WriteContext, top_level_ids};
use crate::license::{self, License};
use crate::model::{Package, PackageKind, Sbom};

const SPEC_VERSION: &str = "1.6";
const SCHEMA_URL: &str = "http://cyclonedx.org/schema/bom-1.6.schema.json";
const ROOT_REF: &str = "root";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Bom {
    #[serde(rename = "$schema")]
    schema: &'static str,
    bom_format: &'static str,
    spec_version: &'static str,
    serial_number: String,
    version: u32,
    metadata: Metadata,
    components: Vec<Component>,
    dependencies: Vec<Dependency>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    timestamp: String,
    tools: Tools,
    component: Component,
    properties: Vec<Property>,
}

#[derive(Debug, Serialize)]
struct Tools {
    components: Vec<Component>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Component {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    hashes: Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    licenses: Vec<LicenseChoice>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_references: Vec<ExternalReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<Property>,
}

#[derive(Debug, Serialize)]
struct Hash {
    alg: &'static str,
    content: String,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
enum LicenseChoice {
    Expression { expression: String },
    Named { license: NamedLicense },
}

#[derive(Debug, Serialize)]
struct NamedLicense {
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalReference {
    #[serde(rename = "type")]
    kind: &'static str,
    url: String,
}

#[derive(Debug, Serialize)]
struct Property {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Dependency {
    #[serde(rename = "ref")]
    reference: String,
    depends_on: Vec<String>,
}

/// Build the CycloneDX document for `sbom`.
pub(crate) fn document(sbom: &Sbom, ctx: &WriteContext) -> Bom {
    let mut dependencies = Vec::with_capacity(sbom.packages.len() + 1);
    dependencies.push(Dependency {
        reference: ROOT_REF.into(),
        depends_on: top_level_ids(sbom).into_iter().map(str::to_string).collect(),
    });
    dependencies.extend(sbom.packages.iter().map(|p| Dependency {
        reference: p.id.clone(),
        depends_on: p.dependencies.clone(),
    }));

    Bom {
        schema: SCHEMA_URL,
        bom_format: "CycloneDX",
        spec_version: SPEC_VERSION,
        serial_number: format!("urn:uuid:{}", ctx.uuid),
        version: 1,
        metadata: Metadata {
            timestamp: ctx.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            tools: Tools {
                components: vec![tool_component(ctx)],
            },
            component: root_component(sbom),
            properties: vec![
                property("pixi:environment", &sbom.environment),
                property("pixi:platform", &sbom.platform),
                property("pixi:lockfile", &sbom.lockfile),
            ],
        },
        components: sbom.packages.iter().map(component).collect(),
        dependencies,
    }
}

fn tool_component(ctx: &WriteContext) -> Component {
    Component {
        kind: "application",
        bom_ref: format!("pkg:cargo/pixi-sbom@{}", ctx.tool_version),
        name: "pixi-sbom".into(),
        version: Some(ctx.tool_version.clone()),
        purl: None,
        hashes: vec![],
        licenses: vec![],
        external_references: vec![ExternalReference {
            kind: "vcs",
            url: env!("CARGO_PKG_REPOSITORY").into(),
        }],
        properties: vec![],
    }
}

fn root_component(sbom: &Sbom) -> Component {
    Component {
        kind: "application",
        bom_ref: ROOT_REF.into(),
        name: sbom.root.name.clone(),
        version: sbom.root.version.clone(),
        purl: None,
        hashes: vec![],
        licenses: vec![],
        external_references: vec![],
        properties: vec![],
    }
}

fn component(package: &Package) -> Component {
    let mut properties: Vec<Property> = package.properties.iter().map(|(k, v)| property(k, v)).collect();
    properties.push(property("pixi:kind", kind_name(package.kind)));
    properties.extend(package.extra_purls.iter().map(|purl| property("pixi:purl", purl)));

    let mut hashes = Vec::new();
    if let Some(sha256) = &package.sha256 {
        hashes.push(Hash {
            alg: "SHA-256",
            content: sha256.clone(),
        });
    }
    if let Some(md5) = &package.md5 {
        hashes.push(Hash {
            alg: "MD5",
            content: md5.clone(),
        });
    }

    Component {
        kind: "library",
        bom_ref: package.id.clone(),
        name: package.name.clone(),
        version: package.version.clone(),
        purl: Some(package.purl.clone()),
        hashes,
        licenses: package
            .license
            .as_deref()
            .map(license_choice)
            .into_iter()
            .flatten()
            .collect(),
        external_references: vec![ExternalReference {
            kind: if package.location.starts_with("git+") {
                "vcs"
            } else {
                "distribution"
            },
            url: package.location.clone(),
        }],
        properties,
    }
}

fn license_choice(raw: &str) -> Option<LicenseChoice> {
    match license::normalize(raw) {
        License::Expression(expression) => Some(LicenseChoice::Expression { expression }),
        License::Text(name) if name.is_empty() => None,
        License::Text(name) => Some(LicenseChoice::Named {
            license: NamedLicense { name },
        }),
    }
}

fn kind_name(kind: PackageKind) -> &'static str {
    match kind {
        PackageKind::CondaBinary => "conda",
        PackageKind::CondaSource => "conda-source",
        PackageKind::Pypi => "pypi",
    }
}

fn property(name: &str, value: &str) -> Property {
    Property {
        name: name.into(),
        value: value.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::{fixed_context, sample_sbom};

    fn json() -> serde_json::Value {
        serde_json::to_value(document(&sample_sbom(), &fixed_context())).unwrap()
    }

    #[test]
    fn snapshot() {
        insta::assert_json_snapshot!(json());
    }

    #[test]
    fn header_and_metadata() {
        let doc = json();
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.6");
        assert_eq!(doc["serialNumber"], "urn:uuid:11111111-2222-4333-8444-555555555555");
        assert_eq!(doc["metadata"]["timestamp"], "2026-09-18T12:00:00Z");
        assert_eq!(doc["metadata"]["component"]["name"], "demo");
        assert_eq!(doc["metadata"]["component"]["version"], "2.0.0");
        assert_eq!(doc["metadata"]["tools"]["components"][0]["name"], "pixi-sbom");
        assert_eq!(doc["metadata"]["tools"]["components"][0]["version"], "0.0.0-test");
    }

    #[test]
    fn licenses_are_expressions_or_names() {
        let doc = json();
        let components = doc["components"].as_array().unwrap();
        let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
        assert_eq!(by_name("libzlib")["licenses"][0]["expression"], "Zlib");
        assert_eq!(by_name("zlib")["licenses"][0]["expression"], "MIT OR Apache-2.0");
        assert_eq!(by_name("mylib")["licenses"][0]["license"]["name"], "Proprietary");
        assert!(by_name("six").get("licenses").is_none());
    }

    #[test]
    fn hashes_and_references() {
        let doc = json();
        let libzlib = &doc["components"][0];
        assert_eq!(libzlib["hashes"][0]["alg"], "SHA-256");
        assert_eq!(libzlib["hashes"][1]["alg"], "MD5");
        assert_eq!(libzlib["externalReferences"][0]["type"], "distribution");
        let mylib = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "mylib")
            .unwrap();
        assert!(mylib.get("hashes").is_none());
        assert!(mylib.get("version").is_none());
    }

    #[test]
    fn dependency_graph_starts_at_root() {
        let doc = json();
        let deps = doc["dependencies"].as_array().unwrap();
        assert_eq!(deps[0]["ref"], "root");
        assert_eq!(deps[0]["dependsOn"].as_array().unwrap().len(), 2);
        let zlib = deps
            .iter()
            .find(|d| d["ref"].as_str().unwrap().contains("/zlib@"))
            .unwrap();
        assert!(zlib["dependsOn"][0].as_str().unwrap().contains("libzlib"));
    }

    #[test]
    fn git_locations_are_vcs_references() {
        let mut sbom = sample_sbom();
        sbom.packages[2].location = "git+https://example.com/repo.git@abc".into();
        let doc = serde_json::to_value(document(&sbom, &fixed_context())).unwrap();
        let mylib = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "mylib")
            .unwrap();
        assert_eq!(mylib["externalReferences"][0]["type"], "vcs");
    }

    #[test]
    fn extra_purls_become_properties() {
        let doc = json();
        let zlib = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "zlib")
            .unwrap();
        let props = zlib["properties"].as_array().unwrap();
        assert!(
            props
                .iter()
                .any(|p| p["name"] == "pixi:purl" && p["value"] == "pkg:pypi/zlib@1.3.1")
        );
        assert!(props.iter().any(|p| p["name"] == "pixi:kind" && p["value"] == "conda"));
    }
}
