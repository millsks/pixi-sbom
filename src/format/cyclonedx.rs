//! CycloneDX 1.6 / 1.7 JSON serializer.

use serde::Serialize;

use super::{WriteContext, top_level_ids};
use crate::cli::SpecVersion;
use crate::license::{self, License};
use crate::model::{Author, LicenseFile, Package, PackageKind, Sbom, Supplier};

const ROOT_REF: &str = "root";
/// The document is derived from a lockfile, i.e. from resolved inputs before any build runs.
const LIFECYCLE_PHASE: &str = "pre-build";

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
    /// CycloneDX 1.7 only: who supplied which fields.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    citations: Vec<Citation>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Citation {
    pointers: Vec<&'static str>,
    timestamp: String,
    attributed_to: String,
    note: String,
}

impl SpecVersion {
    fn number(self) -> &'static str {
        match self {
            SpecVersion::V1_6 => "1.6",
            SpecVersion::V1_7 => "1.7",
        }
    }

    fn schema_url(self) -> &'static str {
        match self {
            SpecVersion::V1_6 => "http://cyclonedx.org/schema/bom-1.6.schema.json",
            SpecVersion::V1_7 => "http://cyclonedx.org/schema/bom-1.7.schema.json",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    timestamp: String,
    lifecycles: Vec<Lifecycle>,
    tools: Tools,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    authors: Vec<Contact>,
    component: Component,
    properties: Vec<Property>,
}

#[derive(Debug, Serialize)]
struct Lifecycle {
    phase: &'static str,
}

#[derive(Debug, Serialize)]
struct Contact {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

#[derive(Debug, Serialize)]
struct Entity {
    name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    url: Vec<String>,
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
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<Entity>,
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
    License { license: LicenseObject },
}

/// A CycloneDX `license` object: an SPDX `id` or a free-text `name`, optionally with the text.
#[derive(Debug, Serialize)]
struct LicenseObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<Attachment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    acknowledgement: Option<&'static str>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Attachment {
    content_type: &'static str,
    content: String,
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

    let timestamp = ctx.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let citations = match ctx.spec_version {
        SpecVersion::V1_6 => vec![],
        SpecVersion::V1_7 => vec![Citation {
            pointers: vec!["/metadata/component", "/components", "/dependencies"],
            timestamp: timestamp.clone(),
            attributed_to: tool_ref(ctx),
            note: format!(
                "Derived from the pixi lockfile {} (environment {}, platform {}) and the workspace manifest",
                sbom.lockfile, sbom.environment, sbom.platform
            ),
        }],
    };

    Bom {
        schema: ctx.spec_version.schema_url(),
        bom_format: "CycloneDX",
        spec_version: ctx.spec_version.number(),
        serial_number: format!("urn:uuid:{}", ctx.uuid),
        version: 1,
        metadata: Metadata {
            timestamp,
            lifecycles: vec![Lifecycle { phase: LIFECYCLE_PHASE }],
            tools: Tools {
                components: vec![tool_component(ctx)],
            },
            authors: sbom.root.authors.iter().map(contact).collect(),
            component: root_component(sbom),
            properties: vec![
                property("pixi:environment", &sbom.environment),
                property("pixi:platform", &sbom.platform),
                property("pixi:lockfile", &sbom.lockfile),
            ],
        },
        components: sbom.packages.iter().map(component).collect(),
        dependencies,
        citations,
    }
}

fn tool_ref(ctx: &WriteContext) -> String {
    format!("pkg:cargo/pixi-sbom@{}", ctx.tool_version)
}

fn tool_component(ctx: &WriteContext) -> Component {
    Component {
        kind: "application",
        bom_ref: tool_ref(ctx),
        name: "pixi-sbom".into(),
        version: Some(ctx.tool_version.clone()),
        description: None,
        supplier: None,
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
    let root = &sbom.root;
    Component {
        kind: "application",
        bom_ref: ROOT_REF.into(),
        name: root.name.clone(),
        version: root.version.clone(),
        description: None,
        supplier: None,
        purl: None,
        hashes: vec![],
        licenses: root.license.as_deref().and_then(license_choice).into_iter().collect(),
        external_references: project_references(root.homepage.as_deref(), root.repository.as_deref(), None),
        properties: vec![],
    }
}

fn project_references(
    homepage: Option<&str>,
    repository: Option<&str>,
    documentation: Option<&str>,
) -> Vec<ExternalReference> {
    [
        ("website", homepage),
        ("vcs", repository),
        ("documentation", documentation),
    ]
    .into_iter()
    .filter_map(|(kind, url)| {
        url.map(|url| ExternalReference {
            kind,
            url: url.to_string(),
        })
    })
    .collect()
}

fn contact(author: &Author) -> Contact {
    Contact {
        name: author.name.clone(),
        email: author.email.clone(),
    }
}

fn entity(supplier: &Supplier) -> Entity {
    Entity {
        name: supplier.name.clone(),
        url: supplier.url.iter().cloned().collect(),
    }
}

fn component(package: &Package) -> Component {
    let mut properties: Vec<Property> = package.properties.iter().map(|(k, v)| property(k, v)).collect();
    properties.push(property("pixi:kind", kind_name(package.kind)));
    properties.extend(package.extra_purls.iter().map(|purl| property("pixi:purl", purl)));
    let licenses = package_licenses(package);
    if !matches!(licenses.first(), Some(LicenseChoice::License { .. })) {
        // File names travel as properties whenever they are not carried as license objects.
        properties.extend(
            package
                .license_files
                .iter()
                .map(|f| property("pixi:license-file", &f.name)),
        );
    }

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
        description: package.description.clone(),
        supplier: package.supplier.as_ref().map(entity),
        purl: Some(package.purl.clone()),
        hashes,
        licenses,
        external_references: std::iter::once(ExternalReference {
            kind: if package.location.starts_with("git+") {
                "vcs"
            } else {
                "distribution"
            },
            url: package.location.clone(),
        })
        .chain(project_references(
            package.homepage.as_deref(),
            package.repository.as_deref(),
            package.documentation.as_deref(),
        ))
        .collect(),
        properties,
    }
}

/// The `licenses` array for a package. Without texts this is the declared license as an
/// expression or a name, as always. With texts (`--license-texts`) CycloneDX allows either one
/// expression or a list of license objects, so texts are attached only when the declared
/// license is a single SPDX identifier (as `id` + `text`) or free text (as `name` + `text`);
/// a compound expression is kept as is and the files are listed as properties instead.
/// Additional files become further named entries.
fn package_licenses(package: &Package) -> Vec<LicenseChoice> {
    let with_text: Vec<&LicenseFile> = package.license_files.iter().filter(|f| f.text.is_some()).collect();
    let Some(raw) = package.license.as_deref() else {
        return with_text.iter().map(|f| named_file(f)).collect();
    };
    let (first, files) = match license::normalize(raw) {
        License::Expression(expression) if with_text.is_empty() || !license::is_single_id(&expression) => {
            return vec![LicenseChoice::Expression { expression }];
        }
        License::Expression(id) => (
            LicenseObject {
                id: Some(id),
                name: None,
                text: with_text.first().map(|f| attachment(f)),
                acknowledgement: Some("declared"),
            },
            &with_text[1..],
        ),
        License::Text(name) if name.is_empty() => return vec![],
        License::Text(name) => (
            LicenseObject {
                id: None,
                name: Some(name),
                text: with_text.first().map(|f| attachment(f)),
                acknowledgement: with_text.first().map(|_| "declared"),
            },
            with_text.get(1..).unwrap_or_default(),
        ),
    };
    std::iter::once(LicenseChoice::License { license: first })
        .chain(files.iter().map(|f| named_file(f)))
        .collect()
}

fn named_file(file: &LicenseFile) -> LicenseChoice {
    LicenseChoice::License {
        license: LicenseObject {
            id: None,
            name: Some(file.name.clone()),
            text: Some(attachment(file)),
            acknowledgement: None,
        },
    }
}

fn attachment(file: &LicenseFile) -> Attachment {
    Attachment {
        content_type: "text/plain",
        content: file.text.clone().unwrap_or_default(),
    }
}

fn license_choice(raw: &str) -> Option<LicenseChoice> {
    match license::normalize(raw) {
        License::Expression(expression) => Some(LicenseChoice::Expression { expression }),
        License::Text(name) if name.is_empty() => None,
        License::Text(name) => Some(LicenseChoice::License {
            license: LicenseObject {
                id: None,
                name: Some(name),
                text: None,
                acknowledgement: None,
            },
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
    fn snapshot_1_7() {
        let doc = serde_json::to_value(document(&sample_sbom(), &crate::format::testing::fixed_context_1_7())).unwrap();
        insta::assert_json_snapshot!(doc);
    }

    #[test]
    fn spec_version_1_7_adds_schema_and_citation() {
        let doc = json();
        assert_eq!(doc["specVersion"], "1.6");
        assert_eq!(doc["$schema"], "http://cyclonedx.org/schema/bom-1.6.schema.json");
        assert!(doc.get("citations").is_none());

        let doc = serde_json::to_value(document(&sample_sbom(), &crate::format::testing::fixed_context_1_7())).unwrap();
        assert_eq!(doc["specVersion"], "1.7");
        assert_eq!(doc["$schema"], "http://cyclonedx.org/schema/bom-1.7.schema.json");
        let citation = &doc["citations"][0];
        assert_eq!(citation["attributedTo"], "pkg:cargo/pixi-sbom@0.0.0-test");
        assert_eq!(citation["pointers"][1], "/components");
        assert_eq!(citation["timestamp"], "2026-09-18T12:00:00Z");
        assert!(citation["note"].as_str().unwrap().contains("pixi.lock"));
        assert_eq!(doc["serialNumber"], json()["serialNumber"]);
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
        assert_eq!(doc["metadata"]["lifecycles"][0]["phase"], "pre-build");
    }

    #[test]
    fn authors_and_root_metadata_come_from_the_manifest() {
        let doc = json();
        let authors = doc["metadata"]["authors"].as_array().unwrap();
        assert_eq!(authors.len(), 2);
        assert_eq!(authors[0]["name"], "Ada Lovelace");
        assert_eq!(authors[0]["email"], "ada@example.org");
        assert!(authors[1].get("email").is_none());
        let root = &doc["metadata"]["component"];
        assert_eq!(root["licenses"][0]["expression"], "Apache-2.0");
        assert_eq!(root["externalReferences"][0]["type"], "website");
        assert_eq!(root["externalReferences"][0]["url"], "https://demo.example");
        assert_eq!(root["externalReferences"][1]["type"], "vcs");
        assert!(root.get("supplier").is_none());

        let mut bare = sample_sbom();
        bare.root = crate::model::Root {
            name: "bare".into(),
            ..Default::default()
        };
        let doc = serde_json::to_value(document(&bare, &fixed_context())).unwrap();
        assert!(doc["metadata"].get("authors").is_none());
        assert!(doc["metadata"]["component"].get("licenses").is_none());
        assert!(doc["metadata"]["component"].get("externalReferences").is_none());
    }

    #[test]
    fn suppliers_are_channels_and_indexes() {
        let doc = json();
        let components = doc["components"].as_array().unwrap();
        let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
        assert_eq!(by_name("libzlib")["supplier"]["name"], "conda-forge");
        assert_eq!(
            by_name("libzlib")["supplier"]["url"][0],
            "https://conda.anaconda.org/conda-forge/"
        );
        assert!(by_name("zlib")["supplier"].get("url").is_none());
        assert_eq!(by_name("six")["supplier"]["name"], "pypi.org");
        assert!(by_name("mylib").get("supplier").is_none());
    }

    #[test]
    fn licenses_are_expressions_ids_with_text_or_names() {
        let doc = json();
        let components = doc["components"].as_array().unwrap();
        let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();

        // Single SPDX id with a license file: id + text.
        let libzlib = &by_name("libzlib")["licenses"];
        assert_eq!(libzlib[0]["license"]["id"], "Zlib");
        assert_eq!(libzlib[0]["license"]["text"]["contentType"], "text/plain");
        assert_eq!(libzlib[0]["license"]["text"]["content"], "zlib license text");
        assert_eq!(libzlib[0]["license"]["acknowledgement"], "declared");
        assert_eq!(libzlib.as_array().unwrap().len(), 1);

        // Files without text (no --license-texts): expression plus file-name properties.
        let zlib = by_name("zlib");
        assert_eq!(zlib["licenses"][0]["expression"], "MIT OR Apache-2.0");
        assert_eq!(zlib["licenses"].as_array().unwrap().len(), 1);
        let files: Vec<_> = zlib["properties"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["name"] == "pixi:license-file")
            .map(|p| p["value"].as_str().unwrap())
            .collect();
        assert_eq!(files, ["LICENSE-APACHE", "LICENSE-MIT"]);

        // Free text with a file: name + text.
        let mylib = &by_name("mylib")["licenses"][0]["license"];
        assert_eq!(mylib["name"], "Proprietary");
        assert_eq!(mylib["text"]["content"], "all rights reserved");
        assert!(mylib.get("id").is_none());

        assert!(by_name("six").get("licenses").is_none());
    }

    #[test]
    fn compound_expression_with_texts_keeps_the_expression() {
        let mut sbom = sample_sbom();
        for file in &mut sbom.packages[1].license_files {
            file.text = Some(format!("text of {}", file.name));
        }
        let doc = serde_json::to_value(document(&sbom, &fixed_context())).unwrap();
        let zlib = doc["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "zlib")
            .unwrap();
        assert_eq!(zlib["licenses"][0]["expression"], "MIT OR Apache-2.0");
        assert_eq!(zlib["licenses"].as_array().unwrap().len(), 1);
        assert_eq!(
            zlib["properties"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|p| p["name"] == "pixi:license-file")
                .count(),
            2
        );
    }

    #[test]
    fn extra_license_files_become_named_entries_and_no_text_means_plain_choice() {
        let mut sbom = sample_sbom();
        sbom.packages[0].license_files.push(crate::model::LicenseFile {
            name: "NOTICE".into(),
            text: Some("notice".into()),
        });
        sbom.packages[2].license_files.clear();
        sbom.packages[3].license_files.push(crate::model::LicenseFile {
            name: "LICENSE".into(),
            text: Some("six text".into()),
        });
        let doc = serde_json::to_value(document(&sbom, &fixed_context())).unwrap();
        let components = doc["components"].as_array().unwrap();
        let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
        let libzlib = by_name("libzlib")["licenses"].as_array().unwrap();
        assert_eq!(libzlib.len(), 2);
        assert_eq!(libzlib[1]["license"]["name"], "NOTICE");
        assert_eq!(libzlib[1]["license"]["text"]["content"], "notice");
        assert_eq!(by_name("mylib")["licenses"][0]["license"]["name"], "Proprietary");
        assert!(by_name("mylib")["licenses"][0]["license"].get("text").is_none());
        // No declared license but a file: the file alone.
        assert_eq!(by_name("six")["licenses"][0]["license"]["name"], "LICENSE");
    }

    #[test]
    fn package_metadata_becomes_description_and_references() {
        let doc = json();
        let components = doc["components"].as_array().unwrap();
        let by_name = |name: &str| components.iter().find(|c| c["name"] == name).unwrap();
        let libzlib = by_name("libzlib");
        assert_eq!(libzlib["description"], "zlib data compression library");
        let refs: Vec<_> = libzlib["externalReferences"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["type"].as_str().unwrap(), r["url"].as_str().unwrap()))
            .collect();
        assert_eq!(
            refs,
            [
                (
                    "distribution",
                    "https://conda.anaconda.org/conda-forge/linux-64/libzlib-1.3.1-h1.conda"
                ),
                ("website", "https://zlib.net"),
                ("vcs", "https://github.com/madler/zlib"),
            ]
        );
        assert_eq!(by_name("zlib")["externalReferences"][1]["type"], "documentation");
        assert!(by_name("six").get("description").is_none());
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
