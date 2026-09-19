//! SPDX 2.3 JSON serializer.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use super::{WriteContext, top_level_ids};
use crate::license::{self, License};
use crate::model::{Author, Package, PackageKind, Sbom, Supplier};

const DOCUMENT_ID: &str = "SPDXRef-DOCUMENT";
const ROOT_ID: &str = "SPDXRef-Package-root";
const NOASSERTION: &str = "NOASSERTION";
/// Generation context, the SPDX 2.3 counterpart of a CycloneDX lifecycle phase.
const CREATOR_COMMENT: &str =
    "Generated from the pixi lockfile (resolved dependencies) before any build; lifecycle phase: pre-build";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Document {
    spdx_version: &'static str,
    data_license: &'static str,
    #[serde(rename = "SPDXID")]
    spdx_id: &'static str,
    name: String,
    document_namespace: String,
    creation_info: CreationInfo,
    packages: Vec<SpdxPackage>,
    relationships: Vec<Relationship>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    has_extracted_licensing_infos: Vec<ExtractedLicense>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationInfo {
    comment: &'static str,
    created: String,
    creators: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<String>,
    download_location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    homepage: Option<String>,
    files_analyzed: bool,
    license_concluded: String,
    license_declared: String,
    copyright_text: &'static str,
    primary_package_purpose: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checksums: Vec<Checksum>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_refs: Vec<ExternalRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_info: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Checksum {
    algorithm: &'static str,
    checksum_value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalRef {
    reference_category: &'static str,
    reference_type: &'static str,
    reference_locator: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Relationship {
    spdx_element_id: String,
    relationship_type: &'static str,
    related_spdx_element: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExtractedLicense {
    license_id: String,
    extracted_text: String,
    name: String,
}

/// Build the SPDX document for `sbom`.
pub(crate) fn document(sbom: &Sbom, ctx: &WriteContext) -> Document {
    let ids = assign_ids(&sbom.packages);
    let mut extracted: BTreeMap<String, ExtractedLicense> = BTreeMap::new();

    let packages = sbom
        .packages
        .iter()
        .map(|package| spdx_package(package, &ids, &mut extracted))
        .collect();

    let mut relationships = vec![Relationship {
        spdx_element_id: DOCUMENT_ID.into(),
        relationship_type: "DESCRIBES",
        related_spdx_element: ROOT_ID.into(),
    }];
    relationships.extend(top_level_ids(sbom).into_iter().map(|id| Relationship {
        spdx_element_id: ROOT_ID.into(),
        relationship_type: "DEPENDS_ON",
        related_spdx_element: ids[id].clone(),
    }));
    for package in &sbom.packages {
        relationships.extend(package.dependencies.iter().map(|dep| Relationship {
            spdx_element_id: ids[package.id.as_str()].clone(),
            relationship_type: "DEPENDS_ON",
            related_spdx_element: ids[dep.as_str()].clone(),
        }));
    }

    let name = format!("{}-{}-{}", sbom.root.name, sbom.environment, sbom.platform);
    let mut all_packages = vec![root_package(sbom, &mut extracted)];
    all_packages.extend::<Vec<SpdxPackage>>(packages);

    Document {
        spdx_version: "SPDX-2.3",
        data_license: "CC0-1.0",
        spdx_id: DOCUMENT_ID,
        document_namespace: format!(
            "https://spdx.org/spdxdocs/pixi-sbom/{}/{}",
            id_fragment(&name),
            ctx.uuid
        ),
        name,
        creation_info: CreationInfo {
            comment: CREATOR_COMMENT,
            created: ctx.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            creators: std::iter::once(format!("Tool: pixi-sbom-{}", ctx.tool_version))
                .chain(sbom.root.authors.iter().map(person))
                .collect(),
        },
        packages: all_packages,
        relationships,
        has_extracted_licensing_infos: extracted.into_values().collect(),
    }
}

/// Map every package id to a unique, spec-conforming `SPDXRef-...` identifier.
fn assign_ids(packages: &[Package]) -> HashMap<&str, String> {
    let mut taken: HashSet<String> = HashSet::from([ROOT_ID.to_string()]);
    let mut ids = HashMap::with_capacity(packages.len());
    for package in packages {
        let base = format!(
            "SPDXRef-Package-{}-{}",
            kind_name(package.kind),
            id_fragment(&match &package.version {
                Some(version) => format!("{}-{}", package.name, version),
                None => package.name.clone(),
            })
        );
        let mut candidate = base.clone();
        let mut counter = 1;
        while !taken.insert(candidate.clone()) {
            counter += 1;
            candidate = format!("{base}-{counter}");
        }
        ids.insert(package.id.as_str(), candidate);
    }
    ids
}

/// Keep only the characters SPDX allows in identifiers.
fn id_fragment(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// `Person: name (email)` per the SPDX agent syntax.
fn person(author: &Author) -> String {
    match &author.email {
        Some(email) => format!("Person: {} ({email})", author.name),
        None => format!("Person: {}", author.name),
    }
}

/// `Organization: name (url)`; the url stands in for the contact SPDX puts in parentheses.
fn organization(supplier: &Supplier) -> String {
    match &supplier.url {
        Some(url) => format!("Organization: {} ({url})", supplier.name),
        None => format!("Organization: {}", supplier.name),
    }
}

fn root_package(sbom: &Sbom, extracted: &mut BTreeMap<String, ExtractedLicense>) -> SpdxPackage {
    let root = &sbom.root;
    SpdxPackage {
        spdx_id: ROOT_ID.into(),
        name: root.name.clone(),
        version_info: root.version.clone(),
        supplier: None,
        download_location: root.repository.clone().unwrap_or_else(|| NOASSERTION.into()),
        homepage: root.homepage.clone(),
        files_analyzed: false,
        license_concluded: NOASSERTION.into(),
        license_declared: root
            .license
            .as_deref()
            .map(|raw| license_declared(raw, extracted))
            .unwrap_or_else(|| NOASSERTION.into()),
        copyright_text: NOASSERTION,
        primary_package_purpose: "APPLICATION",
        checksums: vec![],
        external_refs: vec![],
        source_info: Some(format!(
            "pixi workspace; lockfile {}; environment {}; platform {}",
            sbom.lockfile, sbom.environment, sbom.platform
        )),
        comment: None,
    }
}

fn spdx_package(
    package: &Package,
    ids: &HashMap<&str, String>,
    extracted: &mut BTreeMap<String, ExtractedLicense>,
) -> SpdxPackage {
    let mut checksums = Vec::new();
    if let Some(sha256) = &package.sha256 {
        checksums.push(Checksum {
            algorithm: "SHA256",
            checksum_value: sha256.clone(),
        });
    }
    if let Some(md5) = &package.md5 {
        checksums.push(Checksum {
            algorithm: "MD5",
            checksum_value: md5.clone(),
        });
    }

    let external_refs = std::iter::once(&package.purl)
        .chain(&package.extra_purls)
        .map(|purl| ExternalRef {
            reference_category: "PACKAGE-MANAGER",
            reference_type: "purl",
            reference_locator: purl.clone(),
        })
        .collect();

    let is_url = package.location.contains("://");
    let (download_location, source_info) = if is_url {
        (package.location.clone(), None)
    } else {
        (
            NOASSERTION.into(),
            Some(format!("built from source at {}", package.location)),
        )
    };

    let comment = (!package.properties.is_empty()).then(|| {
        package
            .properties
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n")
    });

    SpdxPackage {
        spdx_id: ids[package.id.as_str()].clone(),
        name: package.name.clone(),
        version_info: package.version.clone(),
        supplier: package.supplier.as_ref().map(organization),
        download_location,
        homepage: None,
        files_analyzed: false,
        license_concluded: NOASSERTION.into(),
        license_declared: package
            .license
            .as_deref()
            .map(|raw| license_declared(raw, extracted))
            .unwrap_or_else(|| NOASSERTION.into()),
        copyright_text: NOASSERTION,
        primary_package_purpose: "LIBRARY",
        checksums,
        external_refs,
        source_info,
        comment,
    }
}

/// SPDX expressions pass through; anything else becomes a `LicenseRef-` backed by an
/// extracted licensing info entry so the original text is preserved.
fn license_declared(raw: &str, extracted: &mut BTreeMap<String, ExtractedLicense>) -> String {
    match license::normalize(raw) {
        License::Expression(expression) => expression,
        License::Text(text) if text.is_empty() => NOASSERTION.into(),
        License::Text(text) => {
            let license_id = format!("LicenseRef-pixi-{}", id_fragment(&text));
            extracted.entry(license_id.clone()).or_insert_with(|| ExtractedLicense {
                license_id: license_id.clone(),
                extracted_text: text.clone(),
                name: text,
            });
            license_id
        }
    }
}

fn kind_name(kind: PackageKind) -> &'static str {
    match kind {
        PackageKind::CondaBinary => "conda",
        PackageKind::CondaSource => "conda-source",
        PackageKind::Pypi => "pypi",
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
    fn header_and_creation_info() {
        let doc = json();
        assert_eq!(doc["spdxVersion"], "SPDX-2.3");
        assert_eq!(doc["dataLicense"], "CC0-1.0");
        assert_eq!(doc["SPDXID"], "SPDXRef-DOCUMENT");
        assert_eq!(doc["name"], "demo-default-linux-64");
        assert_eq!(
            doc["documentNamespace"],
            "https://spdx.org/spdxdocs/pixi-sbom/demo-default-linux-64/11111111-2222-4333-8444-555555555555"
        );
        assert_eq!(doc["creationInfo"]["created"], "2026-09-18T12:00:00Z");
        assert_eq!(doc["creationInfo"]["creators"][0], "Tool: pixi-sbom-0.0.0-test");
        assert_eq!(
            doc["creationInfo"]["creators"][1],
            "Person: Ada Lovelace (ada@example.org)"
        );
        assert_eq!(doc["creationInfo"]["creators"][2], "Person: Anonymous");
        assert!(doc["creationInfo"]["comment"].as_str().unwrap().contains("pre-build"));
    }

    #[test]
    fn root_package_carries_manifest_metadata() {
        let doc = json();
        let root = &doc["packages"][0];
        assert_eq!(root["licenseDeclared"], "Apache-2.0");
        assert_eq!(root["homepage"], "https://demo.example");
        assert_eq!(root["downloadLocation"], "https://github.com/example/demo");
        assert!(root.get("supplier").is_none());

        let mut bare = sample_sbom();
        bare.root = crate::model::Root {
            name: "bare".into(),
            license: Some("Proprietary".into()),
            ..Default::default()
        };
        let doc = serde_json::to_value(document(&bare, &fixed_context())).unwrap();
        let root = &doc["packages"][0];
        assert_eq!(root["downloadLocation"], "NOASSERTION");
        assert!(root.get("homepage").is_none());
        assert_eq!(root["licenseDeclared"], "LicenseRef-pixi-Proprietary");
        assert_eq!(doc["creationInfo"]["creators"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn suppliers_use_the_organization_syntax() {
        let doc = json();
        let packages = doc["packages"].as_array().unwrap();
        let by_name = |name: &str| packages.iter().find(|p| p["name"] == name).unwrap();
        assert_eq!(
            by_name("libzlib")["supplier"],
            "Organization: conda-forge (https://conda.anaconda.org/conda-forge/)"
        );
        assert_eq!(by_name("zlib")["supplier"], "Organization: conda-forge");
        assert_eq!(
            by_name("six")["supplier"],
            "Organization: pypi.org (https://pypi.org/simple)"
        );
        assert!(by_name("mylib").get("supplier").is_none());
    }

    #[test]
    fn root_package_is_described_and_depends_on_top_level() {
        let doc = json();
        assert_eq!(doc["packages"][0]["SPDXID"], "SPDXRef-Package-root");
        assert_eq!(doc["packages"][0]["name"], "demo");
        let rels = doc["relationships"].as_array().unwrap();
        assert_eq!(rels[0]["relationshipType"], "DESCRIBES");
        assert_eq!(rels[0]["relatedSpdxElement"], "SPDXRef-Package-root");
        let root_deps: Vec<_> = rels
            .iter()
            .filter(|r| r["spdxElementId"] == "SPDXRef-Package-root" && r["relationshipType"] == "DEPENDS_ON")
            .map(|r| r["relatedSpdxElement"].as_str().unwrap())
            .collect();
        assert_eq!(
            root_deps,
            ["SPDXRef-Package-conda-source-mylib", "SPDXRef-Package-pypi-six-1.17.0"]
        );
    }

    #[test]
    fn package_fields() {
        let doc = json();
        let packages = doc["packages"].as_array().unwrap();
        let by_name = |name: &str| packages.iter().find(|p| p["name"] == name).unwrap();

        let libzlib = by_name("libzlib");
        assert_eq!(libzlib["SPDXID"], "SPDXRef-Package-conda-libzlib-1.3.1");
        assert_eq!(libzlib["versionInfo"], "1.3.1");
        assert_eq!(libzlib["filesAnalyzed"], false);
        assert_eq!(libzlib["licenseDeclared"], "Zlib");
        assert_eq!(libzlib["licenseConcluded"], "NOASSERTION");
        assert_eq!(libzlib["checksums"][0]["algorithm"], "SHA256");
        assert_eq!(libzlib["checksums"][1]["algorithm"], "MD5");
        assert_eq!(libzlib["externalRefs"][0]["referenceType"], "purl");
        assert_eq!(libzlib["comment"], "pixi:channel=conda-forge\npixi:subdir=linux-64");

        let zlib = by_name("zlib");
        assert_eq!(zlib["licenseDeclared"], "MIT OR Apache-2.0");
        assert_eq!(
            zlib["externalRefs"].as_array().unwrap().len(),
            2,
            "extra purls are external refs"
        );

        let six = by_name("six");
        assert_eq!(six["licenseDeclared"], "NOASSERTION");
    }

    #[test]
    fn source_package_uses_noassertion_download_and_source_info() {
        let doc = json();
        let mylib = doc["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "mylib")
            .unwrap();
        assert_eq!(mylib["downloadLocation"], "NOASSERTION");
        assert_eq!(mylib["sourceInfo"], "built from source at ./packages/mylib");
        assert!(mylib.get("versionInfo").is_none());
        assert!(mylib.get("checksums").is_none());
    }

    #[test]
    fn non_spdx_license_becomes_license_ref_with_extracted_text() {
        let doc = json();
        let mylib = doc["packages"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == "mylib")
            .unwrap();
        assert_eq!(mylib["licenseDeclared"], "LicenseRef-pixi-Proprietary");
        let extracted = doc["hasExtractedLicensingInfos"].as_array().unwrap();
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0]["licenseId"], "LicenseRef-pixi-Proprietary");
        assert_eq!(extracted[0]["extractedText"], "Proprietary");
    }

    #[test]
    fn ids_are_sanitized_and_unique() {
        let mut sbom = sample_sbom();
        let mut dup = sbom.packages[0].clone();
        dup.id = "pkg:conda/libzlib@1.3.1?build=h2".into();
        dup.name = "lib zlib!".into();
        sbom.packages.push(dup);
        let mut dup2 = sbom.packages[0].clone();
        dup2.id = "pkg:conda/libzlib@1.3.1?build=h3".into();
        sbom.packages.push(dup2);

        let ids = assign_ids(&sbom.packages);
        assert_eq!(
            ids["pkg:conda/libzlib@1.3.1?build=h2"],
            "SPDXRef-Package-conda-lib-zlib--1.3.1"
        );
        assert_eq!(
            ids["pkg:conda/libzlib@1.3.1?build=h3"],
            "SPDXRef-Package-conda-libzlib-1.3.1-2"
        );
        let unique: HashSet<_> = ids.values().collect();
        assert_eq!(unique.len(), ids.len());
    }
}
