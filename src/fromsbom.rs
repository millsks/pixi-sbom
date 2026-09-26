//! `--from-sbom <FILE>`: read an existing document into the model, so everything the tool
//! does to a lockfile can be done to an SBOM somebody else wrote.
//!
//! The reader is the one [`crate::diff`] already uses for `--against`, which is why CycloneDX
//! 1.4–1.7, SPDX 2.x and SPDX 3.0.1 all work. What comes back is a [`Sbom`] like any other, so
//! the license policy, the reports, the OSV lookup and the vulnerability gate run unchanged;
//! only enrichment that needs a lockfile or a package cache has nothing to read.

use std::path::Path;

use crate::model::{Package, PackageKind, Root, Sbom};
use crate::purl;

/// Property naming the document this one was derived from, by its own identity (a CycloneDX
/// serial number or an SPDX document namespace), so the derivation can be traced.
pub const SOURCE_DOCUMENT_PROPERTY: &str = "pixi:source-document";

/// Why a document could not be read.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum FromSbomError {
    #[error("cannot read {path}: {source}")]
    #[diagnostic(
        code(pixi_sbom::from_sbom::read),
        help(
            "--from-sbom takes a readable CycloneDX, SPDX 2.x or SPDX 3.0 JSON file; check the path and its \
             permissions"
        )
    )]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not a CycloneDX, SPDX 2.x or SPDX 3.0 JSON document")]
    #[diagnostic(
        code(pixi_sbom::from_sbom::parse),
        help("--from-sbom takes a document in one of the formats pixi-sbom itself writes")
    )]
    Parse { path: std::path::PathBuf },
}

/// A document read into the model, with the text it came from (the identity of everything
/// derived from it) and what it calls itself.
#[derive(Debug)]
pub struct Loaded {
    pub sbom: Sbom,
    /// The document's text, which identifies the input the way a lockfile's text does.
    pub contents: String,
    /// The family (`CycloneDX 1.6`, `SPDX 2.3`), for the log line.
    pub format: String,
}

/// Read `path` into the model. `root` carries what the command line said about the described
/// application; what it leaves empty comes from the document's own root component.
pub fn read(path: &Path, root: Root, platform: Option<&str>) -> Result<Loaded, FromSbomError> {
    let contents = std::fs::read_to_string(path).map_err(|source| FromSbomError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let value: serde_json::Value = serde_json::from_str(&contents).map_err(|_| FromSbomError::Parse {
        path: path.to_path_buf(),
    })?;
    let format = family(&value);
    let properties = metadata_properties(&value);
    let mut sbom = Sbom {
        root: root_of(&value, root),
        environment: properties
            .get("pixi:environment")
            .cloned()
            .or_else(|| described(&contents, "environment"))
            .unwrap_or_else(|| "default".to_string()),
        platform: platform
            .map(str::to_string)
            .or_else(|| properties.get("pixi:platform").cloned())
            .or_else(|| described(&contents, "platform"))
            .unwrap_or_default(),
        lockfile: String::new(),
        prefix: None,
        document: Some(identity(&value).unwrap_or_else(|| file_name(path))),
        packages: packages_of(&contents, &value).ok_or_else(|| FromSbomError::Parse {
            path: path.to_path_buf(),
        })?,
        vulnerabilities: Vec::new(),
        excluded: Vec::new(),
        declared_missing: Vec::new(),
        incomplete: crate::model::Incomplete::default(),
    };
    sbom.packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    Ok(Loaded { sbom, contents, format })
}

/// The document family, as the log line and the diff name it.
fn family(value: &serde_json::Value) -> String {
    match value.get("bomFormat") {
        Some(_) => format!(
            "CycloneDX {}",
            value.get("specVersion").and_then(|v| v.as_str()).unwrap_or("")
        )
        .trim()
        .to_string(),
        None => match value.get("spdxVersion").and_then(|v| v.as_str()) {
            Some(version) => version.replace("SPDX-", "SPDX "),
            // SPDX 3.0.1 is a JSON-LD graph: the version is on the CreationInfo node, and the
            // family is what the diff calls it.
            None => match spdx3_version(value) {
                Some(version) => format!(
                    "SPDX {}",
                    version
                        .rsplit_once('.')
                        .map_or(version.as_str(), |(major_minor, _)| major_minor)
                ),
                None => "SPDX".to_string(),
            },
        },
    }
}

/// The `specVersion` of the SPDX 3.0 `CreationInfo` node.
fn spdx3_version(value: &serde_json::Value) -> Option<String> {
    value
        .get("@graph")?
        .as_array()?
        .iter()
        .find_map(|node| node.get("specVersion")?.as_str().map(str::to_string))
}

/// What the document calls itself: a CycloneDX serial number, an SPDX 2.x document namespace,
/// or an SPDX 3.0 document node's id.
fn identity(value: &serde_json::Value) -> Option<String> {
    for pointer in ["/serialNumber", "/documentNamespace"] {
        if let Some(id) = value.pointer(pointer).and_then(|v| v.as_str()) {
            return Some(id.to_string());
        }
    }
    value
        .get("@graph")?
        .as_array()?
        .iter()
        .find(|node| node.get("type").and_then(|v| v.as_str()) == Some("SpdxDocument"))?
        .get("spdxId")?
        .as_str()
        .map(str::to_string)
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// What a `sourceInfo` written by this tool says about the environment or the platform
/// (`pixi workspace; lockfile pixi.lock; environment default; platform linux-64`). SPDX has no
/// properties, so this is where the two facts live in both SPDX versions.
fn described(text: &str, field: &str) -> Option<String> {
    let prefix = format!("{field} ");
    text.split("pixi workspace; ")
        .nth(1)?
        .split("\"")
        .next()?
        .split("; ")
        .find_map(|part| part.trim().strip_prefix(&prefix))
        .map(str::to_string)
        .filter(|value| !value.is_empty())
}

/// The `pixi:*` metadata properties of a document this tool wrote, which say which environment
/// and platform it describes.
fn metadata_properties(value: &serde_json::Value) -> std::collections::BTreeMap<String, String> {
    value
        .pointer("/metadata/properties")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| {
            Some((
                p.get("name")?.as_str()?.to_string(),
                p.get("value")?.as_str()?.to_string(),
            ))
        })
        .collect()
}

/// The described application: what the command line said, else the document's root component.
fn root_of(value: &serde_json::Value, root: Root) -> Root {
    let at = |pointer: &str| value.pointer(pointer).and_then(|v| v.as_str()).map(str::to_string);
    // SPDX 2.x has no metadata component: the root is a package of its own, and the document's
    // own name (`demo-default-linux-64`) is not the application's.
    let spdx_root = |field: &str| {
        value
            .get("packages")?
            .as_array()?
            .iter()
            .find(|p| p.get("SPDXID").and_then(|v| v.as_str()) == Some("SPDXRef-Package-root"))?
            .get(field)?
            .as_str()
            .map(str::to_string)
    };
    // SPDX 3.0.1: the root is the one package whose purpose is `application`.
    let spdx3_root = |field: &str| {
        value
            .get("@graph")?
            .as_array()?
            .iter()
            .find(|node| node.get("software_primaryPurpose").and_then(|v| v.as_str()) == Some("application"))?
            .get(field)?
            .as_str()
            .map(str::to_string)
    };
    let name = at("/metadata/component/name")
        .or_else(|| spdx_root("name"))
        .or_else(|| spdx3_root("name"))
        .or_else(|| at("/name"))
        .unwrap_or_else(|| "document".to_string());
    Root {
        name: if root.name.is_empty() { name } else { root.name },
        version: root
            .version
            .or_else(|| at("/metadata/component/version"))
            .or_else(|| spdx_root("versionInfo"))
            .or_else(|| spdx3_root("software_packageVersion")),
        ..root
    }
}

/// Every package the document describes, with the graph when it has one.
fn packages_of(text: &str, value: &serde_json::Value) -> Option<Vec<Package>> {
    // The root component / package describes the application, not a dependency of it.
    let root: Option<String> = value
        .pointer("/metadata/component/bom-ref")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| value.get("spdxVersion").map(|_| "SPDXRef-Package-root".to_string()));

    if let Some(fragment) = crate::embedded::parse(text) {
        let components: Vec<crate::embedded::Component> = fragment
            .components
            .into_iter()
            .filter(|c| root.as_deref() != Some(c.reference.as_str()))
            .collect();
        // References are the document's own spelling; the model keys on the package id.
        let ids: std::collections::BTreeMap<&str, String> = components
            .iter()
            .map(|c| {
                (
                    c.reference.as_str(),
                    id_of(c.purl.as_deref(), &c.name, c.version.as_deref()),
                )
            })
            .collect();
        return Some(
            components
                .iter()
                .map(|c| {
                    let id = ids[c.reference.as_str()].clone();
                    let mut dependencies: Vec<String> = c
                        .depends_on
                        .iter()
                        .filter_map(|reference| ids.get(reference.as_str()).cloned())
                        .collect();
                    dependencies.sort();
                    dependencies.dedup();
                    Package {
                        purl: id.clone(),
                        id,
                        name: c.name.clone(),
                        version: c.version.clone(),
                        kind: kind_of(c.purl.as_deref()),
                        supplier: supplier_of(&c.properties),
                        extra_purls: Vec::new(),
                        // The document has already answered the identity question.
                        purls_from_lock: true,
                        location: c.location.clone().unwrap_or_default(),
                        sha256: c.sha256.clone(),
                        md5: c.md5.clone(),
                        license: c.license.clone(),
                        license_files: Vec::new(),
                        description: c.description.clone(),
                        homepage: None,
                        repository: None,
                        documentation: None,
                        yanked: None,
                        // `pixi:kind` is derived from the purl and written again, so carrying
                        // the document's copy would only duplicate it.
                        properties: c
                            .properties
                            .iter()
                            .filter(|(key, _)| key.as_str() != "pixi:kind")
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect(),
                        dependencies,
                    }
                })
                .collect(),
        );
    }
    // SPDX 3.0.1: the reader behind --against gives the packages but no graph.
    let previous = crate::diff::parse_previous(text)?;
    Some(
        previous
            .entries
            .into_iter()
            .map(|entry| {
                let id = id_of(entry.purl.as_deref(), &entry.name, entry.version.as_deref());
                Package {
                    purl: id.clone(),
                    id,
                    name: entry.name,
                    version: entry.version,
                    kind: kind_of(entry.purl.as_deref()),
                    supplier: None,
                    extra_purls: Vec::new(),
                    purls_from_lock: true,
                    location: String::new(),
                    sha256: None,
                    md5: None,
                    license: entry.license,
                    license_files: Vec::new(),
                    description: None,
                    homepage: None,
                    repository: None,
                    documentation: None,
                    yanked: None,
                    properties: std::collections::BTreeMap::new(),
                    dependencies: Vec::new(),
                }
            })
            .collect(),
    )
}

/// Where the document says a package came from: the channel of a conda package or the index
/// of a wheel, both of which this tool records as properties.
fn supplier_of(properties: &std::collections::BTreeMap<String, String>) -> Option<crate::model::Supplier> {
    if let Some(channel) = properties.get("pixi:channel") {
        return Some(crate::model::Supplier {
            name: channel.clone(),
            url: properties.get("pixi:channel-url").cloned(),
        });
    }
    let index = properties.get("pixi:index-url")?;
    Some(crate::model::Supplier {
        name: index
            .split('/')
            .nth(2)
            .filter(|host| !host.is_empty())
            .unwrap_or(index)
            .to_string(),
        url: Some(index.clone()),
    })
}

/// A package's identity: its purl, or a `<name>@<version>` stand-in when the document gives
/// none, so packages without purls still have distinct ids.
fn id_of(purl: Option<&str>, name: &str, version: Option<&str>) -> String {
    match purl {
        Some(purl) => purl.to_string(),
        None => match version {
            Some(version) => format!("{}@{version}", purl::normalize_pypi_name(name)),
            None => purl::normalize_pypi_name(name),
        },
    }
}

/// What kind of package a purl describes. Everything that is neither conda nor PyPI is
/// external: the document is the only thing that knows what it is.
fn kind_of(purl: Option<&str>) -> PackageKind {
    match purl
        .and_then(|p| p.strip_prefix("pkg:"))
        .and_then(|p| p.split('/').next())
    {
        Some(kind) if kind.eq_ignore_ascii_case("conda") => PackageKind::CondaBinary,
        Some(kind) if kind.eq_ignore_ascii_case("pypi") => PackageKind::Pypi,
        _ => PackageKind::External,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Format, SpecVersion};
    use crate::format::testing::{fixed_context, sample_sbom};

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        for err in [
            FromSbomError::Read {
                path: std::path::PathBuf::from("/workspace/sbom.json"),
                source: std::io::Error::other("permission denied"),
            },
            FromSbomError::Parse {
                path: std::path::PathBuf::from("/workspace/sbom.json"),
            },
        ] {
            crate::assert_actionable(&err);
        }
    }

    fn write(format: Format, version: SpecVersion) -> (tempfile::TempDir, std::path::PathBuf) {
        let ctx = crate::format::WriteContext {
            spec_version: version,
            ..fixed_context()
        };
        let text = serde_json::to_string(&crate::format::to_value(format, &sample_sbom(), &ctx).unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("previous.json");
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn every_format_we_write_comes_back_as_the_same_packages() {
        // SPDX 3.0.1 is read by the graph reader behind `--against`, which gives the packages
        // and their licenses but no hashes, properties or dependency edges.
        for (format, version, family, whole) in [
            (Format::Cyclonedx, SpecVersion::V1_6, "CycloneDX 1.6", true),
            (Format::Cyclonedx, SpecVersion::V1_7, "CycloneDX 1.7", true),
            (Format::Spdx, SpecVersion::V2_3, "SPDX 2.3", true),
            (Format::Spdx, SpecVersion::V3_0, "SPDX 3.0", false),
        ] {
            let (_dir, path) = write(format, version);
            let loaded = read(&path, Root::default(), None).unwrap();
            assert_eq!(loaded.format, family);
            let names: Vec<&str> = loaded.sbom.packages.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, ["libzlib", "mylib", "zlib", "six"], "{family}");
            assert_eq!(loaded.sbom.root.name, "demo", "{family}");
            assert_eq!(loaded.sbom.environment, "default", "{family}");
            assert_eq!(loaded.sbom.platform, "linux-64", "{family}");
            assert!(loaded.sbom.document.is_some(), "{family}");

            let zlib = loaded.sbom.packages.iter().find(|p| p.name == "zlib").unwrap();
            assert_eq!(zlib.license.as_deref(), Some("MIT OR Apache-2.0"), "{family}");
            assert_eq!(zlib.kind, PackageKind::CondaBinary, "{family}");
            let libzlib_id = "pkg:conda/libzlib@1.3.1?build=h1&channel=conda-forge&subdir=linux-64&type=conda";
            if whole {
                assert_eq!(zlib.sha256.as_deref(), Some("c".repeat(64).as_str()), "{family}");
                assert_eq!(
                    zlib.properties.get("pixi:channel").map(String::as_str),
                    Some("conda-forge"),
                    "{family}"
                );
                assert_eq!(zlib.supplier.as_ref().map(|s| s.name.as_str()), Some("conda-forge"));
                assert_eq!(zlib.dependencies, [libzlib_id], "{family}");
            } else {
                assert!(zlib.sha256.is_none(), "{family}");
                assert!(zlib.properties.is_empty(), "{family}");
                assert!(zlib.dependencies.is_empty(), "{family}");
            }
        }
    }

    #[test]
    fn the_command_line_wins_over_the_document_s_own_name() {
        let (_dir, path) = write(Format::Cyclonedx, SpecVersion::V1_6);
        let root = Root {
            name: "renamed".into(),
            version: Some("9.9.9".into()),
            ..Root::default()
        };
        let loaded = read(&path, root, Some("osx-arm64")).unwrap();
        assert_eq!(loaded.sbom.root.name, "renamed");
        assert_eq!(loaded.sbom.root.version.as_deref(), Some("9.9.9"));
        assert_eq!(loaded.sbom.platform, "osx-arm64");
    }

    #[test]
    fn a_document_from_another_tool_without_purls_or_properties() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("other.spdx.json");
        std::fs::write(
            &path,
            r#"{
              "spdxVersion": "SPDX-2.3",
              "name": "other-tool-output",
              "documentNamespace": "https://example.org/spdx/other-1",
              "packages": [
                {"SPDXID": "SPDXRef-1", "name": "left-pad", "versionInfo": "1.0.0",
                 "licenseDeclared": "MIT", "downloadLocation": "NOASSERTION",
                 "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                   "referenceLocator": "pkg:npm/left-pad@1.0.0"}]},
                {"SPDXID": "SPDXRef-2", "name": "Nameless", "licenseDeclared": "NOASSERTION",
                 "downloadLocation": "NONE"}
              ],
              "relationships": [
                {"spdxElementId": "SPDXRef-1", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-2"}
              ]
            }"#,
        )
        .unwrap();
        let loaded = read(&path, Root::default(), None).unwrap();
        assert_eq!(loaded.format, "SPDX 2.3");
        assert_eq!(loaded.sbom.root.name, "other-tool-output");
        assert_eq!(
            loaded.sbom.document.as_deref(),
            Some("https://example.org/spdx/other-1")
        );
        let names: Vec<(&str, PackageKind)> = loaded.sbom.packages.iter().map(|p| (p.name.as_str(), p.kind)).collect();
        // Neither conda nor PyPI, and one without a purl at all: the document is all there is.
        assert_eq!(
            names,
            [("Nameless", PackageKind::External), ("left-pad", PackageKind::External)]
        );
        let nameless = loaded.sbom.packages.iter().find(|p| p.name == "Nameless").unwrap();
        assert_eq!(nameless.id, "nameless", "a stand-in id, so the two are distinct");
        assert_eq!(nameless.license, None, "NOASSERTION is not a license");
        let left_pad = loaded.sbom.packages.iter().find(|p| p.name == "left-pad").unwrap();
        assert_eq!(left_pad.dependencies, ["nameless"]);
    }

    #[test]
    fn unreadable_and_unparsable_inputs_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert!(matches!(
            read(&missing, Root::default(), None),
            Err(FromSbomError::Read { .. })
        ));
        let junk = dir.path().join("notes.txt");
        std::fs::write(&junk, "hello").unwrap();
        assert!(matches!(
            read(&junk, Root::default(), None),
            Err(FromSbomError::Parse { .. })
        ));
        let json = dir.path().join("something.json");
        std::fs::write(&json, r#"{"hello": "world"}"#).unwrap();
        assert!(matches!(
            read(&json, Root::default(), None),
            Err(FromSbomError::Parse { .. })
        ));
    }
}
