//! SBOM serializers. Each format consumes the shared [`Sbom`] model.

pub mod cyclonedx;
pub mod spdx;
pub mod spdx3;

use std::ffi::OsStr;
use std::io::Write;

use chrono::{DateTime, Utc};
use miette::Diagnostic;
use thiserror::Error;

use crate::cli::{Format, SpecVersion};
use crate::model::Sbom;

/// Namespace for the UUIDv5 document identifiers pixi-sbom derives. Fixed for all time so
/// that the same input always maps to the same identifier.
const DOCUMENT_NAMESPACE: uuid::Uuid = uuid::uuid!("6b1f7f0a-3d0e-5c3a-9e2b-7f1c2d4e5a60");

/// Environment variable that pins the document timestamp, per the reproducible-builds
/// convention: <https://reproducible-builds.org/specs/source-date-epoch/>.
pub const SOURCE_DATE_EPOCH: &str = "SOURCE_DATE_EPOCH";

/// Document-level values that are not part of the [`Sbom`] model: the timestamp, the
/// identifier, and the generating tool's version. Injected so tests can produce stable output.
#[derive(Debug, Clone)]
pub struct WriteContext {
    /// When the document was created.
    pub timestamp: DateTime<Utc>,
    /// The document identifier (CycloneDX `serialNumber`, part of the SPDX namespace).
    pub uuid: uuid::Uuid,
    /// Version of pixi-sbom recorded as the generating tool.
    pub tool_version: String,
    /// CycloneDX specification version to write; ignored by the SPDX writer.
    pub spec_version: SpecVersion,
}

impl WriteContext {
    /// Context for a real run. The identifier is a UUIDv5 derived from the lockfile text,
    /// the environment, the platform, the format, and this crate's version, so identical
    /// inputs yield identical documents. The timestamp is `SOURCE_DATE_EPOCH` when set,
    /// otherwise now.
    pub fn for_document(lock_contents: &str, sbom: &Sbom, format: Format, spec_version: SpecVersion) -> Self {
        let tool_version = env!("CARGO_PKG_VERSION").to_string();
        Self {
            timestamp: timestamp_from_env(),
            uuid: document_uuid(lock_contents, sbom, format, &tool_version),
            tool_version,
            spec_version,
        }
    }
}

fn document_uuid(lock_contents: &str, sbom: &Sbom, format: Format, tool_version: &str) -> uuid::Uuid {
    let mut name = Vec::with_capacity(lock_contents.len() + 64);
    for part in [
        lock_contents,
        &sbom.environment,
        &sbom.platform,
        format.extension(),
        tool_version,
    ] {
        name.extend_from_slice(part.as_bytes());
        name.push(0);
    }
    uuid::Uuid::new_v5(&DOCUMENT_NAMESPACE, &name)
}

/// The document timestamp: `SOURCE_DATE_EPOCH` (seconds since the Unix epoch) when set and
/// valid, otherwise the current time. An unusable value is logged and ignored.
pub fn timestamp_from_env() -> DateTime<Utc> {
    timestamp_from(std::env::var_os(SOURCE_DATE_EPOCH).as_deref())
}

fn timestamp_from(source_date_epoch: Option<&OsStr>) -> DateTime<Utc> {
    let Some(raw) = source_date_epoch else {
        return Utc::now();
    };
    let parsed = raw
        .to_str()
        .and_then(|text| text.trim().parse::<i64>().ok())
        .and_then(|seconds| DateTime::from_timestamp(seconds, 0));
    match parsed {
        Some(timestamp) => timestamp,
        None => {
            tracing::warn!(
                value = ?raw,
                "ignoring {SOURCE_DATE_EPOCH}: not a whole number of seconds since the Unix epoch"
            );
            Utc::now()
        }
    }
}

/// Serialization failure.
#[derive(Debug, Error, Diagnostic)]
pub enum WriteError {
    /// JSON encoding failed.
    #[error("cannot serialize SBOM")]
    #[diagnostic(code(pixi_sbom::format::serialize))]
    Serialize(#[from] serde_json::Error),

    /// Writing to the destination failed.
    #[error("cannot write SBOM")]
    #[diagnostic(code(pixi_sbom::format::io))]
    Io(#[from] std::io::Error),
}

/// Serialize `sbom` in `format` to `out` as pretty-printed JSON.
pub fn write(format: Format, sbom: &Sbom, ctx: &WriteContext, out: &mut dyn Write) -> Result<(), WriteError> {
    let value = to_value(format, sbom, ctx)?;
    serde_json::to_writer_pretty(&mut *out, &value)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Build the JSON document for `format` without writing it anywhere.
pub fn to_value(format: Format, sbom: &Sbom, ctx: &WriteContext) -> Result<serde_json::Value, WriteError> {
    let value = match (format, ctx.spec_version) {
        (Format::Cyclonedx, _) => serde_json::to_value(cyclonedx::document(sbom, ctx))?,
        (Format::Spdx, SpecVersion::V3_0) => serde_json::to_value(spdx3::document(sbom, ctx))?,
        (Format::Spdx, _) => serde_json::to_value(spdx::document(sbom, ctx))?,
    };
    Ok(value)
}

/// Ids of packages nothing else in the SBOM depends on: the environment's top level.
pub(crate) fn top_level_ids(sbom: &Sbom) -> Vec<&str> {
    let depended_on: std::collections::HashSet<&str> = sbom
        .packages
        .iter()
        .flat_map(|p| p.dependencies.iter().map(String::as_str))
        .collect();
    sbom.packages
        .iter()
        .map(|p| p.id.as_str())
        .filter(|id| !depended_on.contains(id))
        .collect()
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::model::{Author, LicenseFile, Package, PackageKind, Root, Supplier};
    use std::collections::BTreeMap;

    /// A fixed context so snapshots do not change between runs.
    pub fn fixed_context() -> WriteContext {
        WriteContext {
            timestamp: DateTime::parse_from_rfc3339("2026-09-18T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            uuid: uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap(),
            tool_version: "0.0.0-test".into(),
            spec_version: SpecVersion::V1_6,
        }
    }

    /// The fixed context, writing CycloneDX 1.7.
    pub fn fixed_context_1_7() -> WriteContext {
        WriteContext {
            spec_version: SpecVersion::V1_7,
            ..fixed_context()
        }
    }

    /// The fixed context, writing SPDX 3.0.
    pub fn fixed_context_3_0() -> WriteContext {
        WriteContext {
            spec_version: SpecVersion::V3_0,
            ..fixed_context()
        }
    }

    /// A small hand-built model covering every package kind and edge case.
    pub fn sample_sbom() -> Sbom {
        let zlib_id = "pkg:conda/zlib@1.3.1?build=h1&channel=conda-forge&subdir=linux-64&type=conda";
        let libzlib_id = "pkg:conda/libzlib@1.3.1?build=h1&channel=conda-forge&subdir=linux-64&type=conda";
        let six_id = "pkg:pypi/six@1.17.0";
        let src_id = "pkg:conda/mylib@0.1.0";
        Sbom {
            root: Root {
                name: "demo".into(),
                version: Some("2.0.0".into()),
                authors: vec![
                    Author {
                        name: "Ada Lovelace".into(),
                        email: Some("ada@example.org".into()),
                    },
                    Author {
                        name: "Anonymous".into(),
                        email: None,
                    },
                ],
                license: Some("Apache-2.0".into()),
                homepage: Some("https://demo.example".into()),
                repository: Some("https://github.com/example/demo".into()),
            },
            environment: "default".into(),
            platform: "linux-64".into(),
            lockfile: "pixi.lock".into(),
            prefix: None,
            packages: vec![
                Package {
                    id: libzlib_id.into(),
                    name: "libzlib".into(),
                    version: Some("1.3.1".into()),
                    kind: PackageKind::CondaBinary,
                    purl: libzlib_id.into(),
                    supplier: Some(Supplier {
                        name: "conda-forge".into(),
                        url: Some("https://conda.anaconda.org/conda-forge/".into()),
                    }),
                    extra_purls: vec![],
                    purls_from_lock: false,
                    location: "https://conda.anaconda.org/conda-forge/linux-64/libzlib-1.3.1-h1.conda".into(),
                    sha256: Some("a".repeat(64)),
                    md5: Some("b".repeat(32)),
                    license: Some("Zlib".into()),
                    license_files: vec![LicenseFile {
                        name: "LICENSE.txt".into(),
                        text: Some("zlib license text".into()),
                    }],
                    description: Some("zlib data compression library".into()),
                    homepage: Some("https://zlib.net".into()),
                    repository: Some("https://github.com/madler/zlib".into()),
                    documentation: None,
                    properties: BTreeMap::from([
                        ("pixi:channel".to_string(), "conda-forge".to_string()),
                        ("pixi:subdir".to_string(), "linux-64".to_string()),
                    ]),
                    dependencies: vec![],
                },
                Package {
                    id: zlib_id.into(),
                    name: "zlib".into(),
                    version: Some("1.3.1".into()),
                    kind: PackageKind::CondaBinary,
                    purl: zlib_id.into(),
                    supplier: Some(Supplier {
                        name: "conda-forge".into(),
                        url: None,
                    }),
                    extra_purls: vec!["pkg:pypi/zlib@1.3.1".into()],
                    purls_from_lock: true,
                    location: "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.3.1-h1.conda".into(),
                    sha256: Some("c".repeat(64)),
                    md5: None,
                    license: Some("MIT/Apache-2.0".into()),
                    license_files: vec![
                        LicenseFile {
                            name: "LICENSE-APACHE".into(),
                            text: None,
                        },
                        LicenseFile {
                            name: "LICENSE-MIT".into(),
                            text: None,
                        },
                    ],
                    description: None,
                    homepage: None,
                    repository: None,
                    documentation: Some("https://zlib.net/manual.html".into()),
                    properties: BTreeMap::from([("pixi:channel".to_string(), "conda-forge".to_string())]),
                    dependencies: vec![libzlib_id.into()],
                },
                Package {
                    id: src_id.into(),
                    name: "mylib".into(),
                    version: None,
                    kind: PackageKind::CondaSource,
                    purl: src_id.into(),
                    supplier: None,
                    extra_purls: vec![],
                    purls_from_lock: false,
                    location: "./packages/mylib".into(),
                    sha256: None,
                    md5: None,
                    license: Some("Proprietary".into()),
                    license_files: vec![LicenseFile {
                        name: "EULA".into(),
                        text: Some("all rights reserved".into()),
                    }],
                    description: None,
                    homepage: None,
                    repository: None,
                    documentation: None,
                    properties: BTreeMap::new(),
                    dependencies: vec![zlib_id.into()],
                },
                Package {
                    id: six_id.into(),
                    name: "six".into(),
                    version: Some("1.17.0".into()),
                    kind: PackageKind::Pypi,
                    purl: six_id.into(),
                    supplier: Some(Supplier {
                        name: "pypi.org".into(),
                        url: Some("https://pypi.org/simple".into()),
                    }),
                    extra_purls: vec![],
                    purls_from_lock: true,
                    location: "https://files.pythonhosted.org/packages/six-1.17.0-py2.py3-none-any.whl".into(),
                    sha256: Some("d".repeat(64)),
                    md5: None,
                    license: None,
                    license_files: vec![],
                    description: None,
                    homepage: None,
                    repository: None,
                    documentation: None,
                    properties: BTreeMap::from([("pixi:requires-python".to_string(), ">=2.7".to_string())]),
                    dependencies: vec![],
                },
            ],
            vulnerabilities: Vec::new(),
            excluded: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_ids_are_packages_nobody_depends_on() {
        let sbom = testing::sample_sbom();
        let ids = top_level_ids(&sbom);
        assert_eq!(ids, ["pkg:conda/mylib@0.1.0", "pkg:pypi/six@1.17.0"]);
    }

    #[test]
    fn document_context_is_deterministic_for_identical_input() {
        let sbom = testing::sample_sbom();
        let a = WriteContext::for_document("version: 6\n", &sbom, Format::Cyclonedx, SpecVersion::V1_6);
        let b = WriteContext::for_document("version: 6\n", &sbom, Format::Cyclonedx, SpecVersion::V1_7);
        assert_eq!(a.tool_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(a.uuid.get_version_num(), 5);
        assert_eq!(a.uuid, b.uuid, "the spec version does not change the document identity");
        assert_eq!(b.spec_version, SpecVersion::V1_7);
    }

    #[test]
    fn document_uuid_changes_with_every_input() {
        let sbom = testing::sample_sbom();
        let base = document_uuid("lock", &sbom, Format::Cyclonedx, "1.0.0");
        assert_ne!(base, document_uuid("lock!", &sbom, Format::Cyclonedx, "1.0.0"));
        assert_ne!(base, document_uuid("lock", &sbom, Format::Spdx, "1.0.0"));
        assert_ne!(base, document_uuid("lock", &sbom, Format::Cyclonedx, "1.0.1"));
        let mut other_env = sbom.clone();
        other_env.environment = "prod".into();
        assert_ne!(base, document_uuid("lock", &other_env, Format::Cyclonedx, "1.0.0"));
        let mut other_platform = sbom.clone();
        other_platform.platform = "win-64".into();
        assert_ne!(base, document_uuid("lock", &other_platform, Format::Cyclonedx, "1.0.0"));
    }

    #[test]
    fn timestamp_honors_source_date_epoch() {
        let pinned = timestamp_from(Some(OsStr::new("1700000000")));
        assert_eq!(pinned.to_rfc3339(), "2023-11-14T22:13:20+00:00");
        assert_eq!(timestamp_from(Some(OsStr::new(" 0 "))).timestamp(), 0);
    }

    #[test]
    fn timestamp_falls_back_to_now_when_unset_or_invalid() {
        let before = Utc::now();
        for value in [
            None,
            Some(OsStr::new("")),
            Some(OsStr::new("yesterday")),
            Some(OsStr::new("1.5")),
        ] {
            let ts = timestamp_from(value);
            assert!(ts >= before && ts <= Utc::now(), "{value:?} -> {ts}");
        }
    }
}

#[cfg(test)]
mod schema_tests {
    use super::*;
    use crate::format::testing::{fixed_context, sample_sbom};

    fn schema(name: &str) -> serde_json::Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/schemas")
            .join(name);
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn assert_valid(validator: &jsonschema::Validator, doc: &serde_json::Value) {
        let errors: Vec<String> = validator
            .iter_errors(doc)
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "schema violations:\n{}", errors.join("\n"));
    }

    fn cyclonedx_validator(version: &str) -> jsonschema::Validator {
        let registry = jsonschema::Registry::new()
            .add(
                "http://cyclonedx.org/schema/spdx.schema.json",
                schema("spdx.schema.json"),
            )
            .unwrap()
            .add(
                "http://cyclonedx.org/schema/jsf-0.82.schema.json",
                schema("jsf-0.82.schema.json"),
            )
            .unwrap()
            .add(
                "http://cyclonedx.org/schema/cryptography-defs.schema.json",
                schema("cryptography-defs.schema.json"),
            )
            .unwrap()
            .prepare()
            .unwrap();
        jsonschema::options()
            .with_registry(&registry)
            .offline()
            .build(&schema(&format!("bom-{version}.schema.json")))
            .unwrap()
    }

    #[test]
    fn sample_cyclonedx_document_is_schema_valid() {
        let doc = to_value(Format::Cyclonedx, &sample_sbom(), &fixed_context()).unwrap();
        assert_valid(&cyclonedx_validator("1.6"), &doc);
    }

    #[test]
    fn sample_cyclonedx_1_7_document_is_schema_valid() {
        let doc = to_value(
            Format::Cyclonedx,
            &sample_sbom(),
            &crate::format::testing::fixed_context_1_7(),
        )
        .unwrap();
        assert_valid(&cyclonedx_validator("1.7"), &doc);
        // and is not accepted by 1.6 (the citations element is new), proving the version matters
        assert!(cyclonedx_validator("1.6").iter_errors(&doc).next().is_some());
    }

    #[test]
    fn sample_spdx_3_document_is_schema_valid() {
        let validator = jsonschema::options()
            .offline()
            .build(&schema("spdx-3.0.1.schema.json"))
            .unwrap();
        let doc = to_value(
            Format::Spdx,
            &sample_sbom(),
            &crate::format::testing::fixed_context_3_0(),
        )
        .unwrap();
        assert_valid(&validator, &doc);
        assert_eq!(doc["@context"], "https://spdx.org/rdf/3.0.1/spdx-context.jsonld");
    }

    #[test]
    fn sample_spdx_document_is_schema_valid() {
        let validator = jsonschema::options()
            .offline()
            .build(&schema("spdx-2.3.schema.json"))
            .unwrap();

        let doc = to_value(Format::Spdx, &sample_sbom(), &fixed_context()).unwrap();
        assert_valid(&validator, &doc);
    }

    #[test]
    fn write_emits_pretty_json_with_trailing_newline() {
        let mut out = Vec::new();
        write(Format::Cyclonedx, &sample_sbom(), &fixed_context(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("{\n  \"$schema\""));
        assert!(text.ends_with("}\n"));
    }

    #[test]
    fn write_reports_io_failure() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk full"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let err = write(Format::Spdx, &sample_sbom(), &fixed_context(), &mut Broken).unwrap_err();
        assert!(matches!(err, WriteError::Serialize(_) | WriteError::Io(_)));
    }
}
