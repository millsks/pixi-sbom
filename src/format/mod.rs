//! SBOM serializers. Each format consumes the shared [`Sbom`] model.

pub mod cyclonedx;
pub mod spdx;

use std::io::Write;

use chrono::{DateTime, Utc};
use miette::Diagnostic;
use thiserror::Error;

use crate::cli::Format;
use crate::model::Sbom;

/// Values that vary between runs; injected so tests can produce stable output.
#[derive(Debug, Clone)]
pub struct WriteContext {
    /// When the document was created.
    pub timestamp: DateTime<Utc>,
    /// A fresh UUID used for the document identifier.
    pub uuid: uuid::Uuid,
    /// Version of pixi-sbom recorded as the generating tool.
    pub tool_version: String,
}

impl WriteContext {
    /// Context for a real run: now, a random UUID, and this crate's version.
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            uuid: uuid::Uuid::new_v4(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

impl Default for WriteContext {
    fn default() -> Self {
        Self::new()
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
    let value = match format {
        Format::Cyclonedx => serde_json::to_value(cyclonedx::document(sbom, ctx))?,
        Format::Spdx => serde_json::to_value(spdx::document(sbom, ctx))?,
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
    use crate::model::{Package, PackageKind, Root};
    use std::collections::BTreeMap;

    /// A fixed context so snapshots do not change between runs.
    pub fn fixed_context() -> WriteContext {
        WriteContext {
            timestamp: DateTime::parse_from_rfc3339("2026-09-18T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            uuid: uuid::Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap(),
            tool_version: "0.0.0-test".into(),
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
            },
            environment: "default".into(),
            platform: "linux-64".into(),
            lockfile: "/work/demo/pixi.lock".into(),
            packages: vec![
                Package {
                    id: libzlib_id.into(),
                    name: "libzlib".into(),
                    version: Some("1.3.1".into()),
                    kind: PackageKind::CondaBinary,
                    purl: libzlib_id.into(),
                    extra_purls: vec![],
                    location: "https://conda.anaconda.org/conda-forge/linux-64/libzlib-1.3.1-h1.conda".into(),
                    sha256: Some("a".repeat(64)),
                    md5: Some("b".repeat(32)),
                    license: Some("Zlib".into()),
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
                    extra_purls: vec!["pkg:pypi/zlib@1.3.1".into()],
                    location: "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.3.1-h1.conda".into(),
                    sha256: Some("c".repeat(64)),
                    md5: None,
                    license: Some("MIT/Apache-2.0".into()),
                    properties: BTreeMap::from([("pixi:channel".to_string(), "conda-forge".to_string())]),
                    dependencies: vec![libzlib_id.into()],
                },
                Package {
                    id: src_id.into(),
                    name: "mylib".into(),
                    version: None,
                    kind: PackageKind::CondaSource,
                    purl: src_id.into(),
                    extra_purls: vec![],
                    location: "./packages/mylib".into(),
                    sha256: None,
                    md5: None,
                    license: Some("Proprietary".into()),
                    properties: BTreeMap::new(),
                    dependencies: vec![zlib_id.into()],
                },
                Package {
                    id: six_id.into(),
                    name: "six".into(),
                    version: Some("1.17.0".into()),
                    kind: PackageKind::Pypi,
                    purl: six_id.into(),
                    extra_purls: vec![],
                    location: "https://files.pythonhosted.org/packages/six-1.17.0-py2.py3-none-any.whl".into(),
                    sha256: Some("d".repeat(64)),
                    md5: None,
                    license: None,
                    properties: BTreeMap::from([("pixi:requires-python".to_string(), ">=2.7".to_string())]),
                    dependencies: vec![],
                },
            ],
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
    fn default_context_uses_crate_version() {
        let ctx = WriteContext::default();
        assert_eq!(ctx.tool_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(ctx.uuid.get_version_num(), 4);
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

    #[test]
    fn sample_cyclonedx_document_is_schema_valid() {
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
            .prepare()
            .unwrap();
        let validator = jsonschema::options()
            .with_registry(&registry)
            .offline()
            .build(&schema("bom-1.6.schema.json"))
            .unwrap();

        let doc = to_value(Format::Cyclonedx, &sample_sbom(), &fixed_context()).unwrap();
        assert_valid(&validator, &doc);
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
