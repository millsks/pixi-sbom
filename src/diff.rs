//! `--report diff --against <PATH>`: what changed between another environment and the one this
//! run describes. The other side may be a document this tool or another wrote (CycloneDX
//! 1.4–1.7, SPDX 2.x or SPDX 3.0.1 JSON), a `pixi.lock`, or an installed environment, which is
//! what makes `--prefix <DIR> --against pixi.lock` a drift check for a container image.
//! Packages are matched by purl type and normalized name, so a version bump is a change rather
//! than a removal plus an addition.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::embedded;
use crate::model::Sbom;

/// Why the previous document could not be read.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum DiffError {
    #[error("cannot read the previous document {path}: {source}")]
    #[diagnostic(
        code(pixi_sbom::diff::read),
        help(
            "--against takes a readable CycloneDX, SPDX 2.x or SPDX 3.0 JSON document, a pixi.lock, or the \
             directory of an installed environment; check the path and its permissions"
        )
    )]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} is not a document, a pixi lockfile or an installed environment")]
    #[diagnostic(
        code(pixi_sbom::diff::parse),
        help(
            "--against takes a CycloneDX, SPDX 2.x or SPDX 3.0 JSON document (written by pixi-sbom or \
             another tool), a pixi.lock, or the directory of an installed environment"
        )
    )]
    Parse { path: PathBuf },
}

/// What `--against` points at: the comparison is the same, the side it reads differs.
#[derive(Debug)]
pub enum Against {
    /// A document a previous run — of this tool or another — wrote.
    Document(Previous),
    /// A lockfile, read for the same environment and platform as the run describes.
    Lock {
        lock: Box<rattler_lock::LockFile>,
        /// The lockfile's name, for the model's provenance.
        name: String,
    },
    /// An installed environment, which is what makes `--prefix <DIR> --against pixi.lock` a
    /// drift check.
    Prefix(PathBuf),
}

/// Decide what `--against` points at, and read what can be read once. A lockfile and a prefix
/// are turned into the comparison side per document, because they answer per environment.
pub fn resolve_against(path: &Path) -> Result<Against, DiffError> {
    if path.join("conda-meta").is_dir() {
        return Ok(Against::Prefix(path.to_path_buf()));
    }
    let text = std::fs::read_to_string(path).map_err(|source| DiffError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some(previous) = parse_previous(&text) {
        return Ok(Against::Document(previous));
    }
    match crate::lock::load(path) {
        Ok(loaded) => Ok(Against::Lock {
            lock: Box::new(loaded.lock),
            name: crate::discover::lockfile_name(path),
        }),
        // Neither a document nor a lockfile: one message for both, since the file is simply
        // not something to compare with.
        Err(err) => {
            tracing::debug!(path = %path.display(), %err, "not a lockfile either");
            Err(DiffError::Parse {
                path: path.to_path_buf(),
            })
        }
    }
}

/// One package as the diff sees it, on either side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub name: String,
    /// Purl type (`conda`, `pypi`, `cargo`, ...), or `-` when the package has no purl.
    pub kind: String,
    pub version: Option<String>,
    pub license: Option<String>,
    pub purl: Option<String>,
    /// What installed it, when the side knows (`pip`, `conda`): only an installed environment
    /// records it, and only it can say that something was pip-installed into a conda prefix.
    pub installer: Option<String>,
}

/// One package of an [`Sbom`] as an [`Entry`].
fn entry_of(package: &crate::model::Package) -> Entry {
    // The document carries the normalized spelling, so compare that, not the raw one.
    let license = package
        .license
        .as_deref()
        .map(crate::license::normalize)
        .map(|l| match l {
            crate::license::License::Expression(e) => e,
            crate::license::License::Text(t) => t,
        });
    Entry {
        kind: kind_of(Some(&package.purl)),
        name: package.name.clone(),
        version: package.version.clone(),
        license,
        purl: Some(package.purl.clone()),
        installer: package.properties.get("pixi:installer").cloned(),
    }
}

/// Reduce a model this run built — from a lockfile or from an installed environment — to the
/// side the comparison reads.
pub fn previous_from_sbom(sbom: &Sbom) -> Previous {
    Previous {
        entries: sbom.packages.iter().map(entry_of).collect(),
        format: sbom.input_description(),
    }
}

/// The conda build string a purl carries, which distinguishes two builds of one version.
fn build_of(purl: Option<&String>) -> Option<String> {
    let (_, qualifiers) = purl?.split_once('?')?;
    qualifiers
        .split('&')
        .find_map(|q| q.strip_prefix("build=").map(str::to_string))
}

/// The previous document, reduced to what the diff compares.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Previous {
    pub entries: Vec<Entry>,
    /// The family of the document (`CycloneDX`, `SPDX 2.3`, `SPDX 3.0`).
    pub format: String,
}

/// Reduce a document's text; `None` when it is none of the three families.
pub fn parse_previous(text: &str) -> Option<Previous> {
    if let Some(fragment) = embedded::parse(text) {
        let value: serde_json::Value = serde_json::from_str(text).ok()?;
        let format = match value.get("bomFormat") {
            Some(_) => format!(
                "CycloneDX {}",
                value.get("specVersion").and_then(|v| v.as_str()).unwrap_or("")
            )
            .trim()
            .to_string(),
            None => value
                .get("spdxVersion")
                .and_then(|v| v.as_str())
                .unwrap_or("SPDX")
                .replace("SPDX-", "SPDX "),
        };
        // The root component / package describes the workspace, not a dependency.
        let root: Option<String> = value
            .pointer("/metadata/component/bom-ref")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .or_else(|| value.get("spdxVersion").map(|_| "SPDXRef-Package-root".to_string()));
        let entries = fragment
            .components
            .into_iter()
            .filter(|c| root.as_deref() != Some(c.reference.as_str()))
            .map(|c| Entry {
                kind: kind_of(c.purl.as_deref()),
                name: c.name,
                version: c.version,
                license: c.license,
                purl: c.purl,
                // A document does not say what installed a package; only a prefix does.
                installer: None,
            })
            .collect();
        return Some(Previous { entries, format });
    }
    parse_spdx3(text)
}

/// SPDX 3.0.1 JSON-LD: every `software_Package` but the root, with its purl from
/// `software_packageUrl` or a `packageUrl` external identifier, and its declared license
/// through the `hasDeclaredLicense` relationship.
fn parse_spdx3(text: &str) -> Option<Previous> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let graph = value.get("@graph")?.as_array()?;
    let licenses: BTreeMap<&str, String> = graph
        .iter()
        .filter_map(|node| {
            let id = node.get("spdxId")?.as_str()?;
            let text = node
                .get("simplelicensing_licenseExpression")
                .or_else(|| node.get("name"))
                .and_then(|v| v.as_str())?;
            Some((id, text.to_string()))
        })
        .collect();
    let mut declared: BTreeMap<&str, String> = BTreeMap::new();
    for node in graph {
        if node.get("type").and_then(|v| v.as_str()) != Some("Relationship")
            || node.get("relationshipType").and_then(|v| v.as_str()) != Some("hasDeclaredLicense")
        {
            continue;
        }
        let Some(from) = node.get("from").and_then(|v| v.as_str()) else {
            continue;
        };
        let texts: Vec<&str> = node
            .get("to")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|t| t.as_str())
            .filter_map(|id| licenses.get(id).map(String::as_str))
            .collect();
        if !texts.is_empty() {
            declared.insert(from, texts.join(" AND "));
        }
    }
    let mut entries = Vec::new();
    let mut seen_root = false;
    for node in graph {
        if node.get("type").and_then(|v| v.as_str()) != Some("software_Package") {
            continue;
        }
        let id = node.get("spdxId").and_then(|v| v.as_str()).unwrap_or("");
        if id.ends_with("#package-root") {
            seen_root = true;
            continue;
        }
        let purl = node
            .get("software_packageUrl")
            .and_then(|v| v.as_str())
            .or_else(|| {
                node.get("externalIdentifier")?
                    .as_array()?
                    .iter()
                    .find(|e| e.get("externalIdentifierType").and_then(|v| v.as_str()) == Some("packageUrl"))?
                    .get("identifier")?
                    .as_str()
            })
            .map(str::to_string);
        entries.push(Entry {
            kind: kind_of(purl.as_deref()),
            name: node.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            version: node
                .get("software_packageVersion")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            license: declared.get(id).cloned(),
            purl,
            installer: None,
        });
    }
    if entries.is_empty() && !seen_root {
        return None;
    }
    Some(Previous {
        entries,
        format: "SPDX 3.0".into(),
    })
}

/// The purl type, which stands for the package's ecosystem on both sides.
fn kind_of(purl: Option<&str>) -> String {
    purl.and_then(|p| p.strip_prefix("pkg:"))
        .and_then(|p| p.split('/').next())
        .map(str::to_string)
        .unwrap_or_else(|| "-".into())
}

fn key(kind: &str, name: &str) -> String {
    format!("{kind}:{}", name.to_ascii_lowercase().replace('_', "-"))
}

/// A package present on one side only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Presence {
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

/// A package on both sides whose version or license differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub name: String,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_license: Option<String>,
    /// Conda build strings, when the change is between two builds of one version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_build: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_build: Option<String>,
}

/// The comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Diff {
    /// The previous document's path and family.
    pub against: String,
    pub against_format: String,
    pub added: Vec<Presence>,
    pub removed: Vec<Presence>,
    /// Same package, different version (the license may have changed too).
    pub version_changed: Vec<Change>,
    /// Same package and version, different license.
    pub license_changed: Vec<Change>,
    /// Same package and version, different conda build string: a rebuild of the same sources
    /// against different dependencies, which a version comparison alone misses.
    pub build_changed: Vec<Change>,
    /// Packages `pip` installed into the environment that the other side does not have. They
    /// are the reason an image drifts from its lockfile, so they are called out rather than
    /// counted as ordinary additions.
    pub pip_installed: Vec<Presence>,
    pub unchanged: usize,
}

impl Diff {
    /// Whether anything differs.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.version_changed.is_empty()
            && self.license_changed.is_empty()
            && self.build_changed.is_empty()
            && self.pip_installed.is_empty()
    }

    /// The sections `--fail-on-diff` asked about that are not empty, in the order the flag
    /// names them, as `<section> (<count>)` for the message on stderr.
    pub fn gate_hits(&self, sections: &[crate::cli::DiffSection]) -> Vec<String> {
        use crate::cli::DiffSection::{Added, Any, Build, License, Pip, Removed, Version};
        let counts = [
            (Added, self.added.len()),
            (Removed, self.removed.len()),
            (Version, self.version_changed.len()),
            (License, self.license_changed.len()),
            (Build, self.build_changed.len()),
            (Pip, self.pip_installed.len()),
        ];
        counts
            .into_iter()
            .filter(|(section, count)| *count > 0 && (sections.contains(section) || sections.contains(&Any)))
            .map(|(section, count)| {
                let name = match section {
                    Added => "added",
                    Removed => "removed",
                    Version => "version changes",
                    License => "license changes",
                    Build => "build changes",
                    Pip => "pip installed",
                    Any => unreachable!("Any is not one of the counted sections"),
                };
                format!("{name} ({count})")
            })
            .collect()
    }
}

/// Exit code when `--fail-on-diff` finds a change it was asked to gate on.
pub const DIFF_EXIT_CODE: i32 = 6;

/// Compare `sbom` (the new side) with `previous`.
pub fn compare(sbom: &Sbom, previous: &Previous, against: &Path) -> Diff {
    let old: BTreeMap<String, &Entry> = previous.entries.iter().map(|e| (key(&e.kind, &e.name), e)).collect();
    let new: BTreeMap<String, Entry> = sbom
        .packages
        .iter()
        .map(|p| {
            let entry = entry_of(p);
            (key(&entry.kind, &entry.name), entry)
        })
        .collect();
    let presence = |e: &Entry| Presence {
        name: e.name.clone(),
        kind: e.kind.clone(),
        version: e.version.clone(),
        license: e.license.clone(),
        purl: e.purl.clone(),
    };
    let mut diff = Diff {
        against: against.display().to_string(),
        against_format: previous.format.clone(),
        ..Diff::default()
    };
    for (k, entry) in &new {
        match old.get(k) {
            // A package pip put into the environment is the reason an image drifts from its
            // lockfile, so it is named as that rather than as an ordinary addition.
            None if entry.installer.as_deref() == Some("pip") => diff.pip_installed.push(presence(entry)),
            None => diff.added.push(presence(entry)),
            Some(before) => {
                let (old_build, new_build) = (build_of(before.purl.as_ref()), build_of(entry.purl.as_ref()));
                let change = Change {
                    name: entry.name.clone(),
                    kind: entry.kind.clone(),
                    old_version: before.version.clone(),
                    new_version: entry.version.clone(),
                    old_license: before.license.clone(),
                    new_license: entry.license.clone(),
                    old_build: old_build.clone(),
                    new_build: new_build.clone(),
                };
                if before.version != entry.version {
                    diff.version_changed.push(change);
                } else if old_build.is_some() && new_build.is_some() && old_build != new_build {
                    diff.build_changed.push(change);
                } else if before.license != entry.license {
                    diff.license_changed.push(change);
                } else {
                    diff.unchanged += 1;
                }
            }
        }
    }
    diff.removed = old
        .iter()
        .filter(|(k, _)| !new.contains_key(*k))
        .map(|(_, e)| presence(e))
        .collect();
    diff
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Format, SpecVersion};
    use crate::format::testing::{fixed_context, sample_sbom};

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        for err in [
            DiffError::Read {
                path: PathBuf::from("/workspace/previous.json"),
                source: std::io::Error::other("permission denied"),
            },
            DiffError::Parse {
                path: PathBuf::from("/workspace/previous.json"),
            },
        ] {
            crate::assert_actionable(&err);
        }
    }

    fn written(format: Format, version: SpecVersion) -> String {
        let ctx = crate::format::WriteContext {
            spec_version: version,
            ..fixed_context()
        };
        serde_json::to_string(&crate::format::to_value(format, &sample_sbom(), &ctx).unwrap()).unwrap()
    }

    #[test]
    fn every_format_we_write_reads_back_without_the_root() {
        for (format, version, family) in [
            (Format::Cyclonedx, SpecVersion::V1_6, "CycloneDX 1.6"),
            (Format::Cyclonedx, SpecVersion::V1_7, "CycloneDX 1.7"),
            (Format::Spdx, SpecVersion::V2_3, "SPDX 2.3"),
            (Format::Spdx, SpecVersion::V3_0, "SPDX 3.0"),
        ] {
            let previous = parse_previous(&written(format, version)).unwrap();
            assert_eq!(previous.format, family);
            let mut names: Vec<&str> = previous.entries.iter().map(|e| e.name.as_str()).collect();
            names.sort();
            assert_eq!(names, ["libzlib", "mylib", "six", "zlib"], "{family}");
            let zlib = previous.entries.iter().find(|e| e.name == "zlib").unwrap();
            assert_eq!(zlib.kind, "conda");
            assert_eq!(zlib.version.as_deref(), Some("1.3.1"));
            assert_eq!(zlib.license.as_deref(), Some("MIT OR Apache-2.0"), "{family}");
            let six = previous.entries.iter().find(|e| e.name == "six").unwrap();
            assert_eq!(six.kind, "pypi");
            assert_eq!(six.license, None);
        }
        assert!(parse_previous("{}").is_none());
        assert!(parse_previous("not json").is_none());
    }

    #[test]
    fn compare_finds_added_removed_and_changed() {
        let previous = parse_previous(&written(Format::Cyclonedx, SpecVersion::V1_6)).unwrap();
        let mut sbom = sample_sbom();
        // Bump zlib, relicense libzlib, drop mylib, add a wheel.
        let zlib = sbom.packages.iter().position(|p| p.name == "zlib").unwrap();
        sbom.packages[zlib].version = Some("1.3.2".into());
        let libzlib = sbom.packages.iter().position(|p| p.name == "libzlib").unwrap();
        sbom.packages[libzlib].license = Some("MIT".into());
        sbom.packages.retain(|p| p.name != "mylib");
        let mut new = sbom.packages[0].clone();
        new.name = "Requests".into();
        new.purl = "pkg:pypi/requests@2.0".into();
        new.version = Some("2.0".into());
        sbom.packages.push(new);

        let diff = compare(&sbom, &previous, Path::new("old.cdx.json"));
        assert_eq!(diff.against, "old.cdx.json");
        assert_eq!(diff.against_format, "CycloneDX 1.6");
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "Requests");
        assert_eq!(diff.added[0].kind, "pypi");
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].name, "mylib");
        assert_eq!(diff.version_changed.len(), 1);
        assert_eq!(diff.version_changed[0].old_version.as_deref(), Some("1.3.1"));
        assert_eq!(diff.version_changed[0].new_version.as_deref(), Some("1.3.2"));
        assert_eq!(diff.license_changed.len(), 1);
        assert_eq!(diff.license_changed[0].old_license.as_deref(), Some("Zlib"));
        assert_eq!(diff.license_changed[0].new_license.as_deref(), Some("MIT"));
        assert_eq!(diff.unchanged, 1, "six");
        assert!(!diff.is_empty());

        let same = compare(&sample_sbom(), &previous, Path::new("old.cdx.json"));
        assert!(same.is_empty());
        assert_eq!(same.unchanged, 4);
    }

    #[test]
    fn a_rebuild_and_a_pip_install_are_their_own_sections() {
        let previous = previous_from_sbom(&sample_sbom());
        assert_eq!(previous.format, "lockfile pixi.lock");
        let mut sbom = sample_sbom();
        // The same zlib version, built differently: a version comparison alone misses it.
        let zlib = sbom.packages.iter_mut().find(|p| p.name == "zlib").unwrap();
        zlib.purl = zlib.purl.replace("build=h1", "build=h2");
        // And something pip put into the environment that the other side never had.
        let mut attrs = sbom.packages[3].clone();
        attrs.name = "attrs".into();
        attrs.purl = "pkg:pypi/attrs@25.4.0".into();
        attrs.version = Some("25.4.0".into());
        attrs.properties.insert("pixi:installer".into(), "pip".into());
        sbom.packages.push(attrs);

        let diff = compare(&sbom, &previous, Path::new("pixi.lock"));
        assert!(diff.added.is_empty(), "a pip install is not an ordinary addition");
        assert_eq!(diff.pip_installed.len(), 1);
        assert_eq!(diff.pip_installed[0].name, "attrs");
        assert_eq!(diff.build_changed.len(), 1);
        assert_eq!(diff.build_changed[0].name, "zlib");
        assert_eq!(diff.build_changed[0].old_build.as_deref(), Some("h1"));
        assert_eq!(diff.build_changed[0].new_build.as_deref(), Some("h2"));
        assert!(diff.version_changed.is_empty(), "the version did not change");
        assert!(!diff.is_empty());

        use crate::cli::DiffSection::{Build, Pip, Version};
        assert_eq!(diff.gate_hits(&[Build]), ["build changes (1)"]);
        assert_eq!(diff.gate_hits(&[Pip]), ["pip installed (1)"]);
        assert!(diff.gate_hits(&[Version]).is_empty());
    }

    #[test]
    fn against_is_a_document_a_lockfile_or_an_installed_environment() {
        let dir = tempfile::tempdir().unwrap();
        let document = dir.path().join("previous.cdx.json");
        std::fs::write(&document, written(Format::Cyclonedx, SpecVersion::V1_6)).unwrap();
        assert!(matches!(resolve_against(&document).unwrap(), Against::Document(_)));

        let lockfile = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/with-pypi/pixi.lock");
        assert!(matches!(resolve_against(&lockfile).unwrap(), Against::Lock { .. }));

        let prefix = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prefix");
        assert!(matches!(resolve_against(&prefix).unwrap(), Against::Prefix(_)));

        let neither = dir.path().join("notes.txt");
        std::fs::write(&neither, "hello").unwrap();
        assert!(matches!(resolve_against(&neither), Err(DiffError::Parse { .. })));
        assert!(matches!(
            resolve_against(&dir.path().join("missing.json")),
            Err(DiffError::Read { .. })
        ));
    }

    #[test]
    fn the_gate_only_fires_on_the_sections_it_was_given() {
        use crate::cli::DiffSection::{Added, Any, License, Removed, Version};
        let previous = parse_previous(&written(Format::Cyclonedx, SpecVersion::V1_6)).unwrap();
        let mut sbom = sample_sbom();
        sbom.packages.retain(|p| p.name != "mylib");
        let libzlib = sbom.packages.iter().position(|p| p.name == "libzlib").unwrap();
        sbom.packages[libzlib].license = Some("MIT".into());
        let diff = compare(&sbom, &previous, Path::new("old.cdx.json"));

        assert_eq!(diff.gate_hits(&[Any]), ["removed (1)", "license changes (1)"]);
        assert_eq!(diff.gate_hits(&[Removed]), ["removed (1)"]);
        assert_eq!(
            diff.gate_hits(&[License, Removed]),
            ["removed (1)", "license changes (1)"]
        );
        assert!(diff.gate_hits(&[Added, Version]).is_empty(), "nothing was added");
        assert!(diff.gate_hits(&[]).is_empty(), "no gate, no hits");
        // An unchanged environment never fires, whatever was asked for.
        let same = compare(&sample_sbom(), &previous, Path::new("old.cdx.json"));
        assert!(same.gate_hits(&[Any]).is_empty());
    }

    #[test]
    fn names_match_across_spelling_and_kinds_do_not_mix() {
        let previous = Previous {
            entries: vec![
                Entry {
                    name: "charset_normalizer".into(),
                    kind: "pypi".into(),
                    version: Some("3.0".into()),
                    license: None,
                    purl: None,
                    installer: None,
                },
                Entry {
                    name: "six".into(),
                    kind: "conda".into(),
                    version: Some("1.17.0".into()),
                    license: None,
                    purl: None,
                    installer: None,
                },
            ],
            format: "CycloneDX".into(),
        };
        let mut sbom = sample_sbom();
        sbom.packages.retain(|p| p.name == "six");
        sbom.packages[0].name = "Charset-Normalizer".into();
        sbom.packages[0].purl = "pkg:pypi/charset-normalizer@3.1".into();
        sbom.packages[0].version = Some("3.1".into());
        let diff = compare(&sbom, &previous, Path::new("x"));
        assert_eq!(diff.version_changed.len(), 1, "spelling differences are not changes");
        assert_eq!(diff.removed.len(), 1, "a conda six is not the pypi six");
        assert!(diff.added.is_empty());
    }
}
