//! `cargo auditable`: the crate list a Rust binary carries in its own `.dep-v0` section.
//!
//! conda-forge builds its Rust packages with `cargo auditable build`, which embeds the
//! resolved crate graph — names, versions, and which of them the program actually links —
//! as zlib-compressed JSON in a section of the binary. For an installed environment
//! (`--prefix`) that is the only record of what went into `ripgrep` or `fd`; the lockfile
//! knows the conda package and nothing below it.
//!
//! The crates are attached as [`PackageKind::Embedded`] packages under the conda package that
//! ships the binary, exactly as [`crate::embedded`] attaches the components of a wheel's PEP
//! 770 SBOM, so they take part in `--vulnerabilities osv` (RUSTSEC records are in OSV) and in
//! the reports.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::embedded::SOURCE_PROPERTY;
use crate::model::{Package, PackageKind, Sbom};
use crate::progress::Progress;

/// The section cargo-auditable writes, in every binary format.
const SECTION: &str = ".dep-v0";

/// What `pixi:embedded-sbom` says when the components came from a binary rather than a file.
const SOURCE_KIND: &str = "cargo-auditable";

/// Files this big are not a program section worth reading; the payload is a few kilobytes.
const MAX_SECTION_BYTES: u64 = 4 * 1024 * 1024;

/// One crate of an audited binary, as cargo-auditable records it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Crate {
    pub name: String,
    pub version: String,
    /// Where it came from: `crates.io`, `git`, `local`, `registry`, `toolchain`.
    #[serde(default)]
    pub source: Option<String>,
    /// `runtime` (the default, and what ends up in the program) or `build`.
    #[serde(default)]
    pub kind: Option<String>,
    /// Indices into the same list.
    #[serde(default)]
    pub dependencies: Vec<usize>,
    /// Whether this is the crate the binary was built from.
    #[serde(default)]
    pub root: bool,
}

impl Crate {
    /// Whether the crate is in the program, as opposed to having only built it.
    fn is_runtime(&self) -> bool {
        self.kind.as_deref().unwrap_or("runtime") == "runtime"
    }

    fn purl(&self) -> String {
        format!("pkg:cargo/{}@{}", self.name, self.version)
    }
}

/// The `.dep-v0` payload.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    pub packages: Vec<Crate>,
}

/// Counts from one pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Binaries that carried a crate list.
    pub binaries: usize,
    /// Crates added to the document.
    pub added: usize,
    /// Crates that were already there (the same version in another binary).
    pub merged: usize,
}

/// The crates a binary records, or `None` when it is not an object file or carries no section.
pub fn crates(bytes: &[u8]) -> Option<VersionInfo> {
    use object::{Object, ObjectSection};
    let file = object::File::parse(bytes).ok()?;
    // Mach-O puts the section in a segment; `object` matches either spelling.
    let section = file
        .section_by_name(SECTION)
        .or_else(|| file.section_by_name("__DATA,.dep-v0"))?;
    let compressed = section.data().ok()?;
    let mut json = String::new();
    flate2::read::ZlibDecoder::new(compressed)
        .take(MAX_SECTION_BYTES)
        .read_to_string(&mut json)
        .ok()?;
    serde_json::from_str(&json).ok()
}

/// Whether a file's first bytes are an object file this can read, so only real binaries are
/// read whole.
fn is_object(magic: &[u8]) -> bool {
    matches!(
        magic,
        // ELF, Mach-O (32/64, both byte orders), a Mach-O universal binary, and PE.
        [0x7f, b'E', b'L', b'F']
            | [0xfe, 0xed, 0xfa, 0xce]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [b'M', b'Z', ..]
    )
}

/// Whether a path in an environment is worth opening: the places programs and shared
/// libraries live, rather than every header and data file in the prefix.
fn is_candidate(relative: &str) -> bool {
    let path = relative.replace('\\', "/");
    let first = path.split('/').next().unwrap_or_default();
    if matches!(first, "bin" | "sbin" | "libexec" | "Scripts" | "Library") {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or_default();
    name.split('.')
        .skip(1)
        .any(|extension| matches!(extension, "so" | "dylib" | "dll" | "pyd" | "exe"))
}

/// The `files` list of every conda package installed in a prefix, by package name.
fn installed_files(prefix: &Path) -> BTreeMap<String, Vec<String>> {
    #[derive(Deserialize)]
    struct Record {
        name: String,
        #[serde(default)]
        files: Vec<String>,
    }
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(prefix.join("conda-meta")) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<Record>(&text) else {
            continue;
        };
        out.insert(record.name, record.files);
    }
    out
}

/// Read every audited binary of an installed environment and attach its crates to the conda
/// package that ships it.
pub fn enrich(sbom: &mut Sbom, prefix: &Path, progress: Progress) -> Outcome {
    let mut outcome = Outcome::default();
    let files = installed_files(prefix);
    // Only the conda packages that ship something worth opening.
    let jobs: Vec<(usize, String, Vec<String>)> = sbom
        .packages
        .iter()
        .enumerate()
        .filter(|(_, p)| matches!(p.kind, PackageKind::CondaBinary | PackageKind::CondaSource))
        .filter_map(|(i, p)| {
            let candidates: Vec<String> = files
                .get(&p.name)?
                .iter()
                .filter(|f| is_candidate(f))
                .cloned()
                .collect();
            (!candidates.is_empty()).then(|| (i, p.name.clone(), candidates))
        })
        .collect();
    if jobs.is_empty() {
        return outcome;
    }
    let bar = progress.bar("packages", jobs.len());
    let mut by_id: HashMap<String, usize> = sbom
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.id.clone(), i))
        .collect();

    for (index, name, candidates) in jobs {
        bar.advance(&name);
        for relative in candidates {
            let path = prefix.join(relative.replace('\\', "/"));
            let Some(info) = read_binary(&path) else { continue };
            outcome.binaries += 1;
            attach(
                sbom,
                index,
                &info,
                &format!("{SOURCE_KIND}:{relative}"),
                &mut by_id,
                &mut outcome,
            );
        }
    }
    bar.finish();
    sbom.packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    outcome
}

/// The crate list of one file, when it is an object file that carries one.
fn read_binary(path: &Path) -> Option<VersionInfo> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 4];
    if std::io::Read::read_exact(&mut file, &mut magic).is_err() || !is_object(&magic) {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let info = crates(&bytes);
    if info.is_none() {
        tracing::trace!(path = %path.display(), "binary without a cargo auditable section");
    }
    info
}

/// Add one binary's crates to the document, under the package that ships it.
fn attach(
    sbom: &mut Sbom,
    package_index: usize,
    info: &VersionInfo,
    source: &str,
    by_id: &mut HashMap<String, usize>,
    outcome: &mut Outcome,
) {
    // Build crates only made the program; they are not in it, so they are not components.
    let ids: Vec<Option<String>> = info.packages.iter().map(|c| c.is_runtime().then(|| c.purl())).collect();
    for (crate_, id) in info.packages.iter().zip(&ids) {
        let Some(id) = id else { continue };
        match by_id.get(id) {
            Some(&existing) => {
                outcome.merged += 1;
                record_source(&mut sbom.packages[existing], source);
            }
            None => {
                let mut package = to_package(crate_, source);
                package.dependencies.clear();
                by_id.insert(id.clone(), sbom.packages.len());
                sbom.packages.push(package);
                outcome.added += 1;
            }
        }
    }
    // Edges between the crates, and from the conda package to the binary's own crate.
    for (crate_, id) in info.packages.iter().zip(&ids) {
        let Some(index) = id.as_ref().and_then(|id| by_id.get(id)).copied() else {
            continue;
        };
        let self_id = sbom.packages[index].id.clone();
        let mut deps: Vec<String> = crate_
            .dependencies
            .iter()
            .filter_map(|&d| ids.get(d).cloned().flatten())
            .filter(|d| *d != self_id)
            .collect();
        deps.extend(sbom.packages[index].dependencies.iter().cloned());
        deps.sort();
        deps.dedup();
        sbom.packages[index].dependencies = deps;
    }
    let roots: Vec<String> = info
        .packages
        .iter()
        .zip(&ids)
        .filter(|(c, _)| c.root)
        .filter_map(|(_, id)| id.clone())
        .collect();
    let package = &mut sbom.packages[package_index];
    package.dependencies.extend(roots);
    package.dependencies.sort();
    package.dependencies.dedup();
    record_source(package, source);
}

/// Note the binary a component came from, keeping what is already there.
fn record_source(package: &mut Package, source: &str) {
    package
        .properties
        .entry(SOURCE_PROPERTY.to_string())
        .and_modify(|value| {
            if !value.split(';').any(|s| s == source) {
                value.push(';');
                value.push_str(source);
            }
        })
        .or_insert_with(|| source.to_string());
}

fn to_package(crate_: &Crate, source: &str) -> Package {
    let purl = crate_.purl();
    let mut properties = BTreeMap::from([(SOURCE_PROPERTY.to_string(), source.to_string())]);
    if let Some(origin) = &crate_.source {
        properties.insert("pixi:cargo-source".to_string(), origin.clone());
    }
    Package {
        id: purl.clone(),
        name: crate_.name.clone(),
        version: Some(crate_.version.clone()),
        kind: PackageKind::Embedded,
        purl,
        supplier: None,
        extra_purls: Vec::new(),
        // The binary is the authority on what is in it.
        purls_from_lock: true,
        location: String::new(),
        sha256: None,
        md5: None,
        license: None,
        license_files: Vec::new(),
        description: None,
        homepage: None,
        repository: None,
        documentation: None,
        yanked: None,
        properties,
        dependencies: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use std::io::Write;

    const INFO: &str = r#"{"packages":[
        {"name":"ripgrep","version":"14.1.0","source":"local","root":true,"dependencies":[1,3]},
        {"name":"grep","version":"0.3.1","source":"crates.io","dependencies":[2]},
        {"name":"memchr","version":"2.7.4","source":"crates.io"},
        {"name":"cc","version":"1.0.0","source":"crates.io","kind":"build"}
    ]}"#;

    /// An object file of `format` carrying `json` in a `.dep-v0` section, the way
    /// cargo-auditable writes it.
    fn audited(format: object::BinaryFormat, json: &str) -> Vec<u8> {
        use object::write::{Object, StandardSegment};
        use object::{Architecture, Endianness, SectionKind};
        let mut compressed = Vec::new();
        let mut encoder = flate2::write::ZlibEncoder::new(&mut compressed, flate2::Compression::default());
        encoder.write_all(json.as_bytes()).unwrap();
        encoder.finish().unwrap();

        let mut object = Object::new(format, Architecture::X86_64, Endianness::Little);
        let section = object.add_section(
            object.segment_name(StandardSegment::Data).to_vec(),
            b".dep-v0".to_vec(),
            SectionKind::ReadOnlyData,
        );
        object.set_section_data(section, compressed, 1);
        object.write().unwrap()
    }

    #[test]
    fn the_crate_list_is_read_out_of_every_binary_format() {
        for format in [object::BinaryFormat::Elf, object::BinaryFormat::MachO] {
            let info = crates(&audited(format, INFO)).unwrap_or_else(|| panic!("{format:?}"));
            assert_eq!(info.packages.len(), 4, "{format:?}");
            let root = info.packages.iter().find(|c| c.root).unwrap();
            assert_eq!((root.name.as_str(), root.version.as_str()), ("ripgrep", "14.1.0"));
            assert_eq!(root.source.as_deref(), Some("local"));
            assert_eq!(info.packages[1].purl(), "pkg:cargo/grep@0.3.1");
            // `kind` is absent for runtime crates, which is the default.
            assert!(info.packages[1].is_runtime());
            assert!(!info.packages[3].is_runtime(), "cc only built it");
        }
    }

    #[test]
    fn anything_without_the_section_is_simply_not_audited() {
        use object::write::Object;
        use object::{Architecture, BinaryFormat, Endianness};
        let plain = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little)
            .write()
            .unwrap();
        assert_eq!(crates(&plain), None, "a binary built without cargo auditable");
        assert_eq!(crates(b"not an object file at all"), None);
        assert_eq!(crates(&[]), None);
    }

    #[test]
    fn only_object_files_in_the_places_programs_live_are_opened() {
        assert!(is_object(&[0x7f, b'E', b'L', b'F']));
        assert!(is_object(&[0xcf, 0xfa, 0xed, 0xfe]), "Mach-O 64");
        assert!(is_object(&[0xca, 0xfe, 0xba, 0xbe]), "a universal binary");
        assert!(is_object(b"MZ\x90\x00"), "PE");
        assert!(!is_object(b"#!/b"));
        assert!(!is_object(&[0x1f, 0x8b, 0x08, 0x00]), "a gzip file");

        for path in [
            "bin/rg",
            "Scripts/rg.exe",
            "libexec/thing",
            "lib/libfoo.so",
            "lib/python3.12/site-packages/x.cpython-312-darwin.so",
            "Library/bin/rg.exe",
        ] {
            assert!(is_candidate(path), "{path}");
        }
        for path in ["include/rg.h", "share/man/man1/rg.1", "info/files", "etc/conf.toml"] {
            assert!(!is_candidate(path), "{path}");
        }
    }

    /// A prefix with one conda package shipping `bin/rg`, audited.
    fn prefix_with(binary: &[u8], files: &[&str]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("conda-meta")).unwrap();
        std::fs::write(
            dir.path().join("conda-meta").join("zlib-1.3.1-h1.json"),
            serde_json::json!({ "name": "zlib", "files": files }).to_string(),
        )
        .unwrap();
        for file in files {
            let path = dir.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, binary).unwrap();
        }
        dir
    }

    #[test]
    fn the_crates_are_attached_under_the_package_that_ships_the_binary() {
        let binary = audited(object::BinaryFormat::Elf, INFO);
        let dir = prefix_with(&binary, &["bin/rg", "share/doc/readme"]);
        let mut sbom = sample_sbom();
        let outcome = enrich(&mut sbom, dir.path(), Progress::default());
        assert_eq!(outcome.binaries, 1, "only bin/rg was opened");
        assert_eq!(outcome.added, 3, "the build-only crate is not in the program");
        assert_eq!(outcome.merged, 0);

        let by_name = |name: &str| sbom.packages.iter().find(|p| p.name == name).unwrap();
        let grep = by_name("grep");
        assert_eq!(grep.kind, PackageKind::Embedded);
        assert_eq!(grep.purl, "pkg:cargo/grep@0.3.1");
        assert_eq!(grep.properties[SOURCE_PROPERTY], "cargo-auditable:bin/rg");
        assert_eq!(grep.properties["pixi:cargo-source"], "crates.io");
        assert_eq!(grep.dependencies, ["pkg:cargo/memchr@2.7.4"]);
        assert!(!sbom.packages.iter().any(|p| p.name == "cc"), "a build dependency");
        // The conda package depends on the crate its binary was built from.
        assert!(
            by_name("zlib")
                .dependencies
                .contains(&"pkg:cargo/ripgrep@14.1.0".to_string()),
            "{:?}",
            by_name("zlib").dependencies
        );
        assert_eq!(by_name("zlib").properties[SOURCE_PROPERTY], "cargo-auditable:bin/rg");
        assert_eq!(
            by_name("ripgrep").dependencies,
            ["pkg:cargo/grep@0.3.1"],
            "the build-only crate is not an edge either"
        );

        // A second binary with the same crates adds nothing and records where it also came from.
        let dir = prefix_with(&binary, &["bin/rg", "bin/rgx"]);
        let mut sbom = sample_sbom();
        let outcome = enrich(&mut sbom, dir.path(), Progress::default());
        assert_eq!((outcome.binaries, outcome.added, outcome.merged), (2, 3, 3));
        let sources = &sbom.packages.iter().find(|p| p.name == "grep").unwrap().properties[SOURCE_PROPERTY];
        assert_eq!(sources, "cargo-auditable:bin/rg;cargo-auditable:bin/rgx");
    }

    #[test]
    fn an_environment_with_nothing_audited_changes_nothing() {
        let dir = prefix_with(b"#!/bin/sh\necho hi\n", &["bin/script"]);
        let mut sbom = sample_sbom();
        let before = sbom.packages.len();
        let outcome = enrich(&mut sbom, dir.path(), Progress::default());
        assert_eq!(outcome, Outcome::default());
        assert_eq!(sbom.packages.len(), before);
        // And a prefix with no conda-meta at all is not an error.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(enrich(&mut sbom, empty.path(), Progress::default()), Outcome::default());
    }
}
