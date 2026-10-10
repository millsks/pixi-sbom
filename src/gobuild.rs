//! The Go modules compiled into a Go binary, from the build information the Go toolchain writes
//! into every binary built with module support (#437). It is what `go version -m` prints: the Go
//! version, the main module, and every dependency module with its version.
//!
//! conda-forge's Go packages (`gh`, `go-yq`, `terraform`) are built from source, so for an
//! installed environment (`--prefix`) the binary is the only record of the modules inside; the
//! conda record knows the package and nothing below it. The modules are attached as
//! [`PackageKind::Embedded`] packages under the conda package that ships the binary, as
//! [`crate::auditable`] attaches a Rust binary's crates, so OSV (and Grype, which indexes Go
//! advisories) can match them. The Go standard library is recorded too, as
//! `pkg:golang/stdlib@<version>`, the way Syft records it, so advisories against the Go runtime
//! match.
//!
//! Only the format Go has written since 1.18 is read: the strings follow the header inline. An
//! older binary's header points at its strings instead, and it is skipped.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::embedded::SOURCE_PROPERTY;
use crate::model::{Package, PackageKind, Sbom};
use crate::progress::Progress;

/// The 14 bytes that start the build information.
const MAGIC: &[u8] = b"\xff Go buildinf:";

/// The header is 32 bytes; since Go 1.18 the version and module strings follow it.
const HEADER: usize = 32;

/// Set in the header's flags byte when the strings are inline.
const FLAG_INLINE: u8 = 0x2;

/// What `pixi:embedded-sbom` says when the components came from a Go binary.
const SOURCE_KIND: &str = "go-buildinfo";

/// One module of a Go binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub path: String,
    pub version: String,
}

impl Module {
    fn purl(&self) -> String {
        format!("pkg:golang/{}@{}", self.path, self.version)
    }
}

/// A Go binary's build information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    /// `go1.27.1`.
    pub go_version: String,
    /// The module the binary was built from; its version is `(devel)` for a source build.
    pub main: Option<Module>,
    /// Every dependency module, after `=>` replacements.
    pub deps: Vec<Module>,
}

/// A varint-prefixed string at the start of `bytes`, and what follows it.
fn read_string(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (mut length, mut shift, mut used) = (0usize, 0u32, 0usize);
    for &byte in bytes.iter().take(10) {
        used += 1;
        length |= usize::from(byte & 0x7f).checked_shl(shift)?;
        if byte & 0x80 == 0 {
            let rest = bytes.get(used..)?;
            return Some((rest.get(..length)?, rest.get(length..)?));
        }
        shift += 7;
    }
    None
}

/// Parse the module list `go version -m` prints, with its framing removed.
fn parse_modules(text: &str) -> (Option<Module>, Vec<Module>) {
    let mut main = None;
    let mut deps: Vec<Module> = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let module = |fields: &[&str]| -> Option<Module> {
            Some(Module {
                path: fields.get(1)?.to_string(),
                version: fields.get(2)?.to_string(),
            })
        };
        match fields.first() {
            Some(&"mod") => main = module(&fields),
            Some(&"dep") => deps.extend(module(&fields)),
            // A replacement applies to the dependency on the line before it.
            Some(&"=>") => {
                if let (Some(last), Some(replacement)) = (deps.last_mut(), module(&fields)) {
                    *last = replacement;
                }
            }
            _ => {}
        }
    }
    (main, deps)
}

/// The build information in a binary's bytes, or `None` when there is none or it is in the
/// pre-1.18 format.
pub fn read(bytes: &[u8]) -> Option<BuildInfo> {
    // The toolchain puts it at a 16-byte boundary of its section; the section's own place in the
    // file is the linker's business, so every offset is a candidate.
    let start = bytes.windows(MAGIC.len()).position(|window| window == MAGIC)?;
    let header = bytes.get(start..start + HEADER)?;
    if header[15] & FLAG_INLINE == 0 {
        return None;
    }
    let (version, rest) = read_string(bytes.get(start + HEADER..)?)?;
    let (modules, _) = read_string(rest)?;
    // The module text is framed by 16 bytes on each side, which the toolchain strips the same way.
    let modules = match modules.len() {
        n if n >= 33 && modules[n - 17] == b'\n' => &modules[16..n - 16],
        _ => modules,
    };
    let (main, deps) = parse_modules(&String::from_utf8_lossy(modules));
    Some(BuildInfo {
        go_version: String::from_utf8_lossy(version).into_owned(),
        main,
        deps,
    })
}

/// Counts from one pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Go binaries whose build information was read.
    pub binaries: usize,
    /// Modules added to the document, the standard library included.
    pub added: usize,
    /// Modules already there (the same version in another binary).
    pub merged: usize,
}

/// Read every Go binary of an installed environment and attach its modules to the conda package
/// that ships it.
pub fn enrich(sbom: &mut Sbom, prefix: &Path, progress: Progress) -> Outcome {
    let mut outcome = Outcome::default();
    let jobs = crate::auditable::binaries_by_package(sbom, prefix);
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
    let mut without = 0usize;
    for (index, name, candidates) in jobs {
        bar.advance(&name);
        for relative in candidates {
            let path = prefix.join(relative.replace('\\', "/"));
            let Some(bytes) = crate::auditable::read_object(&path) else {
                continue;
            };
            let Some(info) = read(&bytes) else {
                without += 1;
                continue;
            };
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
    tracing::debug!(binaries = without, "object files without Go build information");
    sbom.packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    outcome
}

/// The modules of one binary, as the document lists them: the main module when it has a real
/// version, every dependency, and the standard library.
fn modules(info: &BuildInfo) -> Vec<Module> {
    let mut modules: Vec<Module> = info
        .main
        .iter()
        .filter(|main| main.version.starts_with('v'))
        .cloned()
        .collect();
    modules.extend(info.deps.iter().cloned());
    if let Some(version) = info.go_version.strip_prefix("go") {
        // `go1.27.1 X:nocoverageredesign` and similar carry experiments after a space.
        let version = version.split_whitespace().next().unwrap_or(version);
        modules.push(Module {
            path: "stdlib".into(),
            version: version.into(),
        });
    }
    modules
}

/// Add one binary's modules to the document, under the package that ships it.
fn attach(
    sbom: &mut Sbom,
    package_index: usize,
    info: &BuildInfo,
    source: &str,
    by_id: &mut HashMap<String, usize>,
    outcome: &mut Outcome,
) {
    let mut ids = Vec::new();
    for module in modules(info) {
        let id = module.purl();
        match by_id.get(&id) {
            Some(&existing) => {
                outcome.merged += 1;
                record_source(&mut sbom.packages[existing], source);
            }
            None => {
                by_id.insert(id.clone(), sbom.packages.len());
                sbom.packages.push(to_package(&module, source));
                outcome.added += 1;
            }
        }
        ids.push(id);
    }
    // Go's build information lists the modules, not which needs which: they all hang off the
    // binary's own module, or off the conda package when that has no version of its own.
    let main = info
        .main
        .as_ref()
        .filter(|main| main.version.starts_with('v'))
        .map(Module::purl);
    let (owner, children) = match &main {
        Some(main) => (
            by_id[main],
            ids.iter().filter(|id| *id != main).cloned().collect::<Vec<_>>(),
        ),
        None => (package_index, ids.clone()),
    };
    extend_dependencies(&mut sbom.packages[owner], children);
    if let Some(main) = main {
        extend_dependencies(&mut sbom.packages[package_index], vec![main]);
    }
    record_source(&mut sbom.packages[package_index], source);
}

fn extend_dependencies(package: &mut Package, ids: Vec<String>) {
    package.dependencies.extend(ids);
    package.dependencies.sort();
    package.dependencies.dedup();
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

fn to_package(module: &Module, source: &str) -> Package {
    let purl = module.purl();
    // Syft spells the standard library's version as the toolchain does (`go1.27.1`), and so do
    // the scanners that match it.
    let version = match module.path.as_str() {
        "stdlib" => format!("go{}", module.version),
        _ => module.version.clone(),
    };
    Package {
        id: purl.clone(),
        name: module.path.clone(),
        version: Some(version),
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
        properties: BTreeMap::from([(SOURCE_PROPERTY.to_string(), source.to_string())]),
        dependencies: Vec::new(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const MODULES: &str = "path\tgithub.com/mikefarah/yq/v4\nmod\tgithub.com/mikefarah/yq/v4\t(devel)\t\n\
        dep\tgithub.com/a8m/envsubst\tv1.4.3\th1:abc=\n\
        dep\tgolang.org/x/net\tv0.20.0\th1:def=\n=>\tgolang.org/x/net\tv0.33.0\th1:ghi=\n\
        build\t-compiler=gc\nbuild\tGOOS=linux\n";

    /// Build information as the Go toolchain writes it since 1.18.
    pub(crate) fn buildinfo(go_version: &str, modules: &str) -> Vec<u8> {
        let varint = |mut n: usize, out: &mut Vec<u8>| {
            while n >= 0x80 {
                out.push((n as u8) | 0x80);
                n >>= 7;
            }
            out.push(n as u8);
        };
        let mut framed = vec![0x30u8; 16];
        framed.extend_from_slice(modules.as_bytes());
        framed.extend_from_slice(&[0x31u8; 16]);
        let mut bytes = MAGIC.to_vec();
        bytes.push(8);
        bytes.push(FLAG_INLINE);
        bytes.resize(HEADER, 0);
        varint(go_version.len(), &mut bytes);
        bytes.extend_from_slice(go_version.as_bytes());
        varint(framed.len(), &mut bytes);
        bytes.extend_from_slice(&framed);
        bytes
    }

    /// An object file of `format` carrying `data` in a section the toolchain uses for it.
    pub(crate) fn go_binary(format: object::BinaryFormat, data: Vec<u8>) -> Vec<u8> {
        use object::write::{Object, StandardSegment};
        use object::{Architecture, Endianness, SectionKind};
        let mut object = Object::new(format, Architecture::X86_64, Endianness::Little);
        let name: &[u8] = match format {
            object::BinaryFormat::Elf => b".go.buildinfo",
            object::BinaryFormat::MachO => b"__go_buildinfo",
            _ => b".data",
        };
        let section = object.add_section(
            object.segment_name(StandardSegment::Data).to_vec(),
            name.to_vec(),
            SectionKind::Data,
        );
        object.set_section_data(section, data, 16);
        object.write().unwrap()
    }

    #[test]
    fn the_modules_are_read_out_of_every_binary_format() {
        for format in [
            object::BinaryFormat::Elf,
            object::BinaryFormat::MachO,
            object::BinaryFormat::Coff,
        ] {
            let info = read(&go_binary(format, buildinfo("go1.27.1", MODULES))).unwrap_or_else(|| panic!("{format:?}"));
            assert_eq!(info.go_version, "go1.27.1");
            assert_eq!(info.main.as_ref().unwrap().version, "(devel)");
            let deps: Vec<_> = info.deps.iter().map(|m| m.purl()).collect();
            assert_eq!(
                deps,
                [
                    "pkg:golang/github.com/a8m/envsubst@v1.4.3",
                    "pkg:golang/golang.org/x/net@v0.33.0"
                ],
                "the replacement wins"
            );
        }
    }

    #[test]
    fn a_binary_without_build_information_or_in_the_old_format_is_skipped() {
        assert_eq!(read(b"not a go binary at all, just bytes"), None);
        let mut old = buildinfo("go1.17", MODULES);
        old[15] = 0;
        assert_eq!(read(&old), None);
    }

    #[test]
    fn the_standard_library_is_recorded_and_a_devel_main_module_is_not() {
        let info = read(&buildinfo("go1.27.1 X:nocoverageredesign", MODULES)).unwrap();
        let purls: Vec<_> = modules(&info).iter().map(Module::purl).collect();
        assert_eq!(
            purls,
            [
                "pkg:golang/github.com/a8m/envsubst@v1.4.3",
                "pkg:golang/golang.org/x/net@v0.33.0",
                "pkg:golang/stdlib@1.27.1"
            ]
        );
        let released = MODULES.replace("(devel)", "v4.44.3");
        let info = read(&buildinfo("go1.27.1", &released)).unwrap();
        assert_eq!(
            modules(&info)[0].purl(),
            "pkg:golang/github.com/mikefarah/yq/v4@v4.44.3"
        );
        assert_eq!(to_package(&modules(&info)[3], "x").version.as_deref(), Some("go1.27.1"));
    }

    #[test]
    fn modules_hang_off_the_main_module_or_the_conda_package() {
        let mut sbom = crate::format::testing::sample_sbom();
        let mut by_id: HashMap<String, usize> = sbom
            .packages
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.clone(), i))
            .collect();
        let mut outcome = Outcome::default();
        let devel = read(&buildinfo("go1.27.1", MODULES)).unwrap();
        attach(&mut sbom, 0, &devel, "go-buildinfo:bin/yq", &mut by_id, &mut outcome);
        assert!(
            sbom.packages[0]
                .dependencies
                .contains(&"pkg:golang/stdlib@1.27.1".to_string())
        );
        assert_eq!(outcome.added, 3);
        let released = read(&buildinfo("go1.27.1", &MODULES.replace("(devel)", "v4.44.3"))).unwrap();
        attach(
            &mut sbom,
            1,
            &released,
            "go-buildinfo:bin/yq2",
            &mut by_id,
            &mut outcome,
        );
        let main = &sbom.packages[by_id["pkg:golang/github.com/mikefarah/yq/v4@v4.44.3"]];
        assert!(
            main.dependencies
                .contains(&"pkg:golang/golang.org/x/net@v0.33.0".to_string())
        );
        assert!(sbom.packages[1].dependencies.contains(&main.id));
        assert_eq!(outcome.merged, 3, "the second binary's dependencies were already there");
        let stdlib = &sbom.packages[by_id["pkg:golang/stdlib@1.27.1"]];
        assert_eq!(
            stdlib.properties[SOURCE_PROPERTY],
            "go-buildinfo:bin/yq;go-buildinfo:bin/yq2"
        );
    }
}
