//! Dependency hygiene: what the workspace imports but never declared, what it declared but
//! never imports, and what is installed without anybody asking for it.
//!
//! All three are answered from what the tool already has — the declared set from the manifest
//! ([`crate::manifest`]), the installed set from the lockfile or the prefix, the imports from
//! the workspace's sources ([`crate::imports`]) — plus one lookup the environment itself
//! provides: which distribution installs which top-level module.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::filter::Glob;
use crate::imports::Imports;
use crate::model::{Package, PackageKind, Sbom};
use crate::purl::normalize_pypi_name;
use crate::stdlib;

/// What a finding says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Imported by the workspace, declared nowhere, present only because something else
    /// depends on it: the day that path disappears, the import breaks.
    Phantom,
    /// In the environment, declared nowhere, and nothing in the environment depends on it: a
    /// leftover pin or a manual install.
    Undeclared,
    /// Declared and never imported.
    Unused,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Phantom => "phantom",
            Kind::Undeclared => "undeclared",
            Kind::Unused => "unused",
        }
    }
}

/// One package with something to say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: Kind,
    pub name: String,
    pub package_kind: &'static str,
    pub version: String,
    /// The top-level modules the package provides that the finding is about.
    pub modules: Vec<String>,
    /// Files that import them, sorted. Capped by the caller for display.
    pub files: Vec<String>,
}

/// Which distribution provides which top-level module.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Modules {
    /// Module name to the PEP 503 names of the distributions that install it.
    pub by_module: BTreeMap<String, BTreeSet<String>>,
    /// Whether an installed environment answered, rather than the package names alone.
    pub from_environment: bool,
}

impl Modules {
    /// The modules a package provides.
    fn of(&self, package: &str) -> Vec<String> {
        let wanted = normalize_pypi_name(package);
        self.by_module
            .iter()
            .filter(|(_, owners)| owners.contains(&wanted))
            .map(|(module, _)| module.clone())
            .collect()
    }
}

/// Where the environment of a document is installed, if it is: `--prefix`, else pixi's own
/// `.pixi/envs/<environment>` next to the lockfile.
pub fn environment_dir(sbom: &Sbom, workspace: &Path, prefix: Option<&Path>) -> Option<PathBuf> {
    if let Some(prefix) = prefix {
        return Some(prefix.to_path_buf());
    }
    let dir = workspace.join(".pixi").join("envs").join(&sbom.environment);
    dir.is_dir().then_some(dir)
}

/// Build the module lookup: the installed environment's `dist-info` directories when there is
/// one, and the package's own name for everything that leaves unanswered.
pub fn modules(sbom: &Sbom, environment: Option<&Path>) -> Modules {
    let mut modules = Modules::default();
    if let Some(dir) = environment {
        read_environment(dir, &mut modules);
        modules.from_environment = !modules.by_module.is_empty();
    }
    // A wheel no `dist-info` spoke for: its own name, spelled the way an import would be, is
    // the only honest guess. Conda packages get no such guess — most of them ship no Python
    // module at all, and a guess would make every compiler and command line tool look like an
    // unused import.
    for package in &sbom.packages {
        if package.kind != PackageKind::Pypi || !modules.of(&package.name).is_empty() {
            continue;
        }
        modules
            .by_module
            .entry(normalize_pypi_name(&package.name).replace('-', "_"))
            .or_default()
            .insert(normalize_pypi_name(&package.name));
    }
    tracing::debug!(
        modules = modules.by_module.len(),
        from_environment = modules.from_environment,
        "built the module lookup"
    );
    modules
}

/// Read every `*.dist-info` under an installed environment's site-packages.
fn read_environment(prefix: &Path, modules: &mut Modules) {
    for dist_info in crate::prefix::dist_infos(prefix) {
        let Some(name) = dist_info
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".dist-info"))
            .and_then(|n| n.rsplit_once('-'))
            .map(|(name, _version)| normalize_pypi_name(name))
        else {
            continue;
        };
        for module in top_level_modules(&dist_info) {
            modules.by_module.entry(module).or_default().insert(name.clone());
        }
    }
}

/// The modules one `dist-info` says its distribution installs: `top_level.txt` when it has
/// one, else the top of every path in `RECORD`.
fn top_level_modules(dist_info: &Path) -> BTreeSet<String> {
    let mut modules = BTreeSet::new();
    if let Ok(text) = std::fs::read_to_string(dist_info.join("top_level.txt")) {
        modules.extend(text.lines().map(str::trim).filter(|l| is_module(l)).map(str::to_string));
        if !modules.is_empty() {
            return modules;
        }
    }
    let Ok(record) = std::fs::read_to_string(dist_info.join("RECORD")) else {
        return modules;
    };
    for line in record.lines() {
        let path = line.split(',').next().unwrap_or_default();
        let Some(module) = record_module(path) else {
            continue;
        };
        modules.insert(module);
    }
    modules
}

/// The module a `RECORD` path belongs to, when it is an importable top-level one.
fn record_module(path: &str) -> Option<String> {
    let (first, rest) = match path.split_once('/') {
        Some((first, rest)) => (first, Some(rest)),
        None => (path, None),
    };
    if first.is_empty() || first.starts_with("..") || first == "__pycache__" {
        return None;
    }
    let name = match (first.split_once('.'), rest) {
        // `six.py`, `_brotli.cpython-314-darwin.so`: the module is what comes before the first
        // dot, but only for the extensions an import can load.
        (Some((stem, extensions)), _) => {
            if !matches!(extensions.rsplit('.').next().unwrap_or_default(), "py" | "so" | "pyd") {
                return None;
            }
            stem
        }
        // A directory: the package itself.
        (None, Some(_)) => first,
        // A file with no extension at all (`LICENSE`, `entry_points`): nothing imports it.
        (None, None) => return None,
    };
    is_module(name).then(|| name.to_string())
}

/// Whether the manifest declared anything for this environment, which every finding is
/// measured against.
pub fn declares_anything(sbom: &Sbom) -> bool {
    sbom.packages
        .iter()
        .any(|p| p.properties.contains_key(crate::manifest::DIRECT_PROPERTY))
}

fn is_module(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// The findings for one document: phantom imports first, then undeclared packages, then
/// unused declarations; each group by package name.
pub fn findings(sbom: &Sbom, imports: &Imports, modules: &Modules, assume_used: &[Glob]) -> Vec<Finding> {
    // Every finding is "declared or not", so without a manifest that declares something there
    // is nothing to say: the caller reports that instead of calling everything undeclared.
    if !declares_anything(sbom) {
        return Vec::new();
    }
    let by_name: BTreeMap<String, &Package> = sbom
        .packages
        .iter()
        .filter(|p| p.kind != PackageKind::Embedded)
        .map(|p| (normalize_pypi_name(&p.name), p))
        .collect();
    let declared = |package: &Package| package.properties.contains_key(crate::manifest::DIRECT_PROPERTY);
    let assumed = |name: &str| assume_used.iter().any(|glob| glob.matches(name));

    // Phantom: an import nobody declared, satisfied by a package that is only there in
    // passing. Several modules can point at the same package, so collect per package.
    let mut phantom: BTreeMap<&str, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for (module, files) in &imports.by_module {
        if stdlib::is_stdlib(module) || imports.local.contains(module) {
            continue;
        }
        let Some(owners) = modules.by_module.get(module) else {
            tracing::debug!(module, "imported module that no package in the environment provides");
            continue;
        };
        for owner in owners {
            let Some(package) = by_name.get(owner) else { continue };
            if declared(package) {
                continue;
            }
            let entry = phantom.entry(package.name.as_str()).or_default();
            entry.0.insert(module.clone());
            entry.1.extend(files.iter().cloned());
        }
    }
    let mut findings: Vec<Finding> = phantom
        .into_iter()
        .map(|(name, (modules, files))| {
            let package = by_name[&normalize_pypi_name(name)];
            Finding {
                kind: Kind::Phantom,
                name: name.to_string(),
                package_kind: package.kind.name(),
                version: package.version.clone().unwrap_or_else(|| "-".into()),
                modules: modules.into_iter().collect(),
                files: files.into_iter().collect(),
            }
        })
        .collect();

    // Undeclared: in the environment, declared nowhere, and needed by nothing in it.
    let needed: BTreeSet<&str> = sbom
        .packages
        .iter()
        .flat_map(|p| p.dependencies.iter().map(String::as_str))
        .collect();
    let phantom_names: BTreeSet<String> = findings.iter().map(|f| f.name.clone()).collect();
    for package in &sbom.packages {
        if package.kind == PackageKind::Embedded
            || declared(package)
            || needed.contains(package.id.as_str())
            || assumed(&package.name)
            || phantom_names.contains(&package.name)
        {
            continue;
        }
        findings.push(Finding {
            kind: Kind::Undeclared,
            name: package.name.clone(),
            package_kind: package.kind.name(),
            version: package.version.clone().unwrap_or_else(|| "-".into()),
            modules: modules.of(&package.name),
            files: Vec::new(),
        });
    }

    // Unused: declared, provides modules, and none of them is imported. A package that
    // provides nothing importable (a compiler, a command line tool) cannot be judged this way
    // and is left alone.
    for package in &sbom.packages {
        if !declared(package) || assumed(&package.name) {
            continue;
        }
        let provided = modules.of(&package.name);
        if provided.is_empty() || provided.iter().any(|m| imports.by_module.contains_key(m)) {
            continue;
        }
        findings.push(Finding {
            kind: Kind::Unused,
            name: package.name.clone(),
            package_kind: package.kind.name(),
            version: package.version.clone().unwrap_or_else(|| "-".into()),
            modules: provided,
            files: Vec::new(),
        });
    }
    findings.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;
    use crate::manifest::{DECLARED_IN_PROPERTY, DIRECT_PROPERTY};

    /// The sample with `declared` marked as the manifest would mark them.
    fn sbom_declaring(declared: &[&str]) -> Sbom {
        let mut sbom = sample_sbom();
        for package in &mut sbom.packages {
            if declared.contains(&package.name.as_str()) {
                package.properties.insert(DIRECT_PROPERTY.into(), "true".into());
                package.properties.insert(DECLARED_IN_PROPERTY.into(), "default".into());
            }
        }
        sbom
    }

    fn imported(pairs: &[(&str, &str)]) -> Imports {
        let mut imports = Imports {
            files: 1,
            ..Imports::default()
        };
        for (module, file) in pairs {
            imports
                .by_module
                .entry((*module).to_string())
                .or_default()
                .push((*file).to_string());
        }
        imports
    }

    #[test]
    fn an_imported_wheel_nobody_declared_is_a_phantom() {
        let sbom = sbom_declaring(&["zlib"]);
        let modules = modules(&sbom, None);
        let found = findings(&sbom, &imported(&[("six", "app.py")]), &modules, &[]);
        let phantoms: Vec<&Finding> = found.iter().filter(|f| f.kind == Kind::Phantom).collect();
        assert_eq!(phantoms.len(), 1, "{found:?}");
        assert_eq!(phantoms[0].name, "six");
        assert_eq!(phantoms[0].modules, ["six"]);
        assert_eq!(phantoms[0].files, ["app.py"]);
        // The same package is not also reported as an undeclared leftover.
        assert!(!found.iter().any(|f| f.kind == Kind::Undeclared && f.name == "six"));
    }

    #[test]
    fn declared_but_never_imported_is_unused_and_a_leftover_is_undeclared() {
        let sbom = sbom_declaring(&["six"]);
        let modules = modules(&sbom, None);
        let found = findings(&sbom, &imported(&[]), &modules, &[]);
        let seen: Vec<(Kind, &str)> = found.iter().map(|f| (f.kind, f.name.as_str())).collect();
        // mylib is in the environment, declared nowhere and needed by nothing; the conda
        // packages below it are somebody's dependency, and `zlib` provides no module to judge.
        assert_eq!(seen, [(Kind::Undeclared, "mylib"), (Kind::Unused, "six")]);

        // Both kinds answer to --assume-used.
        let quiet = findings(
            &sbom,
            &imported(&[]),
            &modules,
            &[Glob::parse("my*").unwrap(), Glob::parse("six").unwrap()],
        );
        assert!(quiet.is_empty(), "{quiet:?}");
    }

    #[test]
    fn standard_library_and_the_workspace_s_own_modules_are_never_findings() {
        let sbom = sbom_declaring(&["zlib"]);
        let modules = modules(&sbom, None);
        let mut imports = imported(&[("os", "app.py"), ("six", "app.py")]);
        imports.local.insert("six".into());
        let findings = findings(&sbom, &imports, &modules, &[]);
        assert!(findings.iter().all(|f| f.kind != Kind::Phantom), "{findings:?}");
    }

    #[test]
    fn without_a_manifest_there_is_nothing_to_compare_against() {
        let sbom = sample_sbom();
        assert!(!declares_anything(&sbom));
        let modules = modules(&sbom, None);
        assert!(findings(&sbom, &imported(&[("six", "app.py")]), &modules, &[]).is_empty());
    }

    #[test]
    fn conda_packages_get_no_guessed_module_but_wheels_do() {
        let sbom = sample_sbom();
        let modules = modules(&sbom, None);
        assert_eq!(modules.of("six"), ["six"]);
        for conda in ["zlib", "libzlib", "mylib"] {
            assert!(modules.of(conda).is_empty(), "{conda}");
        }
        assert!(!modules.from_environment);
    }

    #[test]
    fn an_installed_environment_says_which_package_provides_which_module() {
        let dir = tempfile::tempdir().unwrap();
        let site = dir.path().join("lib").join("python3.12").join("site-packages");
        let write = |dist_info: &str, file: &str, text: &str| {
            let path = site.join(dist_info);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join(file), text).unwrap();
        };
        write("six-1.17.0.dist-info", "top_level.txt", "six\n\n");
        write(
            "PyYAML-6.0.dist-info",
            "RECORD",
            concat!(
                "yaml/__init__.py,sha256=abc,100\n",
                "_yaml.cpython-312-darwin.so,sha256=def,200\n",
                "PyYAML-6.0.dist-info/METADATA,sha256=ghi,300\n",
                "../../../bin/tool,sha256=jkl,400\n",
                "__pycache__/x.pyc,,\n",
                "LICENSE,sha256=mno,10\n",
            ),
        );
        let sbom = sample_sbom();
        let modules = modules(&sbom, Some(dir.path()));
        assert!(modules.from_environment);
        assert_eq!(modules.by_module["six"], ["six".to_string()].into());
        assert_eq!(modules.by_module["yaml"], ["pyyaml".to_string()].into());
        assert_eq!(modules.by_module["_yaml"], ["pyyaml".to_string()].into());
        assert!(!modules.by_module.contains_key("LICENSE"), "{modules:?}");
        assert!(!modules.by_module.contains_key("__pycache__"), "{modules:?}");
    }
}
