//! JavaScript packages installed in an environment (#438): everything under its `node_modules`
//! trees, as `pkg:npm` components under the conda package that installed them.
//!
//! A conda environment gets npm packages from conda packages: `nodejs` ships npm and npm's own
//! dependencies in `lib/node_modules/npm`, and a JavaScript tool such as `configurable-http-proxy`
//! installs into `lib/node_modules/<tool>` with its dependencies nested under it. Each package is
//! the directory holding a `package.json` directly under a `node_modules` directory
//! (`node_modules/<name>` or `node_modules/@<scope>/<name>`); a `package.json` deeper inside a
//! package (`esm/`, `dist/`) is a file of that package, not another one. Build-time lockfiles and
//! test fixtures inside packages are not under `node_modules` and are never read: only installed
//! code counts. A project's own `node_modules`, outside the environment, is #493's business.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use serde::Deserialize;

use crate::embedded::SOURCE_PROPERTY;
use crate::model::{Package, PackageKind, Sbom};

/// What `pixi:embedded-sbom` says of a package found in a `node_modules` directory.
const SOURCE_KIND: &str = "node_modules";

/// What `pixi:license-source` says when the license came from the installed `package.json`.
pub const LICENSE_SOURCE: &str = "package-json";

/// The directories npm installs into in a conda environment, relative to the prefix.
const ROOTS: [&str; 2] = ["lib/node_modules", "node_modules"];

/// The fields of an installed `package.json` this reads.
#[derive(Debug, Default, Deserialize)]
struct Manifest {
    name: Option<String>,
    version: Option<String>,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    license: Option<serde_json::Value>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    dependencies: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: BTreeMap<String, serde_json::Value>,
}

/// One installed package, where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Installed {
    /// Its directory, relative to the prefix, with `/` separators.
    dir: String,
    name: String,
    version: String,
    license: Option<String>,
    description: Option<String>,
    homepage: Option<String>,
    dependencies: Vec<String>,
}

/// Counts from one pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Installed packages read, every copy counted.
    pub installed: usize,
    /// Components added to the document.
    pub added: usize,
    /// Copies of a release already added from another place.
    pub merged: usize,
    /// Packages no conda package's files contain: installed by npm itself, after the fact.
    pub unowned: usize,
}

/// The license in a `package.json`: a string, or the old `{ "type": ... }` form.
fn license(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Object(object) => object.get("type")?.as_str().map(str::to_string),
        _ => None,
    }
    .filter(|text| !text.trim().is_empty())
}

/// Read the package in `dir` (relative to `prefix`) and everything nested under its own
/// `node_modules`.
fn visit(prefix: &Path, dir: &str, found: &mut Vec<Installed>) {
    let Ok(text) = std::fs::read_to_string(prefix.join(dir).join("package.json")) else {
        return;
    };
    if let Ok(manifest) = serde_json::from_str::<Manifest>(&text)
        && let (Some(name), Some(version)) = (manifest.name, manifest.version)
        && !manifest.private
    {
        found.push(Installed {
            dir: dir.to_string(),
            name,
            version,
            license: manifest.license.as_ref().and_then(license),
            description: manifest.description,
            homepage: manifest.homepage,
            dependencies: manifest
                .dependencies
                .into_keys()
                .chain(manifest.optional_dependencies.into_keys())
                .collect(),
        });
    }
    walk(prefix, &format!("{dir}/node_modules"), found);
}

/// Every package directly under the `node_modules` directory `dir`, scoped ones included.
fn walk(prefix: &Path, dir: &str, found: &mut Vec<Installed>) {
    let Ok(entries) = std::fs::read_dir(prefix.join(dir)) else {
        return;
    };
    let mut names: Vec<String> = entries
        .flatten()
        // A linked package (`npm link`) points elsewhere, and following links could loop.
        .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect();
    names.sort();
    for name in names {
        if name.starts_with('@') {
            let scope = format!("{dir}/{name}");
            let Ok(scoped) = std::fs::read_dir(prefix.join(&scope)) else {
                continue;
            };
            let mut inner: Vec<String> = scoped
                .flatten()
                .filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir()))
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            inner.sort();
            for package in inner {
                visit(prefix, &format!("{scope}/{package}"), found);
            }
        } else {
            visit(prefix, &format!("{dir}/{name}"), found);
        }
    }
}

/// The `node_modules` directories of an environment to read: the ones npm uses, and any other
/// a conda package's files are in.
fn roots(prefix: &Path, owned: &HashMap<String, String>) -> Vec<String> {
    let mut roots: Vec<String> = ROOTS.iter().map(|r| r.to_string()).collect();
    for dir in owned.keys() {
        if let Some(index) = dir.find("node_modules/") {
            roots.push(dir[..index + "node_modules".len()].to_string());
        }
    }
    roots.sort();
    roots.dedup();
    roots.retain(|root| prefix.join(root).is_dir());
    roots
}

/// The package directory a file under `node_modules` belongs to: `lib/node_modules/npm` for
/// `lib/node_modules/npm/package.json`, nothing for a `package.json` deeper in a package.
fn package_dir(file: &str) -> Option<&str> {
    let dir = file.strip_suffix("/package.json")?;
    let (parent, name) = dir.rsplit_once('/')?;
    let is_package = parent.ends_with("node_modules") && !name.starts_with('@')
        || parent
            .rsplit_once('/')
            .is_some_and(|(grand, scope)| scope.starts_with('@') && grand.ends_with("node_modules"));
    is_package.then_some(dir)
}

/// Which conda package installed each package directory, from the environment's conda records.
fn owners(prefix: &Path) -> HashMap<String, String> {
    #[derive(Deserialize)]
    struct Record {
        name: String,
        #[serde(default)]
        files: Vec<String>,
    }
    let mut owners = HashMap::new();
    let Ok(entries) = std::fs::read_dir(prefix.join("conda-meta")) else {
        return owners;
    };
    for entry in entries.flatten() {
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<Record>(&text) else {
            continue;
        };
        for file in &record.files {
            let file = file.replace('\\', "/");
            if let Some(dir) = package_dir(&file) {
                owners.insert(dir.to_string(), record.name.clone());
            }
        }
    }
    owners
}

/// Where Node finds `dependency` from the package in `dir`: its own `node_modules`, then each
/// enclosing `node_modules` outward.
fn resolve<'a>(dir: &str, dependency: &str, by_dir: &'a HashMap<String, usize>) -> Option<&'a usize> {
    let own = format!("{dir}/node_modules/{dependency}");
    if let Some(found) = by_dir.get(&own) {
        return Some(found);
    }
    let mut rest = dir;
    while let Some(index) = rest.rfind("node_modules") {
        let modules = &rest[..index + "node_modules".len()];
        if let Some(found) = by_dir.get(&format!("{modules}/{dependency}")) {
            return Some(found);
        }
        rest = &rest[..index];
    }
    None
}

/// Read every JavaScript package installed in `prefix` and attach it to the conda package that
/// installed it.
pub fn attach(sbom: &mut Sbom, prefix: &Path) -> Outcome {
    let mut outcome = Outcome::default();
    let owned = owners(prefix);
    let mut found = Vec::new();
    for root in roots(prefix, &owned) {
        walk(prefix, &root, &mut found);
    }
    if found.is_empty() {
        return outcome;
    }
    outcome.installed = found.len();
    let by_dir: HashMap<String, usize> = found.iter().enumerate().map(|(i, p)| (p.dir.clone(), i)).collect();
    let mut by_id: HashMap<String, usize> = sbom
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.id.clone(), i))
        .collect();
    let conda: HashMap<String, usize> = sbom
        .packages
        .iter()
        .enumerate()
        .filter(|(_, p)| matches!(p.kind, PackageKind::CondaBinary | PackageKind::CondaSource))
        .map(|(i, p)| (p.name.clone(), i))
        .collect();
    // One component per release; every copy records where it was found.
    let ids: Vec<Option<String>> = found
        .iter()
        .map(|p| crate::purl::npm(&p.name, &p.version).ok())
        .collect();
    for (installed, id) in found.iter().zip(&ids) {
        let Some(id) = id else { continue };
        let source = format!("{SOURCE_KIND}:{}", installed.dir);
        match by_id.get(id) {
            Some(&existing) => {
                outcome.merged += 1;
                record_source(&mut sbom.packages[existing], &source);
            }
            None => {
                by_id.insert(id.clone(), sbom.packages.len());
                sbom.packages.push(to_package(installed, id, &source));
                outcome.added += 1;
            }
        }
    }
    // Edges: each package to the copies of its dependencies Node would load, and each conda
    // package to the packages it installed that nothing else it installed depends on.
    let mut needed = vec![false; found.len()];
    for (index, installed) in found.iter().enumerate() {
        let Some(id) = &ids[index] else { continue };
        let deps: Vec<String> = installed
            .dependencies
            .iter()
            .filter_map(|dependency| resolve(&installed.dir, dependency, &by_dir))
            .filter_map(|&target| {
                needed[target] = true;
                ids[target].clone()
            })
            .filter(|target| target != id)
            .collect();
        let package = &mut sbom.packages[by_id[id]];
        package.dependencies.extend(deps);
        package.dependencies.sort();
        package.dependencies.dedup();
    }
    for (index, installed) in found.iter().enumerate() {
        let Some(id) = &ids[index] else { continue };
        match owned.get(&installed.dir).and_then(|owner| conda.get(owner)) {
            Some(&owner) if !needed[index] => {
                let package = &mut sbom.packages[owner];
                package.dependencies.push(id.clone());
                package.dependencies.sort();
                package.dependencies.dedup();
            }
            Some(_) => {}
            None => outcome.unowned += 1,
        }
    }
    sbom.packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    outcome
}

/// Note another place a release was found, keeping what is already there.
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

fn to_package(installed: &Installed, purl: &str, source: &str) -> Package {
    let mut properties = BTreeMap::from([(SOURCE_PROPERTY.to_string(), source.to_string())]);
    if installed.license.is_some() {
        properties.insert(
            crate::pypi::LICENSE_SOURCE_PROPERTY.to_string(),
            LICENSE_SOURCE.to_string(),
        );
    }
    Package {
        id: purl.to_string(),
        name: installed.name.clone(),
        version: Some(installed.version.clone()),
        kind: PackageKind::Embedded,
        purl: purl.to_string(),
        supplier: None,
        extra_purls: Vec::new(),
        // What is installed is the authority on what is installed.
        purls_from_lock: true,
        location: String::new(),
        sha256: None,
        md5: None,
        license: installed.license.clone(),
        license_files: Vec::new(),
        description: installed.description.clone(),
        homepage: installed.homepage.clone(),
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

    fn write(prefix: &Path, dir: &str, body: serde_json::Value) {
        std::fs::create_dir_all(prefix.join(dir)).unwrap();
        std::fs::write(prefix.join(dir).join("package.json"), body.to_string()).unwrap();
    }

    /// nodejs's npm with a scoped and a nested dependency, a tool beside it, a `package.json`
    /// inside a package, a private package, and a build-time lockfile outside `node_modules`.
    fn environment() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path();
        let nm = "lib/node_modules";
        write(
            prefix,
            &format!("{nm}/npm"),
            serde_json::json!({"name": "npm", "version": "10.9.2", "license": "Artistic-2.0",
            "dependencies": {"@npmcli/arborist": "^8", "semver": "^7"}}),
        );
        write(
            prefix,
            &format!("{nm}/npm/node_modules/@npmcli/arborist"),
            serde_json::json!({"name": "@npmcli/arborist", "version": "8.0.0",
            "dependencies": {"semver": "^7"}}),
        );
        write(
            prefix,
            &format!("{nm}/npm/node_modules/semver"),
            serde_json::json!({"name": "semver", "version": "7.6.3", "license": {"type": "ISC"}}),
        );
        write(
            prefix,
            &format!("{nm}/npm/node_modules/semver/esm"),
            serde_json::json!({"type": "module"}),
        );
        write(
            prefix,
            &format!("{nm}/tool"),
            serde_json::json!({"name": "tool", "version": "1.0.0", "dependencies": {"semver": "^6"}}),
        );
        write(
            prefix,
            &format!("{nm}/tool/node_modules/semver"),
            serde_json::json!({"name": "semver", "version": "6.3.1"}),
        );
        write(
            prefix,
            &format!("{nm}/linked-workspace"),
            serde_json::json!({"name": "ws", "version": "0.0.0", "private": true}),
        );
        std::fs::create_dir_all(prefix.join("share/jupyter/lab/staging")).unwrap();
        std::fs::write(
            prefix.join("share/jupyter/lab/staging/yarn.lock"),
            "lodash@^4:\n  version \"4.17.21\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(prefix.join("conda-meta")).unwrap();
        let record = |name: &str, files: &[&str]| {
            serde_json::json!({"name": name, "version": "1", "build": "0", "files": files}).to_string()
        };
        std::fs::write(
            prefix.join("conda-meta/nodejs-22-0.json"),
            record(
                "nodejs",
                &[
                    "bin/node",
                    "lib/node_modules/npm/package.json",
                    "lib/node_modules/npm/node_modules/semver/package.json",
                    "lib/node_modules/npm/node_modules/semver/esm/package.json",
                    "lib/node_modules/npm/node_modules/@npmcli/arborist/package.json",
                ],
            ),
        )
        .unwrap();
        std::fs::write(
            prefix.join("conda-meta/tool-1-0.json"),
            record("tool", &["lib/node_modules/tool/package.json"]),
        )
        .unwrap();
        dir
    }

    fn sbom_with(names: &[&str]) -> Sbom {
        let mut sbom = crate::format::testing::sample_sbom();
        let template = sbom.packages[0].clone();
        sbom.packages = names
            .iter()
            .map(|name| {
                let mut package = template.clone();
                package.kind = PackageKind::CondaBinary;
                package.name = name.to_string();
                package.id = format!("pkg:conda/{name}@1");
                package.purl = package.id.clone();
                package.dependencies.clear();
                package
            })
            .collect();
        sbom
    }

    #[test]
    fn a_package_json_is_a_package_only_at_a_package_root() {
        assert_eq!(
            package_dir("lib/node_modules/npm/package.json"),
            Some("lib/node_modules/npm")
        );
        assert_eq!(
            package_dir("lib/node_modules/npm/node_modules/@npmcli/arborist/package.json"),
            Some("lib/node_modules/npm/node_modules/@npmcli/arborist")
        );
        assert_eq!(
            package_dir("lib/node_modules/npm/node_modules/semver/esm/package.json"),
            None
        );
        assert_eq!(package_dir("share/jupyter/labextensions/x/package.json"), None);
    }

    #[test]
    fn installed_packages_are_listed_under_the_conda_package_that_installed_them() {
        let dir = environment();
        let mut sbom = sbom_with(&["nodejs", "tool"]);
        let outcome = attach(&mut sbom, dir.path());
        assert_eq!(
            outcome,
            Outcome {
                installed: 5,
                added: 5,
                merged: 0,
                unowned: 1
            },
            "two semvers, both kept; the nested one under tool is not in tool's record"
        );
        let by_purl = |purl: &str| {
            sbom.packages
                .iter()
                .find(|p| p.purl == purl)
                .unwrap_or_else(|| panic!("{purl}"))
        };
        let arborist = by_purl("pkg:npm/%40npmcli/arborist@8.0.0");
        assert_eq!(arborist.name, "@npmcli/arborist");
        assert_eq!(
            arborist.dependencies,
            ["pkg:npm/semver@7.6.3"],
            "the copy Node would load"
        );
        assert_eq!(by_purl("pkg:npm/tool@1.0.0").dependencies, ["pkg:npm/semver@6.3.1"]);
        assert_eq!(by_purl("pkg:npm/semver@7.6.3").license.as_deref(), Some("ISC"));
        assert_eq!(
            by_purl("pkg:npm/semver@7.6.3").properties[SOURCE_PROPERTY],
            "node_modules:lib/node_modules/npm/node_modules/semver"
        );
        let nodejs = sbom.packages.iter().find(|p| p.name == "nodejs").unwrap();
        assert_eq!(
            nodejs.dependencies,
            ["pkg:npm/npm@10.9.2"],
            "only what nothing else it installed needs"
        );
        assert!(
            sbom.packages.iter().all(|p| p.name != "ws" && p.name != "lodash"),
            "private, and not installed"
        );
    }

    #[test]
    fn the_same_release_in_two_places_is_one_component() {
        let dir = environment();
        write(
            dir.path(),
            "lib/node_modules/tool/node_modules/semver",
            serde_json::json!({"name": "semver", "version": "7.6.3"}),
        );
        let mut sbom = sbom_with(&["nodejs", "tool"]);
        let outcome = attach(&mut sbom, dir.path());
        assert_eq!((outcome.added, outcome.merged), (4, 1));
        let semver = sbom.packages.iter().find(|p| p.purl == "pkg:npm/semver@7.6.3").unwrap();
        assert_eq!(semver.properties[SOURCE_PROPERTY].split(';').count(), 2);
    }

    #[test]
    fn an_environment_without_node_modules_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut sbom = sbom_with(&["python"]);
        let before = sbom.clone();
        assert_eq!(attach(&mut sbom, dir.path()), Outcome::default());
        assert_eq!(sbom, before);
    }
}
