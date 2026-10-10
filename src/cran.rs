//! CRAN identities for conda's R packages (#436). An `r-*` conda package is usually a CRAN
//! package, but its only purl is `pkg:conda`, which no advisory database indexes. OSV indexes
//! CRAN, so each one that is on CRAN gets a `pkg:cran` purl beside its conda one, the way a conda
//! Python package gets its PyPI purl.
//!
//! The CRAN name and version come from the best source on hand:
//!
//! 1. the package's own `DESCRIPTION` file, in an installed environment's `lib/R/library/` or in
//!    the package cache's extracted copy. Its `Repository: CRAN` line also says whether the
//!    package is on CRAN at all: a Bioconductor, GitHub or base-R package has none.
//! 2. `data/cran.toml`, for the names CRAN spells differently (`r-rcpp` is `Rcpp`) and the `r-*`
//!    packages that were never on CRAN.
//! 3. the rule: `r-ggplot2` is `ggplot2`, and conda's `1.2_3` is CRAN's `1.2-3`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::model::{PackageKind, Sbom};

const TABLE: &str = include_str!("../data/cran.toml");

/// Where a package's CRAN identity came from: `description`, `table` or `rule`.
pub const SOURCE_PROPERTY: &str = "pixi:cran-source";

#[derive(Debug, Deserialize)]
struct Table {
    renamed: BTreeMap<String, String>,
    #[serde(rename = "not-cran")]
    not_cran: NotCran,
}

#[derive(Debug, Deserialize)]
struct NotCran {
    names: BTreeSet<String>,
}

fn table() -> &'static Table {
    static TABLE_CELL: std::sync::OnceLock<Table> = std::sync::OnceLock::new();
    TABLE_CELL.get_or_init(|| toml::from_str(TABLE).expect("data/cran.toml is checked by its tests"))
}

/// What an R package's `DESCRIPTION` file says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    pub name: String,
    pub version: String,
    /// `Repository: CRAN`.
    pub cran: bool,
}

/// Parse a `DESCRIPTION` file (Debian control format): `None` without a name and version.
pub fn parse_description(text: &str) -> Option<Description> {
    let field = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    };
    Some(Description {
        name: field("Package")?,
        version: field("Version")?,
        cran: field("Repository").as_deref() == Some("CRAN"),
    })
}

/// The R library directories under a prefix or an extracted package.
fn libraries(root: &Path) -> [PathBuf; 2] {
    [root.join("lib/R/library"), root.join("Lib/R/library")]
}

/// Every `DESCRIPTION` under `root`'s R library, by lower-cased package name.
fn descriptions(root: &Path) -> HashMap<String, Description> {
    let mut found = HashMap::new();
    for library in libraries(root) {
        let Ok(entries) = std::fs::read_dir(&library) else {
            continue;
        };
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path().join("DESCRIPTION"))
                && let Some(description) = parse_description(&text)
            {
                found.insert(description.name.to_lowercase(), description);
            }
        }
    }
    found
}

/// What [`identify`] did, by source.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub from_description: usize,
    pub from_table: usize,
    pub from_rule: usize,
    /// `r-*` packages that are not on CRAN, which get no CRAN purl.
    pub not_cran: usize,
}

/// Give every `r-*` conda package that is on CRAN a `pkg:cran` purl. `prefix` is an installed
/// environment to read `DESCRIPTION` files from; `pkgs_dir` is the package cache, read in either
/// case for a package the environment does not have.
pub fn identify(sbom: &mut Sbom, prefix: Option<&Path>, pkgs_dir: &Path) -> Outcome {
    let mut outcome = Outcome::default();
    if !sbom
        .packages
        .iter()
        .any(|p| p.kind == PackageKind::CondaBinary && p.name.starts_with("r-"))
    {
        return outcome;
    }
    let installed = prefix.map(descriptions).unwrap_or_default();
    let table = table();
    for package in &mut sbom.packages {
        let Some(bare) = package.name.strip_prefix("r-") else {
            continue;
        };
        if package.kind != PackageKind::CondaBinary {
            continue;
        }
        let extracted = || {
            let dir = package
                .properties
                .get(crate::prefix::EXTRACTED_DIR_PROPERTY)
                .map(PathBuf::from)
                .filter(|dir| dir.is_dir())
                .or_else(|| {
                    let file = package.properties.get("pixi:file-name")?;
                    let stem = file.strip_suffix(".conda").or_else(|| file.strip_suffix(".tar.bz2"))?;
                    Some(pkgs_dir.join(stem))
                })?;
            descriptions(&dir).remove(&bare.to_lowercase())
        };
        let description = installed.get(&bare.to_lowercase()).cloned().or_else(extracted);
        let (name, version, source) = match description {
            Some(description) if !description.cran => {
                outcome.not_cran += 1;
                continue;
            }
            Some(description) => {
                outcome.from_description += 1;
                (description.name, description.version, "description")
            }
            None if table.not_cran.names.contains(&package.name) => {
                outcome.not_cran += 1;
                continue;
            }
            None => {
                let Some(version) = package.version.as_deref() else {
                    continue;
                };
                let (name, source) = match table.renamed.get(&package.name) {
                    Some(name) => {
                        outcome.from_table += 1;
                        (name.clone(), "table")
                    }
                    None => {
                        outcome.from_rule += 1;
                        (bare.to_string(), "rule")
                    }
                };
                (name, version.replace('_', "-"), source)
            }
        };
        let Ok(purl) = crate::purl::cran(&name, &version) else {
            continue;
        };
        if !package.extra_purls.contains(&purl) {
            package.extra_purls.push(purl);
        }
        package.properties.insert(SOURCE_PROPERTY.into(), source.into());
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Package;

    fn r_package(name: &str, version: &str) -> Package {
        let mut package = crate::format::testing::sample_sbom().packages[0].clone();
        package.kind = PackageKind::CondaBinary;
        package.name = name.into();
        package.version = Some(version.into());
        package.purl = format!("pkg:conda/conda-forge/{name}@{version}");
        package.extra_purls.clear();
        package.properties.clear();
        package
    }

    fn cran_purl(package: &Package) -> Option<&str> {
        package
            .extra_purls
            .iter()
            .find(|p| p.starts_with("pkg:cran/"))
            .map(String::as_str)
    }

    fn write_description(library: &Path, dir: &str, body: &str) {
        std::fs::create_dir_all(library.join(dir)).unwrap();
        std::fs::write(library.join(dir).join("DESCRIPTION"), body).unwrap();
    }

    #[test]
    fn a_description_is_read_as_debian_control() {
        let text = "Package: data.table\nVersion: 1.16.2\nTitle: Extension of\n  data.frame\nRepository: CRAN\n";
        assert_eq!(
            parse_description(text),
            Some(Description {
                name: "data.table".into(),
                version: "1.16.2".into(),
                cran: true
            })
        );
        let bioc = parse_description("Package: limma\nVersion: 3.60.0\nbiocViews: Software\n").unwrap();
        assert!(!bioc.cran, "no Repository: CRAN");
        assert_eq!(parse_description("Package: x\n"), None, "no version");
    }

    #[test]
    fn without_a_description_the_table_and_the_rule_name_it() {
        let mut sbom = crate::format::testing::sample_sbom();
        sbom.packages = vec![
            r_package("r-ggplot2", "3.5.1"),
            r_package("r-rcpp", "1.0.13_1"),
            r_package("r-data.table", "1.16.2"),
            r_package("r-base", "4.4.1"),
            r_package("bioconductor-limma", "3.60.0"),
        ];
        let empty = tempfile::tempdir().unwrap();
        let outcome = identify(&mut sbom, None, empty.path());
        let purls: Vec<_> = sbom.packages.iter().map(cran_purl).collect();
        assert_eq!(
            purls,
            [
                Some("pkg:cran/ggplot2@3.5.1"),
                Some("pkg:cran/Rcpp@1.0.13-1"),
                Some("pkg:cran/data.table@1.16.2"),
                None,
                None,
            ]
        );
        assert_eq!(sbom.packages[1].properties[SOURCE_PROPERTY], "table");
        assert_eq!(sbom.packages[0].properties[SOURCE_PROPERTY], "rule");
        assert_eq!(
            outcome,
            Outcome {
                from_description: 0,
                from_table: 1,
                from_rule: 2,
                not_cran: 1
            }
        );
    }

    #[test]
    fn an_installed_description_wins_and_says_whether_it_is_on_cran() {
        let prefix = tempfile::tempdir().unwrap();
        let library = prefix.path().join("lib/R/library");
        write_description(&library, "Rcpp", "Package: Rcpp\nVersion: 1.0.13-1\nRepository: CRAN\n");
        write_description(&library, "mypkg", "Package: myPkg\nVersion: 0.1\nRemoteType: github\n");
        let mut sbom = crate::format::testing::sample_sbom();
        sbom.packages = vec![r_package("r-rcpp", "1.0.13_1"), r_package("r-mypkg", "0.1")];
        let outcome = identify(&mut sbom, Some(prefix.path()), prefix.path());
        assert_eq!(cran_purl(&sbom.packages[0]), Some("pkg:cran/Rcpp@1.0.13-1"));
        assert_eq!(sbom.packages[0].properties[SOURCE_PROPERTY], "description");
        assert_eq!(cran_purl(&sbom.packages[1]), None, "installed from GitHub, not CRAN");
        assert_eq!((outcome.from_description, outcome.not_cran), (1, 1));
    }

    #[test]
    fn the_package_cache_is_read_for_a_lockfile() {
        let pkgs = tempfile::tempdir().unwrap();
        let extracted = pkgs.path().join("r-adgoftest-0.3-r44h0_1");
        write_description(
            &extracted.join("lib/R/library"),
            "ADGofTest",
            "Package: ADGofTest\nVersion: 0.3\nRepository: CRAN\n",
        );
        let mut sbom = crate::format::testing::sample_sbom();
        let mut package = r_package("r-adgoftest", "0.3");
        package
            .properties
            .insert("pixi:file-name".into(), "r-adgoftest-0.3-r44h0_1.conda".into());
        sbom.packages = vec![package];
        identify(&mut sbom, None, pkgs.path());
        assert_eq!(cran_purl(&sbom.packages[0]), Some("pkg:cran/ADGofTest@0.3"));
        assert_eq!(sbom.packages[0].properties[SOURCE_PROPERTY], "description");
    }

    #[test]
    fn the_shipped_table_loads() {
        assert_eq!(table().renamed.get("r-rcpp").map(String::as_str), Some("Rcpp"));
        assert!(table().not_cran.names.contains("r-base"));
    }
}
