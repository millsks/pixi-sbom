//! CPEs for native conda packages, from the curated table in `data/cpe.toml`.
//!
//! A conda package carries a `pkg:conda` purl, which no advisory database indexes, so a scanner
//! that matches by CPE (Grype, through NVD) finds nothing for openssl or libtiff from conda-forge.
//! The table maps a conda name to the `vendor:product` NVD uses. It is identity data, like the
//! PyPI mapping: nothing is looked up at run time, and a package missing from the table gets no
//! CPE. Guessing one from the name is where scanners' false positives on conda packages come from.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::model::{Package, PackageKind};

/// The table, compiled into the binary.
const TABLE: &str = include_str!("../data/cpe.toml");

/// Where a package read from another document keeps the CPE that document gave it. Not a
/// `pixi:*` property: the writers turn it back into the format's CPE field and never write it as a
/// property.
pub const DOCUMENT_CPE: &str = "cpe";

/// Where a CPE came from, for `--explain`.
pub const SOURCE: &str = "the CPE table (data/cpe.toml)";

#[derive(serde::Deserialize)]
struct Table {
    cpe: BTreeMap<String, String>,
}

/// One table entry: NVD's vendor and product for a conda package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub vendor: String,
    pub product: String,
}

fn table() -> &'static BTreeMap<String, Entry> {
    static PARSED: OnceLock<BTreeMap<String, Entry>> = OnceLock::new();
    PARSED.get_or_init(|| {
        let table: Table = toml::from_str(TABLE).expect("data/cpe.toml is checked by its tests");
        table
            .cpe
            .into_iter()
            .map(|(name, value)| {
                let (vendor, product) = value.split_once(':').expect("vendor:product, checked by tests");
                (
                    name,
                    Entry {
                        vendor: vendor.to_string(),
                        product: product.to_string(),
                    },
                )
            })
            .collect()
    })
}

/// The table entry for a conda package name.
pub fn entry(name: &str) -> Option<&'static Entry> {
    table().get(&name.to_lowercase())
}

/// The CPE 2.3 formatted string for a package: only a conda package from a channel, with a table
/// entry and a version, has one. A pixi-build source package is not the channel's build.
pub fn for_package(package: &Package) -> Option<String> {
    if let Some(cpe) = package.properties.get(DOCUMENT_CPE) {
        return Some(cpe.clone());
    }
    if package.properties.contains_key(crate::prefix::INTERPRETER_PROPERTY) {
        return interpreter(package);
    }
    // A conda package with a PyPI identity is matched by that purl, like any PyPI package.
    if package.kind != PackageKind::CondaBinary || package.extra_purls.iter().any(|p| p.starts_with("pkg:pypi/")) {
        return None;
    }
    let entry = entry(&package.name)?;
    let version = package.version.as_deref().filter(|v| !v.is_empty())?;
    Some(format!(
        "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
        entry.vendor,
        entry.product,
        escape(version)
    ))
}

/// CPython's CPE for an installation's interpreter, only when its full `X.Y.Z` is known: a bare
/// `3.12` would match every 3.12 advisory, fixed or not.
fn interpreter(package: &Package) -> Option<String> {
    let version = package.version.as_deref()?;
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 3 || !parts[..2].iter().all(|p| p.parse::<u32>().is_ok()) {
        return None;
    }
    let entry = entry("python")?;
    Some(format!(
        "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
        entry.vendor,
        entry.product,
        escape(version)
    ))
}

/// A version as a CPE 2.3 formatted-string value: letters, digits, `_`, `-` and `.` as they are,
/// anything else quoted with a backslash.
fn escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|c| {
            let plain = c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.');
            (!plain).then_some('\\').into_iter().chain(std::iter::once(c))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conda(name: &str, version: &str) -> Package {
        Package {
            id: format!("pkg:conda/{name}@{version}"),
            name: name.to_string(),
            version: (!version.is_empty()).then(|| version.to_string()),
            kind: PackageKind::CondaBinary,
            purl: format!("pkg:conda/{name}@{version}"),
            supplier: None,
            extra_purls: Vec::new(),
            purls_from_lock: false,
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
            properties: BTreeMap::new(),
            dependencies: Vec::new(),
        }
    }

    /// Every entry is a valid CPE 2.3 vendor and product: lower case, and only the characters a
    /// formatted string allows unquoted. Keys are conda names, which are lower case.
    #[test]
    fn every_entry_is_a_valid_vendor_and_product() {
        let valid = |part: &str| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'))
        };
        let raw: Table = toml::from_str(TABLE).unwrap();
        assert!(raw.cpe.len() >= 50, "the table was read ({})", raw.cpe.len());
        for (name, value) in &raw.cpe {
            assert_eq!(name, &name.to_lowercase(), "{name}");
            let (vendor, product) = value.split_once(':').unwrap_or_else(|| panic!("{name}: {value}"));
            assert!(valid(vendor) && valid(product), "{name}: {value}");
        }
    }

    #[test]
    fn conda_packages_in_the_table_get_a_cpe_and_nothing_else_does() {
        assert_eq!(
            for_package(&conda("openssl", "3.5.2")).as_deref(),
            Some("cpe:2.3:a:openssl:openssl:3.5.2:*:*:*:*:*:*:*")
        );
        assert_eq!(
            for_package(&conda("libtiff", "4.5.1")).as_deref(),
            Some("cpe:2.3:a:libtiff:libtiff:4.5.1:*:*:*:*:*:*:*")
        );
        assert_eq!(for_package(&conda("some-unknown-lib", "1.0")), None, "never guessed");
        for kind in [PackageKind::Pypi, PackageKind::CondaSource] {
            let mut other = conda("openssl", "3.5.2");
            other.kind = kind;
            assert_eq!(for_package(&other), None, "{kind:?}: not a channel's conda package");
        }
        assert_eq!(for_package(&conda("openssl", "")), None, "no version, no CPE");
        let mut python_package = conda("openssl", "3.5.2");
        python_package.extra_purls.push("pkg:pypi/openssl@3.5.2".into());
        assert_eq!(for_package(&python_package), None, "matched by its PyPI purl instead");
    }

    #[test]
    fn versions_are_quoted_as_a_formatted_string_needs() {
        assert_eq!(escape("1.1.1w"), "1.1.1w");
        assert_eq!(escape("2.0+git1"), "2.0\\+git1");
        assert_eq!(escape("1!2.0"), "1\\!2.0");
    }
}
