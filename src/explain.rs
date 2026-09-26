//! `--explain <PACKAGE>`: every fact the tool has about a package, where that fact came from,
//! and — where there is no fact — which sources were consulted and what each of them said.
//!
//! Nothing here is new bookkeeping: the answers are read back off the model and the `pixi:*`
//! properties the enrichment steps already record. What this module adds is the other half of
//! the story, the sources that were tried and came back empty, which the document has no place
//! for because a document records what is known rather than how it was looked for.

use std::collections::BTreeSet;

use crate::filter::Glob;
use crate::model::{Package, PackageKind, Sbom};

/// Which sources were available to this run, so a missing fact can say *why* it is missing
/// rather than only that it is. Everything else is read off the model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Context {
    /// A workspace manifest was read, so "the manifest does not declare it" is a real answer.
    pub manifest: bool,
    /// `--fetch-licenses` ran: the package cache, the channel archives, the wheels and the
    /// index were all asked.
    pub fetch_licenses: bool,
    /// `--embedded-sboms` ran.
    pub embedded_sboms: bool,
    /// `--scorecard` ran.
    pub scorecard: bool,
    /// `--vulnerabilities <SOURCE>` ran.
    pub vulnerabilities: bool,
    /// A PyPI name mapping was loaded (`--pypi-mapping prefix` / `--pypi-mapping-file`).
    pub pypi_mapping: bool,
    /// `PIXI_SBOM_OFFLINE` forbade every request, so nothing that needs the network was asked.
    pub offline: bool,
}

/// One thing the tool knows, or does not know, about a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    /// What the fact is about (`identity`, `license`, `declared`, ...).
    pub label: String,
    /// What the tool has, or `None` when no source supplied anything.
    pub value: Option<String>,
    /// Where the value came from, in prose.
    pub source: Option<String>,
    /// The other sources that could have supplied it, and what each one did.
    pub considered: Vec<String>,
}

impl Fact {
    /// A fact with a value and the source that supplied it.
    fn known(label: &str, value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            label: label.to_string(),
            value: Some(value.into()),
            source: Some(source.into()),
            considered: Vec::new(),
        }
    }

    /// A fact nothing supplied, with what each source that could have said so.
    fn unknown(label: &str, considered: Vec<String>) -> Self {
        Self {
            label: label.to_string(),
            value: None,
            source: None,
            considered,
        }
    }

    /// The same fact, naming the sources that were consulted besides the one that answered.
    fn considering(mut self, considered: Vec<String>) -> Self {
        self.considered = considered;
        self
    }
}

/// The packages whose names match one of `patterns`, in the model's order.
pub fn matching<'a>(sbom: &'a Sbom, patterns: &[Glob]) -> Vec<&'a Package> {
    sbom.packages
        .iter()
        .filter(|package| patterns.iter().any(|glob| glob.matches(&package.name)))
        .collect()
}

/// The `pixi:*` properties that are reported as a fact of their own, so the catch-all at the
/// end does not print them twice.
const EXPLAINED_PROPERTIES: &[&str] = &[
    crate::manifest::DIRECT_PROPERTY,
    crate::manifest::DECLARED_IN_PROPERTY,
    crate::mapping::MAPPING_PROPERTY,
    crate::embedded::SOURCE_PROPERTY,
    crate::pypi::LICENSE_SOURCE_PROPERTY,
    crate::pypi::YANKED_PROPERTY,
    crate::pypi::YANKED_REASON_PROPERTY,
    crate::pyversion::REQUIRES_PYTHON_PROPERTY,
    crate::scorecard::SCORE_PROPERTY,
    crate::scorecard::DATE_PROPERTY,
    "pixi:license-files-source",
    "pixi:channel",
    "pixi:channel-url",
    "pixi:index-url",
    "pixi:kind",
];

/// Everything the tool has about `package`, fact by fact, in reading order.
pub fn facts(package: &Package, sbom: &Sbom, ctx: Context) -> Vec<Fact> {
    let input = sbom.input_description();
    let mut facts = vec![
        Fact::known("identity", &package.purl, &input),
        Fact::known("kind", package.kind.name(), &input),
    ];
    facts.push(match &package.version {
        Some(version) => Fact::known("version", version, &input),
        // Only a pixi-build source package whose metadata pixi has not evaluated gets this far.
        None => Fact::unknown("version", vec![format!("{input}: the entry carries no version")]),
    });
    facts.push(declared(package, ctx));
    facts.push(obtained_from(package, &input));
    facts.push(match package.location.is_empty() {
        false => Fact::known("location", &package.location, &input),
        true => Fact::unknown("location", vec![format!("{input}: the entry names no location")]),
    });
    facts.push(checksum(package, &input));
    facts.push(license(package, ctx, &input));
    facts.push(license_files(package, ctx, &input));
    facts.push(pypi_identity(package, ctx, &input));
    facts.push(requires_python(package, &input));
    facts.push(embedded(package, ctx, &input));
    facts.push(yanked(package, ctx));
    facts.push(scorecard(package, ctx));
    facts.push(vulnerabilities(package, sbom, ctx));
    facts.extend(edges(package, sbom, &input));
    facts.extend(other_properties(package, &input));
    facts
}

/// Whether the workspace asked for this package itself.
fn declared(package: &Package, ctx: Context) -> Fact {
    match package.properties.get(crate::manifest::DECLARED_IN_PROPERTY) {
        Some(features) => Fact::known("declared", features.replace(',', ", "), "the workspace manifest"),
        None if ctx.manifest => Fact::unknown(
            "declared",
            vec!["the workspace manifest: it declares no dependency of this name, so something else needed it".into()],
        ),
        None => Fact::unknown(
            "declared",
            vec!["the workspace manifest: none was read, so nothing says what was asked for".into()],
        ),
    }
}

/// The channel or index the package came from.
fn obtained_from(package: &Package, input: &str) -> Fact {
    let Some(supplier) = &package.supplier else {
        return Fact::unknown(
            "obtained from",
            vec![format!(
                "{input}: the entry names no channel or index, as for a source or local package"
            )],
        );
    };
    // The channel and index URLs have no fact of their own, so the supplier carries them.
    let url = supplier
        .url
        .as_deref()
        .or_else(|| package.properties.get("pixi:channel-url").map(String::as_str))
        .or_else(|| package.properties.get("pixi:index-url").map(String::as_str));
    let value = match url {
        Some(url) => format!("{} ({url})", supplier.name),
        None => supplier.name.clone(),
    };
    Fact::known("obtained from", value, input)
}

/// The archive hashes the entry carries.
fn checksum(package: &Package, input: &str) -> Fact {
    let hashes: Vec<String> = [("sha256", &package.sha256), ("md5", &package.md5)]
        .into_iter()
        .filter_map(|(name, hash)| hash.as_ref().map(|hash| format!("{name}:{hash}")))
        .collect();
    match hashes.is_empty() {
        false => Fact::known("checksum", hashes.join(", "), input),
        true => Fact::unknown("checksum", vec![format!("{input}: the entry carries no hash")]),
    }
}

/// Prose for the value of `pixi:license-source` / `pixi:license-files-source`.
fn license_source_prose(source: &str) -> String {
    match source {
        "lockfile" => "the lockfile entry".into(),
        crate::pkgcache::LICENSE_SOURCE => "the extracted package in the pixi package cache".into(),
        crate::condaarchive::LICENSE_SOURCE => "the package archive downloaded from the channel".into(),
        crate::wheel::LICENSE_SOURCE => "the wheel's dist-info".into(),
        "pypi" => "the PyPI index metadata".into(),
        other => other.to_string(),
    }
}

/// Every source that could have supplied a license for this package, and what each did, minus
/// the one that actually answered.
fn license_sources(package: &Package, ctx: Context, supplied: Option<&str>) -> Vec<String> {
    let unread = |what: &str| -> String {
        if !ctx.fetch_licenses {
            "not read, --fetch-licenses was not given".to_string()
        } else if ctx.offline && what == "network" {
            // Offline still reads the caches, so the honest answer names both halves.
            "nothing cached for this package, and PIXI_SBOM_OFFLINE forbade a request".to_string()
        } else {
            "nothing for this package there".to_string()
        }
    };
    let conda = matches!(package.kind, PackageKind::CondaBinary | PackageKind::CondaSource);
    let pypi = package.kind == PackageKind::Pypi;
    let mut candidates: Vec<(&str, String)> = vec![("lockfile", "the entry declares none".into())];
    if conda {
        candidates.push((crate::pkgcache::LICENSE_SOURCE, unread("local")));
        candidates.push((crate::condaarchive::LICENSE_SOURCE, unread("network")));
    } else {
        candidates.push((
            crate::pkgcache::LICENSE_SOURCE,
            "the package cache holds conda packages only".into(),
        ));
    }
    if pypi {
        candidates.push((crate::wheel::LICENSE_SOURCE, unread("network")));
        candidates.push(("pypi", unread("network")));
    } else {
        candidates.push(("pypi", "this is not a PyPI package".into()));
    }
    candidates
        .into_iter()
        .filter(|(name, _)| Some(*name) != supplied)
        .map(|(name, what)| format!("{}: {what}", license_source_prose(name)))
        .collect()
}

/// The declared license and where it was read.
fn license(package: &Package, ctx: Context, input: &str) -> Fact {
    let recorded = package
        .properties
        .get(crate::pypi::LICENSE_SOURCE_PROPERTY)
        .map(String::as_str);
    // Without a property the lockfile itself is the only thing that can have declared one.
    let supplied = recorded.or(package.license.as_ref().map(|_| "lockfile"));
    let considered = license_sources(package, ctx, supplied);
    match (&package.license, supplied) {
        (Some(license), Some("lockfile")) => Fact::known("license", license, input).considering(considered),
        (Some(license), Some(source)) => {
            Fact::known("license", license, license_source_prose(source)).considering(considered)
        }
        _ => Fact::unknown("license", considered),
    }
}

/// The license files shipped with the package.
fn license_files(package: &Package, ctx: Context, input: &str) -> Fact {
    let recorded = package.properties.get("pixi:license-files-source").map(String::as_str);
    if package.license_files.is_empty() {
        return Fact::unknown("license files", license_sources(package, ctx, recorded));
    }
    // Without a property the names came with the entry itself, as they do for a conda channel.
    let considered = license_sources(package, ctx, recorded.or(Some("lockfile")));
    let names: Vec<&str> = package.license_files.iter().map(|f| f.name.as_str()).collect();
    let texts = package.license_files.iter().filter(|f| f.text.is_some()).count();
    let value = match texts {
        0 => names.join(", "),
        n => format!("{} ({n} with their text)", names.join(", ")),
    };
    Fact::known(
        "license files",
        value,
        recorded.map(license_source_prose).unwrap_or_else(|| input.to_string()),
    )
    .considering(considered)
}

/// The purls beyond the primary one — for a conda package, the PyPI identity a scanner needs.
fn pypi_identity(package: &Package, ctx: Context, input: &str) -> Fact {
    let mapped = package.properties.get(crate::mapping::MAPPING_PROPERTY);
    if package.extra_purls.is_empty() {
        let mut considered = vec![match package.purls_from_lock {
            true => format!("{input}: the entry states the package's purls and lists no other"),
            false => format!("{input}: the entry names no other purl"),
        }];
        considered.push(match (ctx.pypi_mapping, package.kind) {
            (_, PackageKind::Pypi) => "the conda-forge PyPI mapping: not asked, this is already a PyPI package".into(),
            (true, _) => "the conda-forge PyPI mapping: it has no PyPI name for this package".into(),
            (false, _) => "the conda-forge PyPI mapping: not read, --pypi-mapping prefix was not given".into(),
        });
        return Fact::unknown("other purls", considered);
    }
    let source = match mapped.map(String::as_str) {
        Some("prefix") => "the conda-forge PyPI mapping".to_string(),
        Some("file") => "the PyPI mapping given with --pypi-mapping-file".to_string(),
        Some(other) => format!("the PyPI mapping ({other})"),
        None => input.to_string(),
    };
    Fact::known("other purls", package.extra_purls.join(", "), source)
}

/// The interpreter the distribution says it needs.
fn requires_python(package: &Package, input: &str) -> Fact {
    match package.properties.get(crate::pyversion::REQUIRES_PYTHON_PROPERTY) {
        Some(requires) => Fact::known("requires python", requires, input),
        None => Fact::unknown(
            "requires python",
            vec![format!("{input}: the entry carries no Requires-Python")],
        ),
    }
}

/// The SBOM embedded in the wheel, or the crate list read out of a binary.
fn embedded(package: &Package, ctx: Context, input: &str) -> Fact {
    if let Some(source) = package.properties.get(crate::embedded::SOURCE_PROPERTY) {
        let origin = package.properties.get("pixi:cargo-source");
        let value = match origin {
            Some(origin) => format!("{source} (from {origin})"),
            None => source.clone(),
        };
        return Fact::known("embedded sbom", value, input);
    }
    Fact::unknown(
        "embedded sbom",
        vec![match ctx.embedded_sboms {
            true => "the wheel's dist-info: it declares no embedded SBOM (PEP 770)".into(),
            false => "the wheel's dist-info: not read, --embedded-sboms was not given".to_string(),
        }],
    )
}

/// Whether the index has withdrawn this release.
fn yanked(package: &Package, ctx: Context) -> Fact {
    match &package.yanked {
        Some(yanked) => Fact::known(
            "yanked",
            match &yanked.reason {
                Some(reason) => format!("yes: {reason}"),
                None => "yes, with no reason given".to_string(),
            },
            "the PyPI index metadata",
        ),
        None if package.kind != PackageKind::Pypi => Fact::unknown(
            "yanked",
            vec!["the PyPI index: not asked, this is not a PyPI package".into()],
        ),
        None if ctx.fetch_licenses => Fact::known("yanked", "no", "the PyPI index metadata"),
        None => Fact::unknown(
            "yanked",
            vec!["the PyPI index: not asked, --fetch-licenses was not given".into()],
        ),
    }
}

/// What the OpenSSF Scorecard service said about the repository.
fn scorecard(package: &Package, ctx: Context) -> Fact {
    let score = package.properties.get(crate::scorecard::SCORE_PROPERTY);
    let date = package.properties.get(crate::scorecard::DATE_PROPERTY);
    match (score, &package.repository) {
        (Some(score), _) => {
            let value = match date {
                Some(date) => format!("{score} (scored {date})"),
                None => score.clone(),
            };
            Fact::known("scorecard", value, "the OpenSSF Scorecard service")
        }
        (None, _) if !ctx.scorecard => Fact::unknown(
            "scorecard",
            vec!["the OpenSSF Scorecard service: not asked, --scorecard was not given".into()],
        ),
        (None, None) => Fact::unknown(
            "scorecard",
            vec!["the OpenSSF Scorecard service: not asked, no repository URL is known for this package".into()],
        ),
        (None, Some(repository)) => Fact::unknown(
            "scorecard",
            vec![format!(
                "the OpenSSF Scorecard service: it has never scored {repository}"
            )],
        ),
    }
}

/// The findings attached to this package, when they were looked up.
fn vulnerabilities(package: &Package, sbom: &Sbom, ctx: Context) -> Fact {
    if !ctx.vulnerabilities {
        return Fact::unknown(
            "vulnerabilities",
            vec!["OSV: not queried, --vulnerabilities was not given".into()],
        );
    }
    let ids: Vec<&str> = sbom
        .vulnerabilities
        .iter()
        .filter(|v| v.affects.iter().any(|a| a.package_id == package.id))
        .map(|v| v.id.as_str())
        .collect();
    if ids.is_empty() {
        let queryable = std::iter::once(&package.purl)
            .chain(&package.extra_purls)
            .any(|purl| crate::osv::queryable_purl(purl).is_some());
        return Fact::unknown(
            "vulnerabilities",
            vec![match queryable {
                true => "OSV: queried, no advisory matches this version".to_string(),
                false => "OSV: not queried, the package has no purl the database indexes".to_string(),
            }],
        );
    }
    Fact::known("vulnerabilities", ids.join(", "), "OSV")
}

/// The edges of the graph this package sits on, in both directions.
fn edges(package: &Package, sbom: &Sbom, input: &str) -> Vec<Fact> {
    let name_of = |id: &str| {
        sbom.packages
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| id.to_string())
    };
    let depends: BTreeSet<String> = package.dependencies.iter().map(|id| name_of(id)).collect();
    let needed_by: BTreeSet<String> = sbom
        .packages
        .iter()
        .filter(|other| other.dependencies.contains(&package.id))
        .map(|other| other.name.clone())
        .collect();
    let list = |label: &str, names: BTreeSet<String>, empty: String| match names.is_empty() {
        false => Fact::known(label, names.into_iter().collect::<Vec<_>>().join(", "), input),
        true => Fact::unknown(label, vec![empty]),
    };
    vec![
        list("depends on", depends, format!("{input}: the entry lists no dependency")),
        list(
            "needed by",
            needed_by,
            format!("{input}: nothing else in this environment depends on it"),
        ),
    ]
}

/// Every remaining `pixi:*` property, so nothing the document carries is hidden here.
fn other_properties(package: &Package, input: &str) -> Vec<Fact> {
    package
        .properties
        .iter()
        .filter(|(key, _)| !EXPLAINED_PROPERTIES.contains(&key.as_str()))
        .filter(|(key, _)| !key.starts_with(crate::scorecard::CHECK_PROPERTY_PREFIX))
        .map(|(key, value)| {
            let label = key.strip_prefix("pixi:").unwrap_or(key).replace('-', " ");
            Fact::known(&label, value, input)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    fn fact<'a>(facts: &'a [Fact], label: &str) -> &'a Fact {
        facts.iter().find(|f| f.label == label).expect("the fact is printed")
    }

    fn package<'a>(sbom: &'a Sbom, name: &str) -> &'a Package {
        sbom.packages.iter().find(|p| p.name == name).unwrap()
    }

    #[test]
    fn globs_pick_the_packages_to_explain() {
        let sbom = sample_sbom();
        let names = |patterns: &[&str]| -> Vec<String> {
            let globs: Vec<Glob> = patterns.iter().map(|p| Glob::parse(p).unwrap()).collect();
            matching(&sbom, &globs).iter().map(|p| p.name.clone()).collect()
        };
        assert_eq!(names(&["six"]), ["six"]);
        assert_eq!(names(&["*zlib"]), ["libzlib", "zlib"]);
        assert_eq!(names(&["six", "mylib"]), ["mylib", "six"], "in the model's order");
        assert!(names(&["nothing-here"]).is_empty());
    }

    #[test]
    fn a_lockfile_package_names_the_lockfile_for_what_only_it_knows() {
        let sbom = sample_sbom();
        let zlib = facts(package(&sbom, "zlib"), &sbom, Context::default());
        assert_eq!(fact(&zlib, "identity").source.as_deref(), Some("lockfile pixi.lock"));
        assert_eq!(fact(&zlib, "kind").value.as_deref(), Some("conda"));
        assert_eq!(fact(&zlib, "version").value.as_deref(), Some("1.3.1"));
        assert_eq!(
            fact(&zlib, "obtained from").value.as_deref(),
            Some("conda-forge"),
            "no channel URL, so only the name"
        );
        assert_eq!(
            fact(&zlib, "checksum").value.as_deref(),
            Some(format!("sha256:{}", "c".repeat(64)).as_str())
        );
        assert_eq!(fact(&zlib, "depends on").value.as_deref(), Some("libzlib"));
        assert_eq!(fact(&zlib, "needed by").value.as_deref(), Some("mylib"));
        // The license is the lockfile's own, and the fetching sources are named as not read.
        let license = fact(&zlib, "license");
        assert_eq!(license.value.as_deref(), Some("MIT/Apache-2.0"));
        assert_eq!(license.source.as_deref(), Some("lockfile pixi.lock"));
        assert!(
            license
                .considered
                .iter()
                .any(|line| line.contains("package cache") && line.contains("--fetch-licenses was not given")),
            "{:?}",
            license.considered
        );
        assert!(
            license
                .considered
                .iter()
                .any(|line| line == "the PyPI index metadata: this is not a PyPI package"),
            "{:?}",
            license.considered
        );
        assert_eq!(fact(&zlib, "other purls").value.as_deref(), Some("pkg:pypi/zlib@1.3.1"));
        // Every property without a fact of its own still gets one, with the input behind it.
        let libzlib = facts(package(&sbom, "libzlib"), &sbom, Context::default());
        assert_eq!(fact(&libzlib, "subdir").value.as_deref(), Some("linux-64"));
        assert_eq!(fact(&libzlib, "subdir").source.as_deref(), Some("lockfile pixi.lock"));
        assert!(
            !libzlib.iter().any(|f| f.label == "channel"),
            "the channel is the supplier, not a property of its own"
        );
    }

    #[test]
    fn each_enrichment_source_is_named_for_the_fact_it_supplied() {
        let mut sbom = sample_sbom();
        let six = sbom.packages.iter_mut().find(|p| p.name == "six").unwrap();
        six.license = Some("MIT".into());
        six.license_files = vec![crate::model::LicenseFile {
            name: "LICENSE".into(),
            text: Some("MIT text".into()),
        }];
        six.properties
            .insert(crate::pypi::LICENSE_SOURCE_PROPERTY.into(), "wheel".into());
        six.properties
            .insert("pixi:license-files-source".into(), "wheel".into());
        six.properties
            .insert(crate::pyversion::REQUIRES_PYTHON_PROPERTY.into(), ">=2.7".into());
        six.properties
            .insert(crate::embedded::SOURCE_PROPERTY.into(), "six.whl/sbom.cdx.json".into());
        six.properties
            .insert(crate::scorecard::SCORE_PROPERTY.into(), "6.4".into());
        six.properties
            .insert(crate::scorecard::DATE_PROPERTY.into(), "2026-09-01".into());
        six.properties
            .insert(crate::manifest::DECLARED_IN_PROPERTY.into(), "default,docs".into());
        six.yanked = Some(crate::model::Yanked {
            reason: Some("broken sdist".into()),
        });
        let ctx = Context {
            manifest: true,
            fetch_licenses: true,
            embedded_sboms: true,
            scorecard: true,
            vulnerabilities: true,
            pypi_mapping: true,
            offline: false,
        };
        let facts = facts(package(&sbom, "six"), &sbom, ctx);
        assert_eq!(fact(&facts, "declared").value.as_deref(), Some("default, docs"));
        assert_eq!(
            fact(&facts, "declared").source.as_deref(),
            Some("the workspace manifest")
        );
        assert_eq!(fact(&facts, "license").source.as_deref(), Some("the wheel's dist-info"));
        assert_eq!(
            fact(&facts, "license files").value.as_deref(),
            Some("LICENSE (1 with their text)")
        );
        assert_eq!(fact(&facts, "requires python").value.as_deref(), Some(">=2.7"));
        assert_eq!(
            fact(&facts, "embedded sbom").value.as_deref(),
            Some("six.whl/sbom.cdx.json")
        );
        assert_eq!(fact(&facts, "yanked").value.as_deref(), Some("yes: broken sdist"));
        assert_eq!(
            fact(&facts, "scorecard").value.as_deref(),
            Some("6.4 (scored 2026-09-01)")
        );
        // Queried and clean is an answer, not a gap.
        assert_eq!(
            fact(&facts, "vulnerabilities").considered,
            ["OSV: queried, no advisory matches this version"]
        );
        // The wheel answered, so the other license sources are what was also consulted.
        let license = fact(&facts, "license");
        assert!(
            license
                .considered
                .iter()
                .any(|l| l == "the lockfile entry: the entry declares none"),
            "{:?}",
            license.considered
        );
        assert!(
            license
                .considered
                .iter()
                .any(|l| l.starts_with("the PyPI index metadata: nothing for this package there")),
            "{:?}",
            license.considered
        );
    }

    #[test]
    fn a_package_no_source_could_answer_says_what_each_one_did() {
        let mut sbom = sample_sbom();
        let six = sbom.packages.iter_mut().find(|p| p.name == "six").unwrap();
        six.supplier = None;
        six.sha256 = None;
        six.location = String::new();
        six.dependencies.clear();
        let ctx = Context {
            fetch_licenses: true,
            offline: true,
            vulnerabilities: true,
            ..Context::default()
        };
        let facts = facts(package(&sbom, "six"), &sbom, ctx);
        let unknown: Vec<&str> = facts
            .iter()
            .filter(|f| f.value.is_none())
            .map(|f| f.label.as_str())
            .collect();
        for label in [
            "declared",
            "obtained from",
            "location",
            "checksum",
            "license",
            "license files",
            "other purls",
            "embedded sbom",
            "scorecard",
            "vulnerabilities",
            "depends on",
        ] {
            assert!(unknown.contains(&label), "{label} should have nothing: {unknown:?}");
        }
        // Nothing is left without an explanation, and offline is named where it decided.
        assert!(facts.iter().all(|f| f.value.is_some() || !f.considered.is_empty()));
        let license = fact(&facts, "license");
        assert!(
            license
                .considered
                .iter()
                .any(|l| l.contains("PIXI_SBOM_OFFLINE forbade a request")),
            "{:?}",
            license.considered
        );
        assert_eq!(
            fact(&facts, "declared").considered,
            ["the workspace manifest: none was read, so nothing says what was asked for"]
        );
        assert_eq!(
            fact(&facts, "vulnerabilities").considered,
            ["OSV: queried, no advisory matches this version"]
        );
    }

    #[test]
    fn a_source_package_and_a_prefix_input_say_what_stands_in_for_the_lockfile() {
        let mut sbom = sample_sbom();
        sbom.prefix = Some("app".into());
        let facts = facts(
            package(&sbom, "mylib"),
            &sbom,
            Context {
                manifest: true,
                ..Context::default()
            },
        );
        assert_eq!(fact(&facts, "identity").source.as_deref(), Some("prefix app"));
        assert_eq!(
            fact(&facts, "version").considered,
            ["prefix app: the entry carries no version"]
        );
        assert_eq!(
            fact(&facts, "obtained from").considered,
            ["prefix app: the entry names no channel or index, as for a source or local package"]
        );
        assert_eq!(
            fact(&facts, "declared").considered,
            ["the workspace manifest: it declares no dependency of this name, so something else needed it"]
        );
        assert_eq!(fact(&facts, "needed by").value, None);
    }

    #[test]
    fn a_finding_and_a_scorecard_gap_name_their_service() {
        let mut sbom = sample_sbom();
        let six_id = package(&sbom, "six").id.clone();
        sbom.vulnerabilities = vec![crate::model::Vulnerability {
            id: "GHSA-xxxx".into(),
            source: "OSV".into(),
            url: "https://osv.dev/GHSA-xxxx".into(),
            aliases: vec![],
            summary: None,
            details: None,
            severity: crate::model::Severity::High,
            ratings: vec![],
            cwes: vec![],
            references: vec![],
            published: None,
            modified: None,
            affects: vec![crate::model::Affected {
                package_id: six_id,
                purl: "pkg:pypi/six@1.17.0".into(),
                fixed_version: None,
            }],
            analysis: None,
            kev: None,
        }];
        let ctx = Context {
            vulnerabilities: true,
            scorecard: true,
            ..Context::default()
        };
        let six = package(&sbom, "six").clone();
        let six_facts = facts(&six, &sbom, ctx);
        assert_eq!(fact(&six_facts, "vulnerabilities").source.as_deref(), Some("OSV"));
        assert_eq!(fact(&six_facts, "vulnerabilities").value.as_deref(), Some("GHSA-xxxx"));
        assert_eq!(
            fact(&six_facts, "scorecard").considered,
            ["the OpenSSF Scorecard service: not asked, no repository URL is known for this package"]
        );

        // A repository the service has never scored is named, and so is a purl OSV cannot index.
        let mut libzlib = package(&sbom, "libzlib").clone();
        let libzlib_facts = facts(&libzlib, &sbom, ctx);
        assert_eq!(
            fact(&libzlib_facts, "scorecard").considered,
            ["the OpenSSF Scorecard service: it has never scored https://github.com/madler/zlib"]
        );
        assert_eq!(
            fact(&libzlib_facts, "vulnerabilities").considered,
            ["OSV: not queried, the package has no purl the database indexes"]
        );
        libzlib.extra_purls = vec!["pkg:pypi/zlib@1.3.1".into()];
        let queryable = facts(&libzlib, &sbom, ctx);
        assert_eq!(
            fact(&queryable, "vulnerabilities").considered,
            ["OSV: queried, no advisory matches this version"]
        );
    }
}
