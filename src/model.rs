//! Format-agnostic representation of an SBOM built from one lock environment/platform.
//!
//! Both the CycloneDX and SPDX writers consume this model, so all lockfile
//! interpretation happens exactly once, in [`crate::lock`].

use std::collections::BTreeMap;

/// The complete SBOM content for a single environment and platform.
#[derive(Debug, Clone, PartialEq)]
pub struct Sbom {
    /// The workspace the lockfile belongs to.
    pub root: Root,
    /// Name of the lock environment that was described.
    pub environment: String,
    /// Platform within that environment (e.g. `linux-64`).
    pub platform: String,
    /// Name of the lockfile the SBOM was generated from, relative to the workspace root
    /// (normally `pixi.lock`). Never an absolute path, so documents do not depend on where
    /// they were generated. Empty when the input was an installed environment (`prefix`).
    pub lockfile: String,
    /// Name of the installed environment the SBOM was generated from with `--prefix` (its
    /// directory name, never a path), in place of a lockfile.
    pub prefix: Option<String>,
    /// Identity of the document this one was derived from with `--from-sbom` (its serial
    /// number or namespace, else its file name), in place of a lockfile.
    pub document: Option<String>,
    /// Packages sorted by kind, then name, then version. Order is stable across runs.
    pub packages: Vec<Package>,
    /// Known vulnerabilities of the packages, when looked up. Sorted by severity (worst
    /// first), then id.
    pub vulnerabilities: Vec<Vulnerability>,
    /// Names of packages left out by `--include` / `--exclude`, so the omission is visible in
    /// the document. Sorted, deduplicated.
    pub excluded: Vec<String>,
    /// Names the manifest declares for this environment that no package in it matches — a
    /// dependency of another platform is the usual reason. Sorted, deduplicated.
    pub declared_missing: Vec<String>,
    /// What this document does not know because a step could not finish: the enrichment that
    /// failed, and the data that was served past its lifetime.
    ///
    /// A document built where the lookups failed otherwise looks exactly like one built where
    /// everything answered — licenses are simply absent, `vulnerabilities` is simply empty —
    /// and it outlives the terminal that carried the warnings.
    pub incomplete: Incomplete,
}

/// What a run could not finish, recorded in the document it wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Incomplete {
    /// Steps that did not complete, as `pypi-licenses: 12 of 38 lookups failed`. Sorted.
    pub steps: Vec<String>,
    /// Caches served past their lifetime because the fetch failed, as `kev: 9 days old`.
    pub stale: Vec<String>,
}

impl Incomplete {
    /// Whether everything this run set out to do, it did.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty() && self.stale.is_empty()
    }

    /// Record a step that did not complete, described as `name: what went wrong`.
    pub fn note(&mut self, step: impl Into<String>) {
        let step = step.into();
        if !self.steps.contains(&step) {
            self.steps.push(step);
            self.steps.sort();
        }
    }

    /// Record `failed` of `total` lookups failing, if any did.
    pub fn note_failures(&mut self, name: &str, failed: usize, total: usize, what: &str) {
        if failed > 0 {
            self.note(format!("{name}: {failed} of {total} {what} failed"));
        }
    }

    /// The names of the steps that did not complete, for the summary property.
    pub fn step_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .steps
            .iter()
            .map(|step| step.split(':').next().unwrap_or(step).trim())
            .collect();
        // Sorted already, since `steps` is; two notes about one step name as here.
        names.dedup();
        names
    }
}

/// How bad a vulnerability is, on the CycloneDX / common scanner scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Nothing says how bad it is.
    Unknown,
    /// Rated as having no impact.
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// The lowercase name CycloneDX and the reports use.
    pub fn name(self) -> &'static str {
        match self {
            Severity::Unknown => "unknown",
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Parse the spellings advisory databases use (`MODERATE` is GitHub's `medium`).
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text.trim().to_ascii_lowercase().as_str() {
            "none" => Severity::None,
            "low" => Severity::Low,
            "medium" | "moderate" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => return None,
        })
    }

    /// Severity for a CVSS base score, per the CVSS v3 / v4 qualitative scale.
    pub fn from_cvss_score(score: f64) -> Self {
        if score == 0.0 {
            Severity::None
        } else if score < 4.0 {
            Severity::Low
        } else if score < 7.0 {
            Severity::Medium
        } else if score < 9.0 {
            Severity::High
        } else {
            Severity::Critical
        }
    }
}

/// One severity rating of a vulnerability, from one source.
#[derive(Debug, Clone, PartialEq)]
pub struct Rating {
    /// Who rated it (`GitHub`, `OSV`, ...).
    pub source: String,
    /// CVSS base score, when the rating is a CVSS vector.
    pub score: Option<f64>,
    pub severity: Severity,
    /// CycloneDX rating method (`CVSSv31`, `CVSSv4`, `other`).
    pub method: &'static str,
    /// The CVSS vector string, when there is one.
    pub vector: Option<String>,
}

/// A package the vulnerability applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affected {
    /// The [`Package::id`] of the affected package.
    pub package_id: String,
    /// The purl the advisory matched (a conda package's PyPI purl, for example).
    pub purl: String,
    /// The first version that fixes it, when the advisory says.
    pub fixed_version: Option<String>,
}

/// A known vulnerability of one or more packages in the [`Sbom`].
#[derive(Debug, Clone, PartialEq)]
pub struct Vulnerability {
    /// Advisory id (`GHSA-...`, `PYSEC-...`, `RUSTSEC-...`).
    pub id: String,
    /// Name of the database the record came from (`OSV`).
    pub source: String,
    /// URL of the record.
    pub url: String,
    /// Other ids for the same vulnerability (`CVE-...`, and records merged into this one).
    pub aliases: Vec<String>,
    /// One-line summary, when the record has one.
    pub summary: Option<String>,
    /// Longer description, when the record has one.
    pub details: Option<String>,
    /// The worst severity among the ratings.
    pub severity: Severity,
    pub ratings: Vec<Rating>,
    /// CWE numbers, when known.
    pub cwes: Vec<u32>,
    /// Reference URLs (advisories, fixes, reports).
    pub references: Vec<String>,
    /// RFC 3339 timestamps from the record.
    pub published: Option<String>,
    pub modified: Option<String>,
    /// The packages it applies to. Sorted by package id.
    pub affects: Vec<Affected>,
    /// Set when the finding was accepted with `--ignore-vuln`: it stays in the document but
    /// does not trip the gate.
    pub analysis: Option<Analysis>,
    /// Set with `--kev` when a CVE alias is in CISA's Known Exploited Vulnerabilities catalog.
    pub kev: Option<Kev>,
}

/// A CISA Known Exploited Vulnerabilities catalog entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kev {
    pub cve_id: String,
    pub name: Option<String>,
    /// `YYYY-MM-DD` the entry was added to the catalog.
    pub date_added: Option<String>,
    /// `YYYY-MM-DD` federal agencies must remediate by (BOD 22-01).
    pub due_date: Option<String>,
    /// Whether the catalog records known use in ransomware campaigns.
    pub ransomware: bool,
    pub required_action: Option<String>,
}

/// A VEX-style assessment of a finding (CycloneDX `vulnerabilities[].analysis`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// CycloneDX impact-analysis state (`not_affected`, `false_positive`, ...).
    pub state: &'static str,
    /// Free-text justification.
    pub detail: Option<String>,
}

impl Sbom {
    /// What the document was generated from, for provenance notes: `lockfile pixi.lock` or
    /// `prefix <name>`.
    pub fn input_description(&self) -> String {
        match (&self.prefix, &self.document) {
            (Some(prefix), _) => format!("prefix {prefix}"),
            (None, Some(document)) => format!("document {document}"),
            (None, None) => format!("lockfile {}", self.lockfile),
        }
    }

    /// The `pixi:*` property naming the input and its value.
    pub fn input_property(&self) -> (&'static str, &str) {
        match (&self.prefix, &self.document) {
            (Some(prefix), _) => ("pixi:prefix", prefix),
            (None, Some(document)) => (crate::fromsbom::SOURCE_DOCUMENT_PROPERTY, document),
            (None, None) => ("pixi:lockfile", &self.lockfile),
        }
    }
}

/// The workspace described by the SBOM.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Root {
    /// Workspace name from the manifest, or the lockfile directory name as a fallback.
    pub name: String,
    /// Workspace version from the manifest, if present.
    pub version: Option<String>,
    /// Workspace authors from the manifest; they are recorded as the SBOM's authors.
    pub authors: Vec<Author>,
    /// Workspace license from the manifest, if present. Not guaranteed to be an SPDX expression.
    pub license: Option<String>,
    /// Workspace homepage URL, if present.
    pub homepage: Option<String>,
    /// Workspace source repository URL, if present.
    pub repository: Option<String>,
}

/// A person named in the manifest's author list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Author {
    /// Display name.
    pub name: String,
    /// Email address, if given.
    pub email: Option<String>,
}

impl Author {
    /// Parse the `Name <email>` spelling pixi manifests use; without angle brackets the whole
    /// string is the name.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        match text.rsplit_once('<') {
            Some((name, rest)) if rest.ends_with('>') => {
                let email = rest.trim_end_matches('>').trim();
                let name = name.trim();
                Some(Self {
                    name: if name.is_empty() {
                        email.to_string()
                    } else {
                        name.to_string()
                    },
                    email: (!email.is_empty()).then(|| email.to_string()),
                })
            }
            _ => Some(Self {
                name: text.to_string(),
                email: None,
            }),
        }
    }
}

/// A release the index still serves but has withdrawn (PEP 592): it is broken or unsafe, and
/// a resolver will not pick it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Yanked {
    /// Why it was withdrawn, when the index says.
    pub reason: Option<String>,
}

/// A license file shipped with a package, optionally with its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseFile {
    /// File name, relative to the package's license directory (e.g. `LICENSE`, `third_party/zlib.txt`).
    pub name: String,
    /// The file's contents, read lossily as UTF-8; present only when texts were requested.
    pub text: Option<String>,
}

/// The organization a package was obtained from: a conda channel or a PyPI index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Supplier {
    /// Short name, e.g. `conda-forge` or `pypi.org`.
    pub name: String,
    /// The channel or index URL.
    pub url: Option<String>,
}

/// How a package is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackageKind {
    /// A prebuilt `.conda` / `.tar.bz2` archive from a channel.
    CondaBinary,
    /// A pixi-build source package (path or git).
    CondaSource,
    /// A PyPI wheel or sdist.
    Pypi,
    /// A component declared by an SBOM embedded in a wheel (PEP 770), e.g. a Rust crate
    /// compiled into it. Not installed as a package of its own.
    Embedded,
    /// A package read from an existing document (`--from-sbom`) whose purl is neither conda
    /// nor PyPI, or which has no purl at all: the document is the only thing that knows what
    /// it is.
    External,
}

impl PackageKind {
    /// The short name used in `pixi:kind`, SPDX ids and reports.
    pub fn name(self) -> &'static str {
        match self {
            PackageKind::CondaBinary => "conda",
            PackageKind::CondaSource => "conda-source",
            PackageKind::Pypi => "pypi",
            PackageKind::Embedded => "embedded",
            PackageKind::External => "external",
        }
    }
}

/// A single locked package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Stable identifier, unique within one [`Sbom`]. Currently the purl.
    pub id: String,
    /// Package name as spelled in the lockfile.
    pub name: String,
    /// Package version string. Absent only for pixi-build source packages whose metadata
    /// has not been evaluated yet.
    pub version: Option<String>,
    /// Delivery mechanism.
    pub kind: PackageKind,
    /// Package URL for this package.
    pub purl: String,
    /// Where the package was obtained from, if it came from a channel or index.
    pub supplier: Option<Supplier>,
    /// Additional purls for the package (e.g. a conda package's PyPI purl), from the lockfile
    /// or from PyPI identity enrichment.
    pub extra_purls: Vec<String>,
    /// Whether the lockfile itself states the package's purls (`purls:` present, even if
    /// empty). When true the lockfile's answer is authoritative and enrichment leaves it alone.
    pub purls_from_lock: bool,
    /// Download URL or filesystem path.
    pub location: String,
    /// Hex-encoded SHA-256 of the archive, if known.
    pub sha256: Option<String>,
    /// Hex-encoded MD5 of the archive, if known.
    pub md5: Option<String>,
    /// License string as declared by the package. Not guaranteed to be an SPDX expression.
    pub license: Option<String>,
    /// License files shipped with the package, when fetched (names always, texts on request). Sorted by name.
    pub license_files: Vec<LicenseFile>,
    /// One-line summary of the package, when known.
    pub description: Option<String>,
    /// Project homepage, when known.
    pub homepage: Option<String>,
    /// Source repository URL, when known.
    pub repository: Option<String>,
    /// Documentation URL, when known.
    pub documentation: Option<String>,
    /// Set when the index says this release is yanked (PEP 592).
    pub yanked: Option<Yanked>,
    /// Extra facts that have no first-class field in the SBOM specs
    /// (channel, subdir, build string, ...). Keys are prefixed `pixi:`.
    pub properties: BTreeMap<String, String>,
    /// Ids of packages in the same [`Sbom`] this package depends on. Sorted, deduplicated.
    pub dependencies: Vec<String>,
}

impl Package {
    /// Sort key that keeps output deterministic.
    pub fn sort_key(&self) -> (PackageKind, &str, Option<&str>) {
        (self.kind, &self.name, self.version.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_records_each_step_once_and_names_them() {
        let mut incomplete = Incomplete::default();
        assert!(incomplete.is_empty());
        assert!(incomplete.step_names().is_empty());

        // A step that answered for everything records nothing.
        incomplete.note_failures("pypi-releases", 0, 38, "index lookups");
        assert!(incomplete.is_empty(), "nothing failed, so nothing is recorded");

        incomplete.note_failures("pypi-releases", 12, 38, "index lookups");
        incomplete.note("osv: 0 of 24 packages queryable (no purl the database answers to)");
        incomplete.note("osv: 3 advisory record(s) could not be fetched");
        // The same note twice is one note; two notes about one step are one name.
        incomplete.note("osv: 3 advisory record(s) could not be fetched");
        assert_eq!(incomplete.steps.len(), 3);
        assert_eq!(incomplete.step_names(), vec!["osv", "pypi-releases"]);
        assert_eq!(
            incomplete.steps[2], "pypi-releases: 12 of 38 index lookups failed",
            "sorted, and the detail says how much of the step failed"
        );
        assert!(!incomplete.is_empty());

        // A stale cache alone is enough to make a document incomplete.
        let stale = Incomplete {
            stale: vec!["kev: 9 days old".into()],
            ..Incomplete::default()
        };
        assert!(!stale.is_empty());
        assert!(stale.step_names().is_empty(), "nothing failed; data was only old");
    }

    #[test]
    fn author_parses_name_and_email() {
        let author = Author::parse("Ada Lovelace <ada@example.org>").unwrap();
        assert_eq!(author.name, "Ada Lovelace");
        assert_eq!(author.email.as_deref(), Some("ada@example.org"));
    }

    #[test]
    fn author_without_email_or_with_only_email() {
        assert_eq!(
            Author::parse("  Ada Lovelace  ").unwrap(),
            Author {
                name: "Ada Lovelace".into(),
                email: None
            }
        );
        assert_eq!(
            Author::parse("<ada@example.org>").unwrap(),
            Author {
                name: "ada@example.org".into(),
                email: Some("ada@example.org".into())
            }
        );
        assert_eq!(
            Author::parse("Ada <>").unwrap(),
            Author {
                name: "Ada".into(),
                email: None
            }
        );
        assert_eq!(
            Author::parse("Ada < not an address").unwrap().name,
            "Ada < not an address"
        );
        assert_eq!(Author::parse("   "), None);
    }
}
