//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use clap_verbosity_flag::{InfoLevel, Verbosity};

/// SBOM output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// CycloneDX 1.6 or 1.7 (JSON), see --spec-version
    Cyclonedx,
    /// SPDX 2.3 or 3.0 (JSON), see --spec-version
    Spdx,
}

impl Format {
    /// File extension for this format, including the leading dot.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Cyclonedx => ".cdx.json",
            Format::Spdx => ".spdx.json",
        }
    }

    /// Default file name used when `--output` is not given.
    pub fn default_file_name(self) -> String {
        format!("sbom{}", self.extension())
    }

    /// File name for one document of a batch (`--all-environments` / `--all-platforms`):
    /// `sbom-<label>-<label>...` with the given labels.
    pub fn batch_file_name<'a>(self, labels: impl IntoIterator<Item = &'a str>) -> String {
        let mut name = String::from("sbom");
        for label in labels {
            name.push('-');
            name.push_str(label);
        }
        name.push_str(self.extension());
        name
    }
}

/// Specification version to write: `1.6` / `1.7` for CycloneDX, `2.3` / `3.0` for SPDX.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum SpecVersion {
    /// CycloneDX 1.6
    #[default]
    #[value(name = "1.6")]
    V1_6,
    /// CycloneDX 1.7 (ECMA-424 2nd edition); adds a citation attributing the inventory to its source
    #[value(name = "1.7")]
    V1_7,
    /// SPDX 2.3 (tag-value-style JSON)
    #[value(name = "2.3")]
    V2_3,
    /// SPDX 3.0.1 (JSON-LD graph)
    #[value(name = "3.0")]
    V3_0,
}

impl SpecVersion {
    /// The version written when `--spec-version` is not given.
    pub fn default_for(format: Format) -> Self {
        match format {
            Format::Cyclonedx => SpecVersion::V1_6,
            Format::Spdx => SpecVersion::V2_3,
        }
    }

    /// Whether this version belongs to `format`.
    pub fn applies_to(self, format: Format) -> bool {
        matches!(
            (format, self),
            (Format::Cyclonedx, SpecVersion::V1_6 | SpecVersion::V1_7)
                | (Format::Spdx, SpecVersion::V2_3 | SpecVersion::V3_0)
        )
    }
}

/// Where PyPI identities for conda packages come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PypiMappingSource {
    /// Only the purls recorded in the lockfile (no network).
    Lock,
    /// Also the conda-forge mapping from conda-mapping.prefix.dev, cached for a day.
    Prefix,
}

/// Which purl is the primary identity of a conda package that also has a PyPI one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PrimaryPurl {
    /// `pkg:conda/...` is the purl; the PyPI purl is an extra reference.
    Conda,
    /// `pkg:pypi/...` is the purl so vulnerability scanners can match it; the conda purl is an extra reference.
    Pypi,
}

/// How far behind a package must be to appear in `--report outdated`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutdatedOnly {
    /// Any package behind its index.
    Patch,
    /// A minor or major step behind.
    Minor,
    /// A major step behind.
    Major,
}

/// What `--refresh` may be pointed at: one cache, or all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RefreshTarget {
    /// Every cache.
    All,
    Mapping,
    Osv,
    Kev,
    Wheels,
    Pypi,
    Outdated,
    Scorecard,
}

impl RefreshTarget {
    /// The cache it names, or `None` for `all`.
    pub fn service(self) -> Option<crate::cache::Service> {
        Some(match self {
            RefreshTarget::All => return None,
            RefreshTarget::Mapping => crate::cache::Service::Mapping,
            RefreshTarget::Osv => crate::cache::Service::Osv,
            RefreshTarget::Kev => crate::cache::Service::Kev,
            RefreshTarget::Wheels => crate::cache::Service::Wheels,
            RefreshTarget::Pypi => crate::cache::Service::Pypi,
            RefreshTarget::Outdated => crate::cache::Service::Outdated,
            RefreshTarget::Scorecard => crate::cache::Service::Scorecard,
        })
    }
}

/// How the licenses report is grouped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GroupBy {
    /// One section per license expression, listing the packages under it.
    License,
}

/// The environment variable that selects the log format, for a CI job that cannot change the
/// command line.
pub const LOG_FORMAT_ENV: &str = "PIXI_SBOM_LOG_FORMAT";

/// How the log on stderr is rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum LogFormat {
    /// One line per event, written for a person.
    #[default]
    Text,
    /// One JSON object per event, with the timestamp and every field kept separate.
    Json,
}

impl LogFormat {
    /// The flag, else `PIXI_SBOM_LOG_FORMAT`, else text. A value that is neither is returned
    /// alongside, to be complained about once the subscriber exists: the log is the
    /// diagnostic channel, and refusing to run because its format was misspelled would take
    /// the diagnosis away at the moment it is needed.
    pub fn resolve(flag: Option<LogFormat>, env: Option<&str>) -> (Self, Option<String>) {
        if let Some(format) = flag {
            return (format, None);
        }
        match env.map(str::trim).filter(|value| !value.is_empty()) {
            None => (LogFormat::Text, None),
            Some(value) => match value.to_ascii_lowercase().as_str() {
                "text" => (LogFormat::Text, None),
                "json" => (LogFormat::Json, None),
                _ => (LogFormat::Text, Some(value.to_string())),
            },
        }
    }
}

/// What a VEX says about a finding nobody has assessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum VexOpenState {
    /// Somebody still has to look at it.
    #[default]
    InTriage,
    /// The product is affected and the finding is actionable.
    Exploitable,
}

impl VexOpenState {
    /// The CycloneDX impact-analysis state.
    pub fn state(self) -> &'static str {
        match self {
            VexOpenState::InTriage => "in_triage",
            VexOpenState::Exploitable => "exploitable",
        }
    }
}

/// A section of the diff report `--fail-on-diff` can gate on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DiffSection {
    /// Any of the four below.
    Any,
    /// Packages the previous document does not have.
    Added,
    /// Packages the previous document has and this one does not.
    Removed,
    /// Same package, different version.
    Version,
    /// Same package and version, different license.
    License,
    /// Same package and version, different conda build string.
    Build,
    /// Installed by pip into the environment and not in the other side.
    Pip,
}

/// A package kind, as `--exclude-kind` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Kind {
    /// A prebuilt `.conda` / `.tar.bz2` archive from a channel.
    Conda,
    /// A pixi-build source package.
    CondaSource,
    /// A PyPI wheel or sdist.
    Pypi,
    /// A component declared by an SBOM embedded in a wheel.
    Embedded,
    /// A package from an existing document that is neither conda nor PyPI (`--from-sbom`).
    External,
}

impl Kind {
    /// The model kind.
    pub fn package_kind(self) -> crate::model::PackageKind {
        match self {
            Kind::Conda => crate::model::PackageKind::CondaBinary,
            Kind::CondaSource => crate::model::PackageKind::CondaSource,
            Kind::Pypi => crate::model::PackageKind::Pypi,
            Kind::Embedded => crate::model::PackageKind::Embedded,
            Kind::External => crate::model::PackageKind::External,
        }
    }
}

/// Where known vulnerabilities are looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum VulnerabilitySource {
    /// The Open Source Vulnerabilities database (osv.dev): PyPI, crates.io, npm and other
    /// ecosystems it indexes; conda packages match through their PyPI purl.
    Osv,
}

/// The lowest severity that fails the run with `--fail-on-severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOnSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl FailOnSeverity {
    /// The model severity this threshold stands for.
    pub fn severity(self) -> crate::model::Severity {
        match self {
            FailOnSeverity::Low => crate::model::Severity::Low,
            FailOnSeverity::Medium => crate::model::Severity::Medium,
            FailOnSeverity::High => crate::model::Severity::High,
            FailOnSeverity::Critical => crate::model::Severity::Critical,
        }
    }
}

/// Generate a Software Bill of Materials from a pixi.lock file.
#[derive(Debug, Parser)]
#[command(
    name = "pixi-sbom",
    bin_name = "pixi sbom",
    version,
    about,
    long_about = None,
    after_help = "Documentation: https://millsks.github.io/pixi-sbom/",
    // --report-format renders whichever of the two prints to the terminal, so it requires the
    // group rather than either flag on its own.
    group = clap::ArgGroup::new("reporting").multiple(true).args(["report", "explain"]),
)]
pub struct Args {
    /// Path to the pixi.lock file. Defaults to searching from the current directory upward.
    #[arg(long, value_name = "PATH", conflicts_with = "prefix")]
    pub lockfile: Option<PathBuf>,

    /// Read an existing SBOM instead of a lockfile (CycloneDX 1.4-1.7, SPDX 2.x or SPDX 3.0
    /// JSON) and run the reports, the license policy and the vulnerability gate on it.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["lockfile", "prefix", "scan"])]
    pub from_sbom: Option<PathBuf>,

    /// Describe every pixi workspace under this directory: one document per `pixi.lock`
    /// found, in sorted order. Hidden directories, node_modules, target, build, dist, venv and
    /// __pycache__ are never entered and symlinked directories are not followed. With
    /// --output the documents land under it, mirroring each workspace's path.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["lockfile", "prefix"])]
    pub scan: Option<PathBuf>,

    /// With --scan: how far below the directory to walk (0 is the directory itself).
    #[arg(long, value_name = "N", requires = "scan")]
    pub scan_depth: Option<usize>,

    /// Describe an installed environment instead of a lockfile: a `pixi global` environment
    /// (~/.pixi/envs/<name>), a conda / mamba environment, or one inside a container. Conda
    /// packages come from its conda-meta records, pip-installed ones from site-packages.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["environment", "all_environments", "all_platforms"])]
    pub prefix: Option<PathBuf>,

    /// With --prefix: the name recorded for the described application (default: the
    /// environment directory's name).
    #[arg(long, value_name = "NAME", requires = "prefix")]
    pub name: Option<String>,

    /// With --prefix: the version recorded for the described application.
    #[arg(long, value_name = "VERSION", requires = "prefix")]
    pub root_version: Option<String>,

    /// Configuration file to read before the command line (the command line wins). Defaults to
    /// `[tool.pixi-sbom]` in the pyproject.toml next to the lockfile, else pixi-sbom.toml there.
    #[arg(long, value_name = "PATH", conflicts_with = "no_config")]
    pub config: Option<PathBuf>,

    /// Ignore any configuration file.
    #[arg(long)]
    pub no_config: bool,

    /// SBOM format to generate.
    #[arg(long, value_enum, default_value_t = Format::Cyclonedx)]
    pub format: Format,

    /// Specification version to write: 1.6 (default) or 1.7 for CycloneDX, 2.3 (default) or
    /// 3.0 for SPDX.
    #[arg(long, value_enum, value_name = "VERSION")]
    pub spec_version: Option<SpecVersion>,

    /// Where to write the SBOM. Defaults to the lockfile's directory; `-` writes to stdout.
    /// With --all-environments / --all-platforms this is a directory that receives one
    /// sbom-<environment>, sbom-<platform> or sbom-<environment>-<platform> file per document.
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Lock environment to describe.
    #[arg(short, long, default_value = "default", conflicts_with = "all_environments")]
    pub environment: String,

    /// Generate one SBOM per environment in the lockfile instead of a single environment.
    #[arg(long)]
    pub all_environments: bool,

    /// Platform within the environment (e.g. linux-64). Defaults to the current platform.
    #[arg(short, long, value_name = "PLATFORM", conflicts_with = "all_platforms")]
    pub platform: Option<String>,

    /// Generate one SBOM per platform the environment is locked for instead of a single platform.
    #[arg(long)]
    pub all_platforms: bool,

    /// Where to get PyPI identities for conda packages. `prefix` downloads the conda-forge
    /// mapping (same source pixi uses) so scanners can match conda-installed Python packages.
    #[arg(long, value_enum, default_value_t = PypiMappingSource::Lock, conflicts_with = "pypi_mapping_file")]
    pub pypi_mapping: PypiMappingSource,

    /// Offline copy of the conda-forge PyPI mapping (JSON object of conda name to PyPI name).
    #[arg(long, value_name = "PATH")]
    pub pypi_mapping_file: Option<PathBuf>,

    /// Which purl to use as a conda package's primary identity when it also has a PyPI one.
    #[arg(long, value_enum, default_value_t = PrimaryPurl::Conda)]
    pub primary_purl: PrimaryPurl,

    /// Fetch the license of every package, conda and PyPI alike, where the lockfile has none,
    /// plus the names of the license files it ships. Sources are the local package cache
    /// first, then the package index. Failures are logged and the run continues.
    #[arg(long)]
    pub fetch_licenses: bool,

    /// With --fetch-licenses, also embed the full text of every license file.
    #[arg(long)]
    pub license_texts: bool,

    /// Add the components declared by SBOMs embedded in wheels (PEP 770, e.g. the Rust crates
    /// maturin compiled in) as dependencies of the wheel. Reads each wheel's dist-info like
    /// --fetch-licenses does.
    #[arg(long)]
    pub embedded_sboms: bool,

    /// Deprecated alias for --fetch-licenses (it used to cover PyPI packages only).
    #[arg(long, hide = true)]
    pub pypi_licenses: bool,

    /// Leave packages whose name matches this shell-style pattern out of the document
    /// (repeatable; `*` and `?`, case-insensitive, `-` and `_` alike). What only they needed
    /// is dropped too, and the root records the omission in `pixi:excluded`.
    #[arg(long, value_name = "GLOB")]
    pub exclude: Vec<String>,

    /// Keep only packages whose name matches one of these patterns (repeatable).
    #[arg(long, value_name = "GLOB")]
    pub include: Vec<String>,

    /// Leave every package of this kind out (repeatable).
    #[arg(long, value_enum, value_name = "KIND")]
    pub exclude_kind: Vec<Kind>,

    /// With --exclude / --include: keep the packages that only excluded packages needed.
    #[arg(long)]
    pub keep_orphans: bool,

    /// Only these SPDX licenses (repeatable) are acceptable; a package whose license expression
    /// cannot be satisfied with them alone is a violation. An `-or-later` requirement is
    /// satisfied by any allowed later version of the same license family.
    #[arg(long, value_name = "LICENSE")]
    pub allow_license: Vec<String>,

    /// These SPDX licenses (repeatable) are unacceptable; a package whose license expression
    /// cannot be satisfied without them is a violation. `MIT OR GPL-3.0-only` passes a policy
    /// that denies GPL-3.0-only because MIT is an option.
    #[arg(long, value_name = "LICENSE")]
    pub deny_license: Vec<String>,

    /// The license policy does not apply to these packages (repeatable): a name or a
    /// shell-style pattern as in --exclude, optionally followed by `:justification`. The
    /// package is listed as exempt in the report and carries `pixi:license-exempt` in the
    /// document.
    #[arg(long, value_name = "PACKAGE[:WHY]")]
    pub ignore_license: Vec<String>,

    /// Every package must declare a license that is an SPDX expression.
    #[arg(long)]
    pub require_license: bool,

    /// Ask the OpenSSF Scorecard service how each package's repository is maintained, and
    /// record the score and the checks below --scorecard-min in the document. Needs
    /// --fetch-licenses, which is what collects the repository URLs. Cached for a week.
    #[arg(long)]
    pub scorecard: bool,

    /// With --scorecard: the score a package (or one of its checks) has to reach to be left
    /// alone in the report and the document.
    #[arg(long, value_name = "N", default_value_t = 5.0, requires = "scorecard")]
    pub scorecard_min: f64,

    /// Exit with code 9 after writing the document when a scored package is below this.
    /// Packages the service has never scored never fail the gate.
    #[arg(long, value_name = "N", requires = "scorecard")]
    pub fail_on_scorecard: Option<f64>,

    /// Exit with code 7 after writing the document when any package is a yanked release
    /// (PEP 592). Requires --fetch-licenses, which is what asks the index.
    #[arg(long)]
    pub fail_on_yanked: bool,

    /// Look up known vulnerabilities of every package with a queryable purl and record them
    /// in the document (CycloneDX `vulnerabilities`). Conda packages are matched through their
    /// PyPI purl, so combine with --pypi-mapping prefix. Results are cached for an hour.
    #[arg(long, value_enum, value_name = "SOURCE")]
    pub vulnerabilities: Option<VulnerabilitySource>,

    /// Mark findings that are in CISA's Known Exploited Vulnerabilities catalog (matched by CVE
    /// alias): rated critical, with the catalog's dates and required action recorded. The
    /// catalog is downloaded once a day. Requires --vulnerabilities.
    #[arg(long)]
    pub kev: bool,

    /// Exit with code 4 after writing the document when any open finding is in the KEV
    /// catalog. Requires --kev.
    #[arg(long)]
    pub fail_on_kev: bool,

    /// Exit with code 4 after writing the document when any finding at or above this severity
    /// remains (findings of unknown severity never trip it). Requires --vulnerabilities.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    pub fail_on_severity: Option<FailOnSeverity>,

    /// Accept a finding deliberately (repeatable): `ID`, `ID:justification` or
    /// `ID:state:justification`, where ID is an advisory id or alias (GHSA, CVE, ...) and state
    /// a CycloneDX analysis state (default `not_affected`). The finding stays in the document
    /// with an `analysis` block, is excluded from --fail-on-severity and listed separately in
    /// the report. Requires --vulnerabilities.
    #[arg(long, value_name = "ID[:STATE][:TEXT]")]
    pub ignore_vuln: Vec<String>,

    /// Also write a standalone CycloneDX VEX document here: every finding with its analysis,
    /// linked back to the SBOM this run writes. Needs --vulnerabilities, and a single
    /// document.
    #[arg(long, value_name = "PATH")]
    pub vex: Option<PathBuf>,

    /// The analysis state a VEX gives findings nobody has assessed with --ignore-vuln.
    #[arg(long, value_enum, value_name = "STATE", default_value_t = VexOpenState::InTriage, requires = "vex")]
    pub vex_open: VexOpenState,

    /// Print the version with the build and machine details a bug report needs: the target,
    /// the optional features compiled in, the cache directory, pixi's version, and the proxy
    /// and TLS settings in effect.
    #[arg(long = "version-details", visible_alias = "build-info")]
    pub version_details: bool,

    /// Print a table at the end of the run showing where the time went, phase by phase, with
    /// how much of it was spent waiting on the network.
    #[arg(long)]
    pub timings: bool,

    /// Ask every upstream this build knows about whether it answers, print how the run is set
    /// up and what the caches hold, and exit non-zero if anything is unreachable. Needs no
    /// lockfile. Combine with the flags of the run you are diagnosing to probe only those.
    #[arg(long, conflicts_with_all = ["output", "report", "explain"])]
    pub doctor: bool,

    /// Ignore cached answers for this run and ask again. Without a value every cache is
    /// refreshed; with one (repeatable) only that one is. What is fetched is still cached.
    #[arg(long, value_enum, value_name = "CACHE", num_args = 0.., default_missing_value = "all")]
    pub refresh: Vec<RefreshTarget>,

    /// Neither read nor write any cache, for a clean reproduction.
    #[arg(long, conflicts_with = "refresh")]
    pub no_cache: bool,

    /// Print a report to the terminal instead of writing an SBOM document: `packages` is the
    /// inventory, `licenses` the license view with a summary, `vulnerabilities` the findings
    /// of --vulnerabilities worst first, `diff` what changed since --against, `phantom` the
    /// imports and declarations that do not line up. Nothing is written to disk.
    #[arg(long, value_enum, value_name = "REPORT", conflicts_with_all = ["output", "spec_version"])]
    pub report: Option<crate::report::ReportKind>,

    /// Print every fact the tool has about the packages matching this name or shell-style
    /// pattern (repeatable, as in --exclude) and where each fact came from, including the
    /// sources that were consulted and came back empty. Nothing is written to disk.
    #[arg(long, value_name = "PACKAGE", conflicts_with_all = ["output", "spec_version", "report"])]
    pub explain: Vec<String>,

    /// How to render the report.
    #[arg(long, value_enum, default_value_t = crate::report::ReportFormat::Table, requires = "reporting")]
    pub report_format: crate::report::ReportFormat,

    /// When to colour the terminal report: `auto` follows the terminal, `NO_COLOR` and
    /// `CLICOLOR_FORCE`. Only the `table` format is ever coloured.
    #[arg(long, value_enum, value_name = "WHEN", default_value_t = crate::style::ColorChoice::Auto)]
    pub color: crate::style::ColorChoice,

    /// With --report packages: draw the dependency graph from the root downward instead of a
    /// flat list. A package is expanded once, at its first occurrence; later ones are marked
    /// `(*)`.
    #[arg(long)]
    pub tree: bool,

    /// With --tree: how deep to go (0 shows what the root depends on and nothing below).
    #[arg(long, value_name = "N", requires = "tree")]
    pub depth: Option<usize>,

    /// With --report licenses: one section per license instead of one row per package.
    #[arg(long, value_enum, value_name = "WHAT")]
    pub group_by: Option<GroupBy>,

    /// With --report outdated: list only packages at least this far behind.
    #[arg(long, value_enum, value_name = "STEP")]
    pub outdated_only: Option<OutdatedOnly>,

    /// With --report diff: exit with code 6 when the named sections of the comparison are not
    /// empty. Repeatable; the bare flag means any change at all.
    #[arg(long, value_enum, value_name = "SECTION", num_args = 0.., default_missing_value = "any")]
    pub fail_on_diff: Vec<DiffSection>,

    /// With --report phantom: where the workspace's Python sources are (repeatable). Defaults
    /// to the directory holding the lockfile.
    #[arg(long, value_name = "DIR")]
    pub source: Vec<PathBuf>,

    /// With --report phantom: packages matching these patterns (repeatable) are never
    /// reported as unused or undeclared. For the ones nothing imports by name: plugins
    /// (`pytest-*`), stub packages (`types-*`, `*-stubs`), tools run as commands.
    #[arg(long, value_name = "GLOB")]
    pub assume_used: Vec<String>,

    /// Exit with code 8 after the report when the workspace imports a package it never
    /// declared. Requires --report phantom.
    #[arg(long)]
    pub fail_on_phantom: bool,

    /// With --report diff: the previous document to compare against (CycloneDX, SPDX 2.3 or
    /// SPDX 3.0 JSON, as written by pixi-sbom or another tool).
    #[arg(long, value_name = "PATH", conflicts_with_all = ["all_environments", "all_platforms"])]
    pub against: Option<PathBuf>,

    /// Verify TLS against the certificates in this PEM file instead of the operating system's
    /// trust store — a TLS-intercepting appliance's CA, or a private one. Also
    /// PIXI_SBOM_CA_BUNDLE, and SSL_CERT_FILE when neither is given.
    #[arg(long, value_name = "FILE")]
    pub ca_bundle: Option<PathBuf>,

    /// How to render the log on stderr: `text` for a person, `json` for a log collector (one
    /// JSON object per event, with the timestamp back and every field its own key). Also
    /// PIXI_SBOM_LOG_FORMAT. Distinct from --report-format, which is the report on stdout;
    /// the two are meant to be used together.
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub log_format: Option<LogFormat>,

    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_format_is_the_flag_then_the_environment_then_text() {
        assert_eq!(LogFormat::resolve(None, None), (LogFormat::Text, None));
        assert_eq!(LogFormat::resolve(Some(LogFormat::Json), None).0, LogFormat::Json);
        // The flag wins over the environment, as every other setting does.
        assert_eq!(
            LogFormat::resolve(Some(LogFormat::Text), Some("json")).0,
            LogFormat::Text
        );
        assert_eq!(LogFormat::resolve(None, Some("json")).0, LogFormat::Json);
        assert_eq!(LogFormat::resolve(None, Some(" JSON ")).0, LogFormat::Json);
        assert_eq!(LogFormat::resolve(None, Some("")).0, LogFormat::Text);

        // A misspelling is named and the run logs as text: losing the log would take the
        // diagnosis away at the moment it is needed.
        let (format, unknown) = LogFormat::resolve(None, Some("jsonl"));
        assert_eq!(format, LogFormat::Text);
        assert_eq!(unknown.as_deref(), Some("jsonl"));
    }
}
