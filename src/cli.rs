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
}

impl Kind {
    /// The model kind.
    pub fn package_kind(self) -> crate::model::PackageKind {
        match self {
            Kind::Conda => crate::model::PackageKind::CondaBinary,
            Kind::CondaSource => crate::model::PackageKind::CondaSource,
            Kind::Pypi => crate::model::PackageKind::Pypi,
            Kind::Embedded => crate::model::PackageKind::Embedded,
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
    after_help = "Documentation: https://millsks.github.io/pixi-sbom/"
)]
pub struct Args {
    /// Path to the pixi.lock file. Defaults to searching from the current directory upward.
    #[arg(long, value_name = "PATH", conflicts_with = "prefix")]
    pub lockfile: Option<PathBuf>,

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

    /// Every package must declare a license that is an SPDX expression.
    #[arg(long)]
    pub require_license: bool,

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

    /// Print a report to the terminal instead of writing an SBOM document: `packages` is the
    /// inventory, `licenses` the license view with a summary, `vulnerabilities` the findings
    /// of --vulnerabilities worst first, `diff` what changed since --against. Nothing is
    /// written to disk.
    #[arg(long, value_enum, value_name = "REPORT", conflicts_with_all = ["output", "spec_version"])]
    pub report: Option<crate::report::ReportKind>,

    /// How to render the report.
    #[arg(long, value_enum, default_value_t = crate::report::ReportFormat::Table, requires = "report")]
    pub report_format: crate::report::ReportFormat,

    /// With --report diff: the previous document to compare against (CycloneDX, SPDX 2.3 or
    /// SPDX 3.0 JSON, as written by pixi-sbom or another tool).
    #[arg(long, value_name = "PATH", conflicts_with_all = ["all_environments", "all_platforms"])]
    pub against: Option<PathBuf>,

    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,
}
