//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use clap_verbosity_flag::{InfoLevel, Verbosity};

/// SBOM output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// CycloneDX 1.6 (JSON)
    Cyclonedx,
    /// SPDX 2.3 (JSON)
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

/// Generate a Software Bill of Materials from a pixi.lock file.
#[derive(Debug, Parser)]
#[command(name = "pixi-sbom", bin_name = "pixi sbom", version, about, long_about = None)]
pub struct Args {
    /// Path to the pixi.lock file. Defaults to searching from the current directory upward.
    #[arg(long, value_name = "PATH")]
    pub lockfile: Option<PathBuf>,

    /// SBOM format to generate.
    #[arg(long, value_enum, default_value_t = Format::Cyclonedx)]
    pub format: Format,

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

    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,
}
