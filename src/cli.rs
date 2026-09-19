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

    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,
}
