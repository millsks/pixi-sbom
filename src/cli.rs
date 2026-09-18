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
    /// Default file name used when `--output` is not given.
    pub fn default_file_name(self) -> &'static str {
        match self {
            Format::Cyclonedx => "sbom.cdx.json",
            Format::Spdx => "sbom.spdx.json",
        }
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

    /// Where to write the SBOM. Defaults to the lockfile's directory.
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Lock environment to describe.
    #[arg(short, long, default_value = "default")]
    pub environment: String,

    /// Platform within the environment (e.g. linux-64). Defaults to the current platform.
    #[arg(short, long, value_name = "PLATFORM")]
    pub platform: Option<String>,

    #[command(flatten)]
    pub verbosity: Verbosity<InfoLevel>,
}
