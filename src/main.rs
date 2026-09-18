//! `pixi-sbom`: a pixi extension that generates CycloneDX or SPDX SBOMs from `pixi.lock`.

mod cli;
mod discover;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let args = cli::Args::parse();
    init_tracing(&args);
    tracing::debug!(?args, "parsed arguments");

    let cwd = std::env::current_dir().into_diagnostic()?;
    let lockfile = discover::resolve_lockfile(args.lockfile.as_deref(), &cwd)?;
    let output = discover::resolve_output(args.output.as_deref(), &lockfile, args.format);
    tracing::info!(lockfile = %lockfile.display(), output = %output.display(), format = ?args.format, "resolved paths");
    Ok(())
}

fn init_tracing(args: &cli::Args) {
    let filter = EnvFilter::builder()
        .with_default_directive(args.verbosity.tracing_level_filter().into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .without_time()
        .init();
}
