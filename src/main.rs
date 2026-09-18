//! `pixi-sbom`: a pixi extension that generates CycloneDX or SPDX SBOMs from `pixi.lock`.

mod cli;
mod discover;
mod lock;
mod manifest;
mod model;
mod purl;

use std::io::IsTerminal;

use clap::Parser;
use miette::{IntoDiagnostic, Result};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let args = cli::Args::parse();
    init_tracing(&args);
    init_error_reporting()?;
    tracing::debug!(?args, "parsed arguments");

    let cwd = std::env::current_dir().into_diagnostic()?;
    let lockfile = discover::resolve_lockfile(args.lockfile.as_deref(), &cwd)?;
    let output = discover::resolve_output(args.output.as_deref(), &lockfile, args.format);
    tracing::info!(lockfile = %lockfile.display(), output = %output.display(), format = ?args.format, "resolved paths");

    let root = manifest::root_for_lockfile(&lockfile);
    let selection = lock::Selection {
        environment: &args.environment,
        platform: args.platform.as_deref(),
    };
    let sbom = lock::build_sbom(&lockfile, selection, root)?;
    tracing::info!(packages = sbom.packages.len(), root = %sbom.root.name, "built sbom model");
    Ok(())
}

fn init_error_reporting() -> Result<()> {
    miette::set_hook(Box::new(|_| {
        Box::new(miette::MietteHandlerOpts::new().wrap_lines(false).build())
    }))
    .into_diagnostic()
}

fn init_tracing(args: &cli::Args) {
    let filter = EnvFilter::builder()
        .with_default_directive(args.verbosity.tracing_level_filter().into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .without_time()
        .init();
}
