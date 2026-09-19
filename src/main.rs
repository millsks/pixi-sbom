//! `pixi-sbom`: a pixi extension that generates CycloneDX or SPDX SBOMs from `pixi.lock`.

mod cli;
mod discover;
mod format;
mod license;
mod lock;
mod manifest;
mod model;
mod purl;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use clap::Parser;
use miette::{Context, IntoDiagnostic, Result};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let args = cli::Args::parse();
    init_tracing(&args);
    init_error_reporting()?;
    tracing::debug!(?args, "parsed arguments");

    let cwd = std::env::current_dir().into_diagnostic()?;
    let lockfile = discover::resolve_lockfile(args.lockfile.as_deref(), &cwd)?;
    let lock = lock::load(&lockfile)?;
    let root = manifest::root_for_lockfile(&lockfile);

    let targets: Vec<(String, PathBuf)> = if args.all_environments {
        lock::environment_names(&lock)
            .into_iter()
            .map(|env| {
                let output = discover::resolve_environment_output(args.output.as_deref(), &lockfile, args.format, &env);
                (env, output)
            })
            .collect()
    } else {
        let output = discover::resolve_output(args.output.as_deref(), &lockfile, args.format);
        vec![(args.environment.clone(), output)]
    };
    tracing::debug!(lockfile = %lockfile.display(), ?targets, format = ?args.format, "resolved targets");

    for (environment, output) in &targets {
        let selection = lock::Selection {
            environment,
            platform: args.platform.as_deref(),
        };
        let sbom = lock::sbom_from_lock(&lock, selection, root.clone(), &discover::lockfile_name(&lockfile))?;
        write_output(output, args.format, &sbom)?;
        tracing::info!(
            output = %output.display(),
            format = ?args.format,
            packages = sbom.packages.len(),
            environment = %sbom.environment,
            platform = %sbom.platform,
            "wrote SBOM"
        );
    }
    Ok(())
}

fn write_output(output: &Path, format: cli::Format, sbom: &model::Sbom) -> Result<()> {
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot create output directory {}", parent.display()))?;
    }
    let file = std::fs::File::create(output)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot create {}", output.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    format::write(format, sbom, &format::WriteContext::new(), &mut writer)?;
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
