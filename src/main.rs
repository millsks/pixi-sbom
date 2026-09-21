//! `pixi-sbom`: a pixi extension that generates CycloneDX or SPDX SBOMs from `pixi.lock`.

mod cli;
mod condaarchive;
mod discover;
mod embedded;
mod format;
mod http;
mod license;
mod lock;
mod manifest;
mod mapping;
mod model;
mod parallel;
mod pkgcache;
mod policy;
mod purl;
mod pypi;
mod report;
mod wheel;
mod zipread;

use std::io::{IsTerminal, Write};
use std::path::Path;

use clap::{CommandFactory, Parser};
use miette::{Context, IntoDiagnostic, Result};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let args = cli::Args::parse();
    init_tracing(&args);
    init_error_reporting()?;
    tracing::debug!(?args, "parsed arguments");

    let cwd = std::env::current_dir().into_diagnostic()?;
    let lockfile = discover::resolve_lockfile(args.lockfile.as_deref(), &cwd)?;
    let lock::LoadedLock { lock, contents } = lock::load(&lockfile)?;
    let root = manifest::root_for_lockfile(&lockfile);

    let spec_version = resolve_spec_version(&args);
    let fetch_licenses = args.fetch_licenses || args.pypi_licenses;
    if args.pypi_licenses {
        tracing::warn!("--pypi-licenses is deprecated and now behaves as --fetch-licenses; use that instead");
    }
    if args.license_texts && !fetch_licenses {
        cli::Args::command()
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "'--license-texts' only applies together with '--fetch-licenses'",
            )
            .exit();
    }
    let targets = resolve_targets(&args, &lock, &lockfile)?;
    let pypi_mapping = load_pypi_mapping(&args)?;
    tracing::debug!(lockfile = %lockfile.display(), ?targets, format = ?args.format, "resolved targets");
    let mut reports = Vec::new();
    let policy =
        policy::Policy::new(&args.allow_license, &args.deny_license, args.require_license).unwrap_or_else(|err| {
            cli::Args::command()
                .error(clap::error::ErrorKind::InvalidValue, err.to_string())
                .exit()
        });
    let mut violations: Vec<(String, String, policy::Violation)> = Vec::new();

    for Target {
        environment,
        platform,
        output,
    } in &targets
    {
        let selection = lock::Selection {
            environment,
            platform: platform.as_deref(),
        };
        let mut sbom = lock::sbom_from_lock(&lock, selection, root.clone(), &discover::lockfile_name(&lockfile))?;
        if let Some(mapping) = &pypi_mapping {
            let enriched = mapping::enrich(&mut sbom, mapping);
            tracing::info!(enriched, "added PyPI purls to conda packages");
        }
        if args.primary_purl == cli::PrimaryPurl::Pypi {
            let switched = mapping::prefer_pypi_purl(&mut sbom);
            tracing::info!(switched, "made PyPI purls primary");
        }
        if fetch_licenses || args.embedded_sboms {
            let pkgs = pkgcache::package_cache_dir();
            let cache_dir = mapping::cache_dir();
            let wheel::Outcome {
                fetched,
                failed,
                skipped,
            } = wheel::enrich(&mut sbom, &cache_dir, args.license_texts);
            tracing::info!(fetched, failed, skipped, "read PyPI license details from wheels");
            if args.embedded_sboms {
                let embedded::Outcome {
                    files,
                    unreadable,
                    added,
                    merged,
                } = embedded::enrich(&mut sbom, &cache_dir);
                tracing::info!(files, unreadable, added, merged, "attached embedded SBOM components");
            }
            let pkgcache::Outcome {
                found,
                licenses_filled,
                files,
                missing,
            } = if fetch_licenses {
                pkgcache::enrich(&mut sbom, &pkgs, args.license_texts)
            } else {
                pkgcache::Outcome::default()
            };
            if fetch_licenses {
                tracing::info!(pkgs = %pkgs.display(), found, licenses_filled, files, "read conda license details from the package cache");
            }
            if !missing.is_empty() {
                let condaarchive::Outcome {
                    fetched,
                    failed,
                    skipped,
                } = condaarchive::enrich(&mut sbom, &missing, &cache_dir, args.license_texts);
                tracing::info!(
                    fetched,
                    failed,
                    skipped,
                    "read conda license details from channel archives"
                );
            }
            if fetch_licenses {
                let lookup = pypi::Lookup {
                    index_url: &pypi::index_url(),
                    cache_dir: &cache_dir,
                };
                let pypi::Outcome { found, missing, failed } = lookup.run(&mut sbom);
                tracing::info!(found, missing, failed, "looked up PyPI licenses");
            }
        }
        if let Some(policy) = &policy {
            let found = policy.check(&sbom);
            tracing::info!(violations = found.len(), "checked the license policy");
            violations.extend(
                found
                    .into_iter()
                    .map(|v| (sbom.environment.clone(), sbom.platform.clone(), v)),
            );
        }
        if let Some(kind) = args.report {
            reports.push(report::Report::new(kind, &sbom));
            continue;
        }
        let ctx = format::WriteContext::for_document(&contents, &sbom, args.format, spec_version);
        write_output(output, args.format, &sbom, &ctx)?;
        tracing::info!(
            output = %output,
            format = ?args.format,
            packages = sbom.packages.len(),
            environment = %sbom.environment,
            platform = %sbom.platform,
            "wrote SBOM"
        );
    }
    if !reports.is_empty() {
        let mut stdout = std::io::stdout().lock();
        report::render(&reports, args.report_format, &mut stdout)
            .and_then(|()| stdout.flush())
            .into_diagnostic()
            .wrap_err("cannot write the report to stdout")?;
    }
    if !violations.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "License policy violated by {} package(s):", violations.len());
        for (environment, platform, violation) in &violations {
            let _ = if targets.len() > 1 {
                writeln!(stderr, "  [{environment}/{platform}] {violation}")
            } else {
                writeln!(stderr, "  {violation}")
            };
        }
        let _ = stderr.flush();
        std::process::exit(policy::VIOLATION_EXIT_CODE);
    }
    Ok(())
}

/// The specification version to write: the format's default unless `--spec-version` names a
/// version of that format; naming another format's version is a usage error.
fn resolve_spec_version(args: &cli::Args) -> cli::SpecVersion {
    match args.spec_version {
        None => cli::SpecVersion::default_for(args.format),
        Some(version) if version.applies_to(args.format) => version,
        Some(version) => {
            let version_name = clap::ValueEnum::to_possible_value(&version)
                .map(|p| p.get_name().to_string())
                .unwrap_or_default();
            let format_name = clap::ValueEnum::to_possible_value(&args.format)
                .map(|p| p.get_name().to_string())
                .unwrap_or_default();
            cli::Args::command()
                .error(
                    clap::error::ErrorKind::ArgumentConflict,
                    format!("'--spec-version {version_name}' is not a version of '--format {format_name}'"),
                )
                .exit()
        }
    }
}

/// Load the PyPI mapping the flags ask for; `None` means only the lockfile's own purls.
fn load_pypi_mapping(args: &cli::Args) -> Result<Option<mapping::PypiMapping>> {
    let mapping = match (&args.pypi_mapping_file, args.pypi_mapping) {
        (Some(path), _) => mapping::PypiMapping::from_file(path)?,
        (None, cli::PypiMappingSource::Prefix) => mapping::PypiMapping::fetch(&mapping::cache_dir())?,
        (None, cli::PypiMappingSource::Lock) => return Ok(None),
    };
    tracing::debug!(entries = mapping.len(), "loaded PyPI mapping");
    Ok(Some(mapping))
}

/// One document to write: an environment, a platform (`None` = host), and where it goes.
#[derive(Debug)]
struct Target {
    environment: String,
    platform: Option<String>,
    output: discover::Output,
}

/// Expand `--all-environments` / `--all-platforms` into the list of documents to write, and
/// decide each one's output location.
fn resolve_targets(args: &cli::Args, lock: &rattler_lock::LockFile, lockfile: &Path) -> Result<Vec<Target>> {
    let batch = args.all_environments || args.all_platforms;
    if batch && discover::is_stdout(args.output.as_deref()) {
        let flag = if args.all_environments {
            "--all-environments"
        } else {
            "--all-platforms"
        };
        cli::Args::command()
            .error(
                clap::error::ErrorKind::ArgumentConflict,
                format!("'--output -' writes one document to stdout and cannot be combined with '{flag}'"),
            )
            .exit();
    }

    let environments = if args.all_environments {
        lock::environment_names(lock)
    } else {
        vec![args.environment.clone()]
    };
    let mut targets = Vec::new();
    for environment in environments {
        let platforms: Vec<Option<String>> = if args.all_platforms {
            lock::platform_names(lock, &environment)?
                .into_iter()
                .map(Some)
                .collect()
        } else {
            vec![args.platform.clone()]
        };
        for platform in platforms {
            let output = if batch {
                let labels = args
                    .all_environments
                    .then_some(environment.as_str())
                    .into_iter()
                    .chain(platform.as_deref().filter(|_| args.all_platforms));
                discover::Output::File(discover::resolve_batch_output(
                    args.output.as_deref(),
                    lockfile,
                    args.format,
                    labels,
                ))
            } else {
                discover::resolve_output(args.output.as_deref(), lockfile, args.format)
            };
            targets.push(Target {
                environment: environment.clone(),
                platform,
                output,
            });
        }
    }
    Ok(targets)
}

fn write_output(
    output: &discover::Output,
    format: cli::Format,
    sbom: &model::Sbom,
    ctx: &format::WriteContext,
) -> Result<()> {
    let output = match output {
        discover::Output::Stdout => {
            let mut stdout = std::io::stdout().lock();
            format::write(format, sbom, ctx, &mut stdout)?;
            stdout.flush().into_diagnostic().wrap_err("cannot write to stdout")?;
            return Ok(());
        }
        discover::Output::File(path) => path,
    };
    if let Some(parent) = output.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot create output directory {}", parent.display()))?;
    }
    let file = std::fs::File::create(output)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot create {}", output.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    format::write(format, sbom, ctx, &mut writer)?;
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
