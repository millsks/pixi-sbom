//! `pixi-sbom`: a pixi extension that generates CycloneDX or SPDX SBOMs from `pixi.lock`.

mod cli;
mod condaarchive;
mod config;
mod cvss;
mod diff;
mod discover;
mod embedded;
mod filter;
mod format;
mod http;
mod kev;
mod license;
mod lock;
mod manifest;
mod mapping;
mod model;
mod osv;
mod parallel;
mod pkgcache;
mod policy;
mod prefix;
mod purl;
mod pypi;
mod report;
mod style;
mod vulnpolicy;
mod wheel;
mod zipread;

use std::io::{IsTerminal, Write};
use std::path::Path;

use clap::{CommandFactory, FromArgMatches};
use miette::{Context, IntoDiagnostic, Result};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let matches = cli::Args::command().get_matches();
    let mut args = cli::Args::from_arg_matches(&matches).into_diagnostic()?;
    init_tracing(&args);
    init_error_reporting()?;

    let cwd = std::env::current_dir().into_diagnostic()?;
    // With --prefix there is no lockfile; a stand-in path in the working directory keeps the
    // output and configuration lookups (which are relative to the lockfile) working.
    let lockfile = match &args.prefix {
        Some(_) => cwd.join("pixi.lock"),
        None => discover::resolve_lockfile(args.lockfile.as_deref(), &cwd)?,
    };
    if !args.no_config {
        let dir = lockfile.parent().unwrap_or(Path::new("."));
        if let Some(loaded) = config::load(dir, args.config.as_deref())? {
            config::apply(&loaded, &mut args, &matches)?;
            tracing::info!(path = %loaded.path.display(), "applied the configuration file");
        }
    }
    tracing::debug!(?args, "effective arguments");
    validate(&args);
    let input = match &args.prefix {
        Some(dir) => Input::Prefix {
            dir: dir.clone(),
            root: model::Root {
                name: args.name.clone().unwrap_or_else(|| prefix::environment_name(dir)),
                version: args.root_version.clone(),
                ..model::Root::default()
            },
        },
        None => {
            let lock::LoadedLock { lock, contents } = lock::load(&lockfile)?;
            Input::Lock {
                lock,
                contents,
                root: manifest::root_for_lockfile(&lockfile),
            }
        }
    };

    let spec_version = resolve_spec_version(&args);
    let fetch_licenses = args.fetch_licenses || args.pypi_licenses;
    if args.pypi_licenses {
        tracing::warn!("--pypi-licenses is deprecated and now behaves as --fetch-licenses; use that instead");
    }
    let previous = match &args.against {
        Some(path) => Some((path.clone(), diff::read_previous(path)?)),
        None => None,
    };
    let targets = match &input {
        Input::Lock { lock, .. } => resolve_targets(&args, lock, &lockfile)?,
        Input::Prefix { dir, .. } => vec![Target {
            environment: prefix::environment_name(dir),
            platform: args.platform.clone(),
            output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
        }],
    };
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
    let ignores: Vec<vulnpolicy::Ignore> = args
        .ignore_vuln
        .iter()
        .map(|text| vulnpolicy::Ignore::parse(text))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|err| {
            cli::Args::command()
                .error(clap::error::ErrorKind::InvalidValue, format!("--ignore-vuln: {err}"))
                .exit()
        });
    let mut gate_hits: Vec<(String, String, vulnpolicy::Hit)> = Vec::new();
    let package_filter = filter::Filter {
        include: parse_globs(&args.include, "--include"),
        exclude: parse_globs(&args.exclude, "--exclude"),
        exclude_kinds: args.exclude_kind.iter().map(|k| k.package_kind()).collect(),
        keep_orphans: args.keep_orphans,
    };
    let kev_catalog = if args.kev {
        let catalog = kev::Catalog::load(&mapping::cache_dir())?;
        tracing::info!(
            entries = catalog.len(),
            version = catalog.version.as_deref().unwrap_or("?"),
            "loaded the CISA KEV catalog"
        );
        Some(catalog)
    } else {
        None
    };

    for Target {
        environment,
        platform,
        output,
    } in &targets
    {
        let (mut sbom, contents) = match &input {
            Input::Lock { lock, contents, root } => {
                let selection = lock::Selection {
                    environment,
                    platform: platform.as_deref(),
                };
                let sbom = lock::sbom_from_lock(lock, selection, root.clone(), &discover::lockfile_name(&lockfile))?;
                (sbom, contents.clone())
            }
            Input::Prefix { dir, root } => {
                let sbom = prefix::build_sbom(dir, root.clone(), platform.as_deref())?;
                // Stands in for the lockfile text as the document's identity: the installed
                // packages, in order.
                let contents = sbom
                    .packages
                    .iter()
                    .map(|p| p.id.as_str())
                    .collect::<Vec<_>>()
                    .join("\n");
                tracing::info!(prefix = %dir.display(), packages = sbom.packages.len(), "read the installed environment");
                (sbom, contents)
            }
        };
        if !package_filter.is_empty() {
            let filter::Outcome { excluded, orphans } = package_filter.apply(&mut sbom);
            tracing::info!(
                excluded = excluded.len(),
                orphans = orphans.len(),
                remaining = sbom.packages.len(),
                "filtered packages"
            );
            tracing::debug!(?excluded, ?orphans, "filtered package names");
        }
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
        if let Some(cli::VulnerabilitySource::Osv) = args.vulnerabilities {
            let cache_dir = mapping::cache_dir();
            let lookup = osv::Lookup {
                api_url: &osv::api_url(),
                cache_dir: &cache_dir,
            };
            let osv::Outcome {
                queried,
                without_identity,
                findings,
                failed,
            } = lookup.run(&mut sbom)?;
            tracing::info!(
                queried,
                without_identity,
                findings,
                failed,
                "looked up vulnerabilities on OSV"
            );
            if args.format == cli::Format::Spdx && args.report.is_none() && findings > 0 {
                tracing::warn!(
                    findings,
                    "SPDX documents do not record vulnerabilities; use --format cyclonedx or --report vulnerabilities"
                );
            }
            if let Some(catalog) = &kev_catalog {
                let known_exploited = kev::apply(&mut sbom, catalog);
                tracing::info!(known_exploited, "matched findings against the CISA KEV catalog");
            }
            let ignored = vulnpolicy::apply_ignores(&mut sbom, &ignores);
            if args.fail_on_severity.is_some() || args.fail_on_kev {
                let threshold = args.fail_on_severity.map(|s| s.severity());
                let hits = vulnpolicy::check(&sbom, threshold, args.fail_on_kev);
                tracing::info!(
                    ignored,
                    hits = hits.len(),
                    threshold = threshold.map(|s| s.name()).unwrap_or("-"),
                    kev = args.fail_on_kev,
                    "checked the vulnerability gate"
                );
                gate_hits.extend(
                    hits.into_iter()
                        .map(|h| (sbom.environment.clone(), sbom.platform.clone(), h)),
                );
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
            reports.push(match (kind, &previous) {
                (report::ReportKind::Diff, Some((path, previous))) => {
                    let diff = diff::compare(&sbom, previous, path);
                    tracing::info!(
                        added = diff.added.len(),
                        removed = diff.removed.len(),
                        version_changed = diff.version_changed.len(),
                        license_changed = diff.license_changed.len(),
                        unchanged = diff.unchanged,
                        "compared with the previous document"
                    );
                    report::Report::diff(&sbom, diff)
                }
                _ => report::Report::new(kind, &sbom),
            });
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
        let palette = style::Palette::new(args.color.enabled());
        let mut stdout = std::io::stdout().lock();
        report::render(&reports, args.report_format, palette, &mut stdout)
            .and_then(|()| stdout.flush())
            .into_diagnostic()
            .wrap_err("cannot write the report to stdout")?;
    }
    if !gate_hits.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let rule = match (args.fail_on_severity, args.fail_on_kev) {
            (Some(s), true) => format!("at or above {} or known exploited", s.severity().name()),
            (Some(s), false) => format!("at or above {}", s.severity().name()),
            (None, _) => "known exploited".to_string(),
        };
        let _ = writeln!(
            stderr,
            "Vulnerability gate failed: {} finding(s) {rule}:",
            gate_hits.len()
        );
        for (environment, platform, hit) in &gate_hits {
            let _ = if targets.len() > 1 {
                writeln!(stderr, "  [{environment}/{platform}] {hit}")
            } else {
                writeln!(stderr, "  {hit}")
            };
        }
        let _ = stderr.flush();
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
    if !gate_hits.is_empty() {
        std::process::exit(vulnpolicy::GATE_EXIT_CODE);
    }
    Ok(())
}

/// The relationships between settings that clap cannot check, because a configuration file
/// may supply either side. Every violation is a usage error (exit 2).
fn validate(args: &cli::Args) {
    let usage = |kind: clap::error::ErrorKind, message: &str| -> ! { cli::Args::command().error(kind, message).exit() };
    use clap::error::ErrorKind::{ArgumentConflict, MissingRequiredArgument};
    if args.license_texts && !(args.fetch_licenses || args.pypi_licenses) {
        usage(
            MissingRequiredArgument,
            "'--license-texts' only applies together with '--fetch-licenses'",
        );
    }
    if args.vulnerabilities.is_none() {
        for (set, flag) in [
            (args.kev, "--kev"),
            (args.fail_on_severity.is_some(), "--fail-on-severity"),
            (!args.ignore_vuln.is_empty(), "--ignore-vuln"),
            (
                args.report == Some(report::ReportKind::Vulnerabilities),
                "--report vulnerabilities",
            ),
        ] {
            if set {
                usage(
                    MissingRequiredArgument,
                    &format!("'{flag}' needs '--vulnerabilities <SOURCE>' to look them up"),
                );
            }
        }
    }
    if args.fail_on_kev && !args.kev {
        usage(MissingRequiredArgument, "'--fail-on-kev' needs '--kev'");
    }
    if args.report_format == report::ReportFormat::Sarif && args.report != Some(report::ReportKind::Vulnerabilities) {
        usage(
            ArgumentConflict,
            "'--report-format sarif' only applies to '--report vulnerabilities'",
        );
    }
    match (args.report, &args.against) {
        (Some(report::ReportKind::Diff), None) => usage(
            MissingRequiredArgument,
            "'--report diff' needs '--against <PATH>' to compare with",
        ),
        (kind, Some(_)) if kind != Some(report::ReportKind::Diff) => {
            usage(ArgumentConflict, "'--against' only applies to '--report diff'")
        }
        _ => {}
    }
}

/// Parse `--include` / `--exclude` patterns; a bad one is a usage error.
fn parse_globs(patterns: &[String], flag: &str) -> Vec<filter::Glob> {
    patterns
        .iter()
        .map(|p| {
            filter::Glob::parse(p).unwrap_or_else(|err| {
                cli::Args::command()
                    .error(clap::error::ErrorKind::InvalidValue, format!("{flag} '{p}': {err}"))
                    .exit()
            })
        })
        .collect()
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

/// Where the packages come from.
enum Input {
    /// A `pixi.lock`, with its text (the document identity) and the workspace it belongs to.
    Lock {
        lock: rattler_lock::LockFile,
        contents: String,
        root: model::Root,
    },
    /// An installed environment (`--prefix`).
    Prefix { dir: std::path::PathBuf, root: model::Root },
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
