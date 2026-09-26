//! `pixi-sbom`: a pixi extension that generates CycloneDX or SPDX SBOMs from `pixi.lock`.

mod auditable;
mod cli;
mod condaarchive;
mod config;
mod cvss;
mod diff;
mod discover;
mod embedded;
mod filter;
mod format;
mod fromsbom;
mod http;
mod imports;
mod kev;
mod license;
mod lock;
mod manifest;
mod mapping;
mod model;
mod osv;
mod outdated;
mod parallel;
mod phantom;
mod pkgcache;
mod policy;
mod prefix;
mod progress;
mod purl;
mod pypi;
mod pyversion;
mod report;
mod scorecard;
mod stdlib;
mod style;
mod vulnpolicy;
mod wheel;
mod zipread;

use std::io::{IsTerminal, Write};
use std::path::Path;

use clap::{CommandFactory, FromArgMatches};
use miette::{Context, IntoDiagnostic, Result};
use tracing_subscriber::EnvFilter;

/// Assert that a diagnostic tells the user both what it is and what to do next.
///
/// Every error type in this crate has a test that builds one value of each of its variants and
/// hands it here, so a new variant without a `help(...)` fails its module's tests rather than
/// reaching a user who is then told only what went wrong.
#[cfg(test)]
pub fn assert_actionable(err: &dyn miette::Diagnostic) {
    let code = err.code().map(|code| code.to_string()).unwrap_or_default();
    assert!(!code.trim().is_empty(), "no diagnostic code on: {err}");
    let help = err.help().map(|help| help.to_string()).unwrap_or_default();
    assert!(!help.trim().is_empty(), "no help on {code}: {err}");
}

fn main() -> Result<()> {
    let matches = cli::Args::command().get_matches();
    let mut args = cli::Args::from_arg_matches(&matches).into_diagnostic()?;
    init_tracing(&args);
    init_error_reporting()?;

    let cwd = std::env::current_dir().into_diagnostic()?;
    // With --prefix there is no lockfile; a stand-in path in the working directory keeps the
    // output and configuration lookups (which are relative to the lockfile) working.
    let lockfile = match (&args.prefix, &args.scan, &args.from_sbom) {
        // With --prefix or --from-sbom there is no lockfile, and with --scan there are many; a
        // stand-in path keeps the configuration lookup (which is relative to the lockfile)
        // working, and for a scan it puts that lookup in the scanned directory rather than in
        // each workspace.
        (Some(_), _, _) | (_, _, Some(_)) => cwd.join(discover::LOCKFILE_NAME),
        (None, Some(dir), None) => dir.join(discover::LOCKFILE_NAME),
        (None, None, None) => discover::resolve_lockfile(args.lockfile.as_deref(), &cwd)?,
    };
    let config_dir = lockfile.parent().unwrap_or(Path::new(".")).to_path_buf();
    if args.no_config {
        tracing::debug!("configuration file: none, --no-config was given");
    } else if let Some(loaded) = config::load(&config_dir, args.config.as_deref())? {
        config::apply(&loaded, &mut args, &matches)?;
        tracing::info!(path = %loaded.path.display(), "applied the configuration file");
    } else {
        tracing::debug!(
            dir = %config_dir.display(),
            "configuration file: none found ([tool.pixi-sbom] in pyproject.toml, or pixi-sbom.toml)"
        );
    }
    describe_input(&args, &lockfile, &cwd);
    tracing::debug!(?args, "effective arguments");
    validate(&args);
    // Bars are drawn only for an interactive run whose log level would not overwrite them.
    let progress = progress::Progress::resolve(
        args.verbosity.tracing_level_filter() >= tracing::level_filters::LevelFilter::DEBUG,
        args.verbosity.tracing_level_filter() < tracing::level_filters::LevelFilter::INFO,
    );
    // A scan reads its inputs per workspace, so there is no single one to read here.
    let input = match (&args.prefix, &args.scan) {
        _ if args.from_sbom.is_some() => {
            let path = args.from_sbom.as_deref().expect("just checked");
            let root = model::Root {
                name: args.name.clone().unwrap_or_default(),
                version: args.root_version.clone(),
                ..model::Root::default()
            };
            let loaded = fromsbom::read(path, root, args.platform.as_deref())?;
            tracing::info!(
                path = %path.display(),
                format = %loaded.format,
                packages = loaded.sbom.packages.len(),
                "read the source document"
            );
            Some(Input::Document(Box::new(loaded)))
        }
        (Some(dir), _) => Some(Input::Prefix {
            dir: dir.clone(),
            root: model::Root {
                name: args.name.clone().unwrap_or_else(|| prefix::environment_name(dir)),
                version: args.root_version.clone(),
                ..model::Root::default()
            },
        }),
        (None, Some(_)) => None,
        (None, None) => {
            let lock::LoadedLock { lock, contents } = lock::load(&lockfile)?;
            Some(Input::Lock {
                lock,
                contents,
                manifest: manifest::read(&lockfile),
            })
        }
    };

    let spec_version = resolve_spec_version(&args);
    let fetch_licenses = args.fetch_licenses || args.pypi_licenses;
    if args.pypi_licenses {
        tracing::warn!("--pypi-licenses is deprecated and now behaves as --fetch-licenses; use that instead");
    }
    // Say what this run will talk to before it talks to anything: on another network, the
    // difference is almost always here.
    let network = network_configuration(&args, fetch_licenses);
    if !network.services.is_empty() {
        network.log();
    }
    let previous = match &args.against {
        Some(path) => Some((path.clone(), diff::resolve_against(path)?)),
        None => None,
    };
    // One workspace normally; with --scan, one per lockfile found under the directory.
    let workspaces: Vec<Workspace> = match &args.scan {
        Some(dir) => {
            let found = discover::scan(dir, args.scan_depth)?;
            tracing::info!(lockfiles = found.len(), dir = %dir.display(), "scanned for workspaces");
            found
                .into_iter()
                .map(|lockfile| scanned_workspace(&args, dir, lockfile))
                .collect::<Result<_>>()?
        }
        None => {
            let input = input.expect("only a scan leaves the input unread");
            let targets = match &input {
                Input::Lock { lock, .. } => resolve_targets(&args, lock, &lockfile, None)?,
                Input::Prefix { dir, .. } => vec![Target {
                    environment: prefix::environment_name(dir),
                    platform: args.platform.clone(),
                    output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
                }],
                Input::Document(loaded) => vec![Target {
                    environment: loaded.sbom.environment.clone(),
                    platform: args.platform.clone(),
                    output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
                }],
            };
            vec![Workspace {
                lockfile: lockfile.clone(),
                input,
                targets,
            }]
        }
    };
    let targets: Vec<(&Workspace, &Target)> = workspaces
        .iter()
        .flat_map(|workspace| workspace.targets.iter().map(move |target| (workspace, target)))
        .collect();
    let pypi_mapping = load_pypi_mapping(&args)?;
    tracing::debug!(documents = targets.len(), format = ?args.format, "resolved targets");
    let mut reports = Vec::new();
    let exemptions: Vec<policy::Exemption> = args
        .ignore_license
        .iter()
        .map(|text| policy::Exemption::parse(text))
        .collect::<Result<_, _>>()
        .unwrap_or_else(|err: String| {
            cli::Args::command()
                .error(clap::error::ErrorKind::InvalidValue, format!("--ignore-license: {err}"))
                .exit()
        });
    let policy = policy::Policy::new(
        &args.allow_license,
        &args.deny_license,
        args.require_license,
        exemptions,
    )
    .unwrap_or_else(|err| {
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
    let mut yanked: Vec<(String, String, String)> = Vec::new();
    let mut phantoms: Vec<(String, String, String)> = Vec::new();
    let mut diff_hits: Vec<(String, String, String)> = Vec::new();
    let mut low_scores: Vec<(String, String, String)> = Vec::new();
    let assume_used = parse_globs(&args.assume_used, "--assume-used");
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

    for (
        workspace,
        Target {
            environment,
            platform,
            output,
        },
    ) in &targets
    {
        let (lockfile, input) = (&workspace.lockfile, &workspace.input);
        let (mut sbom, contents) = match input {
            Input::Lock {
                lock,
                contents,
                manifest,
            } => {
                let selection = lock::Selection {
                    environment,
                    platform: platform.as_deref(),
                };
                let mut sbom = lock::sbom_from_lock(
                    lock,
                    selection,
                    manifest.root.clone(),
                    &discover::lockfile_name(lockfile),
                )?;
                // What the workspace asked for itself, as opposed to what came along.
                manifest.apply(&mut sbom);
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
            // Already read: the source document's own text is what identifies everything
            // derived from it.
            Input::Document(loaded) => (loaded.sbom.clone(), loaded.contents.clone()),
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
            } = wheel::enrich(&mut sbom, &cache_dir, args.license_texts, progress);
            tracing::info!(fetched, failed, skipped, "read PyPI license details from wheels");
            if args.embedded_sboms {
                let embedded::Outcome {
                    files,
                    unreadable,
                    added,
                    merged,
                } = embedded::enrich(&mut sbom, &cache_dir);
                tracing::info!(files, unreadable, added, merged, "attached embedded SBOM components");
                // An installed environment is the only place the binaries themselves are, and
                // conda-forge builds its Rust packages with `cargo auditable`.
                if let Input::Prefix { dir, .. } = input {
                    let auditable::Outcome {
                        binaries,
                        added,
                        merged,
                    } = auditable::enrich(&mut sbom, dir, progress);
                    tracing::info!(binaries, added, merged, "read cargo auditable crate lists");
                }
            }
            let pkgcache::Outcome {
                found,
                licenses_filled,
                files,
                missing,
            } = if fetch_licenses {
                pkgcache::enrich(&mut sbom, &pkgs, args.license_texts, progress)
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
                } = condaarchive::enrich(&mut sbom, &missing, &cache_dir, args.license_texts, progress);
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
                let pypi::Outcome {
                    found,
                    missing,
                    failed,
                    yanked,
                } = lookup.run(&mut sbom, progress);
                tracing::info!(found, missing, failed, yanked, "looked up PyPI releases");
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
            } = lookup.run(&mut sbom, progress)?;
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
        if args.fail_on_yanked {
            yanked.extend(sbom.packages.iter().filter_map(|package| {
                let reason = package.yanked.as_ref()?;
                let version = package.version.as_deref().unwrap_or("-");
                Some((
                    sbom.environment.clone(),
                    sbom.platform.clone(),
                    match &reason.reason {
                        Some(reason) => format!("{} {version}: {reason}", package.name),
                        None => format!("{} {version}", package.name),
                    },
                ))
            }));
        }
        if let Some(policy) = &policy {
            let found = policy.check(&sbom);
            tracing::info!(
                violations = found.violations.len(),
                exempt = found.exempt.len(),
                "checked the license policy"
            );
            // An exemption is a decision, so it is recorded in the document rather than only
            // being silent about the package.
            for exempt in &found.exempt {
                if let Some(package) = sbom.packages.iter_mut().find(|p| p.name == exempt.violation.package) {
                    package.properties.insert(
                        policy::EXEMPT_PROPERTY.to_string(),
                        exempt.justification.clone().unwrap_or_else(|| "true".to_string()),
                    );
                }
                tracing::info!(exempt = %exempt, "license policy exemption");
            }
            violations.extend(
                found
                    .violations
                    .into_iter()
                    .map(|v| (sbom.environment.clone(), sbom.platform.clone(), v)),
            );
        }
        if args.report == Some(report::ReportKind::Outdated) {
            let cache_dir = mapping::cache_dir();
            let lookup = outdated::Lookup {
                index_url: &pypi::index_url(),
                anaconda_url: &outdated::anaconda_url(),
                cache_dir: &cache_dir,
            };
            let (statuses, outcome) = lookup.run(&sbom, progress);
            tracing::info!(
                checked = outcome.checked,
                outdated = outcome.outdated,
                unknown = outcome.unknown,
                "checked how far behind the packages are"
            );
            let mut report = report::Report::outdated(&sbom, &statuses, std::time::SystemTime::now());
            if let Some(only) = args.outdated_only {
                report.keep_outdated(only);
            }
            reports.push(report);
            continue;
        }
        if args.scorecard {
            let cache_dir = mapping::cache_dir();
            let lookup = scorecard::Lookup {
                url: &scorecard::url(),
                cache_dir: &cache_dir,
            };
            let scorecard::Outcome {
                scored,
                unknown,
                failed,
            } = lookup.run(&mut sbom, args.scorecard_min, progress);
            tracing::info!(scored, unknown, failed, "read OpenSSF scorecards");
            if let Some(min) = args.fail_on_scorecard {
                low_scores.extend(
                    scorecard::below(&sbom, min)
                        .into_iter()
                        .map(|line| (sbom.environment.clone(), sbom.platform.clone(), line)),
                );
            }
        }
        if args.report == Some(report::ReportKind::Scorecard) {
            reports.push(report::Report::scorecard(&sbom, args.scorecard_min));
            continue;
        }
        if args.report == Some(report::ReportKind::Phantom) {
            let roots = if args.source.is_empty() {
                vec![lockfile.parent().unwrap_or(Path::new(".")).to_path_buf()]
            } else {
                args.source.clone()
            };
            let scanned = imports::scan(&roots);
            let environment = phantom::environment_dir(
                &sbom,
                lockfile.parent().unwrap_or(Path::new(".")),
                args.prefix.as_deref(),
            );
            let modules = phantom::modules(&sbom, environment.as_deref());
            let found = phantom::findings(&sbom, &scanned, &modules, &assume_used);
            tracing::info!(
                files = scanned.files,
                modules = scanned.by_module.len(),
                findings = found.len(),
                from_environment = modules.from_environment,
                "checked the workspace's imports against its dependencies"
            );
            phantoms.extend(
                found
                    .iter()
                    .filter(|f| f.kind == phantom::Kind::Phantom)
                    .map(|f| (sbom.environment.clone(), sbom.platform.clone(), f.name.clone())),
            );
            reports.push(report::Report::phantom(&sbom, found, &scanned, &modules));
            continue;
        }
        if let Some(kind) = args.report {
            reports.push(match (kind, &previous) {
                (report::ReportKind::Diff, Some((path, against))) => {
                    // A document was read once; a lockfile or an installed environment answers
                    // per environment and platform, so the other side is built here.
                    let previous = match against {
                        diff::Against::Document(previous) => std::borrow::Cow::Borrowed(previous),
                        diff::Against::Lock { lock, name } => {
                            // With --prefix the target is named after the directory, which
                            // says nothing about the lockfile; --environment then names the
                            // side to compare with.
                            let selection = lock::Selection {
                                environment: match &args.prefix {
                                    Some(_) => &args.environment,
                                    None => environment,
                                },
                                platform: platform.as_deref(),
                            };
                            let other = lock::sbom_from_lock(lock, selection, model::Root::default(), name)?;
                            std::borrow::Cow::Owned(diff::previous_from_sbom(&other))
                        }
                        diff::Against::Prefix(dir) => {
                            let other = prefix::build_sbom(dir, model::Root::default(), platform.as_deref())?;
                            std::borrow::Cow::Owned(diff::previous_from_sbom(&other))
                        }
                    };
                    let diff = diff::compare(&sbom, &previous, path);
                    tracing::info!(
                        added = diff.added.len(),
                        removed = diff.removed.len(),
                        version_changed = diff.version_changed.len(),
                        license_changed = diff.license_changed.len(),
                        unchanged = diff.unchanged,
                        "compared with the previous document"
                    );
                    if !args.fail_on_diff.is_empty() {
                        let hits = diff.gate_hits(&args.fail_on_diff);
                        if !hits.is_empty() {
                            diff_hits.push((sbom.environment.clone(), sbom.platform.clone(), hits.join(", ")));
                        }
                    }
                    report::Report::diff(&sbom, diff)
                }
                _ => {
                    let mut report = report::Report::new(kind, &sbom);
                    if args.tree {
                        report.as_tree(&sbom, args.depth);
                    }
                    if args.group_by == Some(cli::GroupBy::License) {
                        report.group_by_license();
                    }
                    report
                }
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
        if let Some(path) = &args.vex {
            let value = format::vex_to_value(&sbom, &ctx, args.vex_open.state())?;
            write_json(path, &value)?;
            tracing::info!(
                output = %path.display(),
                findings = sbom.vulnerabilities.len(),
                open_state = args.vex_open.state(),
                "wrote VEX"
            );
        }
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
    if !low_scores.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let min = args.fail_on_scorecard.unwrap_or_default();
        let _ = writeln!(
            stderr,
            "OpenSSF Scorecard below {min:.1} for {} package(s):",
            low_scores.len()
        );
        for (environment, platform, line) in &low_scores {
            let _ = if targets.len() > 1 {
                writeln!(stderr, "  [{environment}/{platform}] {line}")
            } else {
                writeln!(stderr, "  {line}")
            };
        }
        let _ = stderr.flush();
    }
    if !diff_hits.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "The environment changed against the previous document:");
        for (environment, platform, hits) in &diff_hits {
            let _ = if targets.len() > 1 {
                writeln!(stderr, "  [{environment}/{platform}] {hits}")
            } else {
                writeln!(stderr, "  {hits}")
            };
        }
        let _ = stderr.flush();
    }
    if args.fail_on_phantom && !phantoms.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Imported but never declared: {} package(s):", phantoms.len());
        for (environment, platform, name) in &phantoms {
            let _ = if targets.len() > 1 {
                writeln!(stderr, "  [{environment}/{platform}] {name}")
            } else {
                writeln!(stderr, "  {name}")
            };
        }
        let _ = stderr.flush();
    }
    if !yanked.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "Yanked release(s) in the environment: {}", yanked.len());
        for (environment, platform, line) in &yanked {
            let _ = if targets.len() > 1 {
                writeln!(stderr, "  [{environment}/{platform}] {line}")
            } else {
                writeln!(stderr, "  {line}")
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
    if !yanked.is_empty() {
        std::process::exit(YANKED_EXIT_CODE);
    }
    if args.fail_on_phantom && !phantoms.is_empty() {
        std::process::exit(PHANTOM_EXIT_CODE);
    }
    if !diff_hits.is_empty() {
        std::process::exit(diff::DIFF_EXIT_CODE);
    }
    if !low_scores.is_empty() {
        std::process::exit(SCORECARD_EXIT_CODE);
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
    if args.fail_on_yanked && !(args.fetch_licenses || args.pypi_licenses) {
        usage(
            MissingRequiredArgument,
            "'--fail-on-yanked' needs '--fetch-licenses', which is what asks the index",
        );
    }
    if args.report_format == report::ReportFormat::Sarif && args.report != Some(report::ReportKind::Vulnerabilities) {
        usage(
            ArgumentConflict,
            "'--report-format sarif' only applies to '--report vulnerabilities'",
        );
    }
    for (set, flag) in [
        (!args.source.is_empty(), "--source"),
        (!args.assume_used.is_empty(), "--assume-used"),
        (args.fail_on_phantom, "--fail-on-phantom"),
    ] {
        if set && args.report != Some(report::ReportKind::Phantom) {
            usage(
                ArgumentConflict,
                &format!("'{flag}' only applies to '--report phantom'"),
            );
        }
    }
    if args.scorecard && !(args.fetch_licenses || args.pypi_licenses) {
        usage(
            MissingRequiredArgument,
            "'--scorecard' needs '--fetch-licenses', which is what collects the repository URLs",
        );
    }
    if args.report == Some(report::ReportKind::Scorecard) && !args.scorecard {
        usage(MissingRequiredArgument, "'--report scorecard' needs '--scorecard'");
    }
    if args.vex.is_some() {
        if args.vulnerabilities.is_none() {
            usage(
                MissingRequiredArgument,
                "'--vex' needs '--vulnerabilities <SOURCE>': there is nothing to assess without findings",
            );
        }
        for (set, flag) in [
            (args.all_environments, "--all-environments"),
            (args.all_platforms, "--all-platforms"),
            (args.scan.is_some(), "--scan"),
            (args.report.is_some(), "--report"),
        ] {
            if set {
                usage(
                    ArgumentConflict,
                    &format!("'--vex' writes one document beside one SBOM and cannot be combined with '{flag}'"),
                );
            }
        }
    }
    if args.from_sbom.is_some() {
        for (set, flag) in [
            (args.all_environments, "--all-environments"),
            (args.all_platforms, "--all-platforms"),
        ] {
            if set {
                usage(
                    ArgumentConflict,
                    &format!("'{flag}' reads a lockfile and cannot be combined with '--from-sbom'"),
                );
            }
        }
    }
    if args.scan.is_some() {
        if args.against.is_some() {
            usage(
                ArgumentConflict,
                "'--against' compares one environment and cannot be combined with '--scan'",
            );
        }
        if discover::is_stdout(args.output.as_deref()) {
            usage(
                ArgumentConflict,
                "'--output -' writes one document to stdout and cannot be combined with '--scan'",
            );
        }
    }
    if args.tree && args.report != Some(report::ReportKind::Packages) {
        usage(ArgumentConflict, "'--tree' only applies to '--report packages'");
    }
    if args.group_by.is_some() && args.report != Some(report::ReportKind::Licenses) {
        usage(ArgumentConflict, "'--group-by' only applies to '--report licenses'");
    }
    if !args.fail_on_diff.is_empty() && args.report != Some(report::ReportKind::Diff) {
        usage(ArgumentConflict, "'--fail-on-diff' only applies to '--report diff'");
    }
    if args.outdated_only.is_some() && args.report != Some(report::ReportKind::Outdated) {
        usage(
            ArgumentConflict,
            "'--outdated-only' only applies to '--report outdated'",
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

/// Exit code when `--fail-on-yanked` finds a yanked release.
const YANKED_EXIT_CODE: i32 = 7;

/// Exit code for `--fail-on-phantom` when the workspace imports a package it never declared.
const PHANTOM_EXIT_CODE: i32 = 8;

/// Exit code for `--fail-on-scorecard` when a scored repository is below the threshold.
const SCORECARD_EXIT_CODE: i32 = 9;

/// Say what this run is reading and how it got there. Four decisions are made before any work
/// starts — which lockfile, which manifest beside it, which configuration file, and for a scan
/// which directory the configuration came from — and none of them used to be visible.
fn describe_input(args: &cli::Args, lockfile: &Path, cwd: &Path) {
    let (input, how) = match (&args.prefix, &args.scan, &args.from_sbom) {
        (Some(dir), _, _) => (dir.display().to_string(), "--prefix: an installed environment"),
        (_, _, Some(file)) => (file.display().to_string(), "--from-sbom: an existing document"),
        (_, Some(dir), _) => (
            dir.display().to_string(),
            "--scan: every pixi.lock under this directory",
        ),
        (None, None, None) => (
            lockfile.display().to_string(),
            match args.lockfile {
                Some(_) => "--lockfile",
                None => "found by searching upward from the working directory",
            },
        ),
    };
    tracing::debug!(input, how, from = %cwd.display(), "input");
    // A scan reads one configuration for the whole tree; each workspace's own file is skipped
    // on purpose, which is surprising if it is not said.
    if args.scan.is_some() {
        tracing::debug!("with --scan the configuration comes from the scanned directory, not from each workspace");
    }
    if args.prefix.is_some() || args.from_sbom.is_some() {
        return;
    }
    let dir = lockfile.parent().unwrap_or(Path::new("."));
    match ["pixi.toml", "pyproject.toml"]
        .into_iter()
        .map(|name| dir.join(name))
        .find(|path| path.is_file())
    {
        Some(manifest) => tracing::debug!(path = %manifest.display(), "workspace manifest"),
        // Without a manifest there is no declared set, so the root's edges are the graph roots.
        None => tracing::debug!(
            dir = %dir.display(),
            "no workspace manifest: the root component's dependencies are the graph-root heuristic"
        ),
    }
}

/// The upstreams this run may use, given the flags, with their addresses resolved the way the
/// code that calls them resolves them.
fn network_configuration(args: &cli::Args, fetch_licenses: bool) -> http::Configuration {
    let mut services = Vec::new();
    // Wheel metadata and release facts both come from the index.
    if fetch_licenses || args.report == Some(report::ReportKind::Outdated) {
        services.push(http::Service::new("PyPI index", pypi::index_url(), pypi::INDEX_URL_ENV));
    }
    if args.pypi_mapping == cli::PypiMappingSource::Prefix {
        services.push(http::Service::fixed(
            "conda-forge PyPI mapping",
            mapping::PREFIX_MAPPING_URL,
        ));
    }
    if args.vulnerabilities.is_some() {
        services.push(http::Service::new("OSV", osv::api_url(), osv::API_URL_ENV));
    }
    if args.kev {
        services.push(http::Service::new("CISA KEV", kev::url(), kev::URL_ENV));
    }
    if args.report == Some(report::ReportKind::Outdated) {
        services.push(http::Service::new(
            "anaconda.org",
            outdated::anaconda_url(),
            outdated::ANACONDA_URL_ENV,
        ));
    }
    if args.scorecard {
        services.push(http::Service::new(
            "OpenSSF Scorecard",
            scorecard::url(),
            scorecard::SCORECARD_URL_ENV,
        ));
    }
    // Wheels and conda archives are fetched from wherever each package says it lives, so there
    // is no one address to name; the requests themselves are logged.
    if fetch_licenses || args.embedded_sboms {
        services.push(http::Service::fixed(
            "package archives",
            "each package's own download URL",
        ));
    }
    http::Configuration::resolve(services, mapping::cache_dir())
}

/// One workspace to describe: its lockfile (or installed environment) and the documents that
/// come out of it.
#[derive(Debug)]
struct Workspace {
    lockfile: std::path::PathBuf,
    input: Input,
    targets: Vec<Target>,
}

/// One workspace a `--scan` found: its lockfile read, and its documents placed under the
/// output directory at the same relative path, so two workspaces never collide.
fn scanned_workspace(args: &cli::Args, scanned: &Path, lockfile: std::path::PathBuf) -> Result<Workspace> {
    let lock::LoadedLock { lock, contents } = lock::load(&lockfile)?;
    let dir = lockfile.parent().unwrap_or(Path::new(".")).to_path_buf();
    let relative = dir.strip_prefix(scanned).unwrap_or(Path::new(""));
    let output_dir = match &args.output {
        Some(output) => output.join(relative),
        None => dir.clone(),
    };
    let targets = resolve_targets(args, &lock, &lockfile, Some(&output_dir))?;
    let manifest = manifest::read(&lockfile);
    Ok(Workspace {
        lockfile,
        input: Input::Lock {
            lock,
            contents,
            manifest,
        },
        targets,
    })
}

#[derive(Debug)]
enum Input {
    /// A `pixi.lock`, with its text (the document identity) and the manifest of the
    /// workspace it belongs to.
    Lock {
        lock: rattler_lock::LockFile,
        contents: String,
        manifest: manifest::Manifest,
    },
    /// An installed environment (`--prefix`).
    Prefix { dir: std::path::PathBuf, root: model::Root },
    /// An existing document (`--from-sbom`), already read into the model.
    Document(Box<fromsbom::Loaded>),
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
/// The documents one lockfile produces. `dir`, set only by `--scan`, is the directory this
/// workspace's documents go in, which replaces `--output` for them.
fn resolve_targets(
    args: &cli::Args,
    lock: &rattler_lock::LockFile,
    lockfile: &Path,
    dir: Option<&Path>,
) -> Result<Vec<Target>> {
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
            let labels = args
                .all_environments
                .then_some(environment.as_str())
                .into_iter()
                .chain(platform.as_deref().filter(|_| args.all_platforms));
            let output = match (dir, batch) {
                // A scanned workspace always writes into its own directory, under the same
                // file name the equivalent single-workspace run would have used.
                (Some(dir), true) => discover::Output::File(dir.join(args.format.batch_file_name(labels))),
                (Some(dir), false) => discover::Output::File(dir.join(args.format.default_file_name())),
                (None, true) => discover::Output::File(discover::resolve_batch_output(
                    args.output.as_deref(),
                    lockfile,
                    args.format,
                    labels,
                )),
                (None, false) => discover::resolve_output(args.output.as_deref(), lockfile, args.format),
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

/// Write a JSON document to a path, creating its directory.
fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot create output directory {}", parent.display()))?;
    }
    let file = std::fs::File::create(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot create {}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot write {}", path.display()))?;
    writer.write_all(b"\n").into_diagnostic()?;
    writer.flush().into_diagnostic()?;
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
        .with_writer(ProgressAwareStderr)
        .with_ansi(std::io::stderr().is_terminal())
        .without_time()
        .init();
}

/// Writes log lines to stderr with any progress bar hidden for the duration, so the two never
/// overwrite each other.
struct ProgressAwareStderr;

impl std::io::Write for ProgressAwareStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        progress::suspend(|| std::io::stderr().write(buf))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ProgressAwareStderr {
    type Writer = ProgressAwareStderr;

    fn make_writer(&'a self) -> Self::Writer {
        ProgressAwareStderr
    }
}
