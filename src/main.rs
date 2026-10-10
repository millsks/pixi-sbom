//! The `pixi sbom` command: parse the arguments, run the steps the flags asked for, and
//! decide the exit code. Everything it calls lives in the library beside it.

// See the note in lib.rs: the shipped binary contains no `unsafe`, held by the compiler.
#![cfg_attr(not(test), forbid(unsafe_code))]

use pixi_sbom::{
    auditable, batch, cache, cli, concurrency, condaarchive, condalock, config, diff, discover, doctor, embedded, epss,
    explain, explicit, filter, format, fromsbom, http, imports, kev, license, lock, manifest, mapping, merge, mirror,
    model, osv, outdated, pdm, phantom, pkgcache, poetry, policy, prefix, progress, pylock, pypi, report, requirements,
    scorecard, style, timings, uv, verify, vexin, vulnpolicy, wheel,
};

/// The system allocator on macOS and Windows is slow under the many small allocations a
/// document is made of; mimalloc is measured in docs/benchmarks.md.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io::{IsTerminal, Write};
use std::path::Path;

use clap::{CommandFactory, FromArgMatches};
use miette::{Context, IntoDiagnostic, Result};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // A shell asking for completion gets its registration script or its candidates, and the
    // process exits here, before any lockfile is read. Registered and called by the name on
    // PATH, so the script survives an upgrade that moves the binary.
    let shell = std::env::var(cli::COMPLETE_ENV).ok();
    if shell.as_deref() == Some("powershell") && std::env::args_os().len() == 1 {
        print!("{}", cli::powershell_registration());
        return Ok(());
    }
    if cli::completion_requested(shell.as_deref()) {
        clap_complete::CompleteEnv::with_factory(|| cli::Args::command().bin_name("pixi-sbom"))
            .var(cli::COMPLETE_ENV)
            .bin("pixi-sbom")
            .completer("pixi-sbom")
            .complete();
    }
    let started = std::time::Instant::now();
    let matches = cli::Args::command().get_matches();
    let mut args = cli::Args::from_arg_matches(&matches).into_diagnostic()?;
    args.primary_purl_chosen = matches.value_source("primary_purl") == Some(clap::parser::ValueSource::CommandLine);
    let (log_format, unknown_log_format) =
        cli::LogFormat::resolve(args.log_format, std::env::var(cli::LOG_FORMAT_ENV).ok().as_deref());
    init_tracing(&args, log_format);
    if let Some(value) = unknown_log_format {
        tracing::warn!(
            variable = cli::LOG_FORMAT_ENV,
            value,
            "not a log format (text, json); logging as text"
        );
    }
    init_error_reporting()?;
    // `--version -v`: the block a bug report needs, before anything else happens.
    if args.version_details {
        let mut stdout = std::io::stdout().lock();
        write!(stdout, "{}", environment_banner()).into_diagnostic()?;
        stdout.flush().into_diagnostic()?;
        return Ok(());
    }

    let cwd = std::env::current_dir().into_diagnostic()?;
    // With --prefix there is no lockfile; a stand-in path in the working directory keeps the
    // output and configuration lookups (which are relative to the lockfile) working.
    // --doctor describes the network rather than a workspace, so it needs no lockfile at all.
    let lockfile = match (&args.prefix, &args.scan, args.from_sbom.first()) {
        _ if args.doctor => cwd.join(discover::LOCKFILE_NAME),
        // With --prefix or --from-sbom there is no lockfile, and with --scan there are many; a
        // stand-in path keeps the configuration lookup (which is relative to the lockfile)
        // working, and for a scan it puts that lookup in the scanned directory rather than in
        // each workspace.
        (Some(_), _, _) | (_, _, Some(_)) => cwd.join(discover::LOCKFILE_NAME),
        (None, Some(dir), None) => dir.join(discover::LOCKFILE_NAME),
        (None, None, None) => discover::resolve_lockfile(args.lockfile.as_deref(), &cwd)?,
    };
    let config_dir = lockfile.parent().unwrap_or(Path::new(".")).to_path_buf();
    let config_layers: Vec<config::Loaded>;
    if args.no_config {
        config_layers = Vec::new();
        tracing::debug!("configuration file: none, --no-config was given");
    } else {
        config_layers = config::load(&config_dir, args.config.as_deref())?;
        let layers = &config_layers;
        if layers.is_empty() {
            tracing::debug!(
                dir = %config_dir.display(),
                "configuration file: none found (pixi's config directories, .pixi/, [tool.pixi-sbom] in pyproject.toml)"
            );
        } else {
            config::apply_all(layers, &mut args, &matches)?;
            // Every file that took part, least specific first: a setting arriving from a machine-wide
            // file nobody can see in the repository should never be a surprise.
            let paths = layers
                .iter()
                .map(|layer| format!("{} ({})", layer.path.display(), layer.source.label()))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::info!(paths, "applied the configuration");
        }
    }
    describe_input(&args, &lockfile, &cwd);
    tracing::debug!(?args, "effective arguments");
    // How many things may happen at once, before anything starts happening.
    // Precedence: the command line, then the environment, then a configuration file, then the
    // default. The variable beating the file is deliberate — a file is checked into a repository or
    // sits on a machine, while the variable is set by whoever is running *this* invocation, and
    // someone exporting it to get through a slow afternoon should not be overruled by a file they
    // did not write.
    let on_command_line = matches.value_source("concurrency") == Some(clap::parser::ValueSource::CommandLine);
    let from_variable = std::env::var(concurrency::CONCURRENCY_ENV).ok();
    let (requested, chosen) = match (on_command_line, from_variable.as_deref(), args.concurrency) {
        (true, _, requested) => (requested, concurrency::Source::Flag),
        (false, Some(value), _) => (value.trim().parse::<usize>().ok(), concurrency::Source::Variable),
        // Not on the command line and no variable, so anything here came from a file.
        (false, None, Some(requested)) => (Some(requested), concurrency::Source::File),
        (false, None, None) => (None, concurrency::Source::Machine),
    };
    let unusable_concurrency = match (chosen, from_variable.as_deref()) {
        (concurrency::Source::Variable, Some(value)) if requested.is_none_or(|n| n == 0) => Some(value.to_string()),
        _ => None,
    };
    let requested_concurrency = requested.unwrap_or(0);
    let cores = std::thread::available_parallelism().map_or(1, |cores| cores.get());
    let limits = concurrency::Limits::with(requested, chosen, cores);
    concurrency::init(limits);
    if let Some(value) = unusable_concurrency {
        tracing::warn!(
            variable = concurrency::CONCURRENCY_ENV,
            value,
            network = limits.network,
            cpu = limits.cpu,
            "not a positive number of requests; using the default"
        );
    }
    // A number far past what any upstream tolerates is honoured but not silently: the operator may
    // have their own mirror, and may equally have typed an extra zero.
    if let Some(concern) = concurrency::Limits::concern(requested_concurrency) {
        tracing::warn!(variable = concurrency::CONCURRENCY_ENV, "{concern}");
    }
    // What the caches may do this run, before anything reads one.
    cache::init(cache::Policy::new(
        args.refresh.iter().filter_map(|target| target.service()).collect(),
        args.refresh.iter().any(|target| target.service().is_none()),
        args.no_cache,
    ));
    validate(&args);
    // Bars are drawn only for an interactive run whose log level would not overwrite them.
    let progress = progress::Progress::resolve(
        args.verbosity.tracing_level_filter() >= tracing::level_filters::LevelFilter::DEBUG,
        args.verbosity.tracing_level_filter() < tracing::level_filters::LevelFilter::INFO,
        log_format == cli::LogFormat::Json,
    );
    // A scan reads its inputs per workspace, so there is no single one to read here.
    // Say what this run will talk to before it talks to anything: on another network, the
    // difference is almost always here. --doctor stops after saying it, and needs no input.
    // The trust anchors, before anything is fetched: a typo in --ca-bundle should name the
    // file, not come back as a handshake failure ten seconds into the run.
    let tls_roots = http::TlsRoots::from_env(args.ca_bundle.as_deref());
    let mut unusable_bundle = http::init_tls(&tls_roots).err();
    // --doctor exists to say what is wrong with the setup, so it reports an unusable bundle in
    // the configuration block and exits non-zero rather than refusing to print anything.
    if !args.doctor
        && let Some(err) = unusable_bundle.take()
    {
        return Err(miette::Report::new(err));
    }
    let mut network = network_configuration(&args, args.fetch_licenses || args.pypi_licenses, &tls_roots);
    if let Some(err) = &unusable_bundle {
        network.tls_roots = format!("{} — unusable: {err}", tls_roots.describe());
    }
    if args.doctor {
        let palette = style::Palette::new(args.color.enabled());
        let mut stdout = std::io::stdout().lock();
        let healthy = run_doctor(
            &network,
            &config_layers,
            limits,
            args.conda_index_kind,
            &palette,
            &mut stdout,
        )? && unusable_bundle.is_none();
        stdout.flush().into_diagnostic()?;
        std::process::exit(if healthy { 0 } else { DOCTOR_EXIT_CODE });
    }

    let input = match (&args.prefix, &args.scan) {
        _ if !args.from_sbom.is_empty() => {
            let root = model::Root {
                name: args.root_name.clone().unwrap_or_default(),
                version: args.root_version.clone(),
                ..model::Root::default()
            };
            // Merged, --root-name names the new root; each input keeps its own.
            let root = if args.from_sbom.len() > 1 {
                model::Root::default()
            } else {
                root
            };
            let mut documents = Vec::with_capacity(args.from_sbom.len());
            for path in &args.from_sbom {
                let loaded = fromsbom::read(path, root.clone(), args.platform.as_deref())?;
                tracing::info!(
                    path = %path.display(),
                    format = %loaded.format,
                    packages = loaded.sbom.packages.len(),
                    "read the source document"
                );
                documents.push(loaded);
            }
            if documents.len() == 1 {
                documents.pop().map(|loaded| Input::Document(Box::new(loaded)))
            } else {
                let inputs: Vec<merge::Input> = documents
                    .iter()
                    .map(|loaded| merge::Input {
                        name: loaded.sbom.document.clone().unwrap_or_default(),
                        sbom: loaded.sbom.clone(),
                    })
                    .collect();
                Some(Input::Document(Box::new(merged_document(&args, &inputs, &documents))))
            }
        }
        (Some(dir), _) => Some(Input::Prefix {
            dir: dir.clone(),
            infer_extras: args.infer_extras,
            root: model::Root {
                name: args.root_name.clone().unwrap_or_else(|| prefix::environment_name(dir)),
                version: args.root_version.clone(),
                ..model::Root::default()
            },
        }),
        (None, Some(_)) => None,
        (None, None) => Some(read_input(&lockfile)?),
    };

    let spec_version = resolve_spec_version(&args);
    let fetch_licenses = args.fetch_licenses || args.pypi_licenses;
    if args.format == cli::Format::Github
        && args.report.is_none()
        && ["GITHUB_SHA", "GITHUB_REF"]
            .iter()
            .any(|name| std::env::var(name).is_err())
    {
        tracing::warn!(
            "GITHUB_SHA or GITHUB_REF is not set, so the snapshot names no commit and GitHub's submission API \
             will refuse it; GitHub Actions sets both, elsewhere set them to the commit and ref it describes"
        );
    }
    if args.pypi_licenses {
        tracing::warn!("--pypi-licenses is deprecated and now behaves as --fetch-licenses; use that instead");
    }
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
            let workspaces: Vec<Workspace> = found
                .into_iter()
                .map(|lockfile| scanned_workspace(&args, dir, lockfile))
                .collect::<Result<_>>()?;
            if args.merge {
                vec![merge_workspaces(&args, dir, &workspaces)?]
            } else {
                workspaces
            }
        }
        None => {
            let input = input.expect("only a scan leaves the input unread");
            let targets = match &input {
                Input::Lock { lock, .. } => resolve_targets(&args, lock, &lockfile, None)?,
                Input::CondaLock { lock, .. } => condalock_targets(&args, lock, &lockfile),
                Input::Requirements { .. } => {
                    refuse_workspace_flags(&args, "a requirements file");
                    vec![Target {
                        environment: "default".to_string(),
                        platform: args.platform.clone(),
                        output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
                    }]
                }
                Input::Explicit { .. } => {
                    refuse_workspace_flags(&args, "an explicit spec file");
                    vec![Target {
                        environment: "default".to_string(),
                        platform: args.platform.clone(),
                        output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
                    }]
                }
                Input::Pdm { .. } => {
                    refuse_workspace_flags(&args, "pdm.lock");
                    vec![Target {
                        environment: "default".to_string(),
                        platform: args.platform.clone(),
                        output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
                    }]
                }
                Input::Poetry { .. } => {
                    refuse_workspace_flags(&args, "poetry.lock");
                    vec![Target {
                        environment: "default".to_string(),
                        platform: args.platform.clone(),
                        output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
                    }]
                }
                Input::Uv { .. } => {
                    refuse_workspace_flags(&args, "uv.lock");
                    vec![Target {
                        environment: "default".to_string(),
                        platform: args.platform.clone(),
                        output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
                    }]
                }
                Input::Pylock { .. } => {
                    refuse_workspace_flags(&args, "pylock.toml");
                    vec![Target {
                        environment: pylock::environment_name(&lockfile),
                        platform: args.platform.clone(),
                        output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
                    }]
                }
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
    let pypi_mapping = timings::time(timings::Phase::Mapping, || load_pypi_mapping(&args))?;
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
    let mut low_quality: Vec<(String, String, String)> = Vec::new();
    let mut changed_files: Vec<(String, String, String)> = Vec::new();
    let assume_used = parse_globs(&args.assume_used, "--assume-used");
    let explain_patterns = parse_globs(&args.explain, "--explain");
    let explain_context = explain::Context {
        // Set per workspace below: only a lockfile has a manifest beside it.
        manifest: false,
        fetch_licenses,
        embedded_sboms: args.embedded_sboms,
        scorecard: args.scorecard,
        vulnerabilities: args.vulnerabilities.is_some(),
        pypi_mapping: pypi_mapping.is_some(),
        offline: http::offline(),
    };
    let package_filter = filter::Filter {
        include: parse_globs(&args.include, "--include"),
        exclude: parse_globs(&args.exclude, "--exclude"),
        exclude_kinds: args.exclude_kind.iter().map(|k| k.package_kind()).collect(),
        keep_orphans: args.keep_orphans,
    };
    let mut vex_statements = Vec::new();
    for path in &args.vex_in {
        let statements = vexin::load(path)?;
        tracing::info!(path = %path.display(), statements = statements.len(), "read VEX statements");
        vex_statements.extend(statements);
    }
    let mut vex_applied = vec![false; vex_statements.len()];
    let vulnerability_rule = vulnpolicy::Rule {
        severity: args.fail_on_severity.map(|s| s.severity()),
        kev: args.fail_on_kev,
        epss: args.fail_on_epss,
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

    // A run that writes many documents looks the same package up once per document it appears
    // in, and each document drains its own small pool of requests before the next starts
    // filling one. So the lookups happen here instead, once, over every document's packages at
    // once, and each document takes what this found.
    let shared = shared_enrichment(&args, &targets, &package_filter, pypi_mapping.as_ref(), progress)?;

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
        let (mut sbom, contents) = model_for(workspace, environment, platform.as_deref())?;
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
        // Now that the package count is final, do not size the request pool past it: threads
        // beyond the work can only park, and a machine-wide setting carried into a small
        // workspace is how a pool gets asked for that the system may refuse.
        concurrency::limit_to_work(sbom.packages.len());
        if let Some(mapping) = &pypi_mapping {
            let enriched = mapping::enrich(&mut sbom, mapping);
            tracing::info!(enriched, "added PyPI purls to conda packages");
        }
        if args.primary_purl == cli::PrimaryPurl::Pypi {
            let switched = mapping::prefer_pypi_purl(&mut sbom);
            tracing::info!(switched, "made PyPI purls primary");
        }
        warn_unscannable_pypi(&sbom, &args);
        if let Some(dir) = args.prefix.as_deref()
            && (args.verify_files || args.report == Some(report::ReportKind::Files))
        {
            let results = verify::verify(dir);
            let failing = verify::attach(&mut sbom, &results);
            tracing::info!(
                packages = results.len(),
                failing,
                "verified installed files against conda-meta"
            );
            for package in &sbom.packages {
                for (property, state) in [
                    (verify::MODIFIED_PROPERTY, "modified"),
                    (verify::MISSING_PROPERTY, "missing"),
                ] {
                    for path in package.properties.get(property).into_iter().flat_map(|v| v.split(", ")) {
                        changed_files.push((
                            sbom.environment.clone(),
                            sbom.platform.clone(),
                            format!("{state}: {path} ({})", package.name),
                        ));
                    }
                }
            }
        }
        match &shared {
            // Already looked up for every document at once; what is left is only what this
            // document's own model added, which nothing fetches.
            Some(shared) => {
                let filled = shared.apply(&mut sbom);
                tracing::debug!(filled, packages = sbom.packages.len(), "took the shared lookups");
            }
            None => enrich(&mut sbom, &args, input, progress),
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
                unanswered,
            } = timings::time(timings::Phase::Vulnerabilities, || lookup.run(&mut sbom, progress))?;
            timings::describe(
                timings::Phase::Vulnerabilities,
                format!("{queried} queried, {findings} findings"),
            );
            tracing::info!(
                queried,
                without_identity,
                findings,
                failed,
                unanswered,
                "looked up vulnerabilities on OSV"
            );
            // An empty `vulnerabilities[]` has three causes, and only one of them is good
            // news: nothing carried an identity the database answers to, nothing could be
            // asked, or nothing is known. The document says which.
            if queried == 0 && without_identity > 0 {
                sbom.incomplete.note(format!(
                    "osv: 0 of {without_identity} packages queryable (no purl the database answers to)"
                ));
            }
            if unanswered > 0 {
                sbom.incomplete.note(format!(
                    "osv: {unanswered} of {queried} purls unasked (offline, nothing cached)"
                ));
            }
            if failed > 0 {
                sbom.incomplete.note(format!(
                    "osv: {failed} advisory record(s) could not be fetched, and are recorded by id only"
                ));
            }
            // SPDX 3.0.1 has a security profile and carries the findings (#118); 2.3 has nowhere
            // to put them, so the warning is now about the spec version rather than the format.
            let spdx_version = args
                .spec_version
                .unwrap_or_else(|| cli::SpecVersion::default_for(args.format));
            if args.format == cli::Format::Spdx
                && spdx_version == cli::SpecVersion::V2_3
                && args.report.is_none()
                && findings > 0
            {
                tracing::warn!(
                    findings,
                    "SPDX 2.3 does not record vulnerabilities; use --spec-version 3.0, --format cyclonedx, or --report vulnerabilities"
                );
            }
            if let Some(catalog) = &kev_catalog {
                let known_exploited = kev::apply(&mut sbom, catalog);
                tracing::info!(known_exploited, "matched findings against the CISA KEV catalog");
            }
            if args.epss {
                let cves = epss::cves(&sbom);
                let scores = epss::lookup(&mapping::cache_dir(), &cves)?;
                let scored = epss::apply(&mut sbom, &scores);
                tracing::info!(cves = cves.len(), scored, "scored findings with FIRST EPSS");
            }
            if !vex_statements.is_empty() {
                let applied = vexin::apply(&mut sbom, &vex_statements);
                tracing::info!(
                    applied = applied.iter().filter(|a| **a).count(),
                    "applied VEX statements to the findings"
                );
                for (seen, now) in vex_applied.iter_mut().zip(applied) {
                    *seen |= now;
                }
            }
            // After the VEX, so a local decision wins over the vendor's.
            let ignored = vulnpolicy::apply_ignores(&mut sbom, &ignores);
            if vulnerability_rule.is_set() {
                let hits = vulnpolicy::check(&sbom, &vulnerability_rule);
                tracing::info!(
                    ignored,
                    hits = hits.len(),
                    rule = %vulnerability_rule,
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
        // The quality gate grades the document as it stands after the enrichment that fills it in
        // (licenses, hashes, repositories); before the reports that end this target's turn early.
        if let Some(min) = args.min_quality {
            let grade = pixi_sbom::quality::assess(&sbom);
            if grade.overall < min {
                low_quality.push((
                    sbom.environment.clone(),
                    sbom.platform.clone(),
                    format!(
                        "{} of 100, weakest: {}",
                        grade.overall,
                        pixi_sbom::quality::weakest(&grade, 3).join(", ")
                    ),
                ));
            }
        }
        if args.report == Some(report::ReportKind::Outdated) {
            let cache_dir = mapping::cache_dir();
            let lookup = outdated::Lookup {
                index_url: &pypi::index_url(),
                anaconda_url: &outdated::anaconda_url(),
                index_is_configured: outdated::index_is_configured(args.conda_index_kind),
                kind: args.conda_index_kind,
                prefix_index_url: &outdated::prefix_index_url(),
                cache_dir: &cache_dir,
            };
            let (statuses, unavailable, outcome) =
                timings::time(timings::Phase::Outdated, || lookup.run(&sbom, progress));
            // What the phase covered belongs in its row, not only in the cache log beside it: it is
            // the number that separates a 27 s cold run from a 0.4 s warm one.
            if let Some(detail) = cache::describe(cache::Service::Outdated) {
                timings::describe(timings::Phase::Outdated, detail);
            }
            tracing::info!(
                checked = outcome.checked,
                outdated = outcome.outdated,
                unknown = outcome.unknown,
                unavailable = outcome.unavailable,
                "checked how far behind the packages are"
            );
            let mut report = report::Report::outdated(&sbom, &statuses, &unavailable, std::time::SystemTime::now());
            if let Some(only) = args.outdated_min {
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
            } = timings::time(timings::Phase::Scorecard, || {
                lookup.run(&mut sbom, args.scorecard_min, progress)
            });
            tracing::info!(scored, unknown, failed, "read OpenSSF scorecards");
            sbom.incomplete
                .note_failures("scorecard", failed, scored + unknown + failed, "lookups");
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
        if !explain_patterns.is_empty() {
            let context = explain::Context {
                manifest: input.manifest().is_some_and(|manifest| !manifest.declared.is_empty()),
                ..explain_context
            };
            let report = report::Report::explain(&sbom, &explain_patterns, context);
            let summary = report
                .explain_summary
                .as_ref()
                .expect("the explain report summarizes itself");
            tracing::info!(
                matched = summary.matched,
                facts = summary.facts,
                unknown = summary.unknown,
                "explained the matching packages"
            );
            reports.push(report);
            continue;
        }
        if args.report == Some(report::ReportKind::Phantom) {
            let roots = if args.source.is_empty() {
                vec![lockfile.parent().unwrap_or(Path::new(".")).to_path_buf()]
            } else {
                args.source.clone()
            };
            let scanned = timings::time(timings::Phase::Imports, || imports::scan(&roots));
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
                        diff::Against::Other(path) => {
                            // Read as --lockfile would read it, for the platform this side was
                            // described for: a venv's platform comes from its wheels, not the host.
                            let workspace = Workspace {
                                lockfile: path.clone(),
                                input: read_input(path)?,
                                targets: Vec::new(),
                            };
                            let environment = if pylock::is_pylock_name(path) {
                                pylock::environment_name(path)
                            } else {
                                "default".to_string()
                            };
                            let platform = platform.clone().unwrap_or_else(|| sbom.platform.clone());
                            let (other, _) = model_for(&workspace, &environment, Some(&platform))?;
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
                    report.epss = args.epss;
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
        // What the run could not finish belongs in the document too: the warnings on stderr
        // do not survive the upload, and a reader months later cannot tell an empty result
        // from an unasked question.
        // A document that holds only some of its license texts should say which it is.
        let (dropped, held) = license::text_budget();
        if dropped > 0 {
            tracing::warn!(
                dropped,
                held_bytes = held,
                limit_bytes = license::MAX_TOTAL_TEXT_BYTES,
                "the document holds as much license text as it may; the rest are listed by name only"
            );
            sbom.incomplete.note(format!(
                "license-texts: {dropped} file(s) listed by name only, at the {} MiB the document may hold",
                license::MAX_TOTAL_TEXT_BYTES / (1024 * 1024)
            ));
        }
        sbom.incomplete.stale = cache::stale_lines();
        if !sbom.incomplete.is_empty() {
            tracing::warn!(
                steps = sbom.incomplete.step_names().join(", "),
                stale = sbom.incomplete.stale.join(", "),
                "the document records that enrichment was incomplete"
            );
        }
        // Everything that reads the environment's files has run: the document need not say where
        // on this machine they are.
        if let Input::Prefix { dir, .. } = input {
            prefix::make_portable(&mut sbom, dir);
        }
        let ctx = format::WriteContext::for_document(&contents, &sbom, args.format, spec_version);
        let written = timings::time(timings::Phase::Write, || write_output(output, args.format, &sbom, &ctx))?;
        tracing::info!(
            output = %output,
            format = ?args.format,
            packages = sbom.packages.len(),
            environment = %sbom.environment,
            platform = %sbom.platform,
            "{}",
            if written { "wrote SBOM" } else { "SBOM unchanged but for the timestamp; left as it was" }
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
    if args.timings {
        let mut stderr = std::io::stderr().lock();
        for line in timings::table(started.elapsed()) {
            let _ = writeln!(stderr, "{line}");
        }
        let _ = stderr.flush();
    }
    // Where the answers came from: a run that is fast because everything was cached should
    // say so, and one that refreshed should show the fetches.
    cache::log_tally();
    // A document built on data that could not be refreshed is not the same as one built on
    // fresh data, and the difference has to survive the scrollback.
    for (service, age) in cache::stale_services() {
        tracing::warn!(
            cache = service.name(),
            age_s = age.as_secs(),
            "served data past its lifetime because the fetch failed; the result is that old"
        );
    }
    if !reports.is_empty() {
        let palette = style::Palette::new(args.color.enabled());
        // Buffered for the same reason the document is: the JSON and SARIF reports are
        // written straight out rather than assembled into a string first.
        let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
        report::render(&reports, args.report_format, palette, &mut stdout)
            .and_then(|()| stdout.flush())
            .into_diagnostic()
            .wrap_err("cannot write the report to stdout")?;
    }
    for (statement, applied) in vex_statements.iter().zip(&vex_applied) {
        if !applied {
            tracing::warn!(
                statement = statement.describe(),
                "a VEX statement matches no finding: no such vulnerability here, or not for these package versions"
            );
        }
    }
    if !gate_hits.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "Vulnerability gate failed: {} finding(s) {vulnerability_rule}:",
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
    if !changed_files.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(
            stderr,
            "Installed files that differ from conda-meta: {} (--report files lists them):",
            changed_files.len()
        );
        for (environment, platform, line) in &changed_files {
            let _ = if targets.len() > 1 {
                writeln!(stderr, "  [{environment}/{platform}] {line}")
            } else {
                writeln!(stderr, "  {line}")
            };
        }
        let _ = stderr.flush();
    }
    if !low_quality.is_empty() {
        let mut stderr = std::io::stderr().lock();
        let min = args.min_quality.unwrap_or_default();
        let _ = writeln!(stderr, "SBOM quality below {min} (--report quality says why):");
        for (environment, platform, line) in &low_quality {
            let _ = if targets.len() > 1 {
                writeln!(stderr, "  [{environment}/{platform}] {line}")
            } else {
                writeln!(stderr, "  {line}")
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
    }
    // Several gates can fail in one run, and each has printed its own list by now. Only one
    // exit code can be returned, so say which gates failed and which of them chose it: in CI
    // the code is the headline, and a run that failed three gates looked like it failed one.
    let failed = [
        Gate::new("license policy", violations.len(), policy::VIOLATION_EXIT_CODE),
        Gate::new("vulnerabilities", gate_hits.len(), vulnpolicy::GATE_EXIT_CODE),
        Gate::new("yanked releases", yanked.len(), YANKED_EXIT_CODE),
        Gate::new(
            "phantom imports",
            if args.fail_on_phantom { phantoms.len() } else { 0 },
            PHANTOM_EXIT_CODE,
        ),
        Gate::new("the comparison", diff_hits.len(), diff::DIFF_EXIT_CODE),
        Gate::new("scorecards", low_scores.len(), SCORECARD_EXIT_CODE),
        Gate::new("quality", low_quality.len(), pixi_sbom::quality::QUALITY_EXIT_CODE),
        Gate::new("installed files", changed_files.len(), verify::MODIFIED_EXIT_CODE),
    ];
    let failed: Vec<&Gate> = failed.iter().filter(|gate| gate.count > 0).collect();
    if let Some(first) = failed.first() {
        report_gates(&failed);
        std::process::exit(first.code);
    }
    Ok(())
}

/// One gate that can end a run, with what it found.
#[derive(Debug, Clone, Copy)]
struct Gate {
    name: &'static str,
    count: usize,
    code: i32,
}

impl Gate {
    fn new(name: &'static str, count: usize, code: i32) -> Self {
        Self { name, count, code }
    }
}

/// Name every gate that fired and the one whose code is being returned. The gates are given in
/// precedence order, so the first is the one that decides.
fn report_gates(failed: &[&Gate]) {
    let mut stderr = std::io::stderr().lock();
    let deciding = failed[0];
    let counted: Vec<String> = failed
        .iter()
        .map(|gate| format!("{} ({})", gate.name, gate.count))
        .collect();
    let _ = if failed.len() == 1 {
        writeln!(stderr, "Gate failed: {}. Exiting {}.", counted[0], deciding.code)
    } else {
        let others: Vec<String> = failed[1..].iter().map(|gate| gate.code.to_string()).collect();
        writeln!(
            stderr,
            "{} gates failed: {}.\nExiting {} ({}); the others would have been {}.",
            failed.len(),
            counted.join(", "),
            deciding.code,
            deciding.name,
            others.join(" and ")
        )
    };
    let _ = stderr.flush();
}

/// The documents a `conda-lock.yml` gives: one platform, or each locked platform with
/// `--all-platforms`, named as `pixi.lock`'s are. It has no environments to choose among.
fn condalock_targets(args: &cli::Args, lock: &condalock::CondaLock, lockfile: &Path) -> Vec<Target> {
    for (set, flag) in [
        (args.all_environments, "--all-environments"),
        (args.environment != "default", "--environment"),
    ] {
        if set {
            cli::Args::command()
                .error(
                    clap::error::ErrorKind::ArgumentConflict,
                    format!("'{flag}' chooses among a pixi workspace's environments, and conda-lock.yml has none"),
                )
                .exit();
        }
    }
    if !args.all_platforms {
        return vec![Target {
            environment: "default".to_string(),
            platform: args.platform.clone(),
            output: discover::resolve_output(args.output.as_deref(), lockfile, args.format),
        }];
    }
    if discover::is_stdout(args.output.as_deref()) {
        cli::Args::command()
            .error(
                clap::error::ErrorKind::ArgumentConflict,
                "'--output -' writes one document to stdout and cannot be combined with '--all-platforms'",
            )
            .exit();
    }
    condalock::platform_names(lock)
        .into_iter()
        .map(|platform| Target {
            environment: "default".to_string(),
            output: discover::Output::File(discover::resolve_batch_output(
                args.output.as_deref(),
                lockfile,
                args.format,
                std::iter::once(platform.as_str()),
            )),
            platform: Some(platform),
        })
        .collect()
}

/// Refuse the flags that choose among a pixi workspace's environments and platforms, for an input
/// that has neither (exit 2). `-e` is caught only when it names something other than the default.
fn refuse_workspace_flags(args: &cli::Args, input: &str) {
    for (set, flag) in [
        (args.all_environments, "--all-environments"),
        (args.all_platforms, "--all-platforms"),
        (args.environment != "default", "--environment"),
    ] {
        if set {
            cli::Args::command()
                .error(
                    clap::error::ErrorKind::ArgumentConflict,
                    format!(
                        "'{flag}' chooses among a pixi workspace's environments and platforms, and {input} has none; \
                         choose the platform with '--platform'"
                    ),
                )
                .exit();
        }
    }
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
            (args.epss, "--epss"),
            (args.fail_on_severity.is_some(), "--fail-on-severity"),
            (!args.ignore_vuln.is_empty(), "--ignore-vuln"),
            (!args.vex_in.is_empty(), "--vex-in"),
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
    if args.fail_on_epss.is_some() && !args.epss {
        usage(MissingRequiredArgument, "'--fail-on-epss' needs '--epss'");
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
    if args.report == Some(report::ReportKind::Files) && args.prefix.is_none() {
        usage(
            MissingRequiredArgument,
            "'--report files' needs '--prefix <DIR>': only an installed environment has files to check",
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
        if args.format == cli::Format::Github {
            usage(
                ArgumentConflict,
                "'--vex' writes a CycloneDX VEX linked to a CycloneDX SBOM and cannot be combined with '--format github'",
            );
        }
        if args.format == cli::Format::Spdx {
            usage(
                ArgumentConflict,
                "'--vex' writes a CycloneDX VEX linked to a CycloneDX SBOM and cannot be combined with \
                 '--format spdx'; with SPDX, use '--spec-version 3.0', which records the assessments in the \
                 document's security profile",
            );
        }
        for (set, flag) in [
            (args.all_environments, "--all-environments"),
            (args.all_platforms, "--all-platforms"),
            (args.scan.is_some(), "--scan"),
            (args.report.is_some(), "--report"),
            (!args.explain.is_empty(), "--explain"),
        ] {
            if set {
                usage(
                    ArgumentConflict,
                    &format!("'--vex' writes one document beside one SBOM and cannot be combined with '{flag}'"),
                );
            }
        }
    }
    if !args.from_sbom.is_empty() {
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
    // Merged, a scan is one document again, and these apply.
    if args.scan.is_some() && !args.merge {
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
    if args.outdated_min.is_some() && args.report != Some(report::ReportKind::Outdated) {
        usage(ArgumentConflict, "'--outdated-min' only applies to '--report outdated'");
    }
    if args.prefix.is_some() && args.against.is_none() && args.environment != "default" {
        usage(
            ArgumentConflict,
            "'--environment' with '--prefix' names the lockfile side of '--against'; an installed environment has \
             no environments of its own",
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
    let (input, how) = match (&args.prefix, &args.scan, args.from_sbom.first()) {
        (Some(dir), _, _) => (dir.display().to_string(), "--prefix: an installed environment"),
        (_, _, Some(file)) => (file.display().to_string(), "--from-sbom: an existing document"),
        (_, Some(dir), _) => (
            dir.display().to_string(),
            "--scan: one lockfile per project under this directory",
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
    if args.prefix.is_some() || !args.from_sbom.is_empty() {
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

/// Everything a bug report needs about this build and this machine, made to be pasted.
///
/// Which features the binary carries is the fact that decides several answers — whether it can
/// use a SOCKS proxy, whether it verifies TLS against the system store — and it is invisible
/// from the outside.
fn environment_banner() -> String {
    let proxy = http::proxy_for_logging().unwrap_or_else(|| "none".to_string());
    let no_proxy = ["NO_PROXY", "no_proxy"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.trim().is_empty()))
        .unwrap_or_else(|| "none".to_string());
    let cache = mapping::cache_dir();
    let pixi = std::process::Command::new("pixi")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|| "not on PATH".to_string());
    [
        format!(
            "pixi-sbom {} ({} {})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::ARCH,
            std::env::consts::OS
        ),
        format!("features: {FEATURES}"),
        format!(
            "caches:   {} ({})",
            cache.display(),
            if cache.is_dir() { "exists" } else { "not created yet" }
        ),
        format!("pixi:     {pixi}"),
        format!("offline:  {}   proxy: {proxy}   no-proxy: {no_proxy}", http::offline()),
        format!("TLS:      {}", http::TlsRoots::from_env(None).describe()),
        String::new(),
    ]
    .join("\n")
}

/// The optional behaviour compiled in. A missing one explains a failure that otherwise looks
/// like a network problem: without `socks-proxy` an `ALL_PROXY=socks5://...` cannot work.
// Built only for Windows targets, where a proxy can be configured with no environment variable
// at all, so the line says "n/a" rather than "no" everywhere else.
#[cfg(windows)]
const FEATURES: &str = "rustls, gzip, platform-verifier, socks-proxy, win-system-proxy";
#[cfg(not(windows))]
const FEATURES: &str = "rustls, gzip, platform-verifier, socks-proxy, win-system-proxy: n/a";

/// Scanners read only a package's primary purl, so with the default `--primary-purl conda` a conda
/// package's PyPI identity is invisible to them and its advisories go unreported (#449). Said once
/// a run, and not at all once the setting is chosen, `conda` included.
fn warn_unscannable_pypi(sbom: &model::Sbom, args: &cli::Args) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if args.primary_purl_chosen || args.primary_purl != cli::PrimaryPurl::Conda {
        return;
    }
    let hidden = mapping::hidden_pypi_identities(sbom);
    if hidden > 0 && !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            packages = hidden,
            "vulnerability scanners read only the primary purl, so they will not match these conda packages \
             by their PyPI identity; set --primary-purl pypi (or primary-purl = \"pypi\" in pixi-sbom-config.toml) \
             to scan them, or --primary-purl conda to keep conda purls and silence this"
        );
    }
}

/// Exit code for `--doctor` when an upstream could not be reached.
const DOCTOR_EXIT_CODE: i32 = 1;

/// Print how this run is set up, whether each upstream answers, and what the caches hold.
/// Returns whether everything that was asked answered.
fn run_doctor(
    network: &http::Configuration,
    config_layers: &[config::Loaded],
    limits: concurrency::Limits,
    conda_index_kind: cli::CondaIndexKind,
    palette: &style::Palette,
    out: &mut dyn Write,
) -> Result<bool> {
    let write = |out: &mut dyn Write, line: String| -> Result<()> {
        writeln!(out, "{line}")
            .into_diagnostic()
            .wrap_err("cannot write the report")
    };
    write(out, palette.header("Configuration"))?;
    write(
        out,
        format!(
            "  offline    {}\n  proxy      {}\n  no-proxy   {}\n  TLS roots  {}\n  timeout    {}s",
            network.offline,
            network.proxy.as_deref().unwrap_or("none"),
            network.no_proxy.as_deref().unwrap_or("none"),
            network.tls_roots,
            network.timeout.as_secs()
        ),
    )?;
    write(
        out,
        format!(
            // Two settings that decide how a run behaves and were nowhere in this report. The
            // source matters as much as the number: with four places concurrency can come from,
            // "which one won?" is otherwise only answerable with -v.
            "  requests   {} at once ({})\n  index      {} ({})",
            limits.network,
            limits.source.name(),
            match conda_index_kind {
                cli::CondaIndexKind::Anaconda => "anaconda.org's package API",
                cli::CondaIndexKind::Prefix => "prefix.dev's GraphQL API",
            },
            if config_layers
                .iter()
                .any(|layer| layer.config.conda_index_kind.is_some())
            {
                "a configuration file"
            } else {
                "the default"
            },
        ),
    )?;
    write(
        out,
        format!(
            "  cache      {} ({})",
            network.cache_dir.display(),
            if network.cache_exists {
                "exists"
            } else {
                "not created yet"
            }
        ),
    )?;

    write(out, String::new())?;
    write(out, palette.header("Configuration files"))?;
    if config_layers.is_empty() {
        write(out, format!("  {}", palette.dim("none found")))?;
    }
    for layer in config_layers {
        // Least specific first, the order they were merged in, so the last line shown is the one
        // that won. A deprecated location says so here rather than only in a log nobody reads.
        let note = if layer.source.deprecated() {
            palette.severity(&format!(
                "{}, deprecated: move to .pixi/{}",
                layer.source.label(),
                config::FILE_NAME
            ))
        } else {
            palette.dim(layer.source.label())
        };
        write(out, format!("  {:<26} {}", layer.path.display(), note))?;
    }

    let probes = doctor::probes(network, &doctor::request);
    write(out, String::new())?;
    write(out, palette.header("Upstreams"))?;
    for probe in &probes {
        let outcome = probe.outcome.text();
        write(
            out,
            format!(
                "  {:<26} {}\n  {:<26} {}",
                probe.service,
                if probe.outcome.is_ok() {
                    outcome
                } else {
                    palette.severity(&outcome)
                },
                "",
                palette.dim(&format!("{} ({})", probe.url, probe.source))
            ),
        )?;
    }

    let caches = doctor::caches(&network.cache_dir, std::time::SystemTime::now());
    if !caches.is_empty() {
        write(out, String::new())?;
        write(out, palette.header("Caches"))?;
        for cache in &caches {
            write(
                out,
                format!(
                    "  {:<26} {} entries{}",
                    cache.name,
                    cache.entries,
                    match cache.newest {
                        Some(age) => format!(", newest {} old", doctor::ago(age)),
                        None => String::new(),
                    }
                ),
            )?;
        }
    }

    let failed: Vec<&doctor::Probe> = probes.iter().filter(|probe| !probe.outcome.is_ok()).collect();
    write(out, String::new())?;
    if failed.is_empty() {
        write(
            out,
            format!(
                "{} upstream(s) asked, all answered.",
                probes.iter().filter(|p| p.outcome != doctor::Outcome::Skipped).count()
            ),
        )?;
    } else {
        write(
            out,
            format!(
                "{} of {} upstream(s) could not be reached: {}.",
                failed.len(),
                probes.len(),
                failed.iter().map(|p| p.service.as_str()).collect::<Vec<_>>().join(", ")
            ),
        )?;
    }
    Ok(failed.is_empty())
}

/// Whether any flag on this run selects an upstream.
///
/// `--doctor` on its own means "tell me about my setup", so it probes every upstream the build
/// knows about rather than nothing at all; naming the flags of a run still narrows it to those.
fn selects_an_upstream(args: &cli::Args, fetch_licenses: bool) -> bool {
    fetch_licenses
        || args.embedded_sboms
        || args.kev
        || args.epss
        || args.scorecard
        || args.vulnerabilities.is_some()
        || args.pypi_mapping == cli::PypiMappingSource::Prefix
        || args.report == Some(report::ReportKind::Outdated)
}

/// The archive hosts this run would read from, in the order the answer is trusted: the base the
/// operator named, else the hosts the lockfile itself names, else the public defaults.
///
/// `--fetch-licenses` reads a few kilobytes out of each package's archive, so these are real
/// upstreams. They had no single address to probe until now, which let `--doctor` report every
/// upstream answering while every wheel was about to fail.
fn archive_services(lockfile: Option<&std::path::Path>) -> Vec<http::Service> {
    let named = |name: &'static str, env: &'static str| mirror::base(env).map(|url| http::Service::new(name, url, env));
    let from_lock = lockfile
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|text| mirror::archive_hosts(&text));

    let mut services = Vec::new();
    for (name, env, from_lock_hosts, fallback) in [
        (
            "conda package archives",
            mirror::CONDA_ARCHIVE_URL_ENV,
            from_lock.as_ref().map(|(conda, _)| conda),
            mirror::DEFAULT_CONDA_ARCHIVE_HOST,
        ),
        (
            "PyPI wheel archives",
            mirror::WHEEL_ARCHIVE_URL_ENV,
            from_lock.as_ref().map(|(_, wheel)| wheel),
            mirror::DEFAULT_WHEEL_ARCHIVE_HOST,
        ),
    ] {
        if let Some(service) = named(name, env) {
            services.push(service);
        } else if let Some(hosts) = from_lock_hosts {
            // A lockfile that names no archive of this kind has nothing to probe for it.
            services.extend(
                hosts
                    .iter()
                    .map(|host| http::Service::sourced(name, host.clone(), "pixi.lock")),
            );
        } else {
            services.push(http::Service::fixed(name, fallback));
        }
    }
    services
}

/// The lockfile `--doctor` should read for archive hosts, when one can be found.
///
/// Opportunistic: `--doctor` is documented to need no lockfile, so a failure here is silence
/// rather than an error.
fn doctor_lockfile(args: &cli::Args) -> Option<std::path::PathBuf> {
    let start = std::env::current_dir().ok()?;
    discover::resolve_lockfile(args.lockfile.as_deref(), &start).ok()
}

/// Every upstream this build can reach, for a `--doctor` run that named no flags.
///
/// `--report outdated` is the only thing that reaches anaconda.org and `--doctor` conflicts with
/// `--report`, so without this the one host a restricted network is most likely to block could
/// never be probed at all.
/// The conda index `--report outdated` would ask, at the address its kind resolves to.
///
/// One row either way: which service answers is the kind's business, and `--doctor` should report
/// the one this run would actually use rather than a fixed host.
fn conda_index_service(kind: cli::CondaIndexKind) -> http::Service {
    match kind {
        cli::CondaIndexKind::Prefix => http::Service::new(
            "conda package index",
            outdated::prefix_index_url(),
            outdated::PREFIX_INDEX_URL_ENV,
        ),
        cli::CondaIndexKind::Anaconda => http::Service::new(
            "conda package index",
            outdated::anaconda_url(),
            outdated::ANACONDA_URL_ENV,
        ),
    }
}

fn every_service(lockfile: Option<&std::path::Path>, kind: cli::CondaIndexKind) -> Vec<http::Service> {
    vec![
        http::Service::new("PyPI index", pypi::index_url(), pypi::INDEX_URL_ENV),
        http::Service::new(
            "conda-forge PyPI mapping",
            mapping::mapping_url(),
            mapping::MAPPING_URL_ENV,
        ),
        http::Service::new("OSV", osv::api_url(), osv::API_URL_ENV),
        http::Service::new("CISA KEV", kev::url(), kev::URL_ENV),
        http::Service::new("FIRST EPSS", epss::url(), epss::URL_ENV),
        conda_index_service(kind),
        http::Service::new("OpenSSF Scorecard", scorecard::url(), scorecard::SCORECARD_URL_ENV),
    ]
    .into_iter()
    .chain(archive_services(lockfile))
    .collect()
}

/// The upstreams this run may use, given the flags, with their addresses resolved the way the
/// code that calls them resolves them.
fn network_configuration(args: &cli::Args, fetch_licenses: bool, tls_roots: &http::TlsRoots) -> http::Configuration {
    if args.doctor && !selects_an_upstream(args, fetch_licenses) {
        let lockfile = doctor_lockfile(args);
        return http::Configuration::resolve(
            every_service(lockfile.as_deref(), args.conda_index_kind),
            mapping::cache_dir(),
            tls_roots,
        );
    }
    let mut services = Vec::new();
    // Wheel metadata and release facts both come from the index.
    if fetch_licenses || args.report == Some(report::ReportKind::Outdated) {
        services.push(http::Service::new("PyPI index", pypi::index_url(), pypi::INDEX_URL_ENV));
    }
    if args.pypi_mapping == cli::PypiMappingSource::Prefix {
        services.push(http::Service::new(
            "conda-forge PyPI mapping",
            mapping::mapping_url(),
            mapping::MAPPING_URL_ENV,
        ));
    }
    if args.vulnerabilities.is_some() {
        services.push(http::Service::new("OSV", osv::api_url(), osv::API_URL_ENV));
    }
    if args.kev {
        services.push(http::Service::new("CISA KEV", kev::url(), kev::URL_ENV));
    }
    if args.epss {
        services.push(http::Service::new("FIRST EPSS", epss::url(), epss::URL_ENV));
    }
    if args.report == Some(report::ReportKind::Outdated) {
        services.push(conda_index_service(args.conda_index_kind));
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
        services.extend(archive_services(doctor_lockfile(args).as_deref()));
    }
    http::Configuration::resolve(services, mapping::cache_dir(), tls_roots)
}

/// One workspace to describe: its lockfile (or installed environment) and the documents that
/// come out of it.
#[derive(Debug)]
struct Workspace {
    lockfile: std::path::PathBuf,
    input: Input,
    targets: Vec<Target>,
}

/// Read the lockfile at `lockfile`, whichever kind it is: by name for the kinds that have one,
/// by its `@EXPLICIT` line for an explicit spec file, and as `pixi.lock` otherwise.
fn read_input(lockfile: &Path) -> Result<Input> {
    let manifest = || timings::time(timings::Phase::Manifest, || manifest::read(lockfile));
    if condalock::is_conda_lock_name(lockfile) {
        let condalock::Loaded { lock, contents } = timings::time(timings::Phase::Input, || condalock::load(lockfile))?;
        return Ok(Input::CondaLock {
            lock,
            contents,
            manifest: manifest(),
        });
    }
    if pdm::is_pdm_lock_name(lockfile) {
        let pdm::Loaded { lock, contents } = timings::time(timings::Phase::Input, || pdm::load(lockfile))?;
        return Ok(Input::Pdm {
            lock,
            contents,
            manifest: manifest(),
        });
    }
    if poetry::is_poetry_lock_name(lockfile) {
        let poetry::Loaded { lock, contents } = timings::time(timings::Phase::Input, || poetry::load(lockfile))?;
        return Ok(Input::Poetry {
            lock,
            contents,
            manifest: manifest(),
        });
    }
    if uv::is_uv_lock_name(lockfile) {
        let uv::Loaded { lock, contents } = timings::time(timings::Phase::Input, || uv::load(lockfile))?;
        return Ok(Input::Uv {
            lock,
            contents,
            manifest: manifest(),
        });
    }
    if pylock::is_pylock_name(lockfile) {
        let pylock::Loaded { lock, contents } = timings::time(timings::Phase::Input, || pylock::load(lockfile))?;
        return Ok(Input::Pylock {
            lock,
            contents,
            manifest: manifest(),
        });
    }
    // An explicit spec file is recognised by its @EXPLICIT line; its name says nothing.
    if explicit::is_explicit(lockfile) {
        let explicit::Loaded { explicit, contents } =
            timings::time(timings::Phase::Input, || explicit::load(lockfile))?;
        return Ok(Input::Explicit {
            explicit,
            contents,
            manifest: manifest(),
        });
    }
    // A manifest that declares rather than locks: say which command locks it, rather than failing
    // to parse it as a pixi.lock.
    if let Some(not_a_lock) = pixi_sbom::unlocked::diagnose(lockfile) {
        return Err(miette::Report::new(not_a_lock));
    }
    // A pinned requirements file (pip-compile's), by its name and its plain requirement lines.
    if requirements::is_requirements(lockfile) {
        let requirements::Loaded { requirements, contents } =
            timings::time(timings::Phase::Input, || requirements::load(lockfile))?;
        return Ok(Input::Requirements {
            requirements,
            contents,
            manifest: manifest(),
        });
    }
    let lock::LoadedLock { lock, contents } = timings::time(timings::Phase::Input, || lock::load(lockfile))?;
    Ok(Input::Lock {
        lock,
        contents,
        manifest: manifest(),
    })
}

/// One workspace a `--scan` found: its lockfile read, and its documents placed under the
/// output directory at the same relative path, so two workspaces never collide.
///
/// A pixi workspace gets its environments and platforms as a single run would; any other kind of
/// lockfile describes one environment, so it gets one document, whatever `--all-environments`
/// or `--all-platforms` asked of the pixi workspaces beside it.
fn scanned_workspace(args: &cli::Args, scanned: &Path, lockfile: std::path::PathBuf) -> Result<Workspace> {
    let input = read_input(&lockfile)?;
    let dir = lockfile.parent().unwrap_or(Path::new(".")).to_path_buf();
    let relative = dir.strip_prefix(scanned).unwrap_or(Path::new(""));
    let output_dir = match &args.output {
        Some(output) => output.join(relative),
        None => dir.clone(),
    };
    let targets = match &input {
        Input::Lock { lock, .. } => resolve_targets(args, lock, &lockfile, Some(&output_dir))?,
        _ => {
            if args.all_environments || args.all_platforms || args.environment != "default" {
                tracing::debug!(
                    lockfile = %lockfile.display(),
                    "the environment and platform flags choose among a pixi workspace's; this lockfile gets one document"
                );
            }
            let environment = match &input {
                Input::Pylock { .. } => pylock::environment_name(&lockfile),
                _ => "default".to_string(),
            };
            vec![Target {
                environment,
                platform: args.platform.clone(),
                output: discover::Output::File(output_dir.join(args.format.default_file_name())),
            }]
        }
    };
    Ok(Workspace {
        lockfile,
        input,
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
    /// A fully pinned requirements file, with its text and the manifest beside it (for the
    /// project's name; the file's own `# via -r` lines say what it declared).
    Requirements {
        requirements: requirements::Requirements,
        contents: String,
        manifest: manifest::Manifest,
    },
    /// An explicit conda spec file (`@EXPLICIT`), with its text and the manifest beside it.
    Explicit {
        explicit: explicit::Explicit,
        contents: String,
        manifest: manifest::Manifest,
    },
    /// A unified `conda-lock.yml`, with its text and the manifest beside it.
    CondaLock {
        lock: condalock::CondaLock,
        contents: String,
        manifest: manifest::Manifest,
    },
    /// A `pdm.lock`, with its text and the manifest beside it.
    Pdm {
        lock: pdm::PdmLock,
        contents: String,
        manifest: manifest::Manifest,
    },
    /// A `poetry.lock`, with its text and the manifest beside it (the project's name and what it
    /// asked for live there, not in the lock).
    Poetry {
        lock: poetry::PoetryLock,
        contents: String,
        manifest: manifest::Manifest,
    },
    /// A `uv.lock`, with its text and the manifest beside it.
    Uv {
        lock: uv::UvLock,
        contents: String,
        manifest: manifest::Manifest,
    },
    /// A PEP 751 `pylock.toml`, with its text and the manifest beside it (for the project's name).
    Pylock {
        lock: pylock::Pylock,
        contents: String,
        manifest: manifest::Manifest,
    },
    /// An installed environment (`--prefix`).
    Prefix {
        dir: std::path::PathBuf,
        root: model::Root,
        /// `--infer-extras`.
        infer_extras: bool,
    },
    /// An existing document (`--from-sbom`), already read into the model.
    Document(Box<fromsbom::Loaded>),
}

impl Input {
    /// The manifest read beside the input, for a lockfile of any kind.
    fn manifest(&self) -> Option<&manifest::Manifest> {
        match self {
            Input::Lock { manifest, .. }
            | Input::Explicit { manifest, .. }
            | Input::Requirements { manifest, .. }
            | Input::CondaLock { manifest, .. }
            | Input::Pdm { manifest, .. }
            | Input::Poetry { manifest, .. }
            | Input::Uv { manifest, .. }
            | Input::Pylock { manifest, .. } => Some(manifest),
            _ => None,
        }
    }
}

/// Several documents merged into one, as the input a single `--from-sbom` would have been.
fn merged_document(args: &cli::Args, inputs: &[merge::Input], loaded: &[fromsbom::Loaded]) -> fromsbom::Loaded {
    let root = model::Root {
        name: args.root_name.clone().unwrap_or_else(|| "merged".to_string()),
        version: args.root_version.clone(),
        ..model::Root::default()
    };
    let sbom = merge::merge(inputs, root);
    let conflicts = sbom
        .packages
        .iter()
        .filter(|p| p.properties.contains_key(merge::CONFLICT_PROPERTY))
        .count();
    tracing::info!(
        documents = inputs.len(),
        packages = sbom.packages.len(),
        conflicts,
        "merged the documents into one"
    );
    fromsbom::Loaded {
        sbom,
        // What identifies the input for the document's own identity: every source's text.
        contents: loaded
            .iter()
            .map(|l| l.contents.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        format: format!(
            "merged ({})",
            loaded.iter().map(|l| l.format.as_str()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// `--scan --merge`: every workspace's documents merged into one, written once.
fn merge_workspaces(args: &cli::Args, dir: &Path, workspaces: &[Workspace]) -> Result<Workspace> {
    let mut inputs = Vec::new();
    let mut loaded = Vec::new();
    for workspace in workspaces {
        // With `/` on every platform, so the same tree gives the same document anywhere.
        let relative = workspace
            .lockfile
            .strip_prefix(dir)
            .unwrap_or(&workspace.lockfile)
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        for target in &workspace.targets {
            let (sbom, contents) = model_for(workspace, &target.environment, target.platform.as_deref())?;
            let name = if workspace.targets.len() > 1 {
                format!("{relative} ({}/{})", sbom.environment, sbom.platform)
            } else {
                relative.clone()
            };
            loaded.push(fromsbom::Loaded {
                sbom: sbom.clone(),
                contents,
                format: "lockfile".to_string(),
            });
            inputs.push(merge::Input { name, sbom });
        }
    }
    let lockfile = dir.join(discover::LOCKFILE_NAME);
    let document = merged_document(args, &inputs, &loaded);
    Ok(Workspace {
        targets: vec![Target {
            environment: document.sbom.environment.clone(),
            platform: args.platform.clone(),
            output: discover::resolve_output(args.output.as_deref(), &lockfile, args.format),
        }],
        input: Input::Document(Box::new(document)),
        lockfile,
    })
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
/// Look every document's packages up at once, instead of once per document.
///
/// Returns `None` when there is only one document, or when nothing would be looked up: the
/// single-document run pays nothing for this and takes the ordinary path.
fn shared_enrichment(
    args: &cli::Args,
    targets: &[(&Workspace, &Target)],
    package_filter: &filter::Filter,
    pypi_mapping: Option<&mapping::PypiMapping>,
    progress: progress::Progress,
) -> Result<Option<batch::Shared>> {
    let fetch_licenses = args.fetch_licenses || args.pypi_licenses;
    if targets.len() < 2 || !(fetch_licenses || args.embedded_sboms) {
        return Ok(None);
    }
    // `--embedded-sboms` and `--prefix` add components rather than filling fields in, and what
    // they add depends on the document they are adding it to, so those runs keep to the
    // per-document path.
    if args.embedded_sboms
        || targets
            .iter()
            .any(|(workspace, _)| matches!(workspace.input, Input::Prefix { .. }))
    {
        return Ok(None);
    }

    let mut documents = Vec::with_capacity(targets.len());
    for (workspace, target) in targets {
        let (mut sbom, _) = model_for(workspace, &target.environment, target.platform.as_deref())?;
        // The same steps the per-document path runs before enrichment, so the union holds the
        // packages that will actually be looked up.
        if !package_filter.is_empty() {
            package_filter.apply(&mut sbom);
        }
        if let Some(mapping) = pypi_mapping {
            mapping::enrich(&mut sbom, mapping);
        }
        if args.primary_purl == cli::PrimaryPurl::Pypi {
            mapping::prefer_pypi_purl(&mut sbom);
        }
        documents.push(sbom);
    }

    let before = batch::union(&documents);
    if before.packages.is_empty() {
        return Ok(None);
    }
    let savings = documents.iter().map(|d| d.packages.len()).sum::<usize>();
    tracing::info!(
        documents = documents.len(),
        packages = before.packages.len(),
        instead_of = savings,
        "looking every document's packages up at once"
    );
    let mut after = before.clone();
    // The input is only read for the `cargo auditable` step, which needs an installed prefix;
    // this path has already refused those.
    let input = &targets[0].0.input;
    enrich(&mut after, args, input, progress);
    let shared = batch::Shared::between(&before, &after);
    tracing::debug!(learned = shared.len(), "the shared lookups finished");
    Ok(Some(shared))
}

/// The document's model, before anything is looked up: the lockfile environment, the
/// installed prefix or the source document, plus the text that identifies it.
fn model_for(workspace: &Workspace, environment: &str, platform: Option<&str>) -> Result<(model::Sbom, String)> {
    let (lockfile, input) = (&workspace.lockfile, &workspace.input);
    let (sbom, contents) = match input {
        Input::Lock {
            lock,
            contents,
            manifest,
        } => {
            let selection = lock::Selection { environment, platform };
            let mut sbom = lock::sbom_from_lock_with_extras(
                lock,
                selection,
                manifest.root.clone(),
                &discover::lockfile_name(lockfile),
                &manifest.requested_extras(environment),
            )?;
            // What the workspace asked for itself, as opposed to what came along.
            manifest.apply(&mut sbom);
            (sbom, contents.clone())
        }
        Input::Requirements {
            requirements,
            contents,
            manifest,
        } => {
            let sbom = requirements::build_sbom(
                requirements,
                platform,
                manifest.root.clone(),
                &discover::lockfile_name(lockfile),
            )?;
            (sbom, contents.clone())
        }
        Input::Explicit {
            explicit,
            contents,
            manifest,
        } => {
            let mut sbom = explicit::build_sbom(
                explicit,
                platform,
                manifest.root.clone(),
                &discover::lockfile_name(lockfile),
            )?;
            manifest.apply(&mut sbom);
            (sbom, contents.clone())
        }
        Input::CondaLock {
            lock,
            contents,
            manifest,
        } => {
            let mut sbom = condalock::build_sbom(
                lock,
                platform,
                manifest.root.clone(),
                &discover::lockfile_name(lockfile),
            )?;
            manifest.apply(&mut sbom);
            (sbom, contents.clone())
        }
        Input::Pdm {
            lock,
            contents,
            manifest,
        } => {
            let mut sbom = pdm::build_sbom(
                lock,
                platform,
                manifest.root.clone(),
                &discover::lockfile_name(lockfile),
            )?;
            manifest.apply(&mut sbom);
            (sbom, contents.clone())
        }
        Input::Poetry {
            lock,
            contents,
            manifest,
        } => {
            let mut sbom = poetry::build_sbom(
                lock,
                platform,
                manifest.root.clone(),
                &discover::lockfile_name(lockfile),
            )?;
            manifest.apply(&mut sbom);
            (sbom, contents.clone())
        }
        Input::Uv {
            lock,
            contents,
            manifest,
        } => {
            let mut sbom = uv::build_sbom(
                lock,
                platform,
                manifest.root.clone(),
                &discover::lockfile_name(lockfile),
            )?;
            manifest.apply(&mut sbom);
            (sbom, contents.clone())
        }
        Input::Pylock {
            lock,
            contents,
            manifest,
        } => {
            let mut sbom = pylock::build_sbom(
                lock,
                environment,
                platform,
                manifest.root.clone(),
                &discover::lockfile_name(lockfile),
            )?;
            manifest.apply(&mut sbom);
            (sbom, contents.clone())
        }
        Input::Prefix {
            dir,
            root,
            infer_extras,
        } => {
            let mut sbom = prefix::build_sbom(dir, root.clone(), platform)?;
            if *infer_extras {
                prefix::infer_extras(dir, &mut sbom);
            }
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
    Ok((sbom, contents))
}

/// Fill in what the lockfile does not say: licenses from wheels, from the extracted package
/// cache and from channel archives, the release facts PyPI knows, and — with `--embedded-sboms`
/// — the components a wheel ships an SBOM for.
///
/// Split out of the run so a batch can do it once over every document's packages at once
/// rather than once per document (see [`pixi_sbom::batch`]).
fn enrich(sbom: &mut model::Sbom, args: &cli::Args, input: &Input, progress: progress::Progress) {
    let fetch_licenses = args.fetch_licenses || args.pypi_licenses;
    if !(fetch_licenses || args.embedded_sboms) {
        return;
    }
    {
        let pkgs = pkgcache::package_cache_dir();
        let cache_dir = mapping::cache_dir();
        let wheel::Outcome {
            fetched,
            failed,
            skipped,
        } = timings::time(timings::Phase::Wheels, || {
            wheel::enrich(sbom, &cache_dir, args.license_texts, progress)
        });
        tracing::info!(fetched, failed, skipped, "read PyPI license details from wheels");
        sbom.incomplete
            .note_failures("wheel-licenses", failed, fetched + failed, "wheel reads");
        if args.embedded_sboms {
            let embedded::Outcome {
                files,
                unreadable,
                added,
                merged,
            } = embedded::enrich(sbom, &cache_dir);
            tracing::info!(files, unreadable, added, merged, "attached embedded SBOM components");
            // An installed environment is the only place the binaries themselves are, and
            // conda-forge builds its Rust packages with `cargo auditable`.
            if let Input::Prefix { dir, .. } = input {
                let auditable::Outcome {
                    binaries,
                    added,
                    merged,
                } = auditable::enrich(sbom, dir, progress);
                tracing::info!(binaries, added, merged, "read cargo auditable crate lists");
                // Python distributions a package ships inside itself (setuptools/_vendor).
                let prefix::VendoredOutcome { added, merged } = prefix::attach_vendored(sbom, dir);
                tracing::info!(added, merged, "attached vendored Python distributions");
            }
        }
        let pkgcache::Outcome {
            found,
            licenses_filled,
            files,
            missing,
        } = if fetch_licenses {
            timings::time(timings::Phase::PackageCache, || {
                pkgcache::enrich(sbom, &pkgs, args.license_texts, progress)
            })
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
            } = timings::time(timings::Phase::Archives, || {
                condaarchive::enrich(sbom, &missing, &cache_dir, args.license_texts, progress)
            });
            tracing::info!(
                fetched,
                failed,
                skipped,
                "read conda license details from channel archives"
            );
            sbom.incomplete
                .note_failures("conda-archives", failed, fetched + failed, "archive reads");
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
            } = timings::time(timings::Phase::Pypi, || lookup.run(sbom, progress));
            timings::describe(timings::Phase::Pypi, format!("{found} found, {failed} failed"));
            tracing::info!(found, missing, failed, yanked, "looked up PyPI releases");
            sbom.incomplete
                .note_failures("pypi-releases", failed, found + missing + failed, "index lookups");
        }
    }
}

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
) -> Result<bool> {
    let output = match output {
        discover::Output::Stdout => {
            // Buffered, as the file path already is. The writers serialize straight out in
            // many small pieces, and Rust's stdout flushes on every newline: writing a
            // ten-thousand-package document to a pipe took twice as long as writing it to a
            // file, all of it in syscalls nobody needed.
            let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
            format::write(format, sbom, ctx, &mut stdout)?;
            stdout.flush().into_diagnostic().wrap_err("cannot write to stdout")?;
            return Ok(true);
        }
        discover::Output::File(path) => path,
    };
    if format::unchanged_but_for_timestamp(format, sbom, ctx, output) {
        return Ok(false);
    }
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
    Ok(true)
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

fn init_tracing(args: &cli::Args, format: cli::LogFormat) {
    let filter = EnvFilter::builder()
        .with_default_directive(args.verbosity.tracing_level_filter().into())
        .from_env_lossy();
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(ProgressAwareStderr);
    match format {
        // A person reading along in a terminal knows what time it is; the timestamp would be
        // the widest column in the log and say the least.
        cli::LogFormat::Text => builder.with_ansi(std::io::stderr().is_terminal()).without_time().init(),
        // A collector wants the timestamp back, every field as a field rather than prose, and
        // no escape codes: nothing reading this is a terminal.
        cli::LogFormat::Json => builder.with_ansi(false).json().init(),
    }
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
