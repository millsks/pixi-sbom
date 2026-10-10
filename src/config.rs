//! Configuration files for the settings that otherwise make CI invocations long, read before the
//! command line with the command line winning. Keys mirror the long flags; unknown keys are errors
//! so a typo cannot pass silently.
//!
//! There are three layers, read least specific first and merged per key, so a machine can state
//! what is true of its network once and a workspace need not repeat it:
//!
//! | Layer | Where |
//! |---|---|
//! | system | `/etc/pixi/pixi-sbom-config.toml`, or `%PROGRAMDATA%\pixi\` on Windows |
//! | user | `$PIXI_HOME/pixi-sbom-config.toml`, else `~/.pixi/pixi-sbom-config.toml` |
//! | project | `<workspace>/.pixi/pixi-sbom-config.toml`, else `[tool.pixi-sbom]` in `pyproject.toml`, else the deprecated `pixi-sbom.toml` |
//!
//! Those are pixi's own configuration directories, so `pixi config edit --global` and this file sit
//! together. The name is pixi's word for what it is: `pixi.toml` is a manifest, `config.toml` is
//! settings, and this is settings that need a prefix because they share a directory with pixi's.
//!
//! `--config` replaces the search rather than adding to it, and `--no-config` reads nothing at all
//! (pixi's own `--no-config` keeps project-local files; ours is frozen as the broader meaning).

use std::path::{Path, PathBuf};

use clap::{ArgMatches, ValueEnum, parser::ValueSource};
use serde::Deserialize;

use crate::cli::{
    Args, CondaIndexKind, DiffSection, FailOnSeverity, Format, Kind, PrimaryPurl, PypiMappingSource, SpecVersion,
    VulnerabilitySource,
};

/// The configuration file, in pixi's configuration directories and in `<workspace>/.pixi`.
pub const FILE_NAME: &str = "pixi-sbom-config.toml";

/// The workspace-root file this replaced. Still read, and warned about, until 2.0.
pub const LEGACY_FILE_NAME: &str = "pixi-sbom.toml";

/// Why the configuration could not be used.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum ConfigError {
    /// `--config` names a file that cannot be read.
    #[error("cannot read the configuration file {path}: {source}")]
    #[diagnostic(
        code(pixi_sbom::config::read),
        help("check the path --config was given and its permissions, or pass --no-config to run without a file")
    )]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML, or has a key or value this version does not know.
    #[error("invalid configuration in {path}: {message}")]
    #[diagnostic(
        code(pixi_sbom::config::parse),
        help("keys mirror the long command-line flags, e.g. `format = \"spdx\"`, `deny-license = [\"GPL-3.0-only\"]`")
    )]
    Parse { path: PathBuf, message: String },
}

/// The settings a file may carry. Every field is optional; a missing one leaves the command
/// line's value (or its default) alone.
// The scorecard thresholds are scores, so this cannot be `Eq`.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub format: Option<String>,
    pub spec_version: Option<String>,
    pub pypi_mapping: Option<String>,
    pub pypi_mapping_file: Option<PathBuf>,
    pub conda_index_kind: Option<String>,
    pub concurrency: Option<usize>,
    pub primary_purl: Option<String>,
    pub fetch_licenses: Option<bool>,
    pub license_texts: Option<bool>,
    pub embedded_sboms: Option<bool>,
    pub infer_extras: Option<bool>,
    pub exclude: Option<Vec<String>>,
    pub include: Option<Vec<String>>,
    pub exclude_kind: Option<Vec<String>>,
    pub keep_orphans: Option<bool>,
    pub allow_license: Option<Vec<String>>,
    pub deny_license: Option<Vec<String>>,
    pub require_license: Option<bool>,
    pub fail_on_yanked: Option<bool>,
    pub vulnerabilities: Option<String>,
    pub kev: Option<bool>,
    pub fail_on_kev: Option<bool>,
    pub epss: Option<bool>,
    pub fail_on_epss: Option<f64>,
    pub fail_on_severity: Option<String>,
    pub ignore_vuln: Option<Vec<String>>,
    pub vex_in: Option<Vec<PathBuf>>,
    pub ignore_license: Option<Vec<String>>,
    pub scorecard: Option<bool>,
    pub scorecard_min: Option<f64>,
    pub fail_on_scorecard: Option<f64>,
    pub min_quality: Option<u8>,
    pub fail_on_diff: Option<Vec<String>>,
    pub source: Option<Vec<PathBuf>>,
    pub assume_used: Option<Vec<String>>,
    pub fail_on_phantom: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct PyProject {
    #[serde(default)]
    tool: Option<Tool>,
}

#[derive(Debug, Deserialize)]
struct Tool {
    #[serde(rename = "pixi-sbom")]
    pixi_sbom: Option<toml::Value>,
}

/// Which location a layer was read from, least specific first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Source {
    /// `/etc/pixi/pixi-sbom-config.toml`, or `%PROGRAMDATA%\pixi\` on Windows.
    System,
    /// `$PIXI_HOME/pixi-sbom-config.toml`, else `~/.pixi/pixi-sbom-config.toml`.
    User,
    /// `<workspace>/.pixi/pixi-sbom-config.toml`.
    Project,
    /// `[tool.pixi-sbom]` in the `pyproject.toml` next to the lockfile.
    Pyproject,
    /// `<workspace>/pixi-sbom.toml`, replaced by [`Source::Project`] and unread from 2.0.
    Legacy,
    /// Named by `--config`, which replaces the search rather than adding to it.
    Explicit,
}

impl Source {
    /// What the logs call it.
    pub fn label(self) -> &'static str {
        match self {
            Source::System => "system",
            Source::User => "user",
            Source::Project => "project",
            Source::Pyproject => "[tool.pixi-sbom] in pyproject.toml",
            Source::Legacy => "project",
            Source::Explicit => "--config",
        }
    }

    /// Whether reading from here should warn.
    pub fn deprecated(self) -> bool {
        self == Source::Legacy
    }
}

/// Where a configuration came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    pub config: Config,
    pub path: PathBuf,
    pub source: Source,
}

/// pixi's own configuration directories, least specific first, so that this file sits beside the
/// `config.toml` that `pixi config edit --system` and `--global` write.
fn pixi_config_dirs(env: impl Fn(&str) -> Option<PathBuf>) -> Vec<(Source, PathBuf)> {
    let mut dirs = Vec::new();
    let system = if cfg!(windows) {
        env("PROGRAMDATA").map(|dir| dir.join("pixi"))
    } else {
        Some(PathBuf::from("/etc/pixi"))
    };
    if let Some(dir) = system {
        dirs.push((Source::System, dir));
    }
    // `PIXI_HOME` is what pixi itself honours; `~/.pixi` is where it puts the directory otherwise.
    let user = env("PIXI_HOME")
        .or_else(|| env(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).map(|home| home.join(".pixi")));
    if let Some(dir) = user {
        dirs.push((Source::User, dir));
    }
    dirs
}

/// Find and parse every configuration layer, least specific first: `explicit` alone when given,
/// else the system and user files and the one project file. Empty when there is none.
pub fn load(lockfile_dir: &Path, explicit: Option<&Path>) -> Result<Vec<Loaded>, ConfigError> {
    let dirs = pixi_config_dirs(|name| std::env::var_os(name).map(PathBuf::from));
    load_from(&dirs, lockfile_dir, explicit)
}

fn load_from(
    dirs: &[(Source, PathBuf)],
    lockfile_dir: &Path,
    explicit: Option<&Path>,
) -> Result<Vec<Loaded>, ConfigError> {
    if let Some(path) = explicit {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        return Ok(vec![parse_file(path, &text, Source::Explicit)?]);
    }
    let mut layers = Vec::new();
    for (source, dir) in dirs {
        let path = dir.join(FILE_NAME);
        // A directory that has no file for us is the normal case, not a problem to report.
        if let Ok(text) = std::fs::read_to_string(&path) {
            layers.push(parse_file(&path, &text, *source)?);
        }
    }
    if let Some(project) = project_layer(lockfile_dir)? {
        layers.push(project);
    }
    Ok(layers)
}

/// The one project-level file: the pixi-aligned location, else the `pyproject.toml` table, else
/// the deprecated workspace-root file. First found wins rather than merging, because a workspace
/// saying the same thing in two files is a mistake worth leaving visible.
fn project_layer(lockfile_dir: &Path) -> Result<Option<Loaded>, ConfigError> {
    let aligned = lockfile_dir.join(".pixi").join(FILE_NAME);
    if let Ok(text) = std::fs::read_to_string(&aligned) {
        return parse_file(&aligned, &text, Source::Project).map(Some);
    }
    let pyproject = lockfile_dir.join("pyproject.toml");
    if let Ok(text) = std::fs::read_to_string(&pyproject)
        && let Some(loaded) = parse_pyproject(&pyproject, &text)?
    {
        return Ok(Some(loaded));
    }
    let legacy = lockfile_dir.join(LEGACY_FILE_NAME);
    match std::fs::read_to_string(&legacy) {
        Ok(text) => {
            tracing::warn!(
                path = %legacy.display(),
                move_to = %aligned.display(),
                "`{LEGACY_FILE_NAME}` at the workspace root is deprecated and will not be read from 2.0"
            );
            parse_file(&legacy, &text, Source::Legacy).map(Some)
        }
        Err(_) => Ok(None),
    }
}

/// Apply every layer in order, so a more specific one overwrites what a less specific one said and
/// inherits what it did not mention.
pub fn apply_all(layers: &[Loaded], args: &mut Args, matches: &ArgMatches) -> Result<(), ConfigError> {
    for loaded in layers {
        apply(loaded, args, matches)?;
    }
    Ok(())
}

fn parse_file(path: &Path, text: &str, source: Source) -> Result<Loaded, ConfigError> {
    // A standalone file may also use the pyproject layout, so both spellings work.
    let value: toml::Value = toml::from_str(text).map_err(|err| ConfigError::Parse {
        path: path.to_path_buf(),
        message: err.message().to_string(),
    })?;
    let table = value
        .get("tool")
        .and_then(|t| t.get("pixi-sbom"))
        .cloned()
        .unwrap_or(value);
    let config: Config = table.try_into().map_err(|err: toml::de::Error| ConfigError::Parse {
        path: path.to_path_buf(),
        message: err.message().to_string(),
    })?;
    Ok(Loaded {
        config,
        path: path.to_path_buf(),
        source,
    })
}

fn parse_pyproject(path: &Path, text: &str) -> Result<Option<Loaded>, ConfigError> {
    // Only the `[tool.pixi-sbom]` table matters; anything else in the file is not ours to
    // judge, so a pyproject.toml without the table is simply not a configuration.
    let Ok(project) = toml::from_str::<PyProject>(text) else {
        return Ok(None);
    };
    let Some(table) = project.tool.and_then(|t| t.pixi_sbom) else {
        return Ok(None);
    };
    let config: Config = table.try_into().map_err(|err: toml::de::Error| ConfigError::Parse {
        path: path.to_path_buf(),
        message: format!("[tool.pixi-sbom]: {}", err.message()),
    })?;
    Ok(Some(Loaded {
        config,
        path: path.to_path_buf(),
        source: Source::Pyproject,
    }))
}

/// Whether the command line set `id` itself (as opposed to a default).
fn on_cli(matches: &ArgMatches, id: &str) -> bool {
    matches.value_source(id) == Some(ValueSource::CommandLine)
}

fn parse_enum<T: ValueEnum>(path: &Path, key: &str, value: &str) -> Result<T, ConfigError> {
    T::from_str(value, true).map_err(|_| ConfigError::Parse {
        path: path.to_path_buf(),
        message: format!(
            "`{key}` must be one of {}, not \"{value}\"",
            T::value_variants()
                .iter()
                .filter_map(|v| v.to_possible_value())
                .map(|p| format!("\"{}\"", p.get_name()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

/// Fill in every setting the command line did not give from `config`. Command-line values win
/// wherever they were written, including lists (a list on the command line replaces the file's
/// list rather than extending it).
pub fn apply(loaded: &Loaded, args: &mut Args, matches: &ArgMatches) -> Result<(), ConfigError> {
    let config = &loaded.config;
    let path = loaded.path.as_path();
    // Which settings the file supplied and which the command line overrode; logged together
    // at the end, because "the flag has no effect" usually starts here.
    let mut applied: Vec<String> = Vec::new();
    let mut overridden: Vec<String> = Vec::new();
    macro_rules! set {
        ($field:ident, $id:literal, $value:expr) => {
            if let Some(value) = $value {
                if on_cli(matches, $id) {
                    overridden.push($id.replace('_', "-"));
                } else {
                    args.$field = value;
                    applied.push($id.replace('_', "-"));
                }
            }
        };
    }
    /// Note a setting the file supplied, for the ones the macro does not cover.
    macro_rules! note {
        ($id:literal) => {
            if on_cli(matches, $id) {
                overridden.push($id.replace('_', "-"));
            } else {
                applied.push($id.replace('_', "-"));
            }
        };
    }
    if let Some(format) = &config.format {
        note!("format");
        if !on_cli(matches, "format") {
            args.format = parse_enum::<Format>(path, "format", format)?;
        }
    }
    if let Some(version) = &config.spec_version {
        note!("spec_version");
        if !on_cli(matches, "spec_version") {
            args.spec_version = Some(parse_enum::<SpecVersion>(path, "spec-version", version)?);
        }
    }
    // `pypi-mapping` and `pypi-mapping-file` exclude each other: a command-line choice of
    // either means the file's pair is left alone entirely.
    if on_cli(matches, "pypi_mapping") || on_cli(matches, "pypi_mapping_file") {
        // The command line chose one of the pair, so the file's pair is left alone entirely.
        for (supplied, id) in [
            (config.pypi_mapping_file.is_some(), "pypi-mapping-file"),
            (config.pypi_mapping.is_some(), "pypi-mapping"),
        ] {
            if supplied {
                overridden.push(id.to_string());
            }
        }
    } else {
        if let Some(file) = &config.pypi_mapping_file {
            // A relative path is relative to the configuration file, not the working directory.
            let base = loaded.path.parent().unwrap_or(Path::new("."));
            args.pypi_mapping_file = Some(if file.is_absolute() {
                file.clone()
            } else {
                base.join(file)
            });
            args.pypi_mapping = PypiMappingSource::Lock;
            note!("pypi_mapping_file");
        } else if let Some(source) = &config.pypi_mapping {
            args.pypi_mapping = parse_enum::<PypiMappingSource>(path, "pypi-mapping", source)?;
            note!("pypi_mapping");
        }
    }
    if let Some(kind) = &config.conda_index_kind {
        note!("conda_index_kind");
        if !on_cli(matches, "conda_index_kind") {
            args.conda_index_kind = parse_enum::<CondaIndexKind>(path, "conda-index-kind", kind)?;
        }
    }
    if let Some(purl) = &config.primary_purl {
        note!("primary_purl");
        if !on_cli(matches, "primary_purl") {
            args.primary_purl = parse_enum::<PrimaryPurl>(path, "primary-purl", purl)?;
        }
        args.primary_purl_chosen = true;
    }
    set!(concurrency, "concurrency", config.concurrency.map(Some));
    set!(fetch_licenses, "fetch_licenses", config.fetch_licenses);
    set!(license_texts, "license_texts", config.license_texts);
    set!(embedded_sboms, "embedded_sboms", config.embedded_sboms);
    set!(infer_extras, "infer_extras", config.infer_extras);
    set!(exclude, "exclude", config.exclude.clone());
    set!(include, "include", config.include.clone());
    if let Some(kinds) = &config.exclude_kind {
        note!("exclude_kind");
        if !on_cli(matches, "exclude_kind") {
            args.exclude_kind = kinds
                .iter()
                .map(|k| parse_enum::<Kind>(path, "exclude-kind", k))
                .collect::<Result<_, _>>()?;
        }
    }
    set!(keep_orphans, "keep_orphans", config.keep_orphans);
    set!(allow_license, "allow_license", config.allow_license.clone());
    set!(deny_license, "deny_license", config.deny_license.clone());
    set!(require_license, "require_license", config.require_license);
    set!(ignore_license, "ignore_license", config.ignore_license.clone());
    set!(scorecard, "scorecard", config.scorecard);
    set!(scorecard_min, "scorecard_min", config.scorecard_min);
    if let Some(min) = config.fail_on_scorecard {
        note!("fail_on_scorecard");
        if !on_cli(matches, "fail_on_scorecard") {
            args.fail_on_scorecard = Some(min);
        }
    }
    if let Some(min) = config.min_quality {
        note!("min_quality");
        if !on_cli(matches, "min_quality") {
            args.min_quality = Some(min.min(100));
        }
    }
    set!(fail_on_yanked, "fail_on_yanked", config.fail_on_yanked);
    if let Some(source) = &config.vulnerabilities {
        note!("vulnerabilities");
        if !on_cli(matches, "vulnerabilities") {
            args.vulnerabilities = Some(parse_enum::<VulnerabilitySource>(path, "vulnerabilities", source)?);
        }
    }
    set!(kev, "kev", config.kev);
    set!(fail_on_kev, "fail_on_kev", config.fail_on_kev);
    set!(epss, "epss", config.epss);
    if let Some(threshold) = config.fail_on_epss {
        note!("fail_on_epss");
        if !(0.0..=1.0).contains(&threshold) {
            return Err(ConfigError::Parse {
                path: path.to_path_buf(),
                message: format!("`fail-on-epss` must be a probability between 0.0 and 1.0, not {threshold}"),
            });
        }
        if !on_cli(matches, "fail_on_epss") {
            args.fail_on_epss = Some(threshold);
        }
    }
    if let Some(severity) = &config.fail_on_severity {
        note!("fail_on_severity");
        if !on_cli(matches, "fail_on_severity") {
            args.fail_on_severity = Some(parse_enum::<FailOnSeverity>(path, "fail-on-severity", severity)?);
        }
    }
    set!(ignore_vuln, "ignore_vuln", config.ignore_vuln.clone());
    if let Some(sections) = &config.fail_on_diff {
        note!("fail_on_diff");
        if !on_cli(matches, "fail_on_diff") {
            args.fail_on_diff = sections
                .iter()
                .map(|s| parse_enum::<DiffSection>(path, "fail-on-diff", s))
                .collect::<Result<_, _>>()?;
        }
    }
    set!(source, "source", config.source.clone());
    set!(vex_in, "vex_in", config.vex_in.clone());
    set!(assume_used, "assume_used", config.assume_used.clone());
    set!(fail_on_phantom, "fail_on_phantom", config.fail_on_phantom);
    applied.sort();
    overridden.sort();
    tracing::debug!(
        path = %loaded.path.display(),
        layer = loaded.source.label(),
        applied = applied.join(", "),
        overridden_on_the_command_line = overridden.join(", "),
        "configuration file"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        for err in [
            ConfigError::Read {
                path: PathBuf::from("/workspace/pixi-sbom.toml"),
                source: std::io::Error::other("is a directory"),
            },
            ConfigError::Parse {
                path: PathBuf::from("/workspace/pixi-sbom.toml"),
                message: "unknown field `fmt`".to_string(),
            },
        ] {
            crate::assert_actionable(&err);
        }
    }

    fn args(cli: &[&str]) -> (Args, ArgMatches) {
        let matches = Args::command()
            .try_get_matches_from(std::iter::once("pixi-sbom").chain(cli.iter().copied()))
            .unwrap();
        (Args::from_arg_matches(&matches).unwrap(), matches)
    }

    fn loaded(text: &str) -> Loaded {
        parse_file(Path::new("pixi-sbom-config.toml"), text, Source::Project).unwrap()
    }

    /// `load_from` with no pixi directories, so a real `~/.pixi/pixi-sbom-config.toml` on the
    /// machine running the tests cannot reach them.
    fn load_project(dir: &Path, explicit: Option<&Path>) -> Result<Vec<Loaded>, ConfigError> {
        load_from(&[], dir, explicit)
    }

    #[test]
    fn the_file_says_which_settings_it_supplied_and_which_were_overridden() {
        // `apply` logs the two lists; this checks the bookkeeping behind them by applying a
        // file against a command line that sets one of the same settings.
        let cfg = loaded(
            r#"
            format = "spdx"
            fetch-licenses = true
            exclude = ["pre-commit*"]
            "#,
        );
        let (mut a, m) = args(&["--format", "cyclonedx"]);
        apply(&cfg, &mut a, &m).unwrap();
        assert_eq!(a.format, Format::Cyclonedx, "the command line wins");
        assert!(a.fetch_licenses, "and the rest of the file still applies");
        assert_eq!(a.exclude, ["pre-commit*"]);
    }

    #[test]
    fn file_fills_what_the_command_line_did_not_say() {
        let cfg = loaded(
            r#"
            format = "spdx"
            spec-version = "3.0"
            pypi-mapping = "prefix"
            conda-index-kind = "anaconda"
            concurrency = 25
            primary-purl = "pypi"
            fetch-licenses = true
            deny-license = ["GPL-3.0-only", "AGPL-3.0-only"]
            require-license = true
            ignore-license = ["mylib:internal, reviewed"]
            scorecard = true
            scorecard-min = 6.5
            exclude = ["pre-commit*"]
            exclude-kind = ["conda-source"]
            vulnerabilities = "osv"
            kev = true
            epss = true
            fail-on-epss = 0.1
            fail-on-severity = "high"
            ignore-vuln = ["GHSA-1:not reachable"]
            fail-on-diff = ["added", "removed"]
            source = ["src", "tests"]
            vex-in = ["vendor.openvex.json"]
            assume-used = ["pytest-*"]
            fail-on-phantom = true
            "#,
        );
        let (mut a, m) = args(&[]);
        apply(&cfg, &mut a, &m).unwrap();
        assert_eq!(a.format, Format::Spdx);
        assert_eq!(a.spec_version, Some(SpecVersion::V3_0));
        assert_eq!(a.pypi_mapping, PypiMappingSource::Prefix);
        assert_eq!(a.conda_index_kind, CondaIndexKind::Anaconda);
        assert_eq!(a.concurrency, Some(25));
        assert_eq!(a.primary_purl, PrimaryPurl::Pypi);
        assert!(a.primary_purl_chosen, "a configured primary-purl is a choice");
        assert!(!args(&[]).0.primary_purl_chosen);
        assert!(a.fetch_licenses);
        assert_eq!(a.deny_license, ["GPL-3.0-only", "AGPL-3.0-only"]);
        assert!(a.require_license);
        assert_eq!(a.ignore_license, ["mylib:internal, reviewed"]);
        assert!(a.scorecard);
        assert_eq!(a.scorecard_min, 6.5);
        assert_eq!(a.exclude, ["pre-commit*"]);
        assert_eq!(a.exclude_kind, [Kind::CondaSource]);
        assert_eq!(a.vulnerabilities, Some(VulnerabilitySource::Osv));
        assert!(a.kev);
        assert!(a.epss);
        assert_eq!(a.vex_in, [PathBuf::from("vendor.openvex.json")]);
        assert_eq!(a.fail_on_epss, Some(0.1));
        assert_eq!(a.fail_on_severity, Some(FailOnSeverity::High));
        assert_eq!(a.ignore_vuln, ["GHSA-1:not reachable"]);
        assert_eq!(a.fail_on_diff, [DiffSection::Added, DiffSection::Removed]);
        assert_eq!(a.source, [PathBuf::from("src"), PathBuf::from("tests")]);
        assert_eq!(a.assume_used, ["pytest-*"]);
        assert!(a.fail_on_phantom);
        // Untouched settings keep their defaults.
        assert!(!a.license_texts);
        assert!(a.allow_license.is_empty());
    }

    #[test]
    fn command_line_wins_even_over_lists_and_defaults_are_not_the_command_line() {
        let cfg = loaded(
            r#"
            format = "spdx"
            deny-license = ["GPL-3.0-only"]
            fetch-licenses = true
            pypi-mapping-file = "map.json"
            "#,
        );
        let (mut a, m) = args(&[
            "--format",
            "cyclonedx",
            "--deny-license",
            "MIT",
            "--pypi-mapping",
            "prefix",
        ]);
        apply(&cfg, &mut a, &m).unwrap();
        assert_eq!(
            a.format,
            Format::Cyclonedx,
            "explicitly given, even if it equals the default"
        );
        assert_eq!(
            a.deny_license,
            ["MIT"],
            "a list on the command line replaces the file's"
        );
        assert!(a.fetch_licenses, "not given, so the file applies");
        assert_eq!(a.pypi_mapping, PypiMappingSource::Prefix);
        assert_eq!(a.pypi_mapping_file, None, "the file's mapping pair is left alone");

        let (mut a, m) = args(&[]);
        apply(&cfg, &mut a, &m).unwrap();
        assert_eq!(
            a.pypi_mapping_file.as_deref(),
            Some(Path::new("map.json")),
            "next to the file"
        );
        let mut elsewhere = cfg.clone();
        elsewhere.path = PathBuf::from("/etc/pixi-sbom/ci.toml");
        let (mut a, m) = args(&[]);
        apply(&elsewhere, &mut a, &m).unwrap();
        assert_eq!(
            a.pypi_mapping_file.as_deref(),
            Some(Path::new("/etc/pixi-sbom/map.json"))
        );
    }

    #[test]
    fn the_index_a_network_can_reach_is_a_property_of_the_workspace() {
        // Which index answers is fixed for everyone sharing a network, so it belongs in the
        // file rather than on every `--report outdated` invocation.
        let cfg = loaded("conda-index-kind = \"anaconda\"");
        let (mut a, m) = args(&[]);
        assert_eq!(a.conda_index_kind, CondaIndexKind::Prefix, "the default");
        apply(&cfg, &mut a, &m).unwrap();
        assert_eq!(a.conda_index_kind, CondaIndexKind::Anaconda);

        let (mut a, m) = args(&["--conda-index-kind", "prefix"]);
        apply(&cfg, &mut a, &m).unwrap();
        assert_eq!(a.conda_index_kind, CondaIndexKind::Prefix, "the command line wins");

        let cfg = loaded("conda-index-kind = \"artifactory\"");
        let (mut a, m) = args(&[]);
        let err = apply(&cfg, &mut a, &m).unwrap_err();
        assert!(
            err.to_string()
                .contains("`conda-index-kind` must be one of \"anaconda\", \"prefix\", not \"artifactory\""),
            "{err}"
        );
    }

    #[test]
    fn unknown_keys_and_bad_values_are_errors() {
        let err = parse_file(Path::new("x.toml"), "colour = \"spdx\"", Source::Project).unwrap_err();
        assert!(err.to_string().contains("unknown field `colour`"), "{err}");
        let err = parse_file(Path::new("x.toml"), "format = [1]", Source::Project).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
        let cfg = loaded("format = \"yaml\"");
        let (mut a, m) = args(&[]);
        let err = apply(&cfg, &mut a, &m).unwrap_err();
        assert!(
            err.to_string()
                .contains("`format` must be one of \"cyclonedx\", \"spdx\", not \"yaml\""),
            "{err}"
        );
        let cfg = loaded("exclude-kind = [\"wheel\"]");
        assert!(apply(&cfg, &mut a, &m).is_err());
        let err = apply(&loaded("fail-on-epss = 5.0"), &mut a, &m).unwrap_err();
        assert!(err.to_string().contains("between 0.0 and 1.0, not 5"), "{err}");
        assert!(parse_file(Path::new("x.toml"), "not = = toml", Source::Project).is_err());
    }

    #[test]
    fn every_project_location_and_the_pyproject_table() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_project(dir.path(), None).unwrap().is_empty());

        // The deprecated workspace-root file is still read.
        std::fs::write(dir.path().join(LEGACY_FILE_NAME), "format = \"spdx\"").unwrap();
        let found = load_project(dir.path(), None).unwrap();
        assert_eq!(found[0].config.format.as_deref(), Some("spdx"));
        assert_eq!(found[0].source, Source::Legacy);
        assert!(found[0].source.deprecated(), "and says so");

        // A pyproject.toml without the table does not shadow it...
        std::fs::write(dir.path().join("pyproject.toml"), "[project]\nname = \"x\"\n").unwrap();
        assert_eq!(load_project(dir.path(), None).unwrap()[0].source, Source::Legacy);
        // ...but one with it wins.
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"x\"\n[tool.pixi-sbom]\nformat = \"cyclonedx\"\nkev = true\n",
        )
        .unwrap();
        let found = load_project(dir.path(), None).unwrap();
        assert_eq!(found[0].source, Source::Pyproject);
        assert_eq!(found[0].config.format.as_deref(), Some("cyclonedx"));
        assert_eq!(found[0].config.kev, Some(true));

        // And the pixi-aligned location wins over both.
        std::fs::create_dir_all(dir.path().join(".pixi")).unwrap();
        std::fs::write(dir.path().join(".pixi").join(FILE_NAME), "format = \"spdx\"\n").unwrap();
        let found = load_project(dir.path(), None).unwrap();
        assert_eq!(found.len(), 1, "one project layer, not three");
        assert_eq!(found[0].source, Source::Project);
        assert_eq!(found[0].config.format.as_deref(), Some("spdx"));
        assert!(!found[0].source.deprecated());

        // A bad table is reported, not skipped.
        std::fs::remove_file(dir.path().join(".pixi").join(FILE_NAME)).unwrap();
        std::fs::write(dir.path().join("pyproject.toml"), "[tool.pixi-sbom]\nbogus = 1\n").unwrap();
        let err = load_project(dir.path(), None).unwrap_err();
        assert!(
            err.to_string().contains("[tool.pixi-sbom]: unknown field `bogus`"),
            "{err}"
        );

        // --config: the file must exist, may use either layout, and replaces the search.
        let explicit = dir.path().join("ci.toml");
        std::fs::write(&explicit, "[tool.pixi-sbom]\nformat = \"spdx\"\n").unwrap();
        let found = load_project(dir.path(), Some(&explicit)).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].config.format.as_deref(), Some("spdx"));
        assert_eq!(found[0].path, explicit);
        assert_eq!(found[0].source, Source::Explicit);
        assert!(matches!(
            load_project(dir.path(), Some(Path::new("/missing.toml"))).unwrap_err(),
            ConfigError::Read { .. }
        ));
    }

    #[test]
    fn a_machine_states_what_its_network_needs_and_a_workspace_inherits_it() {
        // The case this hierarchy exists for: the index a network can reach is said once, on the
        // machine, and every workspace on it gets the answer without repeating it.
        let home = tempfile::tempdir().unwrap();
        let etc = tempfile::tempdir().unwrap();
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(etc.path().join(FILE_NAME), "fetch-licenses = true\nformat = \"spdx\"\n").unwrap();
        std::fs::write(home.path().join(FILE_NAME), "conda-index-kind = \"anaconda\"\n").unwrap();
        std::fs::write(ws.path().join(LEGACY_FILE_NAME), "format = \"cyclonedx\"\n").unwrap();
        let dirs = [
            (Source::System, etc.path().to_path_buf()),
            (Source::User, home.path().to_path_buf()),
        ];

        let layers = load_from(&dirs, ws.path(), None).unwrap();
        assert_eq!(
            layers.iter().map(|l| l.source).collect::<Vec<_>>(),
            [Source::System, Source::User, Source::Legacy],
            "least specific first"
        );

        let (mut a, m) = args(&[]);
        apply_all(&layers, &mut a, &m).unwrap();
        assert_eq!(a.conda_index_kind, CondaIndexKind::Anaconda, "from the user layer");
        assert!(a.fetch_licenses, "the system layer is inherited, not reset");
        assert_eq!(a.format, Format::Cyclonedx, "the workspace overrides the system");

        // The command line still beats every layer.
        let (mut a, m) = args(&["--conda-index-kind", "prefix"]);
        apply_all(&layers, &mut a, &m).unwrap();
        assert_eq!(a.conda_index_kind, CondaIndexKind::Prefix);
    }

    #[test]
    fn the_pixi_directories_are_the_ones_pixi_uses() {
        let dirs = |vars: &[(&str, &str)]| {
            let vars: Vec<(String, PathBuf)> = vars.iter().map(|(k, v)| (k.to_string(), PathBuf::from(v))).collect();
            pixi_config_dirs(move |name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
        };
        let home_var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };

        // `PIXI_HOME` wins over the home directory, as it does for pixi itself.
        let found = dirs(&[(home_var, "/home/u"), ("PIXI_HOME", "/opt/pixi")]);
        assert_eq!(found.last().unwrap(), &(Source::User, PathBuf::from("/opt/pixi")));
        let found = dirs(&[(home_var, "/home/u")]);
        assert_eq!(found.last().unwrap(), &(Source::User, PathBuf::from("/home/u/.pixi")));

        // Least specific first, and no user layer at all when there is no home to find.
        let found = dirs(&[]);
        assert!(found.iter().all(|(source, _)| *source == Source::System));
        assert!(found.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }
}
