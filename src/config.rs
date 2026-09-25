//! A configuration file for the settings that otherwise make CI invocations long, read before
//! the command line with the command line winning: `[tool.pixi-sbom]` in `pyproject.toml` next
//! to the lockfile when that table exists, else `pixi-sbom.toml` there, or wherever `--config`
//! points. Keys mirror the long flags; unknown keys are errors so a typo cannot pass silently.

use std::path::{Path, PathBuf};

use clap::{ArgMatches, ValueEnum, parser::ValueSource};
use serde::Deserialize;

use crate::cli::{
    Args, FailOnSeverity, Format, Kind, PrimaryPurl, PypiMappingSource, SpecVersion, VulnerabilitySource,
};

/// The file looked for next to the lockfile after `pyproject.toml`.
pub const FILE_NAME: &str = "pixi-sbom.toml";

/// Why the configuration could not be used.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum ConfigError {
    /// `--config` names a file that cannot be read.
    #[error("cannot read the configuration file {path}: {source}")]
    #[diagnostic(code(pixi_sbom::config::read))]
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
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    pub format: Option<String>,
    pub spec_version: Option<String>,
    pub pypi_mapping: Option<String>,
    pub pypi_mapping_file: Option<PathBuf>,
    pub primary_purl: Option<String>,
    pub fetch_licenses: Option<bool>,
    pub license_texts: Option<bool>,
    pub embedded_sboms: Option<bool>,
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
    pub fail_on_severity: Option<String>,
    pub ignore_vuln: Option<Vec<String>>,
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

/// Where a configuration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    pub config: Config,
    pub path: PathBuf,
    /// `true` when read from `[tool.pixi-sbom]` in `pyproject.toml`.
    pub from_pyproject: bool,
}

/// Find and parse the configuration: `explicit` when given, else the lockfile directory's
/// `pyproject.toml` table or `pixi-sbom.toml`. `Ok(None)` when there is none.
pub fn load(lockfile_dir: &Path, explicit: Option<&Path>) -> Result<Option<Loaded>, ConfigError> {
    if let Some(path) = explicit {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        return parse_file(path, &text).map(Some);
    }
    let pyproject = lockfile_dir.join("pyproject.toml");
    if let Ok(text) = std::fs::read_to_string(&pyproject)
        && let Some(loaded) = parse_pyproject(&pyproject, &text)?
    {
        return Ok(Some(loaded));
    }
    let file = lockfile_dir.join(FILE_NAME);
    match std::fs::read_to_string(&file) {
        Ok(text) => parse_file(&file, &text).map(Some),
        Err(_) => Ok(None),
    }
}

fn parse_file(path: &Path, text: &str) -> Result<Loaded, ConfigError> {
    // A `pixi-sbom.toml` may also use the pyproject layout, so both spellings work.
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
        from_pyproject: false,
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
        from_pyproject: true,
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
    macro_rules! set {
        ($field:ident, $id:literal, $value:expr) => {
            if !on_cli(matches, $id)
                && let Some(value) = $value
            {
                args.$field = value;
            }
        };
    }
    if let Some(format) = &config.format
        && !on_cli(matches, "format")
    {
        args.format = parse_enum::<Format>(path, "format", format)?;
    }
    if let Some(version) = &config.spec_version
        && !on_cli(matches, "spec_version")
    {
        args.spec_version = Some(parse_enum::<SpecVersion>(path, "spec-version", version)?);
    }
    // `pypi-mapping` and `pypi-mapping-file` exclude each other: a command-line choice of
    // either means the file's pair is left alone entirely.
    if !on_cli(matches, "pypi_mapping") && !on_cli(matches, "pypi_mapping_file") {
        if let Some(file) = &config.pypi_mapping_file {
            // A relative path is relative to the configuration file, not the working directory.
            let base = loaded.path.parent().unwrap_or(Path::new("."));
            args.pypi_mapping_file = Some(if file.is_absolute() {
                file.clone()
            } else {
                base.join(file)
            });
            args.pypi_mapping = PypiMappingSource::Lock;
        } else if let Some(source) = &config.pypi_mapping {
            args.pypi_mapping = parse_enum::<PypiMappingSource>(path, "pypi-mapping", source)?;
        }
    }
    if let Some(purl) = &config.primary_purl
        && !on_cli(matches, "primary_purl")
    {
        args.primary_purl = parse_enum::<PrimaryPurl>(path, "primary-purl", purl)?;
    }
    set!(fetch_licenses, "fetch_licenses", config.fetch_licenses);
    set!(license_texts, "license_texts", config.license_texts);
    set!(embedded_sboms, "embedded_sboms", config.embedded_sboms);
    set!(exclude, "exclude", config.exclude.clone());
    set!(include, "include", config.include.clone());
    if let Some(kinds) = &config.exclude_kind
        && !on_cli(matches, "exclude_kind")
    {
        args.exclude_kind = kinds
            .iter()
            .map(|k| parse_enum::<Kind>(path, "exclude-kind", k))
            .collect::<Result<_, _>>()?;
    }
    set!(keep_orphans, "keep_orphans", config.keep_orphans);
    set!(allow_license, "allow_license", config.allow_license.clone());
    set!(deny_license, "deny_license", config.deny_license.clone());
    set!(require_license, "require_license", config.require_license);
    set!(fail_on_yanked, "fail_on_yanked", config.fail_on_yanked);
    if let Some(source) = &config.vulnerabilities
        && !on_cli(matches, "vulnerabilities")
    {
        args.vulnerabilities = Some(parse_enum::<VulnerabilitySource>(path, "vulnerabilities", source)?);
    }
    set!(kev, "kev", config.kev);
    set!(fail_on_kev, "fail_on_kev", config.fail_on_kev);
    if let Some(severity) = &config.fail_on_severity
        && !on_cli(matches, "fail_on_severity")
    {
        args.fail_on_severity = Some(parse_enum::<FailOnSeverity>(path, "fail-on-severity", severity)?);
    }
    set!(ignore_vuln, "ignore_vuln", config.ignore_vuln.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, FromArgMatches};

    fn args(cli: &[&str]) -> (Args, ArgMatches) {
        let matches = Args::command()
            .try_get_matches_from(std::iter::once("pixi-sbom").chain(cli.iter().copied()))
            .unwrap();
        (Args::from_arg_matches(&matches).unwrap(), matches)
    }

    fn loaded(text: &str) -> Loaded {
        parse_file(Path::new("pixi-sbom.toml"), text).unwrap()
    }

    #[test]
    fn file_fills_what_the_command_line_did_not_say() {
        let cfg = loaded(
            r#"
            format = "spdx"
            spec-version = "3.0"
            pypi-mapping = "prefix"
            primary-purl = "pypi"
            fetch-licenses = true
            deny-license = ["GPL-3.0-only", "AGPL-3.0-only"]
            require-license = true
            exclude = ["pre-commit*"]
            exclude-kind = ["conda-source"]
            vulnerabilities = "osv"
            kev = true
            fail-on-severity = "high"
            ignore-vuln = ["GHSA-1:not reachable"]
            "#,
        );
        let (mut a, m) = args(&[]);
        apply(&cfg, &mut a, &m).unwrap();
        assert_eq!(a.format, Format::Spdx);
        assert_eq!(a.spec_version, Some(SpecVersion::V3_0));
        assert_eq!(a.pypi_mapping, PypiMappingSource::Prefix);
        assert_eq!(a.primary_purl, PrimaryPurl::Pypi);
        assert!(a.fetch_licenses);
        assert_eq!(a.deny_license, ["GPL-3.0-only", "AGPL-3.0-only"]);
        assert!(a.require_license);
        assert_eq!(a.exclude, ["pre-commit*"]);
        assert_eq!(a.exclude_kind, [Kind::CondaSource]);
        assert_eq!(a.vulnerabilities, Some(VulnerabilitySource::Osv));
        assert!(a.kev);
        assert_eq!(a.fail_on_severity, Some(FailOnSeverity::High));
        assert_eq!(a.ignore_vuln, ["GHSA-1:not reachable"]);
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
    fn unknown_keys_and_bad_values_are_errors() {
        let err = parse_file(Path::new("x.toml"), "colour = \"spdx\"").unwrap_err();
        assert!(err.to_string().contains("unknown field `colour`"), "{err}");
        let err = parse_file(Path::new("x.toml"), "format = [1]").unwrap_err();
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
        assert!(parse_file(Path::new("x.toml"), "not = = toml").is_err());
    }

    #[test]
    fn both_locations_and_the_pyproject_table() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path(), None).unwrap(), None);

        std::fs::write(dir.path().join(FILE_NAME), "format = \"spdx\"").unwrap();
        let found = load(dir.path(), None).unwrap().unwrap();
        assert_eq!(found.config.format.as_deref(), Some("spdx"));
        assert!(!found.from_pyproject);

        // A pyproject.toml without the table does not shadow pixi-sbom.toml...
        std::fs::write(dir.path().join("pyproject.toml"), "[project]\nname = \"x\"\n").unwrap();
        assert!(!load(dir.path(), None).unwrap().unwrap().from_pyproject);
        // ...but one with it wins.
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"x\"\n[tool.pixi-sbom]\nformat = \"cyclonedx\"\nkev = true\n",
        )
        .unwrap();
        let found = load(dir.path(), None).unwrap().unwrap();
        assert!(found.from_pyproject);
        assert_eq!(found.config.format.as_deref(), Some("cyclonedx"));
        assert_eq!(found.config.kev, Some(true));
        // A bad table is reported, not skipped.
        std::fs::write(dir.path().join("pyproject.toml"), "[tool.pixi-sbom]\nbogus = 1\n").unwrap();
        let err = load(dir.path(), None).unwrap_err();
        assert!(
            err.to_string().contains("[tool.pixi-sbom]: unknown field `bogus`"),
            "{err}"
        );

        // --config: the file must exist, and may use either layout.
        let explicit = dir.path().join("ci.toml");
        std::fs::write(&explicit, "[tool.pixi-sbom]\nformat = \"spdx\"\n").unwrap();
        let found = load(dir.path(), Some(&explicit)).unwrap().unwrap();
        assert_eq!(found.config.format.as_deref(), Some("spdx"));
        assert_eq!(found.path, explicit);
        assert!(matches!(
            load(dir.path(), Some(Path::new("/missing.toml"))).unwrap_err(),
            ConfigError::Read { .. }
        ));
    }
}
