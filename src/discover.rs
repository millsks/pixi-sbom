//! Locating the lockfile and resolving the output path.

use std::path::{Path, PathBuf};

use miette::Diagnostic;
use thiserror::Error;

use crate::cli::Format;

/// Name of the lockfile pixi writes next to its manifest.
pub const LOCKFILE_NAME: &str = "pixi.lock";

/// Errors raised while locating input and output files.
#[derive(Debug, Error, Diagnostic)]
pub enum DiscoverError {
    /// No lockfile found walking up from the start directory.
    #[error("no {LOCKFILE_NAME} found in {start} or any parent directory")]
    #[diagnostic(
        code(pixi_sbom::discover::not_found),
        help("run `pixi lock` in your workspace, or pass --lockfile /path/to/pixi.lock")
    )]
    NotFound {
        /// Directory the search started from.
        start: PathBuf,
    },

    /// The lockfile path given on the command line does not exist.
    #[error("lockfile {path} does not exist")]
    #[diagnostic(code(pixi_sbom::discover::missing))]
    Missing {
        /// The path that was checked.
        path: PathBuf,
    },
}

/// Resolve the lockfile to read: an explicit path if given, otherwise the nearest
/// `pixi.lock` found by walking upward from `start`.
pub fn resolve_lockfile(explicit: Option<&Path>, start: &Path) -> Result<PathBuf, DiscoverError> {
    match explicit {
        Some(path) if path.is_file() => Ok(path.to_path_buf()),
        Some(path) => Err(DiscoverError::Missing {
            path: path.to_path_buf(),
        }),
        None => find_upward(start).ok_or_else(|| DiscoverError::NotFound {
            start: start.to_path_buf(),
        }),
    }
}

fn find_upward(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|dir| dir.join(LOCKFILE_NAME))
        .find(|candidate| candidate.is_file())
}

/// Resolve where the SBOM is written: an explicit path if given, otherwise the format's
/// default file name in the same directory as the lockfile.
pub fn resolve_output(explicit: Option<&Path>, lockfile: &Path, format: Format) -> PathBuf {
    match explicit {
        Some(path) => path.to_path_buf(),
        None => lockfile_dir(lockfile).join(format.default_file_name()),
    }
}

/// Resolve the per-environment output file for `--all-environments`: `sbom-<environment>`
/// inside the explicit output directory if given, otherwise next to the lockfile.
pub fn resolve_environment_output(
    explicit_dir: Option<&Path>,
    lockfile: &Path,
    format: Format,
    environment: &str,
) -> PathBuf {
    explicit_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| lockfile_dir(lockfile))
        .join(format.environment_file_name(environment))
}

fn lockfile_dir(lockfile: &Path) -> PathBuf {
    lockfile.parent().map(Path::to_path_buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_lockfile_is_returned_when_it_exists() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("custom.lock");
        std::fs::write(&lock, "version: 6\n").unwrap();

        let found = resolve_lockfile(Some(&lock), dir.path()).unwrap();
        assert_eq!(found, lock);
    }

    #[test]
    fn explicit_lockfile_that_is_missing_errors() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.lock");

        let err = resolve_lockfile(Some(&missing), dir.path()).unwrap_err();
        assert!(matches!(err, DiscoverError::Missing { path } if path == missing));
    }

    #[test]
    fn lockfile_is_found_in_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join(LOCKFILE_NAME);
        std::fs::write(&lock, "version: 6\n").unwrap();
        let nested = dir.path().join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();

        let found = resolve_lockfile(None, &nested).unwrap();
        assert_eq!(found, lock);
    }

    #[test]
    fn no_lockfile_anywhere_errors() {
        let dir = tempfile::tempdir().unwrap();

        let err = resolve_lockfile(None, dir.path()).unwrap_err();
        assert!(matches!(err, DiscoverError::NotFound { .. }));
        assert!(err.to_string().contains(LOCKFILE_NAME));
    }

    #[test]
    fn output_defaults_next_to_lockfile_per_format() {
        let lock = Path::new("/work/proj/pixi.lock");

        assert_eq!(
            resolve_output(None, lock, Format::Cyclonedx),
            Path::new("/work/proj/sbom.cdx.json")
        );
        assert_eq!(
            resolve_output(None, lock, Format::Spdx),
            Path::new("/work/proj/sbom.spdx.json")
        );
    }

    #[test]
    fn environment_output_defaults_next_to_lockfile() {
        let lock = Path::new("/work/proj/pixi.lock");

        assert_eq!(
            resolve_environment_output(None, lock, Format::Cyclonedx, "prod"),
            Path::new("/work/proj/sbom-prod.cdx.json")
        );
        assert_eq!(
            resolve_environment_output(None, lock, Format::Spdx, "default"),
            Path::new("/work/proj/sbom-default.spdx.json")
        );
    }

    #[test]
    fn environment_output_uses_explicit_directory() {
        let lock = Path::new("/work/proj/pixi.lock");
        let dir = Path::new("/reports");

        assert_eq!(
            resolve_environment_output(Some(dir), lock, Format::Cyclonedx, "web"),
            Path::new("/reports/sbom-web.cdx.json")
        );
    }

    #[test]
    fn explicit_output_wins() {
        let lock = Path::new("/work/proj/pixi.lock");
        let out = Path::new("/elsewhere/bom.json");

        assert_eq!(resolve_output(Some(out), lock, Format::Cyclonedx), out);
    }
}
