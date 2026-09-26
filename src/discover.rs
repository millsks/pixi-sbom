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
    #[diagnostic(
        code(pixi_sbom::discover::missing),
        help("check the path --lockfile was given, or run `pixi lock` in that workspace to write it")
    )]
    Missing {
        /// The path that was checked.
        path: PathBuf,
    },

    /// `--scan` was pointed at something that is not a directory.
    #[error("{path} is not a directory")]
    #[diagnostic(code(pixi_sbom::discover::not_a_directory), help("--scan takes a directory to walk"))]
    NotADirectory {
        /// The path that was checked.
        path: PathBuf,
    },

    /// `--scan` walked the tree and came back with nothing.
    #[error("no {LOCKFILE_NAME} anywhere under {dir}")]
    #[diagnostic(
        code(pixi_sbom::discover::none_found),
        help(
            "--scan skips hidden directories and {skipped}, and stops at --scan-depth; check the \
             directory, or pass --lockfile for a single workspace"
        )
    )]
    NoneFound {
        /// The directory that was walked.
        dir: PathBuf,
        /// The directory names the walk never enters, for the message.
        skipped: String,
    },
}

/// Directories a scan never enters: environments, build output, caches, and dependencies of
/// other ecosystems. Hidden directories (`.pixi`, `.git`, `.venv`) are skipped by their dot.
pub const SCAN_SKIPPED_DIRS: &[&str] = &["node_modules", "target", "build", "dist", "venv", "__pycache__"];

/// Every `pixi.lock` under `dir`, sorted by path so a scan is reproducible.
///
/// A pixi workspace has exactly one lockfile next to its manifest, so one lockfile is one
/// workspace. Hidden directories and [`SCAN_SKIPPED_DIRS`] are never entered, symlinked
/// directories are not followed (a cycle would never end), and `depth` caps how far below
/// `dir` the walk goes (`0` is `dir` itself).
pub fn scan(dir: &Path, depth: Option<usize>) -> Result<Vec<PathBuf>, DiscoverError> {
    if !dir.is_dir() {
        return Err(DiscoverError::NotADirectory {
            path: dir.to_path_buf(),
        });
    }
    let mut found = Vec::new();
    walk(dir, 0, depth.unwrap_or(usize::MAX), &mut found);
    found.sort();
    if found.is_empty() {
        return Err(DiscoverError::NoneFound {
            dir: dir.to_path_buf(),
            skipped: SCAN_SKIPPED_DIRS.join(", "),
        });
    }
    Ok(found)
}

fn walk(dir: &Path, level: usize, max: usize, found: &mut Vec<PathBuf>) {
    let lockfile = dir.join(LOCKFILE_NAME);
    if lockfile.is_file() {
        found.push(lockfile);
    }
    if level >= max {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::debug!(path = %dir.display(), %err, "cannot read directory; skipped");
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `file_type` does not follow the link, so a symlinked directory is simply not one.
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || SCAN_SKIPPED_DIRS.contains(&name.as_str()) {
            continue;
        }
        walk(&path, level + 1, max, found);
    }
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

/// The `--output` spelling that selects standard output.
pub const STDOUT: &str = "-";

/// Where a document goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// Standard output.
    Stdout,
    /// A file, created (with its parent directories) on write.
    File(PathBuf),
}

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Output::Stdout => f.write_str("<stdout>"),
            Output::File(path) => path.display().fmt(f),
        }
    }
}

/// Whether an explicit `--output` value means standard output.
pub fn is_stdout(explicit: Option<&Path>) -> bool {
    explicit.is_some_and(|path| path.as_os_str() == STDOUT)
}

/// Resolve where the SBOM is written: stdout for `-`, an explicit path if given, otherwise
/// the format's default file name in the same directory as the lockfile.
pub fn resolve_output(explicit: Option<&Path>, lockfile: &Path, format: Format) -> Output {
    match explicit {
        Some(_) if is_stdout(explicit) => Output::Stdout,
        Some(path) => Output::File(path.to_path_buf()),
        None => Output::File(lockfile_dir(lockfile).join(format.default_file_name())),
    }
}

/// Resolve one output file of a batch (`--all-environments` / `--all-platforms`):
/// `sbom-<labels...>` inside the explicit output directory if given, otherwise next to the
/// lockfile.
pub fn resolve_batch_output<'a>(
    explicit_dir: Option<&Path>,
    lockfile: &Path,
    format: Format,
    labels: impl IntoIterator<Item = &'a str>,
) -> PathBuf {
    explicit_dir
        .map(Path::to_path_buf)
        .unwrap_or_else(|| lockfile_dir(lockfile))
        .join(format.batch_file_name(labels))
}

/// The lockfile's own name (normally `pixi.lock`), which is what the SBOM records. The
/// lockfile always lives at the workspace root, so this is its workspace-relative path; the
/// absolute path would leak the generating machine's layout and differ between machines.
pub fn lockfile_name(lockfile: &Path) -> String {
    lockfile
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| LOCKFILE_NAME.to_string())
}

fn lockfile_dir(lockfile: &Path) -> PathBuf {
    lockfile.parent().map(Path::to_path_buf).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_carries_a_code_and_a_next_step() {
        for err in [
            DiscoverError::NotFound {
                start: PathBuf::from("/workspace"),
            },
            DiscoverError::Missing {
                path: PathBuf::from("/workspace/pixi.lock"),
            },
            DiscoverError::NotADirectory {
                path: PathBuf::from("/workspace/pixi.lock"),
            },
            DiscoverError::NoneFound {
                dir: PathBuf::from("/workspace"),
                skipped: SCAN_SKIPPED_DIRS.join(", "),
            },
        ] {
            crate::assert_actionable(&err);
        }
    }

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

    /// A tree of directories, each with a `pixi.lock` where the name says so.
    fn tree(dir: &Path, lockfiles: &[&str], empty_dirs: &[&str]) {
        for relative in lockfiles {
            let path = dir.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "version: 6\n").unwrap();
        }
        for relative in empty_dirs {
            std::fs::create_dir_all(dir.join(relative)).unwrap();
        }
    }

    #[test]
    fn scanning_finds_every_workspace_in_sorted_order() {
        let dir = tempfile::tempdir().unwrap();
        tree(
            dir.path(),
            &[
                "services/worker/pixi.lock",
                "services/api/pixi.lock",
                "tools/ci/pixi.lock",
                // Never entered: an installed environment, a hidden directory, and the
                // dependency trees of other ecosystems.
                "services/api/.pixi/envs/default/pixi.lock",
                "node_modules/pkg/pixi.lock",
                "target/debug/pixi.lock",
                ".git/worktree/pixi.lock",
            ],
            &["docs"],
        );
        let found = scan(dir.path(), None).unwrap();
        let relative: Vec<String> = found
            .iter()
            .map(|p| p.strip_prefix(dir.path()).unwrap().to_string_lossy().replace('\\', "/"))
            .collect();
        assert_eq!(
            relative,
            [
                "services/api/pixi.lock",
                "services/worker/pixi.lock",
                "tools/ci/pixi.lock"
            ]
        );
    }

    #[test]
    fn scanning_finds_the_directory_s_own_lockfile_and_stops_at_the_depth() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["pixi.lock", "a/pixi.lock", "a/b/pixi.lock"], &[]);
        let names = |depth: Option<usize>| scan(dir.path(), depth).unwrap().len();
        assert_eq!(names(Some(0)), 1, "the directory itself");
        assert_eq!(names(Some(1)), 2);
        assert_eq!(names(None), 3);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_directory_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["real/pixi.lock"], &[]);
        // A link back to the root would walk for ever.
        std::os::unix::fs::symlink(dir.path(), dir.path().join("real").join("loop")).unwrap();
        assert_eq!(scan(dir.path(), None).unwrap().len(), 1);
    }

    #[test]
    fn scanning_nothing_is_an_error_that_says_what_was_skipped() {
        let dir = tempfile::tempdir().unwrap();
        tree(dir.path(), &["node_modules/pkg/pixi.lock"], &["empty"]);
        let err = scan(dir.path(), None).unwrap_err();
        assert!(matches!(err, DiscoverError::NoneFound { .. }));
        let file = dir.path().join("not-a-directory");
        std::fs::write(&file, "x").unwrap();
        assert!(matches!(scan(&file, None), Err(DiscoverError::NotADirectory { .. })));
    }

    #[test]
    fn lockfile_name_is_the_file_name_only() {
        assert_eq!(lockfile_name(Path::new("/home/alice/proj/pixi.lock")), "pixi.lock");
        assert_eq!(lockfile_name(Path::new("custom.lock")), "custom.lock");
        assert_eq!(lockfile_name(Path::new("/")), LOCKFILE_NAME);
    }

    #[test]
    fn output_defaults_next_to_lockfile_per_format() {
        let lock = Path::new("/work/proj/pixi.lock");

        assert_eq!(
            resolve_output(None, lock, Format::Cyclonedx),
            Output::File("/work/proj/sbom.cdx.json".into())
        );
        assert_eq!(
            resolve_output(None, lock, Format::Spdx),
            Output::File("/work/proj/sbom.spdx.json".into())
        );
    }

    #[test]
    fn explicit_output_path_or_dash() {
        let lock = Path::new("/work/proj/pixi.lock");

        assert_eq!(
            resolve_output(Some(Path::new("out/x.json")), lock, Format::Spdx),
            Output::File("out/x.json".into())
        );
        assert_eq!(resolve_output(Some(Path::new("-")), lock, Format::Spdx), Output::Stdout);
        assert!(is_stdout(Some(Path::new("-"))));
        assert!(!is_stdout(Some(Path::new("-.json"))));
        assert!(!is_stdout(None));
        assert_eq!(Output::Stdout.to_string(), "<stdout>");
        assert_eq!(Output::File("a/b".into()).to_string(), "a/b");
    }

    #[test]
    fn batch_output_defaults_next_to_lockfile() {
        let lock = Path::new("/work/proj/pixi.lock");

        assert_eq!(
            resolve_batch_output(None, lock, Format::Cyclonedx, ["prod"]),
            Path::new("/work/proj/sbom-prod.cdx.json")
        );
        assert_eq!(
            resolve_batch_output(None, lock, Format::Spdx, ["default"]),
            Path::new("/work/proj/sbom-default.spdx.json")
        );
        assert_eq!(
            resolve_batch_output(None, lock, Format::Spdx, ["prod", "linux-64"]),
            Path::new("/work/proj/sbom-prod-linux-64.spdx.json")
        );
    }

    #[test]
    fn batch_output_uses_explicit_directory() {
        let lock = Path::new("/work/proj/pixi.lock");
        let dir = Path::new("/reports");

        assert_eq!(
            resolve_batch_output(Some(dir), lock, Format::Cyclonedx, ["web"]),
            Path::new("/reports/sbom-web.cdx.json")
        );
    }

    #[test]
    fn explicit_output_wins() {
        let lock = Path::new("/work/proj/pixi.lock");
        let out = Path::new("/elsewhere/bom.json");

        assert_eq!(
            resolve_output(Some(out), lock, Format::Cyclonedx),
            Output::File(out.to_path_buf())
        );
    }
}
