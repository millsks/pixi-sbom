//! Explicit conda spec files: what `conda list --explicit` and `conda-lock render --kind explicit`
//! write. An `@EXPLICIT` line, then one exact package URL per line, optionally followed by a
//! hash fragment (`#<md5>`, `#md5:<md5>` or `#sha256:<sha256>`).
//!
//! The file is recognised by its `@EXPLICIT` line rather than its name, since names vary. It
//! covers one platform, named by its `# platform:` comment or by the packages' subdirs. Each
//! package is described as the `pixi.lock` reader describes the same archive.
//!
//! The format records no dependencies, so the document has none beyond the root: every package
//! is a direct child of it, rather than an edge pixi-sbom made up.

use std::path::Path;

use miette::Diagnostic;
use thiserror::Error;

use crate::model::{Root, Sbom};
use crate::purl;

/// The line that makes a file an explicit spec.
const MARKER: &str = "@EXPLICIT";

/// Errors from reading an explicit spec file.
#[derive(Debug, Error, Diagnostic)]
pub enum ExplicitError {
    /// The file could not be read.
    #[error("cannot read {path}")]
    #[diagnostic(code(pixi_sbom::explicit::read))]
    Read {
        /// The file.
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// A line that names a package without pinning its archive.
    #[error("line {line} of {path} is not a package URL: {text}")]
    #[diagnostic(
        code(pixi_sbom::explicit::unpinned),
        help(
            "an explicit spec file lists exact archive URLs; write one with `conda list --explicit --md5`, \\
             or lock the environment"
        )
    )]
    Unpinned {
        /// The file.
        path: String,
        /// The line number, from 1.
        line: usize,
        /// The line as written.
        text: String,
    },

    /// The packages do not agree on a platform, or the file names one and `--platform` another.
    #[error("{path} is for {found}, not {asked}")]
    #[diagnostic(
        code(pixi_sbom::explicit::platform),
        help("an explicit spec file covers one platform; leave --platform out, or pass {found}")
    )]
    Platform {
        /// The file.
        path: String,
        /// The platform the file is for.
        found: String,
        /// The platform asked for.
        asked: String,
    },

    /// A package name the purl spec rejects.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Purl(#[from] purl::PurlError),
}

/// A parsed explicit spec file.
#[derive(Debug, Clone)]
pub struct Explicit {
    /// The platform the file names in its `# platform:` comment, if it does.
    pub platform: Option<String>,
    /// Each package: its URL and the hashes its fragment carried.
    pub packages: Vec<Line>,
}

/// One package line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The archive URL, without its fragment.
    pub url: String,
    /// From a `#<md5>` or `#md5:` fragment.
    pub md5: Option<String>,
    /// From a `#sha256:` fragment.
    pub sha256: Option<String>,
}

/// A parsed file, with the text it was parsed from.
#[derive(Debug)]
pub struct Loaded {
    /// The parsed file.
    pub explicit: Explicit,
    /// The source text, which identifies the input for reproducible document ids.
    pub contents: String,
}

/// Whether the file at `path` is an explicit spec file: it has an `@EXPLICIT` line. Only the
/// start of the file is read, so asking about a large lockfile is cheap.
pub fn is_explicit(path: &Path) -> bool {
    use std::io::{BufRead, BufReader};
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    BufReader::new(file)
        .lines()
        .take(50)
        .map_while(Result::ok)
        .any(|line| line.trim() == MARKER)
}

/// Read and parse the file at `path`.
pub fn load(path: &Path) -> Result<Loaded, ExplicitError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ExplicitError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let explicit = parse(&contents, &path.display().to_string())?;
    Ok(Loaded { explicit, contents })
}

/// Parse file text; `origin` names it in errors.
pub fn parse(contents: &str, origin: &str) -> Result<Explicit, ExplicitError> {
    let mut platform = None;
    let mut packages = Vec::new();
    for (i, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if let Some(named) = line.strip_prefix("# platform:") {
            platform = Some(named.trim().to_string());
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line == MARKER {
            continue;
        }
        if !line.contains("://") {
            return Err(ExplicitError::Unpinned {
                path: origin.to_string(),
                line: i + 1,
                text: line.to_string(),
            });
        }
        let (url, fragment) = line.split_once('#').unwrap_or((line, ""));
        let (mut md5, mut sha256) = (None, None);
        if let Some(digest) = fragment.strip_prefix("sha256:") {
            sha256 = Some(digest.to_string());
        } else if let Some(digest) = fragment.strip_prefix("md5:") {
            md5 = Some(digest.to_string());
        } else if fragment.len() == 64 {
            sha256 = Some(fragment.to_string());
        } else if !fragment.is_empty() {
            md5 = Some(fragment.to_string());
        }
        packages.push(Line {
            url: url.to_string(),
            md5,
            sha256,
        });
    }
    Ok(Explicit { platform, packages })
}

/// The platform the file is for: its `# platform:` comment, else the one subdir its packages
/// share besides `noarch`.
fn file_platform(explicit: &Explicit) -> Option<String> {
    explicit.platform.clone().or_else(|| {
        explicit
            .packages
            .iter()
            .filter_map(|line| line.url.rsplit('/').nth(1))
            .find(|subdir| *subdir != "noarch")
            .map(str::to_string)
    })
}

/// Build the document model. `platform`, when given, must be the file's own.
pub fn build_sbom(
    explicit: &Explicit,
    platform: Option<&str>,
    root: Root,
    file_name: &str,
) -> Result<Sbom, ExplicitError> {
    let found = file_platform(explicit).unwrap_or_else(|| "noarch".to_string());
    if let Some(asked) = platform
        && asked != found
    {
        return Err(ExplicitError::Platform {
            path: file_name.to_string(),
            found,
            asked: asked.to_string(),
        });
    }
    let mut packages = explicit
        .packages
        .iter()
        .map(|line| crate::condalock::conda_package(&line.url, None, None, line.sha256.clone(), line.md5.clone()))
        .collect::<Result<Vec<_>, _>>()?;
    packages.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    tracing::info!(platform = %found, packages = packages.len(), "read the explicit spec file");

    Ok(Sbom {
        root,
        environment: "default".to_string(),
        platform: found,
        lockfile: file_name.to_string(),
        prefix: None,
        document: None,
        packages,
        vulnerabilities: Vec::new(),
        excluded: Vec::new(),
        declared_missing: Vec::new(),
        incomplete: crate::model::Incomplete::default(),
        lifecycles: vec![crate::model::PHASE_LOCKFILE.into()],
        declared_roots: false,
        scopes: std::collections::BTreeMap::new(),
        interpreter: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MD5: &str = "# Generated by conda-lock.
# platform: linux-64
@EXPLICIT
https://conda.anaconda.org/conda-forge/linux-64/python-3.12.14-h5f976f7_3_cpython.conda#98be3cf76eca2e8871f907a03aed3b84
https://conda.anaconda.org/conda-forge/noarch/django-3.2.12-pyhd8ed1ab_0.tar.bz2#0123456789abcdef0123456789abcdef
https://conda.anaconda.org/conda-forge/linux-64/ca-certificates-2026.7.22-hbd8a1cb_0.conda
";

    fn sbom(text: &str, platform: Option<&str>) -> Result<Sbom, ExplicitError> {
        build_sbom(&parse(text, "spec.txt")?, platform, Root::default(), "spec.txt")
    }

    #[test]
    fn every_url_is_a_conda_package_as_pixi_lock_would_describe_it() {
        let doc = sbom(MD5, None).unwrap();
        assert_eq!(doc.platform, "linux-64");
        let python = doc.packages.iter().find(|p| p.name == "python").unwrap();
        assert_eq!(
            python.purl,
            "pkg:conda/python@3.12.14?build=h5f976f7_3_cpython&channel=conda-forge&subdir=linux-64&type=conda"
        );
        assert_eq!(python.md5.as_deref(), Some("98be3cf76eca2e8871f907a03aed3b84"));
        assert_eq!(python.sha256, None);
        let django = doc.packages.iter().find(|p| p.name == "django").unwrap();
        assert_eq!(django.version.as_deref(), Some("3.2.12"));
        assert!(django.purl.ends_with("subdir=noarch&type=tar.bz2"));
        let certs = doc.packages.iter().find(|p| p.name == "ca-certificates").unwrap();
        assert_eq!(certs.version.as_deref(), Some("2026.7.22"), "a name with a dash");
        assert_eq!(
            (certs.md5.as_ref(), certs.sha256.as_ref()),
            (None, None),
            "no fragment, no hash"
        );
        assert!(
            doc.packages.iter().all(|p| p.dependencies.is_empty()),
            "the format has no graph"
        );
    }

    #[test]
    fn sha256_fragments_and_platforms_from_the_urls() {
        let text = "@EXPLICIT\nhttps://conda.anaconda.org/conda-forge/osx-arm64/zlib-1.3.1-h8359307_2.conda#sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\nhttps://conda.anaconda.org/conda-forge/noarch/tzdata-2026c-h151e31d_0.conda#md5:aa\n";
        let doc = sbom(text, None).unwrap();
        assert_eq!(doc.platform, "osx-arm64", "no comment, so the subdir");
        let zlib = doc.packages.iter().find(|p| p.name == "zlib").unwrap();
        assert_eq!(
            zlib.sha256.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            doc.packages.iter().find(|p| p.name == "tzdata").unwrap().md5.as_deref(),
            Some("aa")
        );
    }

    #[test]
    fn a_file_is_recognised_by_its_marker_and_refused_when_it_is_not_explicit() {
        let dir = tempfile::tempdir().unwrap();
        let spec = dir.path().join("whatever-name.txt");
        std::fs::write(&spec, MD5).unwrap();
        assert!(is_explicit(&spec));
        let not = dir.path().join("requirements.txt");
        std::fs::write(&not, "numpy==2.0\n").unwrap();
        assert!(!is_explicit(&not));
        assert!(!is_explicit(&dir.path().join("missing.txt")));

        let unpinned = "@EXPLICIT\nnumpy=2.0\n";
        assert!(matches!(
            parse(unpinned, "x"),
            Err(ExplicitError::Unpinned { line: 2, .. })
        ));
        assert!(matches!(sbom(MD5, Some("win-64")), Err(ExplicitError::Platform { .. })));
        assert!(sbom(MD5, Some("linux-64")).is_ok());
        assert!(load(Path::new("/does/not/exist.txt")).is_err());
    }
}
