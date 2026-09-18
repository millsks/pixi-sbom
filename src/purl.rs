//! Package URL construction for conda and PyPI packages.
//!
//! Follows the purl spec types `conda` (qualifiers `build`, `channel`, `subdir`, `type`)
//! and `pypi`.

use miette::Diagnostic;
use packageurl::PackageUrl;
use thiserror::Error;

/// Failure to build a purl; only happens on names the purl spec rejects.
#[derive(Debug, Error, Diagnostic)]
#[error("cannot build a package URL for {name}@{version}: {source}")]
#[diagnostic(code(pixi_sbom::purl::invalid))]
pub struct PurlError {
    name: String,
    version: String,
    #[source]
    source: packageurl::Error,
}

/// Inputs for a conda purl.
#[derive(Debug, Clone, Copy)]
pub struct CondaPurl<'a> {
    /// Package name.
    pub name: &'a str,
    /// Package version.
    pub version: &'a str,
    /// Build string, if known.
    pub build: Option<&'a str>,
    /// Channel name (e.g. `conda-forge`), if known.
    pub channel: Option<&'a str>,
    /// Subdir (e.g. `linux-64`, `noarch`), if known.
    pub subdir: Option<&'a str>,
    /// Archive type (`conda` or `tar.bz2`), if known.
    pub archive_type: Option<&'a str>,
}

/// Build a `pkg:conda/...` purl.
pub fn conda(input: CondaPurl<'_>) -> Result<String, PurlError> {
    let wrap = |source| PurlError {
        name: input.name.to_string(),
        version: input.version.to_string(),
        source,
    };
    let mut purl = PackageUrl::new("conda", input.name).map_err(wrap)?;
    purl.with_version(input.version).map_err(wrap)?;
    for (key, value) in [
        ("build", input.build),
        ("channel", input.channel),
        ("subdir", input.subdir),
        ("type", input.archive_type),
    ] {
        if let Some(value) = value {
            purl.add_qualifier(key, value).map_err(wrap)?;
        }
    }
    Ok(purl.to_string())
}

/// Build a `pkg:pypi/...` purl. The name is lower-cased and `_`/`.` runs are
/// collapsed to `-` per the purl spec.
pub fn pypi(name: &str, version: &str) -> Result<String, PurlError> {
    let wrap = |source| PurlError {
        name: name.to_string(),
        version: version.to_string(),
        source,
    };
    let normalized = normalize_pypi_name(name);
    let mut purl = PackageUrl::new("pypi", normalized).map_err(wrap)?;
    purl.with_version(version).map_err(wrap)?;
    Ok(purl.to_string())
}

/// PEP 503 name normalization: lowercase, runs of `-`, `_`, `.` become a single `-`.
pub fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_dash = false;
    for ch in name.chars() {
        let is_sep = matches!(ch, '-' | '_' | '.');
        if is_sep {
            if !last_dash {
                out.push('-');
            }
            last_dash = true;
        } else {
            out.extend(ch.to_lowercase());
            last_dash = false;
        }
    }
    out
}

/// Derive the channel name used in purls from a channel base URL
/// (`https://conda.anaconda.org/conda-forge/` -> `conda-forge`).
pub fn channel_name_from_url(url: &str) -> Option<&str> {
    url.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|segment| !segment.is_empty())
}

/// Archive type qualifier derived from an archive file name.
pub fn archive_type_from_file_name(file_name: &str) -> Option<&'static str> {
    if file_name.ends_with(".conda") {
        Some("conda")
    } else if file_name.ends_with(".tar.bz2") {
        Some("tar.bz2")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conda_purl_includes_all_qualifiers() {
        let purl = conda(CondaPurl {
            name: "zlib",
            version: "1.3.2",
            build: Some("h25fd6f3_3"),
            channel: Some("conda-forge"),
            subdir: Some("linux-64"),
            archive_type: Some("conda"),
        })
        .unwrap();
        assert_eq!(
            purl,
            "pkg:conda/zlib@1.3.2?build=h25fd6f3_3&channel=conda-forge&subdir=linux-64&type=conda"
        );
    }

    #[test]
    fn conda_purl_omits_unknown_qualifiers() {
        let purl = conda(CondaPurl {
            name: "mypkg",
            version: "0.1.0",
            build: None,
            channel: None,
            subdir: None,
            archive_type: None,
        })
        .unwrap();
        assert_eq!(purl, "pkg:conda/mypkg@0.1.0");
    }

    #[test]
    fn pypi_purl_normalizes_name() {
        assert_eq!(
            pypi("Typing_Extensions", "4.12.0").unwrap(),
            "pkg:pypi/typing-extensions@4.12.0"
        );
        assert_eq!(pypi("zope.interface", "6.0").unwrap(), "pkg:pypi/zope-interface@6.0");
    }

    #[test]
    fn normalize_collapses_separator_runs() {
        assert_eq!(normalize_pypi_name("A__b.-C"), "a-b-c");
    }

    #[test]
    fn channel_name_is_last_url_segment() {
        assert_eq!(
            channel_name_from_url("https://conda.anaconda.org/conda-forge/"),
            Some("conda-forge")
        );
        assert_eq!(
            channel_name_from_url("https://prefix.dev/my-channel"),
            Some("my-channel")
        );
        assert_eq!(channel_name_from_url(""), None);
    }

    #[test]
    fn archive_type_from_extension() {
        assert_eq!(archive_type_from_file_name("zlib-1.3.2-h1.conda"), Some("conda"));
        assert_eq!(archive_type_from_file_name("zlib-1.3.2-h1.tar.bz2"), Some("tar.bz2"));
        assert_eq!(archive_type_from_file_name("zlib.whl"), None);
    }
}
