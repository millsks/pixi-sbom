//! Repointing the per-package archive hosts at a mirror.
//!
//! The fixed upstreams each have one address and an environment variable naming it. The two
//! archive upstreams do not: `condaarchive` and `wheel` read a few kilobytes out of whatever URL
//! the lockfile recorded for each package, so there is no constant to override. On a network that
//! blocks `conda.anaconda.org` or `files.pythonhosted.org`, `--fetch-licenses` has nowhere else to
//! look.
//!
//! This rewrites those URLs onto a base the operator names. The two kinds need different rules:
//!
//! - **conda**, where `<host>/<channel>/<subdir>/<file>` is reconstructable, so the last three
//!   path segments move onto the new base and any mirror serving a conda channel layout works.
//! - **wheels**, where the path is `packages/<2>/<2>/<64 hex>/<file>` and that hash is assigned by
//!   PyPI's CDN. It cannot be derived from the name and version, so only the host is swapped and
//!   the path is kept. That is correct for a transparent proxy in front of
//!   `files.pythonhosted.org` and wrong for a mirror with a layout of its own.
//!
//! Every archive URL of a kind is rewritten once its variable is set, including packages from a
//! channel that was already reachable. Naming the base is an explicit statement that it serves
//! them.

/// Environment variable naming the base that conda package archives are read from.
pub const CONDA_ARCHIVE_URL_ENV: &str = "PIXI_SBOM_CONDA_ARCHIVE_URL";

/// Environment variable naming the base that PyPI wheel archives are read from.
pub const WHEEL_ARCHIVE_URL_ENV: &str = "PIXI_SBOM_WHEEL_ARCHIVE_URL";

/// The base an archive kind is read from, when one is configured.
pub fn base(env: &str) -> Option<String> {
    std::env::var(env)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
}

/// Split a URL into everything before the path and the path's segments.
fn segments(url: &str) -> Option<(usize, Vec<&str>)> {
    let scheme = url.find("://")? + 3;
    let host_end = url[scheme..].find('/')? + scheme;
    let path = url[host_end + 1..].split('?').next()?;
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    (!parts.is_empty()).then_some((host_end, parts))
}

/// `<base>/<channel>/<subdir>/<file>`, keeping the last three segments of the original.
///
/// Returns `None` when the URL has no recognisable channel and subdir, which leaves the package
/// pointing at wherever the lockfile said rather than guessing.
pub fn conda(location: &str, base: &str) -> Option<String> {
    let (_, parts) = segments(location)?;
    if parts.len() < 3 {
        return None;
    }
    let tail = &parts[parts.len() - 3..];
    Some(format!(
        "{}/{}/{}/{}",
        base.trim_end_matches('/'),
        tail[0],
        tail[1],
        tail[2]
    ))
}

/// `<base>/<the original path>`, because a wheel's path cannot be reconstructed.
pub fn wheel(location: &str, base: &str) -> Option<String> {
    let (host_end, _) = segments(location)?;
    Some(format!("{}{}", base.trim_end_matches('/'), &location[host_end..]))
}

/// Rewrite one archive URL for its kind, logging what moved.
pub fn rewrite(location: &str, base: &str, conda_kind: bool) -> String {
    let moved = if conda_kind {
        conda(location, base)
    } else {
        wheel(location, base)
    };
    match moved {
        Some(url) => {
            tracing::debug!(from = location, to = %url, "reading the archive from the configured mirror");
            url
        }
        None => {
            tracing::warn!(
                location,
                base,
                "cannot map this archive URL onto the mirror; using it unchanged"
            );
            location.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conda_urls_move_channel_subdir_and_file_onto_the_base() {
        let base = "https://mirror.internal";
        assert_eq!(
            conda(
                "https://conda.anaconda.org/conda-forge/linux-64/zlib-1.3.1-h1.conda",
                base
            )
            .as_deref(),
            Some("https://mirror.internal/conda-forge/linux-64/zlib-1.3.1-h1.conda")
        );
        // A channel served from a sub-path keeps its own name, not the whole path.
        assert_eq!(
            conda("https://prefix.dev/channels/my-channel/noarch/thing-1.0-h0.conda", base).as_deref(),
            Some("https://mirror.internal/my-channel/noarch/thing-1.0-h0.conda")
        );
        // A trailing slash on the base does not double up.
        assert_eq!(
            conda("https://host/c/linux-64/f.conda", "https://mirror.internal/").as_deref(),
            Some("https://mirror.internal/c/linux-64/f.conda")
        );
        // Too few segments to name a channel and a subdir: left alone.
        assert_eq!(conda("https://host/f.conda", base), None);
        assert_eq!(conda("not a url", base), None);
    }

    #[test]
    fn wheel_urls_keep_their_cdn_path_and_only_change_host() {
        let base = "https://mirror.internal";
        assert_eq!(
            wheel(
                "https://files.pythonhosted.org/packages/04/11/432f/pyyaml_env_tag-1.1-py3-none-any.whl",
                base
            )
            .as_deref(),
            Some("https://mirror.internal/packages/04/11/432f/pyyaml_env_tag-1.1-py3-none-any.whl")
        );
        // The path is opaque and is preserved exactly, including a base that has its own prefix.
        assert_eq!(
            wheel(
                "https://files.pythonhosted.org/packages/ab/cd/x.whl",
                "https://host/artifactory/pypi"
            )
            .as_deref(),
            Some("https://host/artifactory/pypi/packages/ab/cd/x.whl")
        );
        assert_eq!(wheel("not a url", base), None);
    }

    #[test]
    fn an_unmappable_url_is_used_unchanged_rather_than_guessed_at() {
        assert_eq!(rewrite("not a url", "https://mirror.internal", true), "not a url");
        assert_eq!(
            rewrite("https://host/c/linux-64/f.conda", "https://mirror.internal", true),
            "https://mirror.internal/c/linux-64/f.conda"
        );
    }

    #[test]
    fn an_unset_or_blank_base_is_no_base() {
        // Reads the process environment, so it uses a name nothing else touches.
        let name = "PIXI_SBOM_TEST_MIRROR_BASE";
        unsafe { std::env::remove_var(name) };
        assert_eq!(base(name), None);
        unsafe { std::env::set_var(name, "   ") };
        assert_eq!(base(name), None);
        unsafe { std::env::set_var(name, "https://mirror.internal/") };
        assert_eq!(base(name).as_deref(), Some("https://mirror.internal"));
        unsafe { std::env::remove_var(name) };
    }
}
