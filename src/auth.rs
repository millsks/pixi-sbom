//! Credentials for a private channel or index, from where pixi already keeps them.
//!
//! `--fetch-licenses` reads each archive from the host the lockfile names, and a private channel
//! wants credentials for that. Rather than inventing somewhere to put them, this reads the places
//! the conda ecosystem already uses, in the order `rattler_networking` consults them:
//!
//! 1. the file named by `RATTLER_AUTH_FILE`
//! 2. `~/.rattler/credentials.json`, which is where `pixi auth login` writes
//! 3. `~/.netrc` (`NETRC` overrides the path; `_netrc` on Windows)
//!
//! The platform keyring sits between 1 and 2 for pixi itself and is not read here: it needs a
//! platform dependency, and a keyring entry is not reachable from a CI runner anyway. A run that
//! needs one can export it into `RATTLER_AUTH_FILE`.
//!
//! Host matching follows the same rule: the exact host first, then `*.domain` walking up the
//! labels, so `*.corp.example` covers `artifactory.corp.example`.
//!
//! Credentials never reach a log line, a cache key or a produced document. A conda token changes
//! the URL that is requested, and the original is what gets logged.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Deserialize;

/// Environment variable naming a credentials file, read before the default location.
pub const AUTH_FILE_ENV: &str = "RATTLER_AUTH_FILE";

/// Environment variable naming a netrc file, read instead of the default location.
pub const NETRC_ENV: &str = "NETRC";

/// How a host wants to be authenticated.
///
/// The names and shapes are `rattler_networking`'s, because these files are written by pixi and
/// have to be read exactly as pixi writes them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum Credential {
    /// `Authorization: Bearer <token>`.
    BearerToken(String),
    /// HTTP basic auth.
    BasicHTTP { username: String, password: String },
    /// Sent in the path as `/t/<token>/...` rather than as a header.
    CondaToken(String),
    /// Not usable over HTTP from here; recognised so the file still parses.
    S3Credentials {
        #[serde(default)]
        access_key_id: String,
    },
    /// Needs a refresh flow this does not implement; recognised so the file still parses.
    OAuth {
        #[serde(default)]
        access_token: String,
    },
}

/// What a request should carry, once the credentials are known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// The URL to request, which a conda token rewrites.
    pub url: String,
    /// The `Authorization` header value, when one applies.
    pub authorization: Option<String>,
}

impl Prepared {
    fn plain(url: &str) -> Self {
        Self {
            url: url.to_string(),
            authorization: None,
        }
    }
}

/// Every host this machine has credentials for, loaded once.
fn store() -> &'static BTreeMap<String, Credential> {
    static STORE: OnceLock<BTreeMap<String, Credential>> = OnceLock::new();
    STORE.get_or_init(load)
}

fn load() -> BTreeMap<String, Credential> {
    let mut hosts = BTreeMap::new();
    // Later sources fill gaps rather than overwrite, so the order here is the priority order.
    for path in credential_files() {
        merge(&mut hosts, read_credentials_file(&path));
    }
    merge(&mut hosts, read_netrc(&netrc_path()));
    if !hosts.is_empty() {
        tracing::debug!(hosts = hosts.len(), "loaded credentials");
    }
    hosts
}

fn merge(into: &mut BTreeMap<String, Credential>, from: BTreeMap<String, Credential>) {
    for (host, credential) in from {
        into.entry(host).or_insert(credential);
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// The credentials files to read, in the order they win.
fn credential_files() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(named) = std::env::var_os(AUTH_FILE_ENV).filter(|value| !value.is_empty()) {
        paths.push(PathBuf::from(named));
    }
    if let Some(home) = home() {
        paths.push(home.join(".rattler").join("credentials.json"));
    }
    paths
}

fn netrc_path() -> PathBuf {
    if let Some(named) = std::env::var_os(NETRC_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(named);
    }
    let name = if cfg!(windows) { "_netrc" } else { ".netrc" };
    home()
        .map(|home| home.join(name))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// A `credentials.json`: host to credential, as pixi writes it.
fn read_credentials_file(path: &std::path::Path) -> BTreeMap<String, Credential> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    match serde_json::from_str::<BTreeMap<String, Credential>>(&text) {
        Ok(hosts) => hosts,
        Err(err) => {
            // Worth saying: the file exists and was meant to be used.
            tracing::warn!(path = %path.display(), %err, "cannot read the credentials file");
            BTreeMap::new()
        }
    }
}

/// A `.netrc`: `machine <host> login <user> password <pass>`, plus `default` as a catch-all.
///
/// Hand-parsed rather than taken as a dependency, the way the zip reading is: the format is a
/// whitespace-separated token stream, and `macdef` is the only part that is not.
fn read_netrc(path: &std::path::Path) -> BTreeMap<String, Credential> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let mut hosts = BTreeMap::new();
    let mut tokens = text.split_whitespace().peekable();
    let mut machine: Option<String> = None;
    let (mut login, mut password) = (None, None);

    let mut flush = |machine: &mut Option<String>, login: &mut Option<String>, password: &mut Option<String>| {
        if let (Some(host), Some(username), Some(password)) = (machine.take(), login.take(), password.take()) {
            hosts.insert(host, Credential::BasicHTTP { username, password });
        } else {
            *login = None;
            *password = None;
        }
    };

    while let Some(token) = tokens.next() {
        match token {
            "machine" => {
                flush(&mut machine, &mut login, &mut password);
                machine = tokens.next().map(str::to_string);
            }
            "default" => {
                flush(&mut machine, &mut login, &mut password);
                machine = Some("default".to_string());
            }
            "login" | "user" => login = tokens.next().map(str::to_string),
            "password" => password = tokens.next().map(str::to_string),
            // A macro body runs to a blank line, which whitespace splitting has already eaten;
            // skipping the name is enough to keep its first word from reading as a keyword.
            "macdef" => {
                tokens.next();
            }
            _ => {}
        }
    }
    flush(&mut machine, &mut login, &mut password);
    hosts
}

/// The host of a URL, without the port or the credentials some URLs carry.
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = authority.rsplit_once(':').map_or(authority, |(host, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            host
        } else {
            authority
        }
    });
    (!host.is_empty()).then_some(host)
}

/// The credential for a host: the host itself, then `*.domain` up the labels, then `default`.
fn credential_for(host: &str) -> Option<&'static Credential> {
    let store = store();
    if let Some(found) = store.get(host) {
        return Some(found);
    }
    let mut domain = host;
    loop {
        if let Some(found) = store.get(&format!("*.{domain}")) {
            return Some(found);
        }
        match domain.split_once('.') {
            Some((_, rest)) if rest.contains('.') => domain = rest,
            Some((_, rest)) => {
                domain = rest;
                if let Some(found) = store.get(&format!("*.{domain}")) {
                    return Some(found);
                }
                break;
            }
            None => break,
        }
    }
    store.get("default")
}

/// base64, for basic auth. Twenty lines against a dependency that would only ever do this.
fn base64(input: &str) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A conda token goes in the path: `https://host/channel/...` becomes `https://host/t/<token>/channel/...`.
fn with_conda_token(url: &str, token: &str) -> String {
    match url.split_once("://").and_then(|(scheme, rest)| {
        let (authority, path) = rest.split_once('/')?;
        Some((scheme, authority, path))
    }) {
        Some((scheme, authority, path)) => format!("{scheme}://{authority}/t/{token}/{path}"),
        None => format!("{}/t/{token}", url.trim_end_matches('/')),
    }
}

/// What this URL should be requested as, and with what, given the credentials on this machine.
pub fn prepare(url: &str) -> Prepared {
    let Some(host) = host_of(url) else {
        return Prepared::plain(url);
    };
    match credential_for(host) {
        Some(Credential::BearerToken(token)) => Prepared {
            url: url.to_string(),
            authorization: Some(format!("Bearer {token}")),
        },
        Some(Credential::BasicHTTP { username, password }) => Prepared {
            url: url.to_string(),
            authorization: Some(format!("Basic {}", base64(&format!("{username}:{password}")))),
        },
        Some(Credential::CondaToken(token)) => Prepared {
            url: with_conda_token(url, token),
            authorization: None,
        },
        Some(other) => {
            // Recognised but not usable over HTTP from here; saying so beats a silent 401.
            tracing::warn!(
                host,
                kind = match other {
                    Credential::S3Credentials { .. } => "S3",
                    _ => "OAuth",
                },
                "credentials for this host are of a kind pixi-sbom cannot use; the request goes unauthenticated"
            );
            Prepared::plain(url)
        }
        None => Prepared::plain(url),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credentials_file_is_read_as_pixi_writes_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.json");
        std::fs::write(
            &path,
            r#"{
              "artifactory.corp": {"BearerToken": "abc"},
              "*.example.com": {"BasicHTTP": {"username": "u", "password": "p"}},
              "conda.anaconda.org": {"CondaToken": "tok"},
              "s3.example": {"S3Credentials": {"access_key_id": "k"}}
            }"#,
        )
        .unwrap();
        let hosts = read_credentials_file(&path);
        assert_eq!(hosts.len(), 4, "every shape parses, even the unusable ones");
        assert_eq!(
            hosts.get("artifactory.corp"),
            Some(&Credential::BearerToken("abc".into()))
        );
        assert_eq!(
            hosts.get("*.example.com"),
            Some(&Credential::BasicHTTP {
                username: "u".into(),
                password: "p".into()
            })
        );

        // A file that is not credentials is a warning, not a panic.
        std::fs::write(&path, "not json").unwrap();
        assert!(read_credentials_file(&path).is_empty());
        assert!(read_credentials_file(&dir.path().join("absent.json")).is_empty());
    }

    #[test]
    fn a_netrc_is_read_including_default_and_macdef() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("netrc");
        std::fs::write(
            &path,
            "machine artifactory.corp login alice password s3cret\n\
             macdef init\n\
             machine ignored-by-the-macro\n\
             \n\
             machine other.example login bob password hunter2\n\
             default login anon password none\n",
        )
        .unwrap();
        let hosts = read_netrc(&path);
        assert_eq!(
            hosts.get("artifactory.corp"),
            Some(&Credential::BasicHTTP {
                username: "alice".into(),
                password: "s3cret".into()
            })
        );
        assert_eq!(
            hosts.get("other.example"),
            Some(&Credential::BasicHTTP {
                username: "bob".into(),
                password: "hunter2".into()
            })
        );
        assert!(hosts.contains_key("default"), "default is the catch-all");

        // An entry with no password is not a credential.
        std::fs::write(&path, "machine partial.example login alice\n").unwrap();
        assert!(read_netrc(&path).is_empty());
    }

    #[test]
    fn a_host_is_matched_exactly_then_by_wildcard() {
        assert_eq!(
            host_of("https://artifactory.corp/conda/x.conda"),
            Some("artifactory.corp")
        );
        assert_eq!(host_of("https://user:pw@host.example:8443/a"), Some("host.example"));
        assert_eq!(host_of("https://host.example:8443"), Some("host.example"));
        assert_eq!(host_of("not a url"), None);
    }

    #[test]
    fn basic_auth_is_base64_of_user_colon_password() {
        // The three padding cases.
        assert_eq!(base64("abc"), "YWJj");
        assert_eq!(base64("ab"), "YWI=");
        assert_eq!(base64("a"), "YQ==");
        assert_eq!(base64("alice:s3cret"), "YWxpY2U6czNjcmV0");
    }

    #[test]
    fn a_conda_token_goes_in_the_path() {
        assert_eq!(
            with_conda_token("https://conda.anaconda.org/my-channel/linux-64/x.conda", "tok"),
            "https://conda.anaconda.org/t/tok/my-channel/linux-64/x.conda"
        );
        assert_eq!(
            with_conda_token("https://conda.anaconda.org", "tok"),
            "https://conda.anaconda.org/t/tok"
        );
    }
}
