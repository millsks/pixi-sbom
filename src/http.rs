//! The one HTTP client, used only by opt-in enrichment features.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Environment variable that forbids every network request: caches only.
pub const OFFLINE_ENV: &str = "PIXI_SBOM_OFFLINE";

/// Whether `PIXI_SBOM_OFFLINE` is set to anything but empty or `0`.
pub fn offline() -> bool {
    std::env::var(OFFLINE_ENV).is_ok_and(|v| !v.trim().is_empty() && v.trim() != "0")
}

/// Refuse a request because the run is offline, saying which one, so a run that comes back
/// with nothing can be traced to the requests it did not make.
fn refuse(method: &str, url: &str) -> Box<ureq::Error> {
    tracing::debug!(method, url, "refusing the request: offline");
    offline_error()
}

fn offline_error() -> Box<ureq::Error> {
    Box::new(ureq::Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        format!("offline: {OFFLINE_ENV} is set, no network requests are made"),
    )))
}

/// How long a single request may take, all in.
const TIMEOUT: Duration = Duration::from_secs(120);

/// A CA bundle in PEM form, in place of the operating system's trust store.
pub const CA_BUNDLE_ENV: &str = "PIXI_SBOM_CA_BUNDLE";

/// What the rest of the Python and conda world calls the same file.
pub const SSL_CERT_FILE_ENV: &str = "SSL_CERT_FILE";

/// Where the TLS trust anchors come from, and what said so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum TlsRoots {
    /// The operating system's trust store, through the platform verifier.
    #[default]
    Platform,
    /// A PEM bundle, with the flag or variable that named it.
    Bundle { path: PathBuf, source: &'static str },
}

impl TlsRoots {
    /// `--ca-bundle`, else `PIXI_SBOM_CA_BUNDLE`, else `SSL_CERT_FILE` — which is what the rest
    /// of the Python and conda world already sets in an image with a private CA — else the
    /// platform's own store, which is right wherever the CA is installed system-wide.
    pub fn resolve(flag: Option<&Path>, env: impl Fn(&str) -> Option<String>) -> Self {
        if let Some(path) = flag {
            return TlsRoots::Bundle {
                path: path.to_path_buf(),
                source: "--ca-bundle",
            };
        }
        for name in [CA_BUNDLE_ENV, SSL_CERT_FILE_ENV] {
            if let Some(value) = env(name).filter(|value| !value.trim().is_empty()) {
                return TlsRoots::Bundle {
                    path: PathBuf::from(value.trim()),
                    source: name,
                };
            }
        }
        TlsRoots::Platform
    }

    /// The same, read from the process environment.
    pub fn from_env(flag: Option<&Path>) -> Self {
        Self::resolve(flag, |name| std::env::var(name).ok())
    }

    /// In words, for the configuration block, `--doctor` and `--version-details`.
    pub fn describe(&self) -> String {
        match self {
            TlsRoots::Platform => TLS_ROOTS.to_string(),
            TlsRoots::Bundle { path, source } => {
                format!("the CA bundle at {} ({source})", path.display())
            }
        }
    }
}

/// Why a CA bundle could not be used. Raised before the first request, so a typo in the path
/// does not come back as a TLS handshake failure ten seconds later.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
pub enum CaBundleError {
    /// The file is not there, or cannot be read.
    #[error("cannot read the CA bundle at {path}: {source}")]
    #[diagnostic(
        code(pixi_sbom::http::ca_bundle),
        help("check the path given by {origin}; it must be a PEM file the process can read")
    )]
    Unreadable {
        path: String,
        origin: &'static str,
        #[source]
        source: std::io::Error,
    },
    /// The file was read but holds no certificate.
    #[error("no certificate in the CA bundle at {path}")]
    #[diagnostic(
        code(pixi_sbom::http::ca_bundle),
        help(
            "the file given by {origin} must be PEM, with at least one -----BEGIN CERTIFICATE----- block; a DER file must be converted first (openssl x509 -inform der -in ca.der -out ca.pem)"
        )
    )]
    Empty { path: String, origin: &'static str },
}

/// The trust anchors for this run, parsed once.
static ROOTS: OnceLock<ureq::tls::RootCerts> = OnceLock::new();

/// Read the bundle, if there is one, and keep its certificates for every later request. Called
/// once, before anything is fetched, so the diagnostic names the file rather than the
/// handshake. Later calls are ignored, which keeps the tests honest.
pub fn init_tls(roots: &TlsRoots) -> Result<(), CaBundleError> {
    let TlsRoots::Bundle { path, source } = roots else {
        return Ok(());
    };
    let pem = std::fs::read(path).map_err(|err| CaBundleError::Unreadable {
        path: path.display().to_string(),
        origin: source,
        source: err,
    })?;
    let certificates: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(&pem)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(certificate)) => Some(certificate),
            // A bundle often carries a key beside the certificates, and an unreadable section
            // is not worth refusing over as long as something usable is left.
            _ => None,
        })
        .collect();
    if certificates.is_empty() {
        return Err(CaBundleError::Empty {
            path: path.display().to_string(),
            origin: source,
        });
    }
    tracing::debug!(
        path = %path.display(),
        source = *source,
        certificates = certificates.len(),
        "using a CA bundle instead of the platform trust store"
    );
    let _ = ROOTS.set(ureq::tls::RootCerts::Specific(std::sync::Arc::new(certificates)));
    Ok(())
}

/// Build the agent: the trust anchors this run resolved, proxies from the environment (and,
/// on Windows, from the system settings), one timeout.
fn agent() -> ureq::Agent {
    let roots = ROOTS.get().cloned().unwrap_or(ureq::tls::RootCerts::PlatformVerifier);
    let tls = ureq::tls::TlsConfig::builder().root_certs(roots).build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(TIMEOUT))
        .user_agent(concat!("pixi-sbom/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// The proxy variables ureq reads, in the order it prefers them.
pub const PROXY_ENV: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
];

/// The proxy ureq will use, as `VAR=value`, or `None` when no variable is set. The password is
/// replaced, because this ends up in logs people paste into issues.
pub fn proxy_for_logging() -> Option<String> {
    PROXY_ENV.iter().find_map(|name| {
        let value = std::env::var(name).ok()?;
        (!value.trim().is_empty()).then(|| format!("{name}={}", redact(value.trim())))
    })
}

/// A URL with the password taken out: `http://user:secret@host` becomes `http://user:***@host`.
pub fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let Some((credentials, host)) = rest.split_once('@') else {
        return url.to_string();
    };
    match credentials.split_once(':') {
        Some((user, _)) => format!("{scheme}://{user}:***@{host}"),
        None => format!("{scheme}://{credentials}@{host}"),
    }
}

/// One upstream a run may talk to, and where its address came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// What it is, in words: `PyPI index`, `OSV`, `CISA KEV`.
    pub name: &'static str,
    pub url: String,
    /// The environment variable that set it, when one did.
    pub from_env: Option<&'static str>,
}

impl Service {
    /// A service whose address `env` may override.
    pub fn new(name: &'static str, url: String, env: &'static str) -> Self {
        let overridden = std::env::var(env).is_ok_and(|value| !value.trim().is_empty());
        Self {
            name,
            url,
            from_env: overridden.then_some(env),
        }
    }

    /// A service with no override.
    pub fn fixed(name: &'static str, url: impl Into<String>) -> Self {
        Self {
            name,
            url: url.into(),
            from_env: None,
        }
    }

    /// Where the address came from, for the log and for `--doctor`.
    pub fn source(&self) -> &str {
        self.from_env.unwrap_or("default")
    }
}

/// What this run will do on the network. Logged once before the first request, because a run
/// that behaves differently on another machine usually differs here and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    pub offline: bool,
    /// The proxy variable in effect, as `VAR=value` with the password replaced.
    pub proxy: Option<String>,
    pub no_proxy: Option<String>,
    /// Where the TLS trust anchors come from, in words.
    pub tls_roots: String,
    pub timeout: Duration,
    pub services: Vec<Service>,
    /// Where answers are cached, and whether the directory is there yet.
    pub cache_dir: std::path::PathBuf,
    pub cache_exists: bool,
}

/// How the trust anchors are chosen, in words.
pub const TLS_ROOTS: &str = "the platform verifier (the operating system trust store)";

impl Configuration {
    /// Read the environment for the services this run is going to use.
    pub fn resolve(services: Vec<Service>, cache_dir: std::path::PathBuf, tls_roots: &TlsRoots) -> Self {
        Self {
            offline: offline(),
            proxy: proxy_for_logging(),
            no_proxy: ["NO_PROXY", "no_proxy"].iter().find_map(|name| {
                let value = std::env::var(name).ok()?;
                (!value.trim().is_empty()).then(|| format!("{name}={}", value.trim()))
            }),
            tls_roots: tls_roots.describe(),
            timeout: TIMEOUT,
            cache_exists: cache_dir.is_dir(),
            cache_dir,
            services,
        }
    }

    /// One INFO line, so an ordinary run says how it is set up, and the detail at debug.
    pub fn log(&self) {
        tracing::info!(
            offline = self.offline,
            proxy = self.proxy.as_deref().unwrap_or("none"),
            tls_roots = self.tls_roots.as_str(),
            timeout_s = self.timeout.as_secs(),
            services = self.services.len(),
            "network configuration"
        );
        if let Some(no_proxy) = &self.no_proxy {
            tracing::debug!(no_proxy, "proxy exceptions");
        }
        for service in &self.services {
            tracing::debug!(
                service = service.name,
                url = %service.url,
                source = service.source(),
                "upstream"
            );
        }
        tracing::debug!(
            path = %self.cache_dir.display(),
            exists = self.cache_exists,
            "cache directory"
        );
    }
}

/// Every message of an error and of the errors behind it, joined with `: `.
///
/// `ureq` reports a TLS failure as `io: ...` and keeps `invalid peer certificate: UnknownIssuer`
/// in the source chain, so a warning that prints only the outermost message says nothing about
/// the cause. This walks the chain so one line names it.
pub fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let message = cause.to_string();
        // A wrapper often repeats what it wraps; say it once.
        if !out.contains(&message) {
            out.push_str(": ");
            out.push_str(&message);
        }
        source = cause.source();
    }
    out
}

/// Log a request about to go out. Debug, because a normal run should be quiet.
fn starting(method: &str, url: &str, detail: &str) {
    tracing::debug!(
        method,
        url,
        detail,
        proxy = proxy_for_logging().as_deref().unwrap_or("none"),
        "requesting"
    );
}

/// Log how a request ended, with the time it took.
fn finished(method: &str, url: &str, status: u16, bytes: usize, started: Instant) {
    tracing::debug!(
        method,
        url,
        status,
        bytes,
        ms = started.elapsed().as_millis(),
        "answered"
    );
}

/// Log a failed request with the whole chain, so the line a user pastes carries the cause, and
/// hand the error on unchanged — callers read its variant to tell one dead URL from a dead
/// network.
fn failed(method: &str, url: &str, started: Instant, err: ureq::Error) -> Box<ureq::Error> {
    tracing::debug!(
        method,
        url,
        ms = started.elapsed().as_millis(),
        cause = error_chain(&err),
        "request failed"
    );
    Box::new(err)
}

/// GET `url` and return the body as text, refusing bodies larger than `limit` bytes.
pub fn get_text(url: &str, limit: u64) -> Result<String, Box<ureq::Error>> {
    if offline() {
        return Err(refuse("GET", url));
    }
    let started = Instant::now();
    starting("GET", url, "");
    let mut response = agent()
        .get(url)
        .call()
        .map_err(|err| failed("GET", url, started, err))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(|err| failed("GET", url, started, err))?;
    finished("GET", url, status, body.len(), started);
    Ok(body)
}

/// POST `body` as JSON to `url` and return the response body as text, refusing responses
/// larger than `limit` bytes.
pub fn post_json(url: &str, body: &str, limit: u64) -> Result<String, Box<ureq::Error>> {
    if offline() {
        return Err(refuse("POST", url));
    }
    let started = Instant::now();
    starting("POST", url, &format!("{} byte body", body.len()));
    let mut response = agent()
        .post(url)
        .header("Content-Type", "application/json")
        .send(body)
        .map_err(|err| failed("POST", url, started, err))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(|err| failed("POST", url, started, err))?;
    finished("POST", url, status, text.len(), started);
    Ok(text)
}

/// GET `url` whole, refusing bodies larger than `limit` bytes.
pub fn get_bytes(url: &str, limit: u64) -> Result<Vec<u8>, Box<ureq::Error>> {
    if offline() {
        return Err(refuse("GET", url));
    }
    let started = Instant::now();
    starting("GET", url, "whole body");
    let mut response = agent()
        .get(url)
        .call()
        .map_err(|err| failed("GET", url, started, err))?;
    let status = response.status().as_u16();
    let bytes = response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|err| failed("GET", url, started, err))?;
    finished("GET", url, status, bytes.len(), started);
    Ok(bytes)
}

/// Whether an error means the network itself is unavailable, as opposed to one URL failing,
/// so that further requests are pointless.
pub fn is_connectivity_error(err: &ureq::Error) -> bool {
    matches!(
        err,
        ureq::Error::Io(_) | ureq::Error::ConnectionFailed | ureq::Error::HostNotFound | ureq::Error::Timeout(_)
    )
}

fn other(message: &'static str) -> Box<ureq::Error> {
    Box::new(ureq::Error::Other(message.into()))
}

/// The last `count` bytes of `url` (fewer when the resource is smaller), plus its total size,
/// in one suffix-range request. Errors when the server ignores ranges.
pub fn get_tail(url: &str, count: u64) -> Result<(u64, Vec<u8>), Box<ureq::Error>> {
    if offline() {
        return Err(refuse("GET", url));
    }
    let started = Instant::now();
    starting("GET", url, &format!("range bytes=-{count}"));
    let mut response = match agent().get(url).header("Range", &format!("bytes=-{count}")).call() {
        Ok(response) => response,
        // Some CDNs answer 416 to a suffix longer than the file instead of sending it whole
        // (RFC 9110 allows either). Learn the size and ask for an exact range instead.
        Err(ureq::Error::StatusCode(416)) => {
            tracing::debug!(url, "the server refused a suffix range; asking for an exact one");
            let total = content_length(url)?;
            let start = total.saturating_sub(count);
            let bytes = if total == 0 {
                Vec::new()
            } else {
                get_range(url, start, total - 1)?
            };
            return Ok((total, bytes));
        }
        Err(err) => return Err(failed("GET", url, started, err)),
    };
    if response.status() != 206 {
        return Err(other("server does not support HTTP range requests"));
    }
    let total = response
        .headers()
        .get("Content-Range")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit('/').next())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .ok_or_else(|| other("missing Content-Range total"))?;
    let status = response.status().as_u16();
    let bytes = response
        .body_mut()
        .with_config()
        .limit(count + 1)
        .read_to_vec()
        .map_err(|err| failed("GET", url, started, err))?;
    if bytes.len() as u64 != count.min(total) {
        return Err(other("short range response"));
    }
    finished("GET", url, status, bytes.len(), started);
    Ok((total, bytes))
}

/// Size of the resource at `url`, from a HEAD request.
fn content_length(url: &str) -> Result<u64, Box<ureq::Error>> {
    let started = Instant::now();
    starting("HEAD", url, "");
    let response = agent()
        .head(url)
        .call()
        .map_err(|err| failed("HEAD", url, started, err))?;
    finished("HEAD", url, response.status().as_u16(), 0, started);
    response
        .headers()
        .get("Content-Length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .ok_or_else(|| other("missing Content-Length"))
}

/// The bytes `start..=end` of `url`.
pub fn get_range(url: &str, start: u64, end: u64) -> Result<Vec<u8>, Box<ureq::Error>> {
    if offline() {
        return Err(refuse("GET", url));
    }
    let started_at = Instant::now();
    starting("GET", url, &format!("range bytes={start}-{end}"));
    let mut response = agent()
        .get(url)
        .header("Range", &format!("bytes={start}-{end}"))
        .call()
        .map_err(|err| failed("GET", url, started_at, err))?;
    let status = response.status().as_u16();
    if response.status() != 206 {
        return Err(other("server does not support HTTP range requests"));
    }
    let wanted = end - start + 1;
    // ureq's limit errors on the read that follows exactly `limit` bytes, so allow one more
    // and check the length ourselves.
    let bytes = response
        .body_mut()
        .with_config()
        .limit(wanted + 1)
        .read_to_vec()
        .map_err(|err| failed("GET", url, started_at, err))?;
    if bytes.len() as u64 != wanted {
        return Err(other("short range response"));
    }
    finished("GET", url, status, bytes.len(), started_at);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate, generated once for the tests; any valid PEM would do, the
    /// point is that the parser finds a certificate in it.
    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIBITCByKADAgECAgEBMAoGCCqGSM49BAMCMA8xDTALBgNVBAMMBHRlc3QwHhcN\nMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDDAR0ZXN0MFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbBUiVPRBzQGDJkK6yUKOBxpTfTwCyMCK\nDK3MqzCdEr8ldRQKvJrdYVsSt/EQSjj4Kmrf6dxqUvTlcCKNTVDdT6MdMBswDAYD\nVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwCgYIKoZIzj0EAwIDSAAwRQIhAOMrCPjR\nRG/UoyCkN0e+YX4WOr9mFFEUoqQe1YgjSNbGAiA9nRZbTSsvF3+VZ8PnzWbTrLmb\nR0Ck3LEBELKDGvBsAg==\n-----END CERTIFICATE-----\n";

    #[test]
    fn the_trust_anchors_are_the_flag_then_the_two_variables_then_the_platform() {
        let none = |_: &str| None;
        assert_eq!(TlsRoots::resolve(None, none), TlsRoots::Platform);
        assert_eq!(
            TlsRoots::resolve(None, none).describe(),
            "the platform verifier (the operating system trust store)"
        );

        let flag = TlsRoots::resolve(Some(Path::new("/etc/ssl/corp.pem")), |name| {
            (name == CA_BUNDLE_ENV).then(|| "/ignored.pem".to_string())
        });
        assert_eq!(
            flag,
            TlsRoots::Bundle {
                path: PathBuf::from("/etc/ssl/corp.pem"),
                source: "--ca-bundle",
            },
            "the flag wins over the environment, as every other setting does"
        );
        assert_eq!(flag.describe(), "the CA bundle at /etc/ssl/corp.pem (--ca-bundle)");

        // PIXI_SBOM_CA_BUNDLE first, then SSL_CERT_FILE, which is what the rest of the Python
        // and conda world already sets in an image with a private CA.
        let both = |name: &str| match name {
            CA_BUNDLE_ENV => Some(" /ours.pem ".to_string()),
            SSL_CERT_FILE_ENV => Some("/theirs.pem".to_string()),
            _ => None,
        };
        assert_eq!(
            TlsRoots::resolve(None, both),
            TlsRoots::Bundle {
                path: PathBuf::from("/ours.pem"),
                source: CA_BUNDLE_ENV,
            },
            "and the value is trimmed"
        );
        let theirs = TlsRoots::resolve(None, |name| {
            (name == SSL_CERT_FILE_ENV).then(|| "/theirs.pem".to_string())
        });
        assert_eq!(theirs.describe(), "the CA bundle at /theirs.pem (SSL_CERT_FILE)");

        // An empty variable is not a bundle.
        assert_eq!(
            TlsRoots::resolve(None, |name| (name == CA_BUNDLE_ENV).then(String::new)),
            TlsRoots::Platform
        );
    }

    #[test]
    fn a_bundle_that_cannot_be_used_says_so_before_any_request() {
        let dir = tempfile::tempdir().unwrap();

        let missing = TlsRoots::Bundle {
            path: dir.path().join("nope.pem"),
            source: "--ca-bundle",
        };
        let err = init_tls(&missing).expect_err("the file is not there");
        assert!(matches!(err, CaBundleError::Unreadable { .. }), "{err}");
        assert!(err.to_string().contains("nope.pem"), "{err}");

        // A file that is not PEM, and a PEM file carrying no certificate, are both unusable —
        // and both look like a TLS failure at the first request if nobody checks here.
        let garbage = dir.path().join("cacert.der");
        std::fs::write(&garbage, [0x30u8, 0x82, 0x01, 0x0a]).unwrap();
        let err = init_tls(&TlsRoots::Bundle {
            path: garbage,
            source: SSL_CERT_FILE_ENV,
        })
        .expect_err("not PEM");
        assert!(matches!(err, CaBundleError::Empty { .. }), "{err}");
        assert!(err.to_string().contains("no certificate"), "{err}");

        for err in [
            CaBundleError::Unreadable {
                path: "/etc/ssl/corp.pem".into(),
                origin: "--ca-bundle",
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
            },
            CaBundleError::Empty {
                path: "/etc/ssl/corp.pem".into(),
                origin: CA_BUNDLE_ENV,
            },
        ] {
            crate::assert_actionable(&err);
        }

        // A readable bundle with a certificate in it is accepted, and is what every later
        // request verifies against.
        let good = dir.path().join("corp.pem");
        std::fs::write(&good, PEM).unwrap();
        init_tls(&TlsRoots::Bundle {
            path: good,
            source: "--ca-bundle",
        })
        .expect("a PEM file with a certificate in it");
        assert!(matches!(ROOTS.get(), Some(ureq::tls::RootCerts::Specific(_))));

        // Nothing to do when the platform store is in play.
        init_tls(&TlsRoots::Platform).expect("the default needs no file");
    }

    /// An error with a cause behind it, the shape a TLS failure arrives in.
    #[derive(Debug)]
    struct Layered(&'static str, Option<Box<Layered>>);

    impl std::fmt::Display for Layered {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Layered {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn the_chain_names_the_cause_a_single_message_hides() {
        let tls = Layered(
            "io",
            Some(Box::new(Layered(
                "invalid peer certificate",
                Some(Box::new(Layered("UnknownIssuer", None))),
            ))),
        );
        assert_eq!(error_chain(&tls), "io: invalid peer certificate: UnknownIssuer");
        assert_eq!(error_chain(&Layered("alone", None)), "alone");
        // A wrapper that already quotes its cause does not say it twice.
        let quoted = Layered("failed: because", Some(Box::new(Layered("because", None))));
        assert_eq!(error_chain(&quoted), "failed: because");
    }

    #[test]
    fn a_proxy_password_never_reaches_the_log() {
        assert_eq!(redact("http://user:secret@proxy:8080"), "http://user:***@proxy:8080");
        assert_eq!(redact("http://user@proxy:8080"), "http://user@proxy:8080");
        assert_eq!(redact("http://proxy:8080"), "http://proxy:8080");
        assert_eq!(redact("proxy:8080"), "proxy:8080", "not a URL at all");
    }

    #[test]
    fn a_service_says_whether_an_environment_variable_set_its_address() {
        // Not set: the address is the default.
        unsafe { std::env::remove_var("PIXI_SBOM_TEST_URL") };
        let service = Service::new("OSV", "https://api.osv.dev".into(), "PIXI_SBOM_TEST_URL");
        assert_eq!(service.source(), "default");
        assert_eq!(service.from_env, None);

        unsafe { std::env::set_var("PIXI_SBOM_TEST_URL", "https://mirror.internal") };
        let service = Service::new("OSV", "https://mirror.internal".into(), "PIXI_SBOM_TEST_URL");
        assert_eq!(service.source(), "PIXI_SBOM_TEST_URL");

        // Set but empty is not set, the way every other variable here is read.
        unsafe { std::env::set_var("PIXI_SBOM_TEST_URL", "  ") };
        assert_eq!(
            Service::new("OSV", "https://api.osv.dev".into(), "PIXI_SBOM_TEST_URL").source(),
            "default"
        );
        unsafe { std::env::remove_var("PIXI_SBOM_TEST_URL") };

        assert_eq!(Service::fixed("KEV", "https://example").source(), "default");
    }

    #[test]
    fn the_configuration_reports_what_the_run_will_do() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-yet");
        let config = Configuration::resolve(
            vec![Service::fixed("OSV", "https://api.osv.dev")],
            missing.clone(),
            &TlsRoots::Platform,
        );
        assert_eq!(config.tls_roots, TLS_ROOTS);
        assert_eq!(config.timeout, TIMEOUT);
        assert_eq!(config.services.len(), 1);
        assert!(!config.cache_exists, "the directory is not there yet");
        assert_eq!(config.cache_dir, missing);
        // Logging it is a side effect with no return; this is here so the format string is
        // exercised and a broken field name cannot reach a release.
        config.log();
    }

    #[test]
    fn the_proxy_variables_are_the_ones_ureq_reads() {
        // ureq prefers ALL_PROXY, then HTTPS_PROXY, then HTTP_PROXY, each in both spellings;
        // reporting a different order would name the wrong one.
        assert_eq!(
            PROXY_ENV,
            [
                "ALL_PROXY",
                "all_proxy",
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy"
            ]
        );
    }

    #[test]
    fn offline_errors_count_as_connectivity_failures() {
        let err = offline_error();
        assert!(is_connectivity_error(&err));
        assert!(err.to_string().contains(OFFLINE_ENV));
        assert!(!is_connectivity_error(&ureq::Error::StatusCode(404)));
    }
}
