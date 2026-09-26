//! The one HTTP client, used only by opt-in enrichment features.

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

/// Build the agent: system certificate store, proxies from the environment, one timeout.
fn agent() -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(120)))
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
