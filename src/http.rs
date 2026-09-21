//! The one HTTP client, used only by opt-in enrichment features.

use std::time::Duration;

/// Environment variable that forbids every network request: caches only.
pub const OFFLINE_ENV: &str = "PIXI_SBOM_OFFLINE";

/// Whether `PIXI_SBOM_OFFLINE` is set to anything but empty or `0`.
pub fn offline() -> bool {
    std::env::var(OFFLINE_ENV).is_ok_and(|v| !v.trim().is_empty() && v.trim() != "0")
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

/// GET `url` and return the body as text, refusing bodies larger than `limit` bytes.
pub fn get_text(url: &str, limit: u64) -> Result<String, Box<ureq::Error>> {
    if offline() {
        return Err(offline_error());
    }
    agent()
        .get(url)
        .call()
        .map_err(Box::new)?
        .into_body()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(Box::new)
}

/// POST `body` as JSON to `url` and return the response body as text, refusing responses
/// larger than `limit` bytes.
pub fn post_json(url: &str, body: &str, limit: u64) -> Result<String, Box<ureq::Error>> {
    if offline() {
        return Err(offline_error());
    }
    agent()
        .post(url)
        .header("Content-Type", "application/json")
        .send(body)
        .map_err(Box::new)?
        .into_body()
        .with_config()
        .limit(limit)
        .read_to_string()
        .map_err(Box::new)
}

/// GET `url` whole, refusing bodies larger than `limit` bytes.
pub fn get_bytes(url: &str, limit: u64) -> Result<Vec<u8>, Box<ureq::Error>> {
    if offline() {
        return Err(offline_error());
    }
    agent()
        .get(url)
        .call()
        .map_err(Box::new)?
        .into_body()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(Box::new)
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
        return Err(offline_error());
    }
    let mut response = match agent().get(url).header("Range", &format!("bytes=-{count}")).call() {
        Ok(response) => response,
        // Some CDNs answer 416 to a suffix longer than the file instead of sending it whole
        // (RFC 9110 allows either). Learn the size and ask for an exact range instead.
        Err(ureq::Error::StatusCode(416)) => {
            let total = content_length(url)?;
            let start = total.saturating_sub(count);
            let bytes = if total == 0 {
                Vec::new()
            } else {
                get_range(url, start, total - 1)?
            };
            return Ok((total, bytes));
        }
        Err(err) => return Err(Box::new(err)),
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
    let bytes = response
        .body_mut()
        .with_config()
        .limit(count + 1)
        .read_to_vec()
        .map_err(Box::new)?;
    if bytes.len() as u64 != count.min(total) {
        return Err(other("short range response"));
    }
    Ok((total, bytes))
}

/// Size of the resource at `url`, from a HEAD request.
fn content_length(url: &str) -> Result<u64, Box<ureq::Error>> {
    let response = agent().head(url).call().map_err(Box::new)?;
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
        return Err(offline_error());
    }
    let mut response = agent()
        .get(url)
        .header("Range", &format!("bytes={start}-{end}"))
        .call()
        .map_err(Box::new)?;
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
        .map_err(Box::new)?;
    if bytes.len() as u64 != wanted {
        return Err(other("short range response"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_errors_count_as_connectivity_failures() {
        let err = offline_error();
        assert!(is_connectivity_error(&err));
        assert!(err.to_string().contains(OFFLINE_ENV));
        assert!(!is_connectivity_error(&ureq::Error::StatusCode(404)));
    }
}
