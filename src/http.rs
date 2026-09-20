//! The one HTTP client, used only by opt-in enrichment features.

use std::time::Duration;

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
    let mut response = agent()
        .get(url)
        .header("Range", &format!("bytes=-{count}"))
        .call()
        .map_err(Box::new)?;
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

/// The bytes `start..=end` of `url`.
pub fn get_range(url: &str, start: u64, end: u64) -> Result<Vec<u8>, Box<ureq::Error>> {
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
