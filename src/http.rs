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
