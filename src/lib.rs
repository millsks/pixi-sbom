//! `pixi-sbom`: CycloneDX and SPDX Software Bills of Materials built from a `pixi.lock`.
//!
//! The library exists so the benchmarks and the integration tests can reach the pieces the
//! binary wires together — the lockfile reader, the model, the writers, the reports, the
//! enrichment steps. It is the binary's insides rather than a designed API: the modules are
//! public so they can be measured, and nothing here promises to stay put between releases.

pub mod auditable;
pub mod batch;
pub mod cache;
pub mod cli;
pub mod concurrency;
pub mod condaarchive;
pub mod config;
pub mod cvss;
pub mod diff;
pub mod discover;
pub mod doctor;
pub mod embedded;
pub mod explain;
pub mod filter;
pub mod format;
pub mod fromsbom;
pub mod http;
pub mod imports;
pub mod kev;
pub mod license;
pub mod lock;
pub mod manifest;
pub mod mapping;
pub mod model;
pub mod osv;
pub mod outdated;
pub mod phantom;
pub mod pkgcache;
pub mod policy;
pub mod prefix;
pub mod progress;
pub mod purl;
pub mod pypi;
pub mod pyversion;
pub mod report;
pub mod scorecard;
pub mod stdlib;
pub mod style;
pub mod timings;
pub mod vulnpolicy;
pub mod wheel;
pub mod zipread;

/// Assert that a diagnostic tells the user both what it is and what to do next.
///
/// Every error type in this crate has a test that builds one value of each of its variants and
/// hands it here, so a new variant without a `help(...)` fails its module's tests rather than
/// reaching a user who is then told only what went wrong.
#[cfg(test)]
pub fn assert_actionable(err: &dyn miette::Diagnostic) {
    let code = err.code().map(|code| code.to_string()).unwrap_or_default();
    assert!(!code.trim().is_empty(), "no diagnostic code on: {err}");
    let help = err.help().map(|help| help.to_string()).unwrap_or_default();
    assert!(!help.trim().is_empty(), "no help on {code}: {err}");
}
