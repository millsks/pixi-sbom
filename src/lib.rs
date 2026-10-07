//! `pixi-sbom`: CycloneDX and SPDX Software Bills of Materials built from a `pixi.lock`.
//!
//! **This library is not an API.** It exists because the binary, the integration tests and the
//! criterion benchmarks all need the same insides, and a benchmark is a separate crate that
//! cannot see into a binary. Every module here is `#[doc(hidden)]` and none of it is covered by
//! semantic versioning: modules move, split and disappear between releases, including patch
//! releases, without that counting as a breaking change.
//!
//! The stable surface of this project is the command line, its exit codes, its configuration
//! keys and the documents it writes. Those are in `docs/stability.md`. If you want the model
//! or the writers from another program, say so in an issue and they can be given a real API
//! with real guarantees; do not reach into this one and hope.

// Nothing shipped contains `unsafe`. The two places that do are test helpers setting environment
// variables, which edition 2024 made unsafe; `not(test)` keeps the guarantee honest for the
// binary without pretending the tests are pure. SECURITY.md states this as a property, so it is
// the compiler that holds it rather than a habit.
#![cfg_attr(not(test), forbid(unsafe_code))]

#[doc(hidden)]
pub mod auditable;
pub mod auth;
#[doc(hidden)]
pub mod batch;
#[doc(hidden)]
pub mod cache;
#[doc(hidden)]
pub mod cli;
#[doc(hidden)]
pub mod concurrency;
#[doc(hidden)]
pub mod condaarchive;
pub mod condalock;
#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod cvss;
#[doc(hidden)]
pub mod diff;
#[doc(hidden)]
pub mod discover;
#[doc(hidden)]
pub mod doctor;
#[doc(hidden)]
pub mod embedded;
#[doc(hidden)]
pub mod explain;
pub mod explicit;
#[doc(hidden)]
pub mod filter;
#[doc(hidden)]
pub mod format;
#[doc(hidden)]
pub mod fromsbom;
#[doc(hidden)]
pub mod http;
#[doc(hidden)]
pub mod imports;
#[doc(hidden)]
pub mod kev;
#[doc(hidden)]
pub mod license;
#[doc(hidden)]
pub mod lock;
#[doc(hidden)]
pub mod manifest;
#[doc(hidden)]
pub mod mapping;
pub mod mirror;
#[doc(hidden)]
pub mod model;
#[doc(hidden)]
pub mod osv;
#[doc(hidden)]
pub mod outdated;
#[doc(hidden)]
pub mod pdm;
pub mod phantom;
#[doc(hidden)]
pub mod pkgcache;
pub mod poetry;
#[doc(hidden)]
pub mod policy;
#[doc(hidden)]
pub mod prefix;
#[doc(hidden)]
pub mod progress;
#[doc(hidden)]
pub mod purl;
pub mod pylock;
#[doc(hidden)]
pub mod pypi;
#[doc(hidden)]
pub mod pyversion;
#[doc(hidden)]
pub mod report;
#[doc(hidden)]
pub mod scorecard;
#[doc(hidden)]
pub mod stdlib;
#[doc(hidden)]
pub mod style;
#[doc(hidden)]
pub mod timings;
pub mod uv;
#[doc(hidden)]
pub mod vulnpolicy;
#[doc(hidden)]
pub mod wheel;
#[doc(hidden)]
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
