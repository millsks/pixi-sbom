//! Inputs the benchmarks measure against.
//!
//! Two lockfiles: this repository's own, which is what a real project looks like, and a
//! synthetic one an order of magnitude larger, because the costs that matter at 2000 packages
//! (the dependency graph, the license table, the writers' allocations) are invisible at 300.

use std::path::PathBuf;

use pixi_sbom::lock::{self, LoadedLock, Selection};
use pixi_sbom::model::{Root, Sbom};

/// The repository root, which is where the reference lockfile lives.
pub fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// This repository's own `pixi.lock`: a real project's dependency graph, not a toy.
///
/// Read at run time rather than embedded, because the packaged crate leaves the lockfile out
/// and a benchmark that would not compile without it is worse than one that says it is absent.
pub fn reference_lock() -> LoadedLock {
    let path = manifest_dir().join("pixi.lock");
    lock::load(&path).unwrap_or_else(|err| panic!("cannot read the reference lockfile {}: {err}", path.display()))
}

/// A lockfile with `packages` conda packages in one environment, each depending on a handful
/// of the ones before it, so the graph has the shape of a real environment rather than a list.
pub fn synthetic_lock_text(packages: usize) -> String {
    let mut entries = String::new();
    let mut listed = String::new();
    for index in 0..packages {
        let name = format!("pkg-{index:04}");
        let url = format!("https://conda.anaconda.org/conda-forge/linux-64/{name}-1.{index}.0-h0_0.conda");
        listed.push_str(&format!("      - conda: {url}\n"));
        // Every package needs a few of its predecessors: enough edges to exercise the graph
        // without making it quadratic to build.
        let depends: Vec<String> = (1..=4)
            .filter_map(|back| index.checked_sub(back))
            .map(|other| format!("  - pkg-{other:04} >=1.{other}.0\n"))
            .collect();
        entries.push_str(&format!("- conda: {url}\n"));
        entries.push_str(&format!("  build_number: {}\n", index % 8));
        // Quoted: an all-digit digest is a number to YAML, and a 64-digit one overflows into
        // a float that never reaches the digest parser as text.
        entries.push_str(&format!("  sha256: \"{:064x}\"\n", index + 1));
        entries.push_str(&format!("  md5: \"{:032x}\"\n", index + 1));
        if depends.is_empty() {
            entries.push_str("  depends: []\n");
        } else {
            entries.push_str("  depends:\n");
            for line in depends {
                entries.push_str(&line);
            }
        }
        // A mix of expressions, so license normalization has real work rather than one string
        // repeated: a plain id, a compound expression, and one needing a rewrite.
        let license = match index % 4 {
            0 => "MIT",
            1 => "Apache-2.0 WITH LLVM-exception",
            2 => "BSD-3-Clause OR GPL-2.0-only",
            _ => "LGPL-2.1-or-later",
        };
        entries.push_str(&format!("  license: {license}\n"));
        entries.push_str("  purls: []\n");
        entries.push_str(&format!("  size: {}\n", 10_000 + index));
        entries.push_str("  timestamp: 1770939786096\n");
    }
    let mut out = String::from(
        "version: 7\n\
         platforms:\n\
         - name: linux-64\n\
         environments:\n\
         \x20 default:\n\
         \x20   channels:\n\
         \x20   - url: https://conda.anaconda.org/conda-forge/\n\
         \x20   packages:\n\
         \x20     linux-64:\n",
    );
    out.push_str(&listed);
    out.push_str("packages:\n");
    out.push_str(&entries);
    out
}

/// The synthetic lockfile, parsed.
pub fn synthetic_lock(packages: usize) -> LoadedLock {
    lock::parse(synthetic_lock_text(packages), None, "<synthetic>").expect("the generated lockfile parses")
}

/// The model built from a lockfile's default environment on linux-64.
pub fn model(loaded: &LoadedLock, lockfile_name: &str) -> Sbom {
    lock::sbom_from_lock(
        &loaded.lock,
        Selection {
            environment: "default",
            platform: Some("linux-64"),
        },
        Root {
            name: "bench".into(),
            version: Some("1.0.0".into()),
            ..Root::default()
        },
        lockfile_name,
    )
    .expect("the benchmark lockfiles have a default environment on linux-64")
}
