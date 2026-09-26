//! The work done between reading the lockfile and writing the document, and the reports.
//!
//! License normalization runs once per package and is pure string work, so it is measured on
//! its own. The reports are measured over the whole model, since what costs there is the
//! renderer rather than any one row. The enrichment steps are measured offline, from the
//! fixtures' caches: what is being timed is reading and parsing what came back, not the
//! network, which would make the numbers say more about the day than about the code.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use pixi_sbom::report::{Report, ReportFormat, ReportKind};
use pixi_sbom::style::Palette;
use pixi_sbom::{license, pkgcache};

mod support;

const SYNTHETIC: usize = 2000;

/// Expressions of every shape the normalizer meets: a bare id, a compound, one it rewrites,
/// one it cannot parse, and the empty case.
const EXPRESSIONS: &[&str] = &[
    "MIT",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-3-Clause OR GPL-2.0-only",
    "LGPL-2.1-or-later",
    "GPL2",
    "Public Domain",
    "MIT AND (Apache-2.0 OR BSD-2-Clause)",
    "",
];

fn licenses(c: &mut Criterion) {
    let mut group = c.benchmark_group("license");
    group.throughput(Throughput::Elements(EXPRESSIONS.len() as u64));
    group.bench_function("normalize", |b| {
        b.iter(|| {
            for raw in EXPRESSIONS {
                black_box(license::normalize(black_box(raw)));
            }
        });
    });
    group.finish();
}

fn reports(c: &mut Criterion) {
    let reference = support::model(&support::reference_lock(), "pixi.lock");
    let synthetic = support::model(&support::synthetic_lock(SYNTHETIC), "<synthetic>");

    let mut group = c.benchmark_group("report");
    for (size, sbom) in [("reference", &reference), ("synthetic", &synthetic)] {
        group.throughput(Throughput::Elements(sbom.packages.len() as u64));
        for kind in [ReportKind::Packages, ReportKind::Licenses, ReportKind::Python] {
            let name = format!("{kind:?}").to_lowercase();
            // Building the report and rendering it are separate costs; a run pays both, so
            // both are in the measurement.
            for format in [ReportFormat::Table, ReportFormat::Json] {
                let label = format!("{name}-{}", format!("{format:?}").to_lowercase());
                group.bench_function(BenchmarkId::new(label, size), |b| {
                    b.iter(|| {
                        let report = Report::new(kind, sbom);
                        let mut out = Vec::with_capacity(1 << 16);
                        pixi_sbom::report::render_with_width(
                            std::slice::from_ref(&report),
                            format,
                            120,
                            Palette::new(false),
                            &mut out,
                        )
                        .expect("renders");
                        black_box(out);
                    });
                });
            }
        }
    }
    group.finish();
}

fn tree(c: &mut Criterion) {
    let sbom = support::model(&support::reference_lock(), "pixi.lock");
    let mut group = c.benchmark_group("report");
    group.throughput(Throughput::Elements(sbom.packages.len() as u64));
    // The tree walks the dependency graph rather than the package list, which is the one
    // report whose cost is in the edges.
    group.bench_function("packages-tree", |b| {
        b.iter(|| {
            let mut report = Report::new(ReportKind::Packages, &sbom);
            report.as_tree(&sbom, None);
            black_box(report);
        });
    });
    group.finish();
}

fn conda_licenses(c: &mut Criterion) {
    // The extracted package cache that `--fetch-licenses` reads first: real `info/` directories
    // recorded under tests/fixtures, so the measurement is the reading and parsing.
    let packages = support::manifest_dir().join("tests/fixtures/package-cache/pkgs");
    if !packages.is_dir() {
        // The packaged crate leaves the fixtures out; say so rather than failing the run.
        eprintln!("skipping conda-licenses: {} is not there", packages.display());
        return;
    }
    let sbom = support::model(&support::reference_lock(), "pixi.lock");
    let mut group = c.benchmark_group("enrich");
    group.throughput(Throughput::Elements(sbom.packages.len() as u64));
    group.bench_function("conda-licenses-from-cache", |b| {
        b.iter(|| {
            let mut sbom = sbom.clone();
            let outcome = pkgcache::enrich(&mut sbom, &packages, false, Default::default());
            black_box((sbom, outcome));
        });
    });
    group.finish();
}

criterion_group!(benches, licenses, reports, tree, conda_licenses);
criterion_main!(benches);
