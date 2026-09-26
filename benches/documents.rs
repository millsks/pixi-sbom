//! Reading a lockfile and writing a document: the path every run takes.
//!
//! Three groups, so a regression says where it is rather than only that it happened: parsing
//! the lockfile text, building the model from the parsed lockfile, and serializing the model
//! in each format.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use pixi_sbom::cli::{Format, SpecVersion};
use pixi_sbom::format::{self, WriteContext};
use pixi_sbom::lock;

mod support;

/// The sizes measured: a real project, and an order of magnitude more.
const SYNTHETIC: usize = 2000;

fn parsing(c: &mut Criterion) {
    let reference = support::reference_lock();
    let synthetic = support::synthetic_lock_text(SYNTHETIC);

    let mut group = c.benchmark_group("parse");
    group.throughput(Throughput::Bytes(reference.contents.len() as u64));
    group.bench_function("reference", |b| {
        b.iter(|| {
            let loaded = lock::parse(reference.contents.clone(), None, "pixi.lock").expect("parses");
            black_box(loaded);
        });
    });
    group.throughput(Throughput::Bytes(synthetic.len() as u64));
    group.bench_function(BenchmarkId::new("synthetic", SYNTHETIC), |b| {
        b.iter(|| {
            let loaded = lock::parse(synthetic.clone(), None, "<synthetic>").expect("parses");
            black_box(loaded);
        });
    });
    group.finish();
}

fn model(c: &mut Criterion) {
    let reference = support::reference_lock();
    let synthetic = support::synthetic_lock(SYNTHETIC);

    let mut group = c.benchmark_group("model");
    for (name, loaded) in [("reference", &reference), ("synthetic", &synthetic)] {
        let packages = support::model(loaded, "pixi.lock").packages.len();
        group.throughput(Throughput::Elements(packages as u64));
        group.bench_function(name, |b| {
            b.iter(|| black_box(support::model(loaded, "pixi.lock")));
        });
    }
    group.finish();
}

fn writing(c: &mut Criterion) {
    let reference = support::model(&support::reference_lock(), "pixi.lock");
    let synthetic = support::model(&support::synthetic_lock(SYNTHETIC), "<synthetic>");

    let mut group = c.benchmark_group("write");
    for (size, sbom) in [("reference", &reference), ("synthetic", &synthetic)] {
        group.throughput(Throughput::Elements(sbom.packages.len() as u64));
        for (name, format, spec) in [
            ("cyclonedx-1.6", Format::Cyclonedx, SpecVersion::V1_6),
            ("cyclonedx-1.7", Format::Cyclonedx, SpecVersion::V1_7),
            ("spdx-2.3", Format::Spdx, SpecVersion::V2_3),
            ("spdx-3.0", Format::Spdx, SpecVersion::V3_0),
        ] {
            let ctx = WriteContext::for_document("", sbom, format, spec);
            group.bench_function(BenchmarkId::new(name, size), |b| {
                b.iter(|| {
                    let mut out = Vec::with_capacity(1 << 20);
                    format::write(format, sbom, &ctx, &mut out).expect("writes");
                    black_box(out);
                });
            });
        }
    }
    group.finish();
}

criterion_group!(benches, parsing, model, writing);
criterion_main!(benches);
