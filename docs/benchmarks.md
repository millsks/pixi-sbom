# Benchmarks

`pixi run bench` runs the [criterion](https://bheisler.github.io/criterion.rs/book/) suite in `benches/` and
writes a report to `target/criterion/`. `pixi run bench-test` runs every benchmark once without timing it, which
is what CI does: a shared runner's numbers say more about the runner than about the code, but a benchmark that no
longer compiles or panics on its inputs is a real break.

## What is measured, and against what

Two lockfiles:

| Input | What it is | Packages in the document |
|---|---|---|
| **reference** | This repository's own `pixi.lock` — a real project's dependency graph, 289 locked entries across its environments | 72 for `default` / `linux-64` |
| **synthetic** | Generated in the benchmark: 2000 conda packages in one environment, each depending on four of its predecessors, with a mix of license expressions | 2000 |

The synthetic one exists because the costs that matter at 2000 packages — the dependency graph, the license
table, the writers' allocations — are invisible at 72.

| Group | What it times |
|---|---|
| `parse` | Lockfile text → parsed lockfile (rattler's YAML reader) |
| `model` | Parsed lockfile → the format-agnostic model: purls, the dependency graph, license normalization |
| `write` | Model → document bytes, once per format and spec version |
| `license/normalize` | One pass over eight expressions: a bare id, a compound, one needing a rewrite, one unparsable, and the empty case |
| `report` | Building and rendering a report, per kind and per output format |
| `enrich` | Reading conda licenses out of an extracted package cache — offline, from the recorded fixtures, so the number is the reading and parsing rather than the network |

Network enrichment is deliberately absent: a benchmark whose result depends on what PyPI felt like doing that
morning measures the morning.

## Numbers

Apple M4 (10 cores), macOS 26.2, rustc 1.98.1, release profile, criterion's median of its sample.

### Reading and writing

| Benchmark | reference (72 packages) | synthetic (2000 packages) |
|---|---|---|
| `parse` | 4.76 ms | 25.1 ms |
| `model` | 255 µs | 6.84 ms |
| `write` cyclonedx 1.6 | 454 µs | 12.3 ms |
| `write` cyclonedx 1.7 | 452 µs | 12.3 ms |
| `write` spdx 2.3 | 367 µs | 11.2 ms |
| `write` spdx 3.0 | 525 µs | 15.1 ms |

**Parsing dominates.** On the reference lockfile it is 4.76 ms against 255 µs to build the model and under half a
millisecond to write the document: reading `pixi.lock` is roughly nine tenths of an offline run. That cost is
rattler's YAML reader, not this crate's code, and it scales with the whole file rather than with the environment
selected — which is also why `--all-environments` is much cheaper per document than the first one.

SPDX 3.0 is the most expensive writer (a JSON-LD graph, one node per element); SPDX 2.3 is the cheapest.

### Reports and enrichment

| Benchmark | reference | synthetic |
|---|---|---|
| `report` packages, table | 378 µs | 11.2 ms |
| `report` packages, json | 44.0 µs | 1.06 ms |
| `report` licenses, table | 174 µs | 7.28 ms |
| `report` licenses, json | 46.9 µs | 1.08 ms |
| `report` python, table | 2.83 µs | 5.37 µs |
| `report` python, json | 1.03 µs | 3.19 µs |
| `report` packages, tree | 112 µs | — |
| `license/normalize` (8 expressions) | 1.53 µs | — |
| `enrich` conda licenses from the package cache | 183 µs | — |

The table renderer costs an order of magnitude more than the JSON one at every size: that is `comfy-table`
measuring and wrapping every cell to fit a terminal, which the JSON form never does. The `python` report only
looks at packages that constrain the interpreter, so it barely grows.

## A run that writes many documents

`--all-environments --all-platforms` on this repository writes 15 documents holding 853 package entries between
them, over 289 distinct packages. Cold cache, `--fetch-licenses`, measured end to end:

| | wall | requests |
|---|---|---|
| Before 0.10.0, ten at a time | 6.0 s | 325 |
| Before 0.10.0, `PIXI_SBOM_CONCURRENCY=24` | 4.17 s | 325 |
| Shared lookups, ten at a time | 5.08 s | 325 |
| **Shared lookups, `PIXI_SBOM_CONCURRENCY=24`** | **3.08 s** | 325 |

The request count does not move, because the download cache already stopped the second document re-fetching what
the first one downloaded. What changed is that the run no longer drains a small pool of requests per document
before starting the next one: every document's packages are looked up together, so the pool stays full. That is
worth 15% on its own, and it is what lets the concurrency setting pay off — the two together halve the run.

With a warm cache the whole batch takes about 0.05 s either way, so none of this is visible on a second run.

## Memory

Documents are serialized straight from the writers' own structs to the output. Building a
`serde_json::Value` first — which is what happened before 0.10.0 — held the whole document twice: once as a tree
of boxed strings and maps, once as the bytes.

Peak resident set size writing one document from a generated lockfile, measured with `/usr/bin/time -l`:

| Lockfile | Format | Before | After |
|---|---|---|---|
| 2000 packages | CycloneDX 1.6 | 59.3 MB | 60.1 MB |
| 10000 packages | CycloneDX 1.6 | 227.6 MB | **151.5 MB** |
| 10000 packages | SPDX 2.3 | 203.1 MB | **148.0 MB** |

At 2000 packages the difference is inside the noise — the high-water mark there is the lockfile parser, not the
writer. At 10000 it is a third of the peak. The output is byte-identical either way, which a unit test asserts by
writing each format both ways and comparing.

### The license-text budget

`--license-texts` embeds the text of every licence file, and each file is capped at 1 MiB on its own. Across a
large environment that is still unbounded, so a document holds at most **64 MiB** of licence text in total. Past
that the files are still listed by name, the run warns, and the document records it as
`license-texts: N file(s) listed by name only` in `pixi:incomplete` — the same bargain the per-file cap already
strikes, and visible in the document rather than silent.

## Reading a regression

Criterion compares each run with the previous one in `target/criterion/` and prints the change, so the useful
sequence is: run the suite on `main`, make the change, run it again, and read the percentages. A change above
about 5% on this machine is real; below that is noise unless it repeats.

The numbers above are the 0.9.5 baseline, recorded before the 0.10.0 performance work began, so what that
milestone changes can be judged against something.
