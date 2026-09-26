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

## Reading a regression

Criterion compares each run with the previous one in `target/criterion/` and prints the change, so the useful
sequence is: run the suite on `main`, make the change, run it again, and read the percentages. A change above
about 5% on this machine is real; below that is noise unless it repeats.

The numbers above are the 0.9.5 baseline, recorded before the 0.10.0 performance work began, so what that
milestone changes can be judged against something.
