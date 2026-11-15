# Development guide

This page is how the code is built, checked, tested, and released. For what the code does, see
[the architecture page](architecture.md).

## Toolchain

Everything runs through [pixi](https://pixi.sh). `pixi.toml` pins the Rust toolchain from conda-forge and defines
every task; `Cargo.toml` describes the crate. You do not need rustup or a system Rust.

```sh
git clone https://github.com/millsks/pixi-sbom
cd pixi-sbom
pixi install          # rust, cargo-llvm-cov, pre-commit, taplo, typos, git-cliff, ...
pixi run bootstrap    # installs the git pre-commit and commit-msg hooks
```

Cargo is never called directly. `pixi run cargo <anything>` works if you need something a task does not cover, but
prefer adding a task.

| Task | Runs | Purpose |
|---|---|---|
| `fmt` | `cargo fmt` | Format (`rustfmt.toml`: edition 2024, 120 columns) |
| `lint` | `cargo clippy --all-targets -- -D warnings` | Lint; warnings are errors |
| `check` | `cargo check --all-targets` | Type-check without building |
| `test` | `cargo test` | Unit tests (in `src/`), end-to-end tests (`tests/cli.rs`) and network tests (`tests/network.rs`) |
| `test-integration` | `cargo test --test '*'` | End-to-end tests only |
| `cov` | `cargo llvm-cov --all-targets --fail-under-lines 90` | Full suite with a 90% line-coverage gate |
| `build` | `cargo build --release` | Optimized binary (`lto`, `codegen-units = 1`, stripped) at `target/release/pixi-sbom` |
| `pre-commit-run` | `pre-commit run --all-files` | All hooks over the tree |
| `ci` | `pre-commit-run` → `build` → `check` → `lint` → `cov` | The gate; must exit 0 before work is considered done |
| `changelog` | `bash scripts/changelog.sh vX.Y.Z` | Add a release's section to `CHANGELOG.md`; the release workflow runs it |
| `bootstrap` | `pre-commit install ...` | One-time hook installation |
| `docs-serve` | `mkdocs serve` (`docs` environment) | Live preview of the documentation site at http://127.0.0.1:8000 |
| `docs-build` | `mkdocs build --strict` (`docs` environment) | Build the site into `site/`; a broken link or a page missing from the nav fails |

The documentation site is [MkDocs](https://www.mkdocs.org) with the Material theme and the Aesir brand
(`docs/overrides/`: `aesir.css` and the A mark in `.icons/`), configured in `mkdocs.yml`. The pages are the Markdown
files in `docs/`, plus `CHANGELOG.md` and `SECURITY.md`, which `mkdocs_hooks.py` publishes as the changelog and
security pages at build time from `extra.repo_pages`. The `docs` pixi environment is separate from the Rust one, so
`pixi run -e docs docs-serve` does not pull the Rust toolchain into a docs-only checkout.

## The change harness

The workflow is a fast inner loop while editing and one full gate before each commit.

**Inner loop.** Run `pixi run test` after every meaningful change; unit tests finish in well under a second and the
end-to-end suite in about half a second more. Run `pixi run fmt` before staging and `pixi run lint` when a chunk is
done, so clippy findings do not pile up.

**Gate.** `pixi run ci` before committing. It is ordered fast-fail: pre-commit (formatting, clippy, taplo, typos,
whitespace, actionlint) → release build → check → lint → coverage. If pre-commit rewrites a file, re-stage it before re-running or
the next run fails identically. Coverage below 90% lines fails the gate; new code needs tests.

**Dependencies.** `pixi run -e lint deny` checks the dependency tree against `deny.toml`: RUSTSEC advisories,
license terms, banned crates and unexpected sources. It is not part of `pixi run ci` — it fetches the advisory
database, so it wants the network and a few seconds, and a commit is the wrong moment to pay for that. CI runs it
on every pull request and weekly. When it fails on a license, the fix is a line in the `allow` list with a sentence
saying why that license is acceptable here, not a wider `confidence-threshold`. When it fails on an advisory, the
fix is getting off the crate; an entry in `ignore` needs the issue that tracks doing so.

**Hooks.** `pixi run bootstrap` installs pre-commit for the `pre-commit` and `commit-msg` stages. The local hooks call
`pixi run cargo fmt`, `pixi run cargo clippy`, `pixi run taplo`, `pixi run typos` and `pixi run actionlint`, because
the git hook runs outside the pixi environment. actionlint is there because the release path cannot be exercised by a
pull request: a wrong `needs:` reference or a typo in an expression would otherwise be found on the day of a release. The `commit-msg` hook enforces Conventional Commits. `--no-verify` is not used.

**Claude Code.** `.claude/settings.json` registers `.claude/hooks/stop-ci.sh` as a Stop hook. It fingerprints the
working tree (HEAD, staged and unstaged changes, untracked files) and runs `pixi run ci` only when that differs from
the state recorded at the last green run (`.pixi/.last-ci-ok`), so a stop that changed nothing costs nothing. A
failing gate exits 2 with the tail of `.pixi/.last-ci.log`, which blocks the stop and hands the failure back to the
assistant rather than only printing it. `.claude/memory/` holds the recorded design decisions and environment notes.

**The docs environment is the one place this project is not conda-forge-first.** `mkdocs`,
`mkdocs-material`, `mike` and `pymdown-extensions` come from PyPI, because conda-forge's only mkdocs 1.6.1 build
declares `click >=7.0,<8.3.0a0` and that held the lockfile on click 8.2.1 — PYSEC-2026-2132, a high-severity command
injection in `click.edit()` that this project's own SBOM job reported against its own lockfile (#211). mkdocs' real
metadata asks for `click>=7.0`; the cap is the conda packaging, not the code, and `mkdocs build --strict`,
`mkdocs serve` with live reload and `mike deploy` were all checked by hand against click 8.5.0. `click >=8.3.3`
stays on the conda side of the docs feature so a future dependency that caps it again fails the solve rather than
quietly reintroducing the advisory. Move the four back when conda-forge ships an mkdocs build without the cap.

## Tests

Three layers, all under `pixi run test`:

### Unit tests (`#[cfg(test)]` in each module)

Exercise one module's contract. `discover`, `manifest`, `purl`, `license` are tested with temp dirs or pure inputs.
`lock` tests parse the fixture lockfiles and assert on the resulting model (purls, hashes, properties, dependency
edges, error variants). `format/*` tests run each writer over `format::testing::sample_sbom()`, a hand-built model
covering every package kind plus edge cases (missing version, non-SPDX license, local path source, extra purls), and
check specific fields.

### The minimum supported Rust version

`rust-version` in `Cargo.toml` is **1.89**, and the `msrv` environment pins exactly that toolchain so the claim is
checked rather than asserted: `pixi run -e msrv msrv-check`, which CI runs on every pull request.

It was 1.85 until someone looked. That number came from edition 2024 and was never true — this crate uses
let-chains in `kev.rs` and `osv.rs`, and those did not stabilize until 1.88. Nothing caught it because every job
built on the toolchain `pixi.toml` pins, which is far newer. It rose to 1.89 in 1.14.0 for `serde-saphyr`, the pure-Rust YAML
reader that replaced `serde_yaml` (#21).

Raising the MSRV is a breaking change for anyone pinned to an older toolchain, so after 1.0 it belongs in a minor
release at the earliest, with the new number in the changelog. Lowering it is free. Either way the `msrv`
environment and `Cargo.toml` change together, or the check is measuring the wrong thing.

### Benchmarks (`benches/`, criterion)

`pixi run bench` times the lockfile reader, the model builder, each writer, license normalization, the report
renderers and the offline enrichment path, against this repository's own lockfile and a generated 2000-package
one. The numbers and what they say are in [the benchmarks page](benchmarks.md); CI runs `pixi run bench-test`, which
executes each benchmark once without timing it, since a shared runner's timings are noise.

The benchmarks reach into the crate through the library target (`src/lib.rs`), which exists for them and for the
tests.

**That library is deliberately not an API.** It is not published (#106); every module is marked `#[doc(hidden)]`
anyway, plus a crate-level note saying that none of it is covered by semantic versioning. Modules may move, split
or disappear in any release, patch releases included.

An `internals` module that everything had to be reached through was tried and rejected: Rust will not re-export a
private module, so doing it properly means declaring every module inside `internals` with `#[path]` and rewriting
every `crate::…` reference in 36 files — a large mechanical change for a signal that `#[doc(hidden)]` and the
crate docs already carry.

The stable surface of this project is the command line, the exit codes, the configuration keys and the documents.
If someone wants the model or the writers from their own program, the answer is to give them a real API with real
guarantees, not to let them reach into this one.

### Snapshot tests (`insta`)

Each writer has one `insta::assert_json_snapshot!` over the sample model, stored in `src/format/snapshots/`. They
catch unintended output changes. A `WriteContext` with a fixed timestamp, UUID and tool version keeps them stable.
When an output change is intended, review the diff and accept it:

```sh
pixi run cargo test                        # fails, writes .snap.new
pixi run cargo insta review                # or: INSTA_UPDATE=always pixi run cargo test
```

### End-to-end tests (`tests/cli.rs`)

Run the built binary with `assert_cmd` against copies of the fixtures in temp directories, then read the file it
wrote and validate it with the `jsonschema` crate against the schemas in `tests/schemas/`. They cover lockfile
discovery, every option including `--all-environments`, both formats, and each error path's message and exit code.
They run with `PIXI_SBOM_OFFLINE=1`, so they never make a request.

### Network tests (`tests/network.rs`)

The third kind, for behaviour that only shows in how requests go over the wire: unit tests stub `Fetch` and never
speak HTTP, and the end-to-end tests are offline. `tests/support/` is a small HTTP/1.1 server on `127.0.0.1` (the
standard library and threads, no dependency) that answers a script and records every request: which connection
carried it, when it started and finished, and its body. The tests run the real binary with every upstream pointed at
it through the `PIXI_SBOM_*_URL` overrides, so nothing leaves the machine. They cover connection reuse, batched
queries and their follow-ups overlapping, the cache counters on a cold and a warm run, batched, refused and
partly-failed batches producing the same report, and which statuses are retried.

A behaviour that is about requests (how many, on how many connections, in what order or overlap, retried or not)
gets its test here rather than a stopwatch reading in the PR description.

### Every report on every input (`tests/matrix.rs`)

One table-driven test runs each input kind — `pixi.lock`, `uv.lock`, `pylock.toml`, `poetry.lock`, `pdm.lock`,
`conda-lock.yml`, an explicit spec, a conda prefix, a venv and `--from-sbom` — through every report, `--explain` and
every gate, against one local upstream (the [`support::Server`](#network-tests-testsnetworkrs)) that answers for any
package: an advisory, a KEV entry, a newer release, a license, a wheel naming a repository, a scorecard. Each cell is
reduced to its exit code and row count (and, for licenses and scorecard, how many rows the enrichment reached), and
the whole grid is one insta snapshot with notes on every limited cell. A reader that stops passing a field to some
report changes the table, which is the point: such a gap shows as an empty column, never as a failure. Nothing leaves
the machine; the test asserts the upstream saw every service's requests.

### Against syft, through Grype (`pixi run grype-compare`)

The acceptance test for replacing syft in front of Grype. For each corpus environment (`pixi/01-django`, a web
stack; `pixi/04-data-analysis`, a scientific stack; `pixi/10-dev-tooling`, Rust binaries; a pip venv of `requirements/02-flask`; Go
and npm tools (`pixi/16-go-tools`, `pixi/17-node-tools`); a pip venv of `requirements/18-image-wheels`, whose Pillow
wheels bundle a vulnerable libwebp; and the JavaScript frontend `npm/19-web-frontend`, described from its
`package-lock.json` by both tools rather than installed), `scripts/grype_compare.py` installs it, describes it with syft and with
`pixi sbom --prefix --primary-purl pypi --embedded-sboms` (offline: everything pixi-sbom needs is on disk or in its
own tables), and scans both documents with the same Grype and the same database. syft and Grype run through
`pixi exec` at versions pinned in the script, so neither is a dependency of the project.

Every conda, Python or npm finding from syft's document must also come from pixi-sbom's. One that does not fails the
run unless `tests/grype/exceptions.toml` lists it, for that environment, with a reason: an exception is for a
difference that is right, such as a Grype match on a CPE syft guessed from a name for code the package does not
contain. Findings only pixi-sbom's document produces are printed, not failed. The run prints the Grype database's
build date, because findings change as advisories are published.

Some environments are in the corpus for one finding: `REQUIRED` in the script names it, and the run fails if
pixi-sbom's document does not give it, whatever syft finds. The Pillow venv must give CVE-2023-4863 on the libwebp
its wheels bundle.

It needs the network (installing the environments, Grype's database) and takes a few minutes, so it is not part of
`pixi run ci`. The `Grype comparison` workflow runs it on pull requests that touch identity code, weekly, and on
demand; `pixi run grype-compare --only django` runs one environment locally. `pixi run grype-compare-test` tests
the comparison itself.

### Schema validation

`tests/schemas/` contains the official CycloneDX 1.6 and 1.7 schemas (with the `spdx.schema.json`,
`jsf-0.82.schema.json` and `cryptography-defs.schema.json` they reference, registered under their canonical `$id`s so
no network access happens), the SPDX 2.3 schema, the SPDX 3.0.1 JSON schema and the SARIF 2.1.0 schema. Both the sample model and every end-to-end document are validated,
CycloneDX against the schema of the version written. When adding a spec version, vendor its schema and extend
`cli::SpecVersion` and the writer's `schema_url` / `number` tables.

### Fixtures (`tests/fixtures/`)

| Fixture | Origin | Exercises |
|---|---|---|
| `conda-only` | `pixi lock` on the committed `pixi.toml` (`zlib` on linux-64 + osx-arm64) | Minimal conda case, virtual-package filtering, platform selection |
| `with-pypi` | `pixi lock` (python 3.12 + `six`, `requests` in a `web` feature/environment) | PyPI wheels, PyPI→PyPI and PyPI→conda edges, noarch, multiple environments |
| `source-packages` | Hand-composed from rattler's conda-lock v7 test data | pixi-build source packages: git, URL, path sources; partial metadata; source→binary edges |
| `multi-env` | Hand-composed | Environment ordering for `--all-environments` |

To refresh a real fixture, run `pixi lock` in a scratch copy of its `pixi.toml` and copy the resulting `pixi.lock`
back; then update any version-specific assertions in `src/lock.rs` and `tests/cli.rs`. Hand-composed fixtures are
deliberately tiny and reuse the `libzlib` record from `conda-only` so their hashes are real.

## Trying it as a real extension

Tests run the binary directly. To exercise pixi's extension discovery and a real workspace:

```sh
pixi run build
cp target/release/pixi-sbom ~/.pixi/bin/      # any PATH directory works
pixi --list | grep sbom                       # sbom  (via pixi-sbom)
cd /some/pixi/workspace && pixi sbom -v
```

`syft convert sbom.cdx.json -o spdx-json` (or `cyclonedx-cli validate`) is a useful independent check on a large
real document; the fixtures are small by design.

## Conventions

- Branches: `feature/<topic>`, `bugfix/<topic>`, `hotfix/<topic>`. `main` is protected; changes arrive by PR.
- Commits: [Conventional Commits](https://www.conventionalcommits.org) (`feat:`, `fix:`, `docs:`, `refactor:`,
  `test:`, `chore:`), enforced by the commit-msg hook and consumed by git-cliff for the changelog.
- Rust: edition 2024, `rustfmt` defaults at 120 columns, clippy clean with `-D warnings`. Public items in every module
  carry a doc comment; error enums derive `thiserror::Error` and `miette::Diagnostic` with a `code(...)`.
- Every behavior change comes with a test in the layer that owns the behavior (model changes → `lock.rs` tests;
  output changes → writer tests and snapshots; CLI changes → `tests/cli.rs`; request behaviour → `tests/network.rs`).
- Dependencies: prefer what `rattler_lock` already pulls in; avoid git dependencies. `serde_json` uses
  `preserve_order` so keys are emitted in struct order.
- Never print to stdout; logs go through `tracing` to stderr.

## The CPE table

`data/cpe.toml` maps a conda package name to NVD's `vendor:product`, and is compiled into the binary
(`src/cpe.rs`). A package missing from it gets no CPE: one is never guessed from a name.

**Adding an entry** is one line in `data/cpe.toml`, `<conda name> = "<vendor>:<product>"`, plus nothing else:
`cpe::tests::every_entry_is_a_valid_vendor_and_product` checks every line's format, and the Grype comparison
(`pixi run grype-compare`) shows what the entry matches. Before adding one, check the pair is the one NVD and Grype's
database use for that code:

- Look the product up in Grype's database (`grype db status` says where it is; the `cpes` table joined to
  `affected_cpe_handles` gives each vendor:product its advisory count), or in NVD's CPE dictionary. Use the vendor
  that carries the advisories; where NVD splits a product between vendors that are not the same code, leave the
  package out.
- Leave out compiler runtimes and C libraries (gcc, glibc), whose advisories are for code a conda package does not
  contain, and packages whose conda version is spelled unlike upstream's.

**Weekly upkeep** (`.github/workflows/cpe-upkeep.yml`, also on demand) runs `scripts/cpe_upkeep.py` and keeps one
issue, *CPE table upkeep*, up to date with what it finds:

| Section | What to do |
|---|---|
| Deprecated in NVD | Review the pull request the workflow opened, which rewrites each entry to NVD's replacement |
| Unknown to NVD | The pair is wrong or was withdrawn: correct or remove the entry |
| Not a conda-forge package | The name is not one conda-forge uses, so the entry can never match: rename or remove it |
| Version spelled unlike NVD's | conda-forge's latest version has a different shape from every version NVD records; check whether CPEs from it still match |
| Candidates | Native packages in the examples with neither a CPE nor a PyPI identity. Add an entry, or list the package in `tests/cpe/reviewed.toml` with the reason it has none, so it is not proposed again |

Nothing is added to the table automatically: which CPE a package should get is a person's call.
**The CRAN table** (`data/cran.toml`, #436) is generated, not curated: `pixi run cran-table` rebuilds it from CRAN's
package list and archive and conda-forge's channel data, and `pixi run cran-table --check` says whether it is out of
date. It lists only the exceptions: `r-*` packages CRAN spells differently and the ones never on CRAN.
`pixi run cran-table-test` tests the generator.

`pixi run cpe-upkeep --report <file>` runs the same checks locally (about ten minutes: NVD allows five requests in
thirty seconds without an API key); `pixi run cpe-upkeep-test` tests them.

## The bundled-library signatures

`data/signatures.toml` says how each [bundled native library](output-format.md#bundled-native-libraries)
is recognized: the files it is installed as, the conda packages that are the library itself, the CPE table key, and
where its version is (`text` after a prefix, an exported `symbol` holding the string, a `symbol-pointer` to it, or a
`packed-function` returning `major << 16 | minor << 8 | patch`). `src/bundled.rs` reads it.

**Adding a library** is one table in that file, plus its two releases in `bundled::tests::RELEASES`, which builds
synthetic ELF, Mach-O and PE files for each and reads the version back. Find where the real library keeps its
version first: `strings` on conda-forge's build shows a version text if there is one; when there is none, look
for an exported symbol (`nm -gU`, `objdump -T`). Then run `pixi run signature-check --report <file> --only <library>`,
which downloads conda-forge's latest build for Linux, macOS and Windows, puts the library in a wheel's `.libs`
directory, and checks pixi-sbom reads the package's own version out of each.

The same check runs weekly as the `signatures` job of `.github/workflows/cpe-upkeep.yml`, and fails, with its
report in the job summary, when a build no longer gives its version. `pixi run signature-check-test` tests the
script.

## The GitHub Action

`actions/pixi-sbom/action.yml` is a composite action, published on each release to
[millsks/pixi-sbom-action](https://github.com/millsks/pixi-sbom-action) (see the release steps): it resolves the version (the action's own tag, an
explicit `version` input, or the latest release), downloads the matching release archive and its `.sha256`,
verifies it, puts the binary on `PATH`, maps the inputs to CLI flags and runs it, then uploads the output with
`actions/upload-artifact`. The `sbom` job in `ci.yml` dogfoods it on **all five release platforms** with the
latest release, so a change to the action is exercised by CI before it is tagged. Five rather than the usual three,
because what this job tests is the action's own `RUNNER_OS-RUNNER_ARCH` case statement mapping a runner to a release
archive; two of those five branches used to run nowhere, so a wrong platform string or archive extension in them
would have reached a user first (#225). One step runs every environment with license
fetching, embedded SBOMs and a deny list that pre-commit's `python` (Python-2.0) violates on every platform, with
`fail-on-policy` off, and asserts the `policy-violated` output; a second step runs a policy that passes. New CLI flags reach the action only once a
release containing them exists; keep `action.yml` inputs and the CLI in step at release time.

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests. On `main` every job runs. On a pull
request, a `What changed` job decides which jobs the change needs (#90), and a final `CI result` job passes when
every job that ran passed. A job a filter skipped counts as passed, so `CI result` is the one check a pull request
must pass:

| Pull request changes | Runs |
|---|---|
| Rust code, any `Cargo.toml`, `Cargo.lock`, `pixi.toml`, `pixi.lock`, `rustfmt.toml`, `ci.yml` | Tests on Linux, macOS and Windows; coverage, MSRV, benchmarks |
| Files the tests read: `docs/`, `examples/`, `README.md`, `mkdocs.yml`, `actions/pixi-sbom/action.yml`, the release workflows, `scripts/whats_new.py` | Tests on Linux only |
| `docs/`, `mkdocs.yml`, the hook, `CHANGELOG.md`, `SECURITY.md` | The docs build |
| `Cargo.lock`, any `Cargo.toml`, `deny.toml` | Dependency advisories and licenses |
| `cli.rs`, `main.rs`, `Cargo.lock`, `docs/completion/`, `scripts/completion_e2e.py` | Shell completion on all three |
| `actions/`, `cli.rs`, `main.rs` | SBOM via action on all five, and the action on a uv project |
| Anything | Lint and the script tests |

A newer push to a pull request cancels its running CI; on `main` every commit's run completes.

| Job | Runs on | Does |
|---|---|---|
| Lint | ubuntu | `pixi run pre-commit-run`, `cargo fmt --check`, `lint`, `check`, `actionlint` |
| Test | `ubuntu-latest`, `macos-latest`, `windows-latest` | `pixi run test` |
| Coverage gate | ubuntu | `pixi run cov` |
| Dependency advisories and licenses | ubuntu | `pixi run -e lint deny`: RUSTSEC advisories, license terms, banned crates and unexpected sources |
| Builds on the MSRV | ubuntu | `pixi run -e msrv msrv-check`: the oldest toolchain `Cargo.toml` claims |
| Benchmarks compile and run | ubuntu | `pixi run bench-test`: every benchmark runs once, untimed, in a debug build |
| Script tests | ubuntu | The Python scripts' own tests: `action-test`, `perf-test`, `whats-new-test`, `repo-release-test`, `changelog-test` and the rest |
| Performance (separate workflow) | all five release platforms | `pixi run perf`: builds two refs on one runner and compares them; fails on binary size or peak memory, reports wall time. On demand, weekly and for each release candidate (its tag, against the last final release); not on pull requests or pushes to `main` (#91). See [the benchmarks page](benchmarks.md) |
| Build | same three | `pixi run build` and `--version` smoke test, with the release profile; on `main` only, not on pull requests (#91) |
| Docs | ubuntu | `pixi run docs-build`: the site must build with `--strict` |
| SBOM via action | all five release platforms | The repository's own action against its own lockfile; SARIF and the attestation from the linux-64 leg only. See [The GitHub Action](#the-github-action) |
| Action on a uv project, without pixi | ubuntu-latest | The action on `examples/projects/uv/01-django/uv.lock` and on a venv built in the job (`prefix`), on a runner with no pixi; refuses `lockfile` with `prefix`. It runs the head binary, built by `action-head-binary` and placed where the action reuses an install, so it tests what the next release does rather than what the last one did |

`.github/workflows/supply-chain.yml` runs that same dependency check on a schedule (Mondays, and on demand).
The per-pull-request run cannot see an advisory published after a merge, and the weekly one is what catches it:
nothing about the repository changes and one day the answer is different.

`.github/workflows/docs.yml` publishes the site to GitHub Pages (https://millsks.github.io/pixi-sbom/) every time
a release is published, building from the release tag so the site matches the released binary. The site is versioned
with [mike](https://github.com/jimporter/mike) the way pixi's own docs are: each release deploys under its tag
(`/v1.13.2/`), `latest` is an alias of the newest final release and the root opens it, so links should use
`/latest/...`, and `dev` follows `main`. The versions live on the `gh-pages` branch, which the workflow then publishes
as the Pages artifact; the repository's Pages source stays "GitHub Actions" and the `github-pages` environment, which
allows `main` and `v*` tags, records every deployment. `gh workflow run docs.yml -f ref=<tag>` redeploys a release's
docs; any other ref (or none) redeploys `dev`. `pixi run -e docs mike serve` previews every deployed version locally
from `gh-pages`. Docs for 1.12.0 to 1.13.1 were published on aesir-oss/pixi-ext-contrib's site, which is gone.

The `github-pages` environment's deployment branch policy must allow the `v*` tag pattern as well as `main`
(Settings → Environments → github-pages), because a release event runs on the tag; without it the deploy job fails
with "Branch ... is not allowed to deploy to github-pages".

All jobs use `prefix-dev/setup-pixi` with caching, so they run the same pinned toolchain as local development. Every
CI job that compiles also restores the compiled dependencies with `Swatinem/rust-cache` (#89), keyed by operating
system, toolchain and `Cargo.lock`. The jobs that compile the same debug build (tests, benchmarks, completion, the
action's binary) share one cache per operating system; lint, coverage, MSRV and the release build each keep their
own, since what they compile differs. Only pushes to `main` save it, so a pull request starts from `main`'s
cache and never writes one of its own: the 10 GB a repository gets holds one set, not one per branch. The release
workflows use no build cache on purpose: what goes into a signed archive or wheel is compiled from the tag alone. CI
sticks to the `-latest` labels (x64 Linux and Windows, arm64 macOS) for the jobs that compile and test the code,
which has no platform-specific paths. The two jobs that are *about* a platform rather than merely running on one —
`sbom`, which tests the action's runner-to-archive mapping, and the separate performance workflow — use all five,
adding `ubuntu-24.04-arm` and `macos-15-intel` for linux-aarch64 and osx-64. The release builds every platform's
binary once, as a wheel (step 5), cross-compiling osx-64 on the arm runner.

## The README recording

`docs/assets/demo.gif` is generated, not captured by hand: `pixi run demo` replays
`docs/assets/demo.tape` through [vhs](https://github.com/charmbracelet/vhs) and overwrites the GIF.
Re-record it when the output it shows changes.

**vhs is not a project dependency.** It pulls ttyd and ffmpeg — 95 packages, and it more than
doubled `pixi.lock` (220 KB to 476 KB) — for a task that runs by hand every few months and never in
CI. Install it once, globally, and it is there for every project:

```sh
pixi global install vhs
```

Everything in the recording is real output from a release build. What is staged is the input:
`scripts/demo-workspace.sh` builds a throwaway workspace from the `with-pypi` fixture with urllib3
pinned back to a vulnerable 1.26.4, and drops the recorded OSV and CISA KEV responses the tests
already use into the cache, so the run needs no network and takes the same time every time. It
makes the same substitution as `workspace_with_vulnerable_urllib3` in `tests/cli.rs` and fails
loudly if the fixture has drifted out from under it. The 1.8 clips add three more inputs: the recorded FIRST EPSS
answer written into the cache the way a lookup leaves it, the OpenVEX fixture trimmed to its one urllib3 statement
(so the clip is not buried in warnings about statements this workspace has nothing for), and syft's document for a
venv, to grade beside this one.

The cache and the `pixi-sbom` symlink live *beside* the recorded directory rather than in it, so
`ls` shows a workspace and not the scaffolding.

`pixi run demo <name>` re-records one clip; `pixi run demo` does all of them. One tape per clip,
each sizing its own terminal to what its command prints — a table that scrolls loses its header,
which is the half that explains it.

**Two clips need the network.** `report-outdated` and `report-scorecard` ask live services, and
the responses are far too large to stage as fixtures — the anaconda.org project documents behind
`outdated` alone are 19 MB. Their tapes `unset PIXI_SBOM_OFFLINE` in the hidden block and say so
at the top.

That costs connectivity when re-recording, and nothing else: the committed artifact is the GIF,
not the cache. What those two show was true on the day they were recorded, the way any screenshot
of live data is; scores and release counts drift, and the prose beside them does not depend on the
exact numbers.

Both warm the cache inside the hidden block before filming, so the network wait — about nine
seconds for `outdated` — happens off camera, and what is filmed is a warm run. That is also what
the second run of anything looks like.

## Releasing

Two workflows. `release.yml` is run by hand from the Actions tab (*Release* → *Run workflow* on `main`) and ends at
the tag push; that tag then starts `release-artifacts.yml`, which builds, signs and publishes everything: the archives
(`pixi-sbom-vX.Y.Z-<platform>`), the wheels, the GitHub release, PyPI (TestPyPI for a release candidate), and, for a
final, the action repository (tagged `vX.Y.Z`, `v1` moved, and a release there that the Marketplace listing follows)
and the pre-commit mirror. One operator action, two runs. A final release is this
repository's *Latest*; a release candidate never is.

Releases are tagged `vX.Y.Z`. Those up to 1.11.x were made in the original millsks/pixi-sbom (now
millsks/pixi-sbom.org) and those from 1.12.0 to 1.13.1 in aesir-oss/pixi-ext-contrib (tagged `pixi-sbom-vX.Y.Z`
there); their tags are carried here as `vX.Y.Z`, and their GitHub releases were copied here with every asset, the
signed `.sigstore.json` bundles included, so this repository is the only release source the action and the install docs use. Their attestations still name the repository that
built them; [Installation](installation.md) shows the offline check against the bundle.

`release.yml` inputs:

| Input | Default | Meaning |
|---|---|---|
| `version` | blank | Version to release without the `v` (e.g. `1.2.0`). Blank auto-increments the patch of the latest `v*` tag; for the very first release it uses `Cargo.toml`'s version. |
| `force_recreate` | false | Delete an existing tag and release of that version first, then recreate them. |

A **pre-release is expressed in the version**, not by a separate flag: `1.0.0-rc.1` is one and `1.0.0` is not.

### Changelogs

`CHANGELOG.md` gets one section per release, added by `scripts/changelog.sh` (git-cliff, `cliff.toml`) below the
header and above the newest section. Sections already there are never regenerated: those from 1.12.0 to 1.13.1 were
written in aesir-oss/pixi-ext-contrib and those before in millsks/pixi-sbom, and their links point at the
repositories they were written in. Never edit them. Release candidates are not sections of their own. Commit types map
to sections via `cliff.toml`: `feat` → Features, `fix` → Bug Fixes, `perf`, `refactor`, `docs`, `test`,
`ci`/`build` → CI and Build; `chore` commits are omitted. `pixi run changelog-notes` prints the newest release's
section, which is what the GitHub release carries.
