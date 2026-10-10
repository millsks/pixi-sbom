# Development guide

This page is how the code is built, checked, tested, and released. For what the code does, see
[architecture.md](architecture.md).

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
| `changelog` | `git cliff --config cliff.toml -o CHANGELOG.md` | Regenerate the changelog from conventional commits |
| `bootstrap` | `pre-commit install ...` | One-time hook installation |
| `docs-serve` | `mkdocs serve` (`docs` environment) | Live preview of the documentation site at http://127.0.0.1:8000 |
| `docs-build` | `mkdocs build --strict` (`docs` environment) | Build the site into `site/`; a broken link or a page missing from the nav fails |

The documentation site is [MkDocs](https://www.mkdocs.org) with the Material theme, configured in `mkdocs.yml`; the
pages are the Markdown files in `docs/` with `index.md` as the landing page, plus the repository `CHANGELOG.md`, which
`mkdocs_hooks.py` publishes as the changelog page at build time. The `docs` pixi environment is separate
from the Rust one, so `pixi run -e docs docs-serve` (or plain `pixi run docs-serve`, which resolves to it) does not
pull the Rust toolchain into a docs-only checkout.

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

`rust-version` in `Cargo.toml` is **1.88**, and the `msrv` environment pins exactly that toolchain so the claim is
checked rather than asserted: `pixi run -e msrv msrv-check`, which CI runs on every pull request.

It was 1.85 until someone looked. That number came from edition 2024 and was never true — this crate uses
let-chains in `kev.rs` and `osv.rs`, and those did not stabilize until 1.88. Nothing caught it because every job
built on the toolchain `pixi.toml` pins, which is far newer.

Raising the MSRV is a breaking change for anyone pinned to an older toolchain, so after 1.0 it belongs in a minor
release at the earliest, with the new number in the changelog. Lowering it is free. Either way the `msrv`
environment and `Cargo.toml` change together, or the check is measuring the wrong thing.

### Benchmarks (`benches/`, criterion)

`pixi run bench` times the lockfile reader, the model builder, each writer, license normalization, the report
renderers and the offline enrichment path, against this repository's own lockfile and a generated 2000-package
one. The numbers and what they say are in [benchmarks.md](benchmarks.md); CI runs `pixi run bench-test`, which
executes each benchmark once without timing it, since a shared runner's timings are noise.

The benchmarks reach into the crate through the library target (`src/lib.rs`), which exists for them and for the
tests.

**That library is published to crates.io and is deliberately not an API.** The binary depends on it, so it cannot
be left out of the package; what it gets instead is every module marked `#[doc(hidden)]`, so nothing appears on
docs.rs, plus a crate-level note saying that none of it is covered by semantic versioning. Modules may move, split
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
stack; `pixi/04-data-analysis`, a scientific stack; `pixi/10-dev-tooling`, Rust binaries; and a pip venv of
`requirements/02-flask`), `scripts/grype_compare.py` installs it, describes it with syft and with
`pixi sbom --prefix --primary-purl pypi --embedded-sboms` (offline: everything pixi-sbom needs is on disk or in its
own tables), and scans both documents with the same Grype and the same database. syft and Grype run through
`pixi exec` at versions pinned in the script, so neither is a dependency of the project.

Every conda or Python finding from syft's document must also come from pixi-sbom's. One that does not fails the
run unless `tests/grype/exceptions.toml` lists it, for that environment, with a reason: an exception is for a
difference that is right, such as a Grype match on a CPE syft guessed from a name for code the package does not
contain. Findings only pixi-sbom's document produces are printed, not failed. The run prints the Grype database's
build date, because findings change as advisories are published.

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
(`src/cpe.rs`). An entry is added only when the pair is the one NVD and Grype's database use for that code, and the
conda package's version is spelled as upstream's:

- Look the product up in Grype's database (`grype db status` says where it is; the `cpes` table joined to
  `affected_cpe_handles` gives each vendor:product its advisory count), or in NVD's CPE dictionary. Use the vendor
  that carries the advisories; where NVD splits a product between vendors that are not the same code, leave the
  package out.
- Leave out compiler runtimes and C libraries (gcc, glibc), whose advisories are for code a conda package does not
  contain, and packages whose conda version differs from upstream's spelling.
- `cpe::tests::every_entry_is_a_valid_vendor_and_product` checks the format; it cannot check that a pair is right,
  which is why every entry needs that lookup. Scheduled checks that every entry still matches are #435.

## The GitHub Action

`action.yml` at the repository root is a composite action: it resolves the version (the action's own tag, an
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

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests:

| Job | Runs on | Does |
|---|---|---|
| Lint | ubuntu | `pixi run pre-commit-run`, `cargo fmt --check`, `lint`, `check`, `actionlint` |
| Test | `ubuntu-latest`, `macos-latest`, `windows-latest` | `pixi run test` |
| Coverage gate | ubuntu | `pixi run cov` |
| Dependency advisories and licenses | ubuntu | `pixi run -e lint deny`: RUSTSEC advisories, license terms, banned crates and unexpected sources |
| Builds on the MSRV | ubuntu | `pixi run -e msrv msrv-check`: the oldest toolchain `Cargo.toml` claims |
| Benchmarks compile and run | ubuntu | `pixi run bench-test`: every benchmark runs once, untimed |
| Performance (separate workflow) | all five release platforms | `pixi run perf`: builds two refs on one runner and compares them; fails on binary size or peak memory, reports wall time. On demand, weekly and on pushes to `main` — not on pull requests. See [benchmarks.md](benchmarks.md) |
| Build | same three | `pixi run build` and `--version` smoke test |
| Docs | ubuntu | `pixi run docs-build`: the site must build with `--strict` |
| SBOM via action | all five release platforms | The repository's own action against its own lockfile; SARIF and the attestation from the linux-64 leg only. See [The GitHub Action](#the-github-action) |
| Action on a uv project, without pixi | ubuntu-latest | The action on `examples/projects/uv/01-django/uv.lock` and on a venv built in the job (`prefix`), on a runner with no pixi; refuses `lockfile` with `prefix`. It runs the head binary, built by `action-head-binary` and placed where the action reuses an install, so it tests what the next release does rather than what the last one did |

`.github/workflows/supply-chain.yml` runs that same dependency check on a schedule (Mondays, and on demand).
The per-pull-request run cannot see an advisory published after a merge, and the weekly one is what catches it:
nothing about the repository changes and one day the answer is different.

`.github/workflows/docs.yml` publishes the site to GitHub Pages (https://millsks.github.io/pixi-sbom/) every time
a release is published, building from the release tag so the site matches the released binary. The site is
versioned with [mike](https://github.com/jimporter/mike) the way pixi's own docs are: each release deploys under
its tag (`/v0.5.5/`), `latest` is an alias of the newest non-pre-release version and the root redirects to it, so
links should use `/latest/...`, and `dev` follows `main` (redeployed on every push that touches `docs/`,
`mkdocs.yml`, the hook or the changelog). The versions live on the `gh-pages` branch, which the workflow then
publishes as the Pages artifact; the repository's Pages source stays "GitHub Actions" and the `github-pages`
environment records every deployment. `gh workflow run docs.yml -f ref=<tag>` redeploys a release's docs;
any other ref (or none) redeploys `dev`. `pixi run -e docs mike serve` previews every deployed version locally
from `gh-pages`; `mike delete --push <version>` removes one.

The `github-pages` environment's deployment branch policy must allow the `v*` tag pattern as well as `main`
(Settings → Environments → github-pages), because a release event runs on the tag; without it the deploy job fails
with "Branch ... is not allowed to deploy to github-pages".

All jobs use `prefix-dev/setup-pixi` with caching, so they run the same pinned toolchain as local development. CI
sticks to the `-latest` labels (x64 Linux and Windows, arm64 macOS) for the jobs that compile and test the code,
which has no platform-specific paths. The two jobs that are *about* a platform rather than merely running on one —
`sbom`, which tests the action's runner-to-archive mapping, and the separate performance workflow — use all five,
adding `ubuntu-24.04-arm` and `macos-15-intel` for linux-aarch64 and osx-64. The release build uses the same five,
since it must produce a native binary for each.

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
the tag push; that tag then starts `release-artifacts.yml`, which builds, signs and publishes everything. One
operator action, two runs.

`release.yml` inputs:

| Input | Default | Meaning |
|---|---|---|
| `version` | blank | Version to release without the `v` (e.g. `1.2.0`). Blank auto-increments the patch of the latest `v*` tag; for the very first release it uses `Cargo.toml`'s version. |
| `force_recreate` | false | Delete an existing tag and release of that version first, then recreate them. |

A **pre-release is expressed in the version**, not by a separate flag: `1.0.0-rc.1` is one and `1.0.0` is not.

**Write the release up in [What's new](whats-new.md) as you go**, under a `## Unreleased` section at the top of
the page: a pull request that changes something a user would notice adds its line there, saying what it means for
someone using the tool, not what the commits were. Before cutting a final release, give the section an editing
pass in its own pull request. The release workflow refuses to tag a final release whose `## Unreleased` is missing
or empty (`pixi run whats-new check <version>` asks the same question locally), and renames it to `## <version>`
in the `chore(release)` commit next to the changelog, so the tag carries its notes and `main` never has a release
the page does not describe. `the_whats_new_page_covers_every_release_since_1_0` in `tests/cli.rs` fails the build
for a release without a section, for a section naming a release that does not exist, and for an `## Unreleased`
that is not the only one or not above every release. Release candidates do not get a section, and leave
`## Unreleased` as it is; their final does. A release with nothing a user would notice still gets one line, such
as "No changes to behaviour; dependency updates only."
That is what semver already means by the suffix, and a flag could contradict the version it was attached to.

What the two do, in order:

1. **Version and guard.** Finds the latest `v*` tag, computes the next version, and exits quietly (no release) if
   nothing changed on `main` since that tag. Validates the version and refuses to reuse an existing tag unless
   `force_recreate` is set. For a final release, refuses to go on unless `docs/whats-new.md` has a non-empty
   `## Unreleased` section.
2. **Bump.** Writes the version into `Cargo.toml`, `Cargo.lock` (via `cargo update --workspace`) and `pixi.toml`.
3. **Gate.** Runs `pixi run ci` on the bumped tree; a red gate stops the release before anything is pushed.
4. **Changelog.** Regenerates `CHANGELOG.md` with `git-cliff --tag vX.Y.Z` (`cliff.toml`), renames What's new's
   `## Unreleased` to `## X.Y.Z` (final releases only), commits the bump, changelog and page as
   `chore(release): vX.Y.Z`, tags that commit, and pushes both to `main`. It then waits until
   `release-artifacts.yml` is visibly running for that tag before going green: a tag that pushed but started
   nothing would otherwise look like a successful release with no binaries behind it.

   *`release-artifacts.yml` takes over here, triggered by the tag.*

5. **Build.** Checks out the tag on five runners and builds `pixi-sbom` for linux-64, linux-aarch64, osx-64,
   osx-arm64 and win-64, packaged with `LICENSE`, `README.md`, `CHANGELOG.md` and a `.sha256` each.
6. **Attest.** `actions/attest-build-provenance` signs a provenance statement for each archive: what built it, from
   which commit, in which workflow run. It runs on the build runner, before the artifact upload, so the claim covers
   the round trip through artifact storage as well. The statement goes to the repository's attestation store, and
   the Sigstore bundle also ships beside the archive as `.sigstore.json` for anyone verifying offline.
7. **Publish.** Creates the GitHub release with this version's changelog section (from `git-cliff --latest`) plus an
   artifact table as the notes and the packages as assets, marked pre-release when the tag carries a suffix.
   A final release then moves the floating major tag (`v0`, later `v1`) to itself, which is what
   `uses: millsks/pixi-sbom@v1` follows; a rebuild of an older release leaves it alone. `release-artifacts.yml`
   only triggers on `vX.Y.Z` tags and the version lookups match `vX.Y.Z` only, so the floating tag starts nothing
   and is never taken for the latest release.
8. **Crate.** `publish-crate.yml` (reusable, also dispatchable by hand with a `tag` input to republish) checks the
   tag out clean and runs `cargo publish --locked` (skipped with a warning while the `CARGO_REGISTRY_TOKEN` secret
   is missing). The `[package.metadata.binstall]` table in `Cargo.toml` points `cargo binstall` at the release
   archives.
9. **Wheels.** The `wheels` job builds the same binary into PyPI platform wheels with
   [maturin](https://www.maturin.rs/) (`pyproject.toml`, `bindings = "bin"`: no Python code, version from
   `Cargo.toml`, so `1.7.0-rc.1` becomes `1.7.0rc1`), from the tag, with the Rust `pixi.toml` pins: manylinux and
   musllinux for x86_64 and aarch64, macOS x86_64 and arm64, Windows x86_64. Each is installed into a fresh venv and
   run (except musllinux, which the glibc runner cannot run) and attested like the archives. Once the GitHub release
   is out, a release candidate's wheels go to **TestPyPI** (`testpypi` job) and a final release's to **PyPI**
   (`pypi` job), through trusted publishing: no token, PyPI checks the run's OIDC identity. The
   `attach-wheels` job also adds them to the GitHub release as assets, once the release and every wheel exist; the
   `publish` job takes only the archives, so the release's assets never depend on which job finished first. There is no sdist,
   which would need a Rust toolchain and the crates.io index at install time.

10. **pre-commit mirror.** After a final release's wheels are on PyPI, the `pre-commit-mirror` job renders
    `pre-commit-mirror/` (the hooks, and a `pyproject.toml` pinning `pixi-sbom==X.Y.Z`) into
    [`millsks/pixi-sbom-pre-commit`](https://github.com/millsks/pixi-sbom-pre-commit), commits and tags it `vX.Y.Z`.
    The hooks cannot live here: pre-commit installs a `language: python` hook by `pip install .` of its repository,
    which here would compile the binary. The mirror repository must exist with the release GitHub App installed on
    it. To try the hooks before a release: `pre-commit-mirror/render.sh 1.7.0 /tmp/mirror`, commit that in a git
    repository, and `PIP_FIND_LINKS=<dir with a locally built wheel> pre-commit try-repo /tmp/mirror pixi-sbom` in a
    project.

**PyPI's side of trusted publishing** is set up once per index, by the maintainer, under the project's
*Publishing* settings (or as a *pending publisher* before the first upload creates the project):

| Field | PyPI | TestPyPI |
|---|---|---|
| Project name | `pixi-sbom` | `pixi-sbom` |
| Owner / repository | `millsks` / `pixi-sbom` | `millsks` / `pixi-sbom` |
| Workflow | `release-artifacts.yml` | `release-artifacts.yml` |
| Environment | `pypi` | `testpypi` |

The two GitHub environments of the same names are created on the first run that uses them; a required reviewer on
`pypi` turns the final upload into a click.

**Why the split exists.** `actions/attest-build-provenance` signs the OIDC identity of the run it is in, and that
identity comes from the event, not from what the job checked out. While the build lived in the `workflow_dispatch`
run, the provenance named `refs/heads/main` at the commit the release was dispatched from — one commit before the
`chore(release):` bump that the build job then checked out. The v0.11.0 archives are attested to `05fc3c8` although
they were built from `4029b71` (#218). Following the recorded commit gets you a tree whose `Cargo.toml` still says
the previous version, which is precisely the question an attestation exists to answer. Triggered by the tag, the
run being signed *is* the run that built the binaries, and the provenance names `refs/tags/vX.Y.Z` at the right
commit.

This works because the tag is pushed with the release GitHub App's token. A push made with the default
`GITHUB_TOKEN` deliberately does not start workflows; an App installation token does. If that ever changes, step 4's
handover check fails the release rather than letting it end quietly with nothing built, and
`release-artifacts.yml` can be dispatched by hand with a `tag` input.

**What is not attested, and why.** The wheels are attested twice over: the build provenance above, and the
publish attestations PyPI shows beside each file. The crates.io publish is not: crates.io has no attestation verification, so a
statement about the uploaded `.crate` would be one nobody could check at install time, and `cargo install` builds
from source anyway. Neither is the conda-forge package: the feedstock builds on conda-forge's own infrastructure
from the source tarball, so any provenance there is theirs to make, not ours. What is attested is the set of
binaries we build and hand out ourselves — which is also what `cargo binstall` downloads.

**conda-forge is not ours to release.** The package is built by
[`conda-forge/pixi-sbom-feedstock`](https://github.com/conda-forge/pixi-sbom-feedstock), whose autotick bot opens the
version bump against the new source tarball on its own, usually within hours of a release; nothing in this repository
takes part. A change to how the conda package is built — a build dependency, a platform, the build script — is a pull
request against the feedstock's own `recipe/recipe.yaml`.

This repository used to carry a copy of that recipe under `recipe/`, from the original `staged-recipes` submission. It
was removed in #219: it had a placeholder `sha256` that was never going to be filled, and it had drifted from the real
one in ways that mattered — the feedstock builds with `cargo auditable` so the binary carries its own dependency list,
and our copy still said plain `cargo install`. A second recipe that is authoritative nowhere is worse than none.

Publishing a release also deploys the documentation site (see [Continuous integration](#continuous-integration)).

It also updates the action's [Marketplace listing](https://github.com/marketplace/actions/pixi-sbom), which was
published by hand from the v1.0.0 release page and is updated by every release after it. Listing it was a one-time
manual step with no API behind it: it needs the Marketplace Developer Agreement accepted, and that is tied to a
person rather than a token. Should it ever need doing again — on a release page, *Edit* → tick *Publish this Action
to the GitHub Marketplace* → accept the agreement → category *Security* → *Update release*.

The Marketplace validates `action.yml` on that form, and all three currently pass: the `name` must be unique among
actions and must not match a GitHub user or organization (`pixi-sbom` is free on both counts), `branding` must be set
(`icon: shield`, `color: blue`), and the `description` must be at most 125 characters — it is 117, so keep the long
form in the README and the docs rather than growing that line.

Operator prerequisite: the release commit and tag land on `main` under the branch ruleset, so the workflow
authenticates with the release GitHub App (already in the ruleset's bypass list) rather than `GITHUB_TOKEN`. The
App's credentials must be present as the repository secrets `APP_ID` and `APP_PRIVATE_KEY`; the workflow mints a
short-lived token from them per run.

`pixi run changelog` regenerates `CHANGELOG.md` locally with an *Unreleased* section if you want to preview it; do
not commit that. Commit types map to sections via `cliff.toml`: `feat` → Features, `fix` → Bug Fixes, `perf`,
`refactor`, `docs`, `test`, `ci`/`build` → CI and Build; `chore` commits are omitted.
