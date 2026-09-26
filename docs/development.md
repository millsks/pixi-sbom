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
| `test` | `cargo test` | Unit tests (in `src/`) and end-to-end tests (`tests/cli.rs`) |
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
whitespace) → release build → check → lint → coverage. If pre-commit rewrites a file, re-stage it before re-running or
the next run fails identically. Coverage below 90% lines fails the gate; new code needs tests.

**Hooks.** `pixi run bootstrap` installs pre-commit for the `pre-commit` and `commit-msg` stages. The local hooks call
`pixi run cargo fmt`, `pixi run cargo clippy`, `pixi run taplo`, `pixi run typos`, because the git hook runs outside
the pixi environment. The `commit-msg` hook enforces Conventional Commits. `--no-verify` is not used.

**Claude Code.** `.claude/settings.json` registers `.claude/hooks/stop-ci.sh` as a Stop hook. It fingerprints the
working tree (HEAD, staged and unstaged changes, untracked files) and runs `pixi run ci` only when that differs from
the state recorded at the last green run (`.pixi/.last-ci-ok`), so a stop that changed nothing costs nothing. A
failing gate exits 2 with the tail of `.pixi/.last-ci.log`, which blocks the stop and hands the failure back to the
assistant rather than only printing it. `.claude/memory/` holds the recorded design decisions and environment notes.

## Tests

Three layers, all under `pixi run test`:

### Unit tests (`#[cfg(test)]` in each module)

Exercise one module's contract. `discover`, `manifest`, `purl`, `license` are tested with temp dirs or pure inputs.
`lock` tests parse the fixture lockfiles and assert on the resulting model (purls, hashes, properties, dependency
edges, error variants). `format/*` tests run each writer over `format::testing::sample_sbom()`, a hand-built model
covering every package kind plus edge cases (missing version, non-SPDX license, local path source, extra purls), and
check specific fields.

### Benchmarks (`benches/`, criterion)

`pixi run bench` times the lockfile reader, the model builder, each writer, license normalization, the report
renderers and the offline enrichment path, against this repository's own lockfile and a generated 2000-package
one. The numbers and what they say are in [benchmarks.md](benchmarks.md); CI runs `pixi run bench-test`, which
executes each benchmark once without timing it, since a shared runner's timings are noise.

The benchmarks reach into the crate through the library target (`src/lib.rs`), which exists for them and for the
tests. It is the binary's insides made reachable, not a designed API, and nothing in it promises to stay put.

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
  output changes → writer tests and snapshots; CLI changes → `tests/cli.rs`).
- Dependencies: prefer what `rattler_lock` already pulls in; avoid git dependencies. `serde_json` uses
  `preserve_order` so keys are emitted in struct order.
- Never print to stdout; logs go through `tracing` to stderr.

## The GitHub Action

`action.yml` at the repository root is a composite action: it resolves the version (the action's own tag, an
explicit `version` input, or the latest release), downloads the matching release archive and its `.sha256`,
verifies it, puts the binary on `PATH`, maps the inputs to CLI flags and runs it, then uploads the output with
`actions/upload-artifact`. The `sbom` job in `ci.yml` dogfoods it on Linux and Windows with the latest release,
so a change to the action is exercised by CI before it is tagged: one step runs every environment with license
fetching, embedded SBOMs and a deny list that pre-commit's `python` (Python-2.0) violates on every platform, with
`fail-on-policy` off, and asserts the `policy-violated` output; a second step runs a policy that passes. New CLI flags reach the action only once a
release containing them exists; keep `action.yml` inputs and the CLI in step at release time.

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests:

| Job | Runs on | Does |
|---|---|---|
| Lint | ubuntu | `pixi run pre-commit-run`, `cargo fmt --check`, `lint`, `check` |
| Test | `ubuntu-latest`, `macos-latest`, `windows-latest` | `pixi run test` |
| Coverage gate | ubuntu | `pixi run cov` |
| Benchmarks compile and run | ubuntu | `pixi run bench-test`: every benchmark runs once, untimed |
| Build | same three | `pixi run build` and `--version` smoke test |
| Docs | ubuntu | `pixi run docs-build`: the site must build with `--strict` |

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
sticks to the `-latest` labels (x64 Linux and Windows, arm64 macOS); the code has no platform-specific paths, so the
remaining architectures are only exercised by the release build, which must produce a native binary for each of the
five pixi platforms and therefore uses `ubuntu-24.04-arm` and `macos-15-intel` for linux-aarch64 and osx-64.

## Releasing

One workflow, `release.yml`, run by hand from the Actions tab (*Release* → *Run workflow* on `main`). Inputs:

| Input | Default | Meaning |
|---|---|---|
| `version` | blank | Version to release without the `v` (e.g. `1.2.0`). Blank auto-increments the patch of the latest `v*` tag; for the very first release it uses `Cargo.toml`'s version. |
| `prerelease` | false | Mark the GitHub release as a pre-release. |
| `force_recreate` | false | Delete an existing tag and release of that version first, then recreate them. |

What it does, in order:

1. **Version and guard.** Finds the latest `v*` tag, computes the next version, and exits quietly (no release) if
   nothing changed on `main` since that tag. Validates the version and refuses to reuse an existing tag unless
   `force_recreate` is set.
2. **Bump.** Writes the version into `Cargo.toml`, `Cargo.lock` (via `cargo update --workspace`), `pixi.toml` and
   `recipe/recipe.yaml`.
3. **Gate.** Runs `pixi run ci` on the bumped tree; a red gate stops the release before anything is pushed.
4. **Changelog.** Regenerates `CHANGELOG.md` with `git-cliff --tag vX.Y.Z` (`cliff.toml`), commits the bump and
   changelog as `chore(release): vX.Y.Z`, tags that commit, and pushes both to `main`.
5. **Build.** Checks out the tag on five runners and builds `pixi-sbom` for linux-64, linux-aarch64, osx-64,
   osx-arm64 and win-64, packaged with `LICENSE`, `README.md`, `CHANGELOG.md` and a `.sha256` each.
6. **Publish.** Creates the GitHub release with this version's changelog section (from `git-cliff --latest`) plus an
   artifact table as the notes and the packages as assets. The job summary prints the source tarball's SHA-256 for
   `recipe/recipe.yaml`.
7. **Crate.** `publish-crate.yml` (reusable, also dispatchable by hand with a `tag` input to republish) checks the
   tag out clean and runs `cargo publish --locked` (skipped with a warning while the `CARGO_REGISTRY_TOKEN` secret
   is missing). The `[package.metadata.binstall]` table in `Cargo.toml` points `cargo binstall` at the release
   archives.

For `pixi global install pixi-sbom`, put that SHA-256 into `recipe/recipe.yaml` and submit it to conda-forge
`staged-recipes` once; after that the feedstock bot handles version bumps.

Publishing a release also deploys the documentation site (see [Continuous integration](#continuous-integration)) and
updates the action's [Marketplace listing](https://github.com/marketplace/actions/pixi-sbom). The listing itself was
created once by hand: on the release page, *Edit* → tick *Publish this Action to the GitHub Marketplace* → accept
the developer agreement → category *Security*. The Marketplace validates `action.yml` on that page: the `name` must
be unique among actions and not match a GitHub user or organization, `branding` must be set, and the `description`
must be at most 125 characters, so keep the long form in the README and the docs.

Operator prerequisite: the release commit and tag land on `main` under the branch ruleset, so the workflow
authenticates with the release GitHub App (already in the ruleset's bypass list) rather than `GITHUB_TOKEN`. The
App's credentials must be present as the repository secrets `APP_ID` and `APP_PRIVATE_KEY`; the workflow mints a
short-lived token from them per run.

`pixi run changelog` regenerates `CHANGELOG.md` locally with an *Unreleased* section if you want to preview it; do
not commit that. Commit types map to sections via `cliff.toml`: `feat` → Features, `fix` → Bug Fixes, `perf`,
`refactor`, `docs`, `test`, `ci`/`build` → CI and Build; `chore` commits are omitted.
