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

**Claude Code.** `.claude/settings.json` registers a Stop hook that runs `pixi run ci`, so an AI-assisted session
cannot finish with a red gate. `.claude/memory/` holds the recorded design decisions and environment notes.

## Tests

Three layers, all under `pixi run test`:

### Unit tests (`#[cfg(test)]` in each module)

Exercise one module's contract. `discover`, `manifest`, `purl`, `license` are tested with temp dirs or pure inputs.
`lock` tests parse the fixture lockfiles and assert on the resulting model (purls, hashes, properties, dependency
edges, error variants). `format/*` tests run each writer over `format::testing::sample_sbom()`, a hand-built model
covering every package kind plus edge cases (missing version, non-SPDX license, local path source, extra purls), and
check specific fields.

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

`tests/schemas/` contains the official CycloneDX 1.6 schema (with the `spdx.schema.json` and `jsf-0.82.schema.json`
it references, registered under their canonical `$id`s so no network access happens) and the SPDX 2.3 schema. Both
the sample model and every end-to-end document are validated. When upgrading a spec version, replace the schema files
and update the `$schema` / `specVersion` constants in the writer.

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

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests:

| Job | Runs on | Does |
|---|---|---|
| Lint | ubuntu | `pixi run pre-commit-run`, `cargo fmt --check`, `lint`, `check` |
| Test | `ubuntu-latest`, `macos-latest`, `windows-latest` | `pixi run test` |
| Coverage gate | ubuntu | `pixi run cov` |
| Build | same three | `pixi run build` and `--version` smoke test |

All jobs use `prefix-dev/setup-pixi` with caching, so they run the same pinned toolchain as local development. CI
sticks to the `-latest` labels (x64 Linux and Windows, arm64 macOS); the code has no platform-specific paths, so the
remaining architectures are only exercised by the release build, which must produce a native binary for each of the
five pixi platforms and therefore uses `ubuntu-24.04-arm` and `macos-15-intel` for linux-aarch64 and osx-64.

## Releasing

1. Make sure `main` is green and `Cargo.toml` `version` is bumped (the tag must match it).
2. `pixi run changelog`, commit `CHANGELOG.md`.
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
4. `.github/workflows/release.yml` builds `pixi-sbom` for linux-64, linux-aarch64, osx-64, osx-arm64 and win-64,
   packages each with `LICENSE` and `README.md` plus a `.sha256`, and publishes a GitHub release with notes generated
   by git-cliff from the commits since the previous tag.
5. For `pixi global install pixi-sbom`, update `recipe/recipe.yaml` (version and the source tarball's SHA-256) and
   submit it to conda-forge `staged-recipes`; once the feedstock exists, later releases are version bumps there.
