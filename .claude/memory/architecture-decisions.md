---
name: architecture-decisions
description: Settled design decisions for pixi-sbom (Rust pixi extension) made 2026-09-18
metadata:
  type: project
---

pixi-sbom is a Rust pixi extension (`pixi-sbom` binary -> `pixi sbom`). Decisions made 2026-09-18:

- Lockfile parsing via `rattler_lock` (same crate pixi uses); no `pixi_manifest` git dependency.
- Own serde models for both CycloneDX 1.6 JSON and SPDX 2.3 JSON; `cyclonedx-bom` crate rejected (capped at 1.5, heavy). Outputs validated against vendored official JSON schemas in tests.
- One SBOM per (environment, platform); default is `default` env + host platform. `-e/--environment`, `-p/--platform` select others. `--all-environments` (added 2026-09-18) loops over every environment writing `sbom-<env>.<ext>` files (`default` first, then alphabetical); it still never merges environments into one document.
- Workspace root metadata (name/version) read from `pixi.toml` / `pyproject.toml` with the `toml` crate.
- Default output: `<lockfile dir>/sbom.cdx.json` or `sbom.spdx.json`; `--output` overrides.
- Intermediate format-agnostic model (`model.rs`) sits between `lock.rs` and the writers in `format/`.

From 2026-10-11 to the split (aesir-oss/pixi-ext-contrib#131, October 2026) the crate lived in the
`aesir-oss/pixi-ext-contrib` Cargo workspace beside pixi-policy, sharing license normalization, the license verdict,
the lockfile facts, purl builders, terminal styling and pipe handling through a `pixi-ext-common` crate. It is a
single crate again, in `aesir-oss/pixi-sbom` (now `millsks/pixi-sbom`): `license.rs`, `style.rs` and `pipe.rs` are back in `src/`, and the
purl builders, the verdict and the lockfile facts are the `core`, `verdict` and `facts` modules of `purl.rs`,
`policy.rs` and `lock.rs`. pixi-policy keeps its own copy; nothing keeps the two in step. Nothing is published to
crates.io (#106, decided 2026-10-11): conda-forge, PyPI and the release archives all build from this repository, and
crates.io carried about 2% of pixi-sbom's downloads.

Release binaries (#93, decided 2026-10-11): every platform is compiled once, as its PyPI wheel (maturin,
`bindings = "bin"`), and the release archive carries the binary from that wheel. Linux archives use the manylinux
wheel's binary, built against glibc 2.17 so it runs on every glibc distribution from CentOS 7 / Amazon Linux 2 on,
newer ones included; the runner-built archives needed glibc 2.28. The `archive` job checks the 2.17 floor. Do not
go back to building the Linux archives with `pixi run build` on the runner without revisiting this: it raises the
floor to conda-forge's sysroot and splits pip and archive users onto two binaries.

**Why:** keeps the dependency tree small, gets current spec versions, and matches what downstream SBOM tools expect (one env/platform per document).
**How to apply:** do not introduce `cyclonedx-bom`, `spdx-rs`, or pixi git deps without revisiting these notes.
