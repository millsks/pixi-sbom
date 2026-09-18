---
name: architecture-decisions
description: Settled design decisions for pixi-sbom (Rust pixi extension) made 2026-09-18
metadata:
  type: project
---

pixi-sbom is a Rust pixi extension (`pixi-sbom` binary -> `pixi sbom`). Decisions made 2026-09-18:

- Lockfile parsing via `rattler_lock` (same crate pixi uses); no `pixi_manifest` git dependency.
- Own serde models for both CycloneDX 1.6 JSON and SPDX 2.3 JSON; `cyclonedx-bom` crate rejected (capped at 1.5, heavy). Outputs validated against vendored official JSON schemas in tests.
- One SBOM per (environment, platform); default is `default` env + host platform. `-e/--environment`, `-p/--platform` select others.
- Workspace root metadata (name/version) read from `pixi.toml` / `pyproject.toml` with the `toml` crate.
- Default output: `<lockfile dir>/sbom.cdx.json` or `sbom.spdx.json`; `--output` overrides.
- Intermediate format-agnostic model (`model.rs`) sits between `lock.rs` and the writers in `format/`.

**Why:** keeps the dependency tree small, gets current spec versions, and matches what downstream SBOM tools expect (one env/platform per document).
**How to apply:** do not introduce `cyclonedx-bom`, `spdx-rs`, or pixi git deps without revisiting these notes.
