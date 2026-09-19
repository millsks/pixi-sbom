---
name: dev-environment
description: Local quirks for testing pixi-sbom as a real pixi extension on this machine
metadata:
  type: project
---

- The hand-copied dev binary at `~/.pixi/bin/pixi-sbom` was removed 2026-09-19 so `pixi global install pixi-sbom` (conda-forge feedstock, staged-recipes PR #34888 merged 2026-09-19) can own that path. To test a local build for real, run `target/release/pixi-sbom` directly or `pixi global install --path`-style from a local channel; do not copy over the global trampoline.
- `~/openteams` (120-package osx-arm64 lock) is a handy real-world workspace for manual runs; `syft` is on PATH and `syft convert <file> -o spdx-json` is an independent parser check (its WARN line goes to stdout, so filter before piping to a JSON parser).
- Local pre-commit hooks call `pixi run <tool>` because the git hook runs outside the pixi env.
- miette wraps error text at 80 columns by default; `main.rs` disables wrapping so lists of names in errors stay greppable.

**Why:** these are environment facts not derivable from the repo.
**How to apply:** use them when manually verifying the extension; see [[architecture-decisions]] for design constraints.
