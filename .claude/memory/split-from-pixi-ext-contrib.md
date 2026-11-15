---
name: split-from-pixi-ext-contrib
description: "pixi-sbom was split back out of the aesir-oss/pixi-ext-contrib monorepo in October 2026: what came with it and what stayed behind"
metadata:
  type: project
---

pixi-sbom started in millsks/pixi-sbom, moved into the aesir-oss/pixi-ext-contrib Cargo workspace on 2026-10-11
(releases 1.12.0 to 1.13.1, tagged `pixi-sbom-vX.Y.Z` there), and moved to this repository in October 2026 (plan:
aesir-oss/pixi-ext-contrib#131). Its whole history came with it, so commit messages reference both earlier
repositories' issues and PRs by number.

- Every release is here as `vX.Y.Z`: the GitHub releases of 1.12.0 to 1.13.1 (from pixi-ext-contrib) and up to
  1.11.x (from millsks/pixi-sbom) were copied with their assets and `.sigstore.json` bundles. Their attestations still
  name the repository that built them, so verify old archives offline with `gh attestation verify --bundle`.
- aesir-oss/pixi-ext-contrib was deleted after the split; its issues were moved here and to aesir-oss/pixi-policy
  (workspace-only ones in the closed `pixi-ext-contrib` and `pixi-ext-common` milestones), its PRs were lost.
- The original millsks/pixi-sbom kept its issues and served `uses: millsks/pixi-sbom@v1` (a deprecated wrapper
  forwarding to millsks/pixi-sbom-action@v1). In November 2026 it was renamed millsks/pixi-sbom.org, and this
  repository (then aesir-oss/pixi-sbom), the action and the pre-commit mirror were transferred to millsks.
- The code once shared with pixi-policy is this crate's own again (see [[architecture-decisions]]); pixi-policy keeps
  its own copy, and nothing keeps the two in step.
- The docs for 1.12.0 to 1.13.1 went with pixi-ext-contrib's site; this repository's site starts with 1.13.2.

**Why:** the maintainer wanted each extension in its own repository, so either can be handed to a new owner by
transferring one repository.

**How to apply:** links to the earlier repositories in old commits, the changelog and What's new are history; do not
rewrite them. New issues and PRs live here.
