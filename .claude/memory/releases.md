---
name: releases
description: "How pixi-sbom releases: tags vX.Y.Z, rc to TestPyPI and final to PyPI, the action and pre-commit mirrors on a final, a field test after every rc"
metadata:
  type: project
---

- Releases start from the Release workflow (`version` input) and are tagged `vX.Y.Z`; the tag starts Release
  artifacts. Archives are `pixi-sbom-vX.Y.Z-<platform>`, with provenance attestations signed by this repository's
  `release-artifacts.yml`. A final needs a non-empty `## Unreleased` on `docs/whats-new.md`, which becomes its section.
- A release candidate (`1.13.2-rc.1`) is a GitHub pre-release and goes to TestPyPI; a final goes to PyPI, is this
  repository's Latest release, and updates millsks/pixi-sbom-action (`vX.Y.Z`, `v1` moved, and a GitHub release there, Latest when `v1` moved) and
  millsks/pixi-sbom-pre-commit. The docs deploy under the version; a final also moves `latest`.
- After every release candidate the maintainer's field-test checklist is run against the published files before a
  final is cut. Ask before cutting any release.
- Every release is in this repository, tagged `vX.Y.Z`: up to 1.11.x and 1.12.0 to 1.13.1 were copied here from
  millsks/pixi-sbom and aesir-oss/pixi-ext-contrib (now deleted). From 1.14.0 (#25) the action reads only this
  repository's release list; `action-version.sh` still accepts a `pixi-sbom-vX.Y.Z` version.
- conda-forge builds from the `v*` source tarballs; the feedstock's bot follows new tags.

Related: [[issue-delivery-loop]], [[split-from-pixi-ext-contrib]], [[release-notes-span-last-tag]].
