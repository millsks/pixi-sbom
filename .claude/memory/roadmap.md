---
name: roadmap
description: Post-0.1.0 review findings and the proposed 0.2.0 / 0.3.0 roadmap and goal (proposed 2026-09-19)
metadata:
  type: project
---

Review of v0.1.0 on 2026-09-19 (tests green, CycloneDX 1.6 + SPDX 2.3 schema-valid, binaries for 5 platforms).

Key evidence: a real 120-package conda-only Python env (`~/openteams`) yields 0 `pkg:pypi` purls, yet 69/120 (58%)
map to PyPI via the conda-forge mapping pixi itself uses
(`https://conda-mapping.prefix.dev/compressed-v0/compressed_mapping.json`, ~34k entries, ~950 KB). OSV/GHSA/trivy/grype
have no conda ecosystem, so `pkg:conda/...` alone matches nothing and scans come back falsely clean.

Proposed roadmap:
- 0.2.0 "reproducible & compliant": lockfile path relative to workspace (no absolute local paths in output);
  `SOURCE_DATE_EPOCH` + UUIDv5 serial number for byte-identical reruns; `--output -` (stdout); `--all-platforms`;
  CISA 2026 minimum elements (authors from `[workspace] authors`, `metadata.lifecycles` phase, component `supplier`
  = channel / PyPI, root license/homepage/repository); conda-forge feedstock: user opened the staged-recipes PR before 2026-09-19 (README already advertises
  `pixi global install pixi-sbom`, which does not work yet).
- 0.3.0 "scanner-actionable": opt-in PyPI identity enrichment from the prefix.dev mapping (offline file option),
  `--primary-purl pypi` so scanners that only read `purl` can match; optional PyPI license lookup; CycloneDX 1.7 as a
  selectable spec version.

Goal: `pixi sbom --output - | grype` on a conda-only Python environment reports real findings; on the openteams lock,
>= 60/120 components carry a PyPI purl, and two runs with `SOURCE_DATE_EPOCH` set are byte-identical.

**Why:** the SBOM is only useful to the community if scanners can act on it and CI can diff it.
**How to apply:** work items in this order; network features stay opt-in; adding an HTTP client is a new runtime
dependency that needs user confirmation. See [[architecture-decisions]].
