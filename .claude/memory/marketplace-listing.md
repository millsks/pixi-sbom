---
name: marketplace-listing
description: Where the pixi-sbom GitHub Action is listed, how the old millsks/pixi-sbom listing was retired, and the manual Marketplace step
metadata:
  type: project
---

The action's source is `actions/pixi-sbom/` here. The `action-repo` job in `release-artifacts.yml` copies it to
`millsks/pixi-sbom-action` on every release, tags `vX.Y.Z`, and on a final moves `vX` and creates a GitHub release
there (Latest only when `vX` moved). The Marketplace listing `pixi-sbom` (github.com/marketplace/actions/pixi-sbom) has
been published from that repository since v1.13.2 (2026-10-14).

The original `millsks/pixi-sbom` (renamed `millsks/pixi-sbom.org` in November 2026, when this repository moved back
from `aesir-oss/pixi-sbom` and took the name) held the original listing. Its v1.11.1 (2026-10-14) made its action.yml a wrapper named
`pixi-sbom (deprecated)` that warns and forwards every input and output to `millsks/pixi-sbom-action@v1`; `v1` points
there, and the old listing now lives at /marketplace/actions/pixi-sbom-deprecated. Its release, release-artifacts,
publish-crate and docs workflows are disabled so a tag there publishes nothing. Since the rename,
`uses: millsks/pixi-sbom@v1` resolves to this repository, which has no `v1` tag or root `action.yml`.

**Why:** action names are unique on the Marketplace and its URL is the name's slug; renaming the old action freed the
name without delisting it, so people who find the old listing are pointed at the new one.

**How to apply:** ticking "Publish this Action to the GitHub Marketplace" has no API. The release job creates the
release; if the listing does not follow a new final on its own, the maintainer ticks the box on that release's edit
page. Docs say `uses: millsks/pixi-sbom-action@v1`.
