# Papers

Long-form writing about the problem pixi-sbom exists to solve, and about the tool
itself. These are kept here because they are versioned alongside the code they
describe, not because they are part of the documentation site: `mkdocs.yml`
excludes `papers/` from the build, the same way it excludes `release-notes/` and
`presentations/`.

| Paper | Audience |
|---|---|
| [`package-identity-sbom-matching.md`](package-identity-sbom-matching.md) | Vendor-neutral. Why package identity breaks across conda, PyPI and system packages, what it costs, and what a correct implementation requires. pixi-sbom appears in one section. |
| [`pixi-sbom-design.md`](pixi-sbom-design.md) | Design and implementation: the intermediate model, the dual-identity scheme, enrichment and caching, the 1.0 stability contract. |

Each has a typeset PDF beside it. The Markdown is the source of truth; the PDF is
generated.

## The measurements

Both papers report the same study: 118 public conda and pixi workspaces, 15,722
packages, each processed twice with only the identification strategy changed.
Identity resolution surfaced 1,274 advisories that conventional identification
did not, a 37.1 percent increase, and lost none.

The corpus list, the per-workspace numbers and the scripts that produced them are
in [`data/`](data/README.md). Measurements were taken on 30 September 2026 with
pixi-sbom 1.0.0 against OSV. Advisory databases change daily, so a re-run will
not reproduce the counts exactly. The shape of the result should hold, since it
follows from which purl namespaces the databases index.

## Rebuilding the PDFs

Needs `pandoc` and Google Chrome:

```sh
cd docs/papers
./build.sh package-identity-sbom-matching.md package-identity-sbom-matching
./build.sh pixi-sbom-design.md pixi-sbom-design
```

`build.sh` writes an intermediate `.html` next to the PDF, inlining
`paper.css`. Those intermediates are not committed.

## If a number here changes

The papers cite figures that drift: source line counts, test counts, coverage,
the frozen interface totals. `docs/architecture.md` carried stale numbers for a
long time before anyone noticed (#254), so if you update one of these, check
whether a paper repeats it.
