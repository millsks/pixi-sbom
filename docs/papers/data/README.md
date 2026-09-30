# Supplementary data

Accompanies "Package Identity and the Limits of SBOM Vulnerability Matching"
and "pixi-sbom: Bill-of-Materials Generation for Mixed-Ecosystem Environments".

| File | Contents |
|---|---|
| `corpus-repos.txt` | The 118 GitHub repositories analyzed, one per line |
| `results.json` | Per-workspace measurements: component counts, conda/PyPI split, identities gained, advisory counts per arm, severity breakdown |
| `fetch.sh` | Retrieves one `pixi.lock` per repository from its default branch |
| `run_one.sh` | One measurement arm for one workspace |
| `campaign.sh` | Both arms for one workspace |

Measurements taken 30 September 2026 with pixi-sbom 1.0.0 against OSV.
Advisory databases change daily; re-running will not reproduce the counts exactly.

## Reproducing

    bash fetch.sh <owner/repo> <path-to-pixi.lock>
    bash campaign.sh corpus/<owner__repo>

Each workspace yields `out/<slug>.A.json` (conda identity) and
`out/<slug>.B.json` (PyPI identity). The difference between their
`vulnerabilities` arrays is the subject of both papers.
