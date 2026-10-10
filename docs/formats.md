# Which format to pick

`pixi sbom` writes one of four document flavours from the same model, so the choice is about who reads the file, not
what goes into it. The [output format reference](output-format.md) covers every field.

| | CycloneDX 1.6 | CycloneDX 1.7 | SPDX 2.3 | SPDX 3.0.1 |
|---|---|---|---|---|
| Flags | (default) | `--spec-version 1.7` | `--format spdx` | `--format spdx --spec-version 3.0` |
| File | `sbom.cdx.json` | `sbom.cdx.json` | `sbom.spdx.json` | `sbom.spdx.json` |
| Shape | components + dependency graph | same, plus `citations` | packages + relationships | JSON-LD graph of elements |
| Best for | vulnerability scanners (grype, trivy, OSV), most SBOM tooling | consumers that already read 1.7 | procurement, NTIA / CISA minimum-elements checklists, legacy SPDX tooling | SPDX 3 native tooling, linking into larger SPDX 3 graphs |
| License texts (`--license-texts`) | `licenses[].license.text` | same | extracted licensing infos | `SimpleLicensingText` elements |
| Vulnerabilities (`--vulnerabilities`) | `vulnerabilities[]` | same | **not recorded** — a warning says so | `security_Vulnerability` elements with CVSS, KEV and VEX assessments |
| Validated against | CycloneDX 1.6 schema | 1.7 schema | SPDX 2.3 schema | SPDX 3.0.1 schema |

Rules of thumb:

- **Scanning for vulnerabilities**: CycloneDX 1.6, piped straight in (`pixi sbom --output - | grype`). Add
  `--pypi-mapping prefix --primary-purl pypi` so conda-installed Python packages match PyPI advisories; see
  [Scanning with Grype](ci-recipes.md#scanning-with-grype).
- **Handing a bill of materials to a customer or auditor**: SPDX 2.3 is the most widely accepted interchange, and its
  `licenseDeclared` / `licenseConcluded` split maps onto compliance workflows. If the findings have to travel with it,
  use SPDX 3.0.1 instead — 2.3 has nowhere to record them.
- **A newer consumer that reads it**: CycloneDX 1.7 or SPDX 3.0.1. The defaults stay at 1.6 / 2.3 until the common
  consumers move; a version of the other format is a usage error.

Every flavour records which environment and platform it describes and carries the same purls, licenses and
dependency edges, so converting later with `syft convert` loses nothing that `pixi sbom` put in.

## GitHub's dependency graph

`--format github` writes a [dependency submission](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/using-the-dependency-submission-api)
snapshot, `sbom.github.json`, instead of an SBOM. Submitted, it puts the environment's packages in the repository's
dependency graph, and Dependabot raises alerts for the ones it has advisories for:

```sh
pixi sbom --format github --output - |
  gh api --method POST "repos/OWNER/REPO/dependency-graph/snapshots" --input -
```

It is not an SBOM, so it records packages, versions, which are direct and which development-only, and the dependency
edges, and nothing else: no licenses, hashes or findings, and `--spec-version` does not apply. A conda package that
has a PyPI identity is submitted by it whatever `--primary-purl` says, since GitHub's advisory database has PyPI
advisories and no conda ones; the rest keep their conda purl.

The snapshot names the commit and workflow run it describes, from `GITHUB_SHA`, `GITHUB_REF`, `GITHUB_RUN_ID`,
`GITHUB_WORKFLOW` and `GITHUB_JOB`. GitHub Actions sets them; elsewhere the API refuses a snapshot without a sha and
a ref, and pixi-sbom warns when they are missing. Each environment and platform gets its own correlator, so
submitting several does not replace one with another. In the [GitHub Action](github-action.md#dependabot-alerts),
`dependency-submission: "true"` writes and submits it.
