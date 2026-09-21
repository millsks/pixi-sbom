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
| Validated against | CycloneDX 1.6 schema | 1.7 schema | SPDX 2.3 schema | SPDX 3.0.1 schema |

Rules of thumb:

- **Scanning for vulnerabilities**: CycloneDX 1.6, piped straight in (`pixi sbom --output - | grype`). Add
  `--pypi-mapping prefix --primary-purl pypi` so conda-installed Python packages match PyPI advisories.
- **Handing a bill of materials to a customer or auditor**: SPDX 2.3 is the most widely accepted interchange, and its
  `licenseDeclared` / `licenseConcluded` split maps onto compliance workflows.
- **A newer consumer that reads it**: CycloneDX 1.7 or SPDX 3.0.1. The defaults stay at 1.6 / 2.3 until the common
  consumers move; a version of the other format is a usage error.

Every flavour records which environment and platform it describes and carries the same purls, licenses and
dependency edges, so converting later with `syft convert` loses nothing that `pixi sbom` put in.
