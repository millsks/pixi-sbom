# pixi-sbom documentation

| Document | Audience | Contents |
|---|---|---|
| [usage.md](usage.md) | Operators, CI authors | Installing and running `pixi sbom`, every option, output naming, exit codes, error messages, CI recipes, consuming the output with other tools |
| [output-format.md](output-format.md) | SBOM consumers | Exactly what lands in a CycloneDX 1.6 or SPDX 2.3 document, field by field, and the rules behind purls, licenses, and the dependency graph |
| [architecture.md](architecture.md) | Contributors | The pipeline from lockfile to document, what each module owns, and the design decisions with their rationale |
| [development.md](development.md) | Contributors | Toolchain, tasks, the change harness, test strategy, fixtures, conventions, and releasing |

The top-level [README](../README.md) is the short version of all of this.
