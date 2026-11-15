# pixi-sbom action

A GitHub Action that writes a CycloneDX or SPDX SBOM for a pixi project, or a uv, Poetry, PDM, pylock or conda-lock
one, with licenses, vulnerabilities and a license policy gate. It downloads the
[pixi-sbom](https://github.com/millsks/pixi-sbom) release binary for the runner,
verifies its checksum, runs it and uploads the documents as a workflow artifact. pixi itself is not needed.

```yaml
- uses: actions/checkout@v4
- uses: millsks/pixi-sbom-action@v1
  with:
    all-environments: "true"
    fetch-licenses: "true"
    pypi-mapping: prefix
    primary-purl: pypi
    deny-license: "GPL-3.0-only AGPL-3.0-only"
    require-license: "true"
```

`@v1` follows the newest 1.x.y release. Pin an exact release (`@v1.12.0`) or a commit sha for a build that never
changes underneath you.

Every input and output, and more examples, are in the
[GitHub Action guide](https://millsks.github.io/pixi-sbom/latest/github-action/).

This repository is published from
[`actions/pixi-sbom`](https://github.com/millsks/pixi-sbom/tree/main/actions/pixi-sbom) in
[millsks/pixi-sbom](https://github.com/millsks/pixi-sbom) on each release; issues and changes go
there.

## License

[Apache-2.0](LICENSE)
