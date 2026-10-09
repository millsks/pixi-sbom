# Release with a signed SBOM

**When:** you publish an SBOM with a release, and the people who receive it need to know it came from your build
and was not altered.

## In the release workflow

The action signs what it writes with a GitHub artifact attestation, bound to the workflow run:

```yaml
permissions:
  contents: read
  id-token: write
  attestations: write
steps:
  - uses: actions/checkout@v4
  - uses: millsks/pixi-sbom@v1
    with:
      platform: linux-64
      pypi-mapping: prefix
      vulnerabilities: osv
      kev: "true"
      vex: vex.cdx.json
      attest: "true"
      attest-subject: dist/myapp-1.2.0.tar.gz   # the artifact the SBOM describes
```

- With `attest-subject`, the SBOM is attached to that artifact as an SBOM attestation, so verifying the artifact
  also tells you its SBOM.
- Without it, the documents themselves get a build provenance attestation.
- `vex` writes a standalone CycloneDX VEX beside the SBOM, linked back to it: the assessments can then be updated
  without re-issuing the SBOM.

Forks have no `id-token`, so attest on pushes and tags only. See [Signed SBOMs](../github-action.md#signed-sboms).

## The same SBOM, locally

What the workflow runs, without the signing, to check the output before tagging:

```sh
pixi sbom -p linux-64 --pypi-mapping prefix --vulnerabilities osv --kev --output sbom.cdx.json --vex vex.cdx.json   # needs the network
```

## Verifying what was published

Anyone with the document checks it against your repository:

```sh
gh attestation verify sbom.cdx.json --repo <owner>/<repo>
```

A document that was altered, or that came from another repository's workflow, fails verification.
