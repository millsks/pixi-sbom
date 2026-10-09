# Field manual

The rest of the documentation is organised by flag. This part is organised by job: you have a problem, and each
page below is the shortest route through the tool to solving it. A playbook gives the commands in order, says
what success and failure look like, and links the reference for the details.

| You need to… | Playbook |
|---|---|
| fail a pull request on a known-exploited or high-severity vulnerability, or a license | [Gate a repository in CI](ci-gate.md) |
| decide whether to trust an SBOM a vendor sent you, and gate on it | [Take in a vendor's SBOM](vendor-sbom.md) |
| hand a customer one SBOM for a product made of several parts | [One SBOM for a product](product-sbom.md) |
| answer "are we exposed to CVE-X?" across everything you ship, today | [Are we exposed?](are-we-exposed.md) |
| run it where the network is filtered, proxied or absent | [A restricted network](restricted-network.md) |
| describe a project that uses uv, Poetry, PDM, conda-lock or pip instead of pixi | [A project without pixi](without-pixi.md) |
| publish an SBOM that anyone can verify came from your build | [Release with a signed SBOM](signed-release.md) |

Every command in these playbooks is run by a test against the repository's
[examples](../try-the-examples.md), so they work as written. The ones marked `# needs the network` look things
up online. In CI, the platform is named explicitly (`-p linux-64`): describe the platform you ship, not
whichever one the runner happens to be.

The exit codes a gate can end with are the contract a pipeline reads; they are listed under
[Exit codes and errors](../cli.md#exit-codes-and-errors), and none of them changes before 2.0.
