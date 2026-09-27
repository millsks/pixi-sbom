# Installation

`pixi-sbom` is a [pixi extension](https://pixi.sh/latest/integration/extensions/introduction/): a standalone
executable named `pixi-sbom`. Pixi finds any `pixi-<name>` binary on `PATH` (or in its own global bin directory) and
runs it when you type `pixi <name>`. There is no plugin registration; installing the binary is the whole setup.

## Methods

| Method | Command |
|---|---|
| pixi global (recommended) | `pixi global install pixi-sbom` |
| Prebuilt binary | Download `pixi-sbom-<version>-<platform>.tar.gz` (or `.zip` on Windows) from the [releases page](https://github.com/millsks/pixi-sbom/releases), check its provenance (below), and put `pixi-sbom` on your `PATH` |
| cargo binstall | `cargo binstall pixi-sbom` downloads the release binary for your platform from GitHub (no compiler needed); `cargo install pixi-sbom` builds it from crates.io instead |
| From source | `pixi run build` in a clone, then copy `target/release/pixi-sbom` to `~/.pixi/bin/` |

Check it is picked up:

```sh
pixi --list          # ...  sbom  (via pixi-sbom)
pixi sbom --version
```

`pixi-sbom --help` and `pixi sbom --help` are equivalent; the binary can be run directly without pixi.

## Checking where a binary came from

Each release archive has a `.sha256` and a signed `.sigstore.json` beside it. They answer different questions. The
checksum says the file did not change between the release page and your disk. It says nothing about who made the
file — anyone can publish a binary and a correct checksum of it.

The provenance attestation is the one worth running. It is a Sigstore-signed statement that this exact archive was
built by this repository's release workflow, from a named commit, in a named workflow run. Releases carry one from
**0.11.0 onward**; earlier archives have a checksum and nothing else.

```sh
gh attestation verify pixi-sbom-<version>-linux-64.tar.gz --repo millsks/pixi-sbom
```

```console
Loaded digest sha256:... for file://pixi-sbom-<version>-linux-64.tar.gz
Loaded 1 attestation from GitHub API

The following policy criteria will be enforced:
- Predicate type must match:................ https://slsa.dev/provenance/v1
- Source Repository Owner URI must match:... https://github.com/millsks
- Source Repository URI must match:......... https://github.com/millsks/pixi-sbom

✓ Verification succeeded!
```

That needs the [GitHub CLI](https://cli.github.com) and reaches `api.github.com` to fetch the statement. On a
machine that cannot, pass the bundle that ships with the archive and the check runs entirely offline:

```sh
gh attestation verify pixi-sbom-<version>-linux-64.tar.gz \
  --bundle pixi-sbom-<version>-linux-64.tar.gz.sigstore.json \
  --repo millsks/pixi-sbom
```

Two things are deliberately not attested. The crates.io package is not, because nothing checks an attestation at
`cargo install` time and that path builds from source regardless. The conda-forge package is not, because the
feedstock builds on conda-forge's infrastructure rather than ours — the provenance there would be theirs to make.
The binaries this project builds and hands out are the ones covered, which includes what `cargo binstall` fetches.

## Upgrading

`pixi global update pixi-sbom` follows the conda-forge feedstock, which tracks releases within a day or two; a
downloaded binary is replaced by the next one from the releases page. `pixi sbom --version` prints the running
version, and every release is listed in the [changelog](changelog.md).

Next: [run it](cli.md), [use it in CI](github-action.md), or see [which format to pick](formats.md).
