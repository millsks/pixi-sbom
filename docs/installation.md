# Installation

`pixi-sbom` is a [pixi extension](https://pixi.sh/latest/integration/extensions/introduction/): a standalone
executable named `pixi-sbom`. Pixi finds any `pixi-<name>` binary on `PATH` (or in its own global bin directory) and
runs it when you type `pixi <name>`. There is no plugin registration; installing the binary is the whole setup.

## Methods

| Method | Command |
|---|---|
| pixi global (recommended) | `pixi global install pixi-sbom` |
| Prebuilt binary | Download `pixi-sbom-<version>-<platform>.tar.gz` (or `.zip` on Windows) from the [releases page](https://github.com/millsks/pixi-sbom/releases), verify the `.sha256` next to it, and put `pixi-sbom` on your `PATH` |
| cargo binstall | `cargo binstall pixi-sbom` downloads the release binary for your platform from GitHub (no compiler needed); `cargo install pixi-sbom` builds it from crates.io instead |
| From source | `pixi run build` in a clone, then copy `target/release/pixi-sbom` to `~/.pixi/bin/` |

Check it is picked up:

```sh
pixi --list          # ...  sbom  (via pixi-sbom)
pixi sbom --version
```

`pixi-sbom --help` and `pixi sbom --help` are equivalent; the binary can be run directly without pixi.

## Upgrading

`pixi global update pixi-sbom` follows the conda-forge feedstock, which tracks releases within a day or two; a
downloaded binary is replaced by the next one from the releases page. `pixi sbom --version` prints the running
version, and every release is listed in the [changelog](changelog.md).

Next: [run it](cli.md), [use it in CI](github-action.md), or see [which format to pick](formats.md).
