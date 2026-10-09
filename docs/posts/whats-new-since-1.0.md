# pixi-sbom since 1.0: no pixi required, and other people's SBOMs

pixi-sbom writes CycloneDX and SPDX Software Bills of Materials from a lockfile, with conda and PyPI
packages described together, so a scanner can match both. At 1.0 it froze its command line, exit
codes and output names. Eight minor releases later nothing on that list has changed, and quite a
lot has been added around it.

## You don't need pixi

pixi-sbom now reads `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock.toml`, `conda-lock.yml`, explicit
conda specs, fully pinned `requirements.txt` files and plain venvs. It's on PyPI, so a uv or Poetry
project can run it without installing anything:

```sh
uvx pixi-sbom --lockfile uv.lock
```

There are also pre-commit hooks that keep an SBOM next to the lockfile and enforce a license policy
before a commit lands. pixi-sbom never resolves anything: it reads what your tool locked, and when
it's handed a manifest instead of a lock, it tells you the command that makes one.

## Someone else's SBOM

If a vendor ships an SBOM and your pipeline gates on it, 1.8 has three new steps for you:

```sh
pixi sbom --from-sbom vendor.cdx.json --report quality              # is it complete enough to trust?
pixi sbom --from-sbom vendor.cdx.json --min-quality 70 \
  --vulnerabilities osv --fail-on-severity high \
  --vex-in vendor.openvex.json                                      # apply their VEX, then gate
pixi sbom --from-sbom app.cdx.json --from-sbom vendor.spdx.json \
  --root-name product --output product.cdx.json                     # one document for the product
```

A document with no purls passes a vulnerability scan by having nothing to match. Grading it first
catches that.

## Which findings to fix first

CISA's Known Exploited Vulnerabilities catalog says what's being exploited now. 1.8 adds FIRST's
EPSS score for everything else: the probability of exploitation in the next 30 days. Either one can
fail a build:

```sh
pixi sbom --pypi-mapping prefix --vulnerabilities osv --kev --fail-on-kev --epss --fail-on-epss 0.1
```

## Restricted networks

Every upstream, conda and wheel archive hosts included, can point at a mirror. pixi's own
credentials are used for private channels. `--doctor` probes each host and says which one is the
problem. Everything works offline from a warmed cache.

## Try it

```sh
pixi global install pixi-sbom     # or: uvx pixi-sbom
pixi sbom --report packages
```

The repository's `examples/projects` has more than a hundred real projects, one per lockfile kind
for each of fourteen scenarios. Some have known vulnerabilities, some have license problems, and
some are built to be refused.

- What changed, release by release: https://millsks.github.io/pixi-sbom/latest/whats-new/
- Without pixi: https://millsks.github.io/pixi-sbom/latest/without-pixi/
- Source: https://github.com/millsks/pixi-sbom
