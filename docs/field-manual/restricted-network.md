# A restricted network

**When:** the runner sits behind a proxy, a private certificate authority, an Artifactory or Nexus mirror, or no
network at all, and pixi-sbom comes back empty, slow or failing.

## 1. Ask the tool what it sees

```sh
pixi sbom --doctor --vulnerabilities osv --kev --epss --fetch-licenses   # needs the network
```

`--doctor` probes every upstream the named flags would use, prints the proxy, the certificates it trusts, the
request concurrency and the cache it reads, and exits 1 if anything is unreachable. Every upstream is listed with
its address and the environment variable that overrides it. See [--doctor: is it the network?](../cli.md#-doctor-is-it-the-network)
and [Troubleshooting](../troubleshooting.md).

## 2. Point the blocked upstreams at a mirror

Each upstream has a `PIXI_SBOM_*_URL` variable: the PyPI index, OSV, CISA KEV, FIRST EPSS, the conda index, the
conda-to-PyPI mapping, OpenSSF Scorecard, and the conda and wheel archive hosts. Set the ones `--doctor` reported,
then ask again:

```sh
PIXI_SBOM_PYPI_URL=https://artifactory.example.com/api/pypi/pypi/pypi pixi sbom --doctor --fetch-licenses   # needs the network
```

The full list, with defaults, is under [Every upstream it can reach](../cli.md#every-upstream-it-can-reach). A
private certificate authority goes in `--ca-bundle` or `PIXI_SBOM_CA_BUNDLE`; credentials for a private channel
are read from where pixi keeps them ([A channel that needs credentials](../troubleshooting.md#a-channel-that-needs-credentials)).

## 3. Or warm the cache somewhere else

When nothing can be reached, run once where the network is, then carry the cache across:

```sh
PIXI_SBOM_CACHE_DIR=./sbom-cache pixi sbom -p linux-64 --pypi-mapping prefix --fetch-licenses --vulnerabilities osv --kev --epss --output -   # needs the network
```

Copy `sbom-cache` to the restricted machine and run the same command offline:

```sh
PIXI_SBOM_OFFLINE=1 PIXI_SBOM_CACHE_DIR=./sbom-cache pixi sbom -p linux-64 --fetch-licenses --output sbom.cdx.json
```

`PIXI_SBOM_OFFLINE=1` makes no request at all and uses the cache at any age. What it could not answer is
recorded in the document itself (`pixi:incomplete`, `pixi:stale-cache`), so an SBOM built offline never reads as
"no known vulnerabilities" by accident. See [Work from the cache](../troubleshooting.md#4-work-from-the-cache).

## When it is slow rather than blocked

A proxy that throttles shows up as `Could not be checked` lines and slow runs. Lower the concurrency:

```sh
pixi sbom -p linux-64 --report outdated --concurrency 2 --timings   # needs the network
```

`--timings` says how much of the run was spent waiting on the network. See
[Where the time went](../cli.md#where-the-time-went).
