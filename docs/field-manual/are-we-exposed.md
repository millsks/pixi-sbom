# Are we exposed?

**When:** an advisory is in the news, and you need to know, today, whether anything you ship is affected and
where.

## From the lockfiles

Every project under a directory, looked up together, as a CSV you can search:

```sh
pixi sbom --scan . -p linux-64 --pypi-mapping prefix --vulnerabilities osv --report vulnerabilities --report-format csv > findings.csv   # needs the network
```

Then search it for the advisory by any of its names: the CVE, the GHSA, the PYSEC id. The `aliases` column
holds the others:

```sh
grep -i "CVE-2021-33503" findings.csv
```

Each matching row names the environment, platform, package, version and fixed version. No row means no project
under the directory has an affected version, for the packages the database can identify: the report's
*No queryable identity* line lists the ones it could not ask about, which is where a false "no" hides.

## From the SBOMs you already published

If each release published an SBOM, the answer for what is already deployed comes from those, not from today's
lockfiles:

```sh
pixi sbom --from-sbom app.cdx.json --vulnerabilities osv --report vulnerabilities --report-format csv   # needs the network
```

The lookup is against today's advisories, so an old document gets today's answer about its packages.

## How urgent is it

A finding that is known exploited, or likely to be, comes first:

```sh
pixi sbom --scan . -p linux-64 --pypi-mapping prefix --vulnerabilities osv --kev --epss --report vulnerabilities   # needs the network
```

The KEV column marks CISA's known-exploited entries with their remediation due date; EPSS is the probability of
exploitation in the next 30 days. See [Looking up vulnerabilities](../cli.md#looking-up-vulnerabilities).

## Where a package came from

To see why a package is in an environment at all (what depends on it, and what declared it):

```sh
pixi sbom -p linux-64 --explain sqlparse
```
