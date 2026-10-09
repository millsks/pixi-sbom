# One SBOM for a product

**When:** a customer or regulator wants one document per product, and your product is an application plus the
components you ship with it, or several projects in one repository.

## An application and what ships with it

Write your own document, then merge the vendor documents into it. Packages with the same purl become one; each
input's root is kept as a component under a new root you name:

```sh
pixi sbom -p linux-64 --output app.cdx.json
pixi sbom --from-sbom app.cdx.json --from-sbom vendor.cdx.json --from-sbom vendor.spdx.json --root-name product --output product.cdx.json
```

CycloneDX and SPDX inputs mix freely. When two inputs disagree about a package's license, or about the hash of a
package whose purl names one file (a conda build), the first input's value is kept, a warning is logged, and the
package records the disagreement as `pixi:merge-conflict`, which `--explain` shows. Two documents that recorded
different files of one PyPI release (a wheel, the sdist) do not disagree:

```sh
pixi sbom --from-sbom app.cdx.json --from-sbom vendor.cdx.json --root-name product --explain six
```

## Every project in a repository

`--scan --merge` does the same for every project under a directory, of any lockfile kind:

```sh
pixi sbom --scan . -p linux-64 --merge --root-name product --output product.cdx.json
```

Each package records which inputs it came from in `pixi:source-document`: a lockfile path for a scan, a document
identity for `--from-sbom`. See [Merging documents](../cli.md#merging-documents).

## Then gate the product as a whole

Everything the tool does to one document it does to the merged one:

```sh
pixi sbom --from-sbom app.cdx.json --from-sbom vendor.cdx.json --root-name product --vulnerabilities osv --kev --fail-on-kev --output product.cdx.json   # needs the network
```
