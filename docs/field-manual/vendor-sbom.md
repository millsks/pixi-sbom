# Take in a vendor's SBOM

**When:** a supplier sends you an SBOM for something you ship or run, and you have to decide whether to trust it
and whether it is safe to accept, ideally in a pipeline that fails on your behalf.

The order matters. A document without purls or a dependency graph passes a vulnerability scan by having nothing
to match, so grade it before believing what a scan of it says.

## 1. Grade it

```sh
pixi sbom --from-sbom vendor.cdx.json --report quality
```

Each element is scored 0 to 100: the seven NTIA minimum elements (supplier, name, version, unique identifier,
dependency relationships, author, timestamp) and license and hash coverage. *Unique identifier* is the one a
vulnerability lookup lives on: it is the share of packages with a purl. Anything well below 100 there means a scan
of this document will under-report.

Make it a gate with a threshold you choose:

```sh
pixi sbom --from-sbom vendor.cdx.json --min-quality 70 --output -   # exit 10
```

Exit 10 lists the weakest elements: what to ask the vendor for. See
[How complete the document is](../cli.md#how-complete-the-document-is).

## 2. Look its packages up, and apply the vendor's VEX

A vendor that ships an SBOM often ships a VEX saying which findings do not affect their product. Apply it before
the gate, so what the vendor has already assessed does not fail your build:

```sh
pixi sbom --from-sbom vendor.cdx.json --vulnerabilities osv --kev --fail-on-kev --fail-on-severity high --vex-in vendor.openvex.json --output vendor-checked.cdx.json   # needs the network
```

- `not_affected`, `false_positive` and `resolved` statements clear a finding from the gate; the finding stays in
  the document with the vendor's statement and a `pixi:vex-source` naming the file.
- `exploitable` and `in_triage` statements are recorded and leave the finding open.
- A statement that matches nothing here is logged: often a sign the VEX is for another version of the product.

CycloneDX VEX (standalone, or inside the SBOM) and OpenVEX are read. See
[Applying a vendor's VEX](../cli.md#applying-a-vendors-vex).

## 3. Decide what you think

Your own assessment wins over the vendor's. `--ignore-vuln` takes precedence over any `--vex-in` statement:

```sh
pixi sbom --from-sbom vendor.cdx.json --vulnerabilities osv --fail-on-severity high --vex-in vendor.openvex.json --ignore-vuln "CVE-2021-33503:in_triage:we have not confirmed the vendor's claim" --output vendor-checked.cdx.json   # needs the network
```

## The whole intake as one gate

```sh
pixi sbom --from-sbom vendor.cdx.json --min-quality 70 --vulnerabilities osv --kev --fail-on-kev --fail-on-severity high --vex-in vendor.openvex.json --output vendor-checked.cdx.json   # needs the network
```

| Exit | Meaning | What to do |
|---|---|---|
| 0 | complete enough, nothing open at or above the bar | accept |
| 4 | an open finding the VEX did not clear | ask the vendor, or assess it yourself with `--ignore-vuln` |
| 10 | the document is too thin to judge | ask for a better document; the weakest elements are on stderr |

When both gates trip, the run exits 4 and stderr lists both: the findings, and the weakest elements.
