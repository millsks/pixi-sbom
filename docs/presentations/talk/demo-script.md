# The Hole in Your SBOM: demo script

The live part of the talk, step by step. Each step names the slide it belongs to, the command to type, what comes
back, and the recording to play if the live run fails.

## Before you go on

From a clone of the repository, in the terminal you will present from:

```console
pixi global install pixi-sbom
export PIXI_SBOM_OFFLINE=1
export PIXI_SBOM_CACHE_DIR=$PWD/examples/lab-cache
```

The cache was recorded on 9 October 2026 (see `examples/lab-cache/README.md`). Offline, every answer below comes from
it, so the counts match the slides and nothing depends on the venue's network. Online, advisory counts drift as new
ones are published; say so if you run live against the network.

Run each command once beforehand, then open the fallback recordings in browser tabs, so switching to one is a click.

## Running order

| Slide | Full talk | 5-minute cut |
|---|---|---|
| 1 The hole in your SBOM | 0:00–0:45 | 0:00–0:20 |
| 2 An SBOM is an inventory | 0:45–1:45 | skip |
| 3 The hole | 1:45–3:15 | 0:20–1:35 |
| 4 How big the hole is | 3:15–4:30 | 1:35–2:25 |
| 5 The fix | 4:30–5:30 | skip |
| 6 Demo 1: read | 5:30–7:00 | folded into demo 2 |
| 7 Demo 2: find and gate | 7:00–8:30 | 2:25–4:25 |
| 8 Demo 3: someone else's SBOM | 8:30–10:00 | skip |
| 9 Any locked Python project | 10:00–10:45 | one sentence |
| 10 In CI | 10:45–11:30 | skip |
| 11 What it does not do | 11:30–12:30 | one line |
| 12 Is the hole there? | 12:30–13:30 | 4:25–5:00 |

Full talk: 13 minutes 30 seconds, then questions. Five-minute cut: 5 minutes.

## Demo 1: read (slide 6)

```console
pixi sbom --lockfile examples/projects/pixi/01-django/pixi.lock -p linux-64 --report packages
pixi sbom --lockfile examples/projects/pixi/01-django/pixi.lock -p linux-64 --output sbom.cdx.json
```

The first prints a table ending `Summary: 66 packages, 9 declared by the workspace`. Point at Python and the system
libraries: a conda environment ships them, and a tool that reads only PyPI never sees them. The second writes the
CycloneDX document.

**In the 5-minute cut:** run the first command only, as the opening of demo 2.

**Fallback:** `docs/assets/report-packages.gif`, the packages report on the docs' demo workspace. Its counts differ
from the slide; say it is a different project.

## Demo 2: find and gate (slide 7)

```console
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock -p linux-64 --vulnerabilities osv --kev --epss --report vulnerabilities
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock -p linux-64 --vulnerabilities osv --fail-on-severity high --output sbom.cdx.json # exit 4
echo $?
```

The first ends `Summary: 41 findings in 8 packages`. None is in CISA's KEV catalog, so the EPSS column is what
orders them. The second prints the 17 findings at high or above, then `Gate failed: vulnerabilities (17). Exiting 4.`,
and `echo $?` prints `4`. The document is written either way.

**Fallbacks:** `docs/assets/report-vulnerabilities.gif` for the findings and `docs/assets/report-epss.gif` for the
EPSS column, both on the docs' demo workspace.

## Demo 3: someone else's SBOM (slide 8)

Make the vendor document first; it stands in for a file a supplier sent you:

```console
pixi sbom --lockfile examples/projects/requirements/12-aws-cloud/requirements.txt --output vendor.cdx.json
```

Then:

```console
pixi sbom --from-sbom vendor.cdx.json --report quality
pixi sbom --from-sbom vendor.cdx.json --min-quality 80 --output - # exit 10
pixi sbom --lockfile examples/projects/uv/02-flask/uv.lock -p linux-64 --vulnerabilities osv --vex-in examples/lab/vendor.openvex.json --report vulnerabilities
```

- The quality report ends `Quality: 77 of 100 for 24 packages`. It is missing an author and every license.
- The gate at 80 prints `Gate failed: quality (1). Exiting 10.`
- The VEX run goes back to the Flask project from demo 2, because the statement in `examples/lab/vendor.openvex.json`
  is about its packages. It ends `Summary: 40 open findings in 8 packages, 1 ignored`, and the ignored finding is
  listed with the reason the vendor gave. That statement is illustrative, written for the lab; say so if asked.

**Fallbacks:** `docs/assets/report-quality.gif` for the score and `docs/assets/vex-in.gif` for VEX, both on the docs'
demo workspace.

## Where the numbers come from

| On the slide | Source |
|---|---|
| 118 workspaces, 15,722 packages, +37.1%, 1,274 advisories, 45 of 96, 0 lost | [the paper](../../papers/package-identity-sbom-matching.md), measured 30 September 2026 against OSV |
| `pkg:conda/numpy@2.3.4?build=py312h33ff503_0…` and `pkg:pypi/numpy@2.3.4` | `examples/projects/pixi/04-data-analysis/pixi.lock`, linux-64, with `--pypi-mapping prefix` |
| 66 packages, 9 declared | demo 1, offline against `examples/lab-cache` |
| 41 findings in 8 packages; 17 at high; exit 4 | demo 2, the same |
| Quality 77 of 100, 24 packages; exit 10 at 80 | demo 3, the same |
| 40 open findings, 1 ignored | demo 3, the same |
| Exit codes 3, 4, 6, 7, 8, 9, 10 | [cli.md](../../cli.md#exit-codes-and-errors) |
| Lockfiles read | the README's "Reads" row |

The `pkg:conda/numpy@2.3.1` purls on slide 3 are an illustration of the two forms, not output.
