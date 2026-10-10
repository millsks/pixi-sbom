"""Upkeep checks for the curated CPE table (data/cpe.toml), run weekly (#435).

The table goes stale on its own: NVD deprecates or renames products, conda-forge spells a version
differently from upstream, and new native packages appear with no entry. This checks for each,
writes one report for the maintainer, and with --apply rewrites deprecated entries to the name NVD
says replaces them. It never adds an entry: which CPE a new package should get is a person's call.

    pixi run cpe-upkeep --report target/cpe-upkeep.md [--apply]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TABLE = ROOT / "data" / "cpe.toml"
REVIEWED = ROOT / "tests" / "cpe" / "reviewed.toml"
NVD = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
ANACONDA = "https://api.anaconda.org/package/conda-forge/"
# Without an API key NVD allows 5 requests in a rolling 30 seconds.
NVD_PAUSE = 6.5


def table(text: str) -> dict[str, tuple[str, str]]:
    """The table's entries: conda name to (vendor, product)."""
    return {name: tuple(value.split(":", 1)) for name, value in tomllib.loads(text)["cpe"].items()}


def reviewed(text: str) -> dict[str, str]:
    """Conda names reviewed and deliberately left without a CPE, each with its reason."""
    loaded = {}
    for name, reason in tomllib.loads(text).get("reviewed", {}).items():
        if not str(reason).strip():
            raise ValueError(f"{name}: a reviewed package needs a reason")
        loaded[name] = str(reason)
    return loaded


@dataclass
class Status:
    """What NVD says about one vendor:product."""

    known: bool
    replacement: tuple[str, str] | None = None
    versions: list[str] = field(default_factory=list)


def nvd_status(response: dict) -> Status:
    """Read NVD's answer for one vendor:product: unknown, current, or deprecated in favour of another.

    A product counts as deprecated only when every CPE NVD has for it is, and then its replacement is
    the vendor:product most of them point to."""
    products = [p["cpe"] for p in response.get("products", [])]
    if not products:
        return Status(known=False)
    versions = [p["cpeName"].split(":")[5] for p in products]
    if not all(p.get("deprecated") for p in products):
        return Status(known=True, versions=versions)
    targets = Counter()
    for product in products:
        for successor in product.get("deprecatedBy", []):
            parts = successor.get("cpeName", "").split(":")
            if len(parts) > 5:
                targets[(parts[3], parts[4])] += 1
    replacement = targets.most_common(1)[0][0] if targets else None
    return Status(known=True, replacement=replacement, versions=versions)


def version_shape(version: str) -> str:
    """The shape of a version: digits as `9`, letters as `a`, punctuation as itself (`3.5.2` -> `9.9.9`)."""
    return re.sub(r"[a-zA-Z]+", "a", re.sub(r"\d+", "9", version))


def version_mismatch(conda_version: str, nvd_versions: list[str]) -> bool:
    """Whether conda-forge's latest version is spelled unlike every version NVD records for the product:
    a sign the entry needs a version rule (imagemagick's `7.1.1_39` against NVD's `7.1.1-39`)."""
    shapes = {version_shape(v) for v in nvd_versions if v not in ("*", "-", "")}
    return bool(shapes) and version_shape(conda_version) not in shapes


def candidates(documents: list[dict], entries: set[str], skip: set[str]) -> Counter:
    """Native conda packages in the documents with neither a CPE nor a PyPI purl, and not reviewed:
    how many documents each appears in."""
    found = Counter()
    for doc in documents:
        names = set()
        for component in doc.get("components", []):
            purl = component.get("purl", "")
            properties = {p["name"]: p["value"] for p in component.get("properties", [])}
            pypi = any(v.startswith("pkg:pypi/") for k, v in properties.items() if k == "pixi:purl")
            if purl.startswith("pkg:conda/") and not pypi and not component.get("cpe"):
                names.add(component["name"])
        found.update(n for n in names if n not in entries and n not in skip)
    return found


def apply(text: str, renames: dict[str, tuple[str, str]]) -> str:
    """The table text with each renamed entry's vendor:product replaced, comments and order kept."""
    for name, (vendor, product) in renames.items():
        text = re.sub(rf'(?m)^({re.escape(name)} = )"[^"]*"', rf'\g<1>"{vendor}:{product}"', text)
    return text


def report(
    deprecated: dict, unknown: list[str], mismatches: dict, found: Counter, applied: bool, absent: list[str] | None = None
) -> str:
    """The maintainer's report, as Markdown."""
    lines = ["# CPE table upkeep", "", "Weekly checks of `data/cpe.toml` (#435). This issue is edited in place.", ""]
    lines += ["## Deprecated in NVD", ""]
    if deprecated:
        lines += [f"- `{n}`: `{old}` is now `{new[0]}:{new[1]}`" for n, (old, new) in sorted(deprecated.items())]
        lines += ["", "A pull request applies these." if applied else ""]
    else:
        lines += ["None."]
    lines += ["", "## Unknown to NVD", ""]
    lines += [f"- `{n}`" for n in unknown] or ["None."]
    lines += ["", "## Not a conda-forge package (the entry can never match)", ""]
    lines += [f"- `{n}`" for n in absent or []] or ["None."]
    lines += ["", "## Version spelled unlike NVD's (may need a version rule)", ""]
    lines += [f"- `{n}`: conda-forge `{conda}`, NVD has e.g. `{nvd}`" for n, (conda, nvd) in sorted(mismatches.items())]
    if not mismatches:
        lines += ["None."]
    lines += ["", "## Candidates: native packages with no CPE and no PyPI identity", ""]
    lines += ["How many corpus documents each appears in. Add an entry, or list it in `tests/cpe/reviewed.toml`", ""]
    lines += [f"- `{n}` ({count})" for n, count in found.most_common()] or ["None."]
    return "\n".join(lines) + "\n"


def get_json(url: str) -> dict:
    """GET a URL and parse its JSON."""
    request = urllib.request.Request(url, headers={"User-Agent": "pixi-sbom-cpe-upkeep"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def corpus_documents(binary: Path) -> list[dict]:
    """CycloneDX documents for every pixi example, with the PyPI mapping, for the candidate check."""
    documents = []
    for lock in sorted((ROOT / "examples" / "projects" / "pixi").glob("*/pixi.lock")):
        result = subprocess.run(
            [str(binary), "--lockfile", str(lock), "-p", "linux-64", "--pypi-mapping", "prefix", "--output", "-", "-q"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode == 0:
            documents.append(json.loads(result.stdout))
        else:
            sys.stderr.write(f"warning: {lock}: {result.stderr.strip()[-300:]}\n")
    return documents


def main(argv: list[str] | None = None) -> int:
    """Run the checks and write the report."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--apply", action="store_true", help="rewrite deprecated entries in data/cpe.toml")
    parser.add_argument("--pixi-sbom", type=Path, default=ROOT / "target" / "debug" / "pixi-sbom")
    args = parser.parse_args(argv)
    text = TABLE.read_text(encoding="utf-8")
    entries = table(text)
    deprecated, unknown, mismatches, absent = {}, [], {}, []
    for name, (vendor, product) in sorted(entries.items()):
        query = urllib.parse.urlencode({"cpeMatchString": f"cpe:2.3:a:{vendor}:{product}", "resultsPerPage": 2000})
        status = nvd_status(get_json(f"{NVD}?{query}"))
        time.sleep(NVD_PAUSE)
        if not status.known:
            unknown.append(name)
            continue
        if status.replacement and status.replacement != (vendor, product):
            deprecated[name] = (f"{vendor}:{product}", status.replacement)
        try:
            latest = get_json(ANACONDA + name).get("latest_version", "")
        except urllib.error.HTTPError as error:
            if error.code == 404:
                absent.append(name)
                continue
            sys.stderr.write(f"warning: {name}: conda-forge version unavailable: {error}\n")
            continue
        except OSError as error:
            sys.stderr.write(f"warning: {name}: conda-forge version unavailable: {error}\n")
            continue
        if latest and version_mismatch(latest, status.versions):
            mismatches[name] = (latest, status.versions[-1])
    found = candidates(corpus_documents(args.pixi_sbom), set(entries), set(reviewed(REVIEWED.read_text(encoding="utf-8"))))
    if args.apply and deprecated:
        TABLE.write_text(apply(text, {n: new for n, (_, new) in deprecated.items()}), encoding="utf-8")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(report(deprecated, unknown, mismatches, found, args.apply, absent), encoding="utf-8")
    sys.stderr.write(
        f"{len(deprecated)} deprecated, {len(unknown)} unknown, {len(absent)} not on conda-forge, "
        f"{len(mismatches)} version shapes, "
        f"{len(found)} candidates\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
