"""Grype's findings from pixi-sbom's SBOM against syft's, for the same installed environments.

The acceptance test for replacing syft in front of Grype (#434). Each corpus environment is
installed, described by syft and by `pixi sbom --prefix`, and both documents are scanned by the same
Grype with the same database. Every conda or Python finding from syft's document must also come from
pixi-sbom's, or be listed in tests/grype/exceptions.toml with a reason. Findings only pixi-sbom's
document produces are reported, not failed. What the default flags would lose (#449) is reported too.

    pixi run grype-compare                   # the whole corpus
    pixi run grype-compare --only django     # one environment
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCEPTIONS = ROOT / "tests" / "grype" / "exceptions.toml"
SYFT = "syft==1.54.1"
GRYPE = "grype==0.120.1"

# name, project, how it is installed
CORPUS = [
    ("django", "examples/projects/pixi/01-django", "pixi"),
    ("data-analysis", "examples/projects/pixi/04-data-analysis", "pixi"),
    ("dev-tooling", "examples/projects/pixi/10-dev-tooling", "pixi"),
    ("venv-flask", "examples/projects/requirements/02-flask/requirements.txt", "venv"),
]

# syft artifact types this comparison is about: what a conda or Python environment installs.
COMPARED_TYPES = {"python", "conda", "binary"}


@dataclass(frozen=True, order=True)
class Finding:
    """One vulnerability Grype reported against one package."""

    vulnerability: str
    package: str
    version: str


def normalize(name: str) -> str:
    """A package name both tools spell the same way: lower case, `_` and `.` as `-`."""
    return name.strip().lower().replace("_", "-").replace(".", "-")


def findings(grype_json: dict, types: set[str] | None = None) -> set[Finding]:
    """The findings in Grype's JSON output, optionally only for some artifact types."""
    found = set()
    for match in grype_json.get("matches", []):
        artifact = match.get("artifact", {})
        if types is not None and artifact.get("type") not in types:
            continue
        found.add(Finding(match["vulnerability"]["id"], normalize(artifact["name"]), artifact.get("version", "")))
    return found


def load_exceptions(text: str) -> dict[tuple[str, str, str], str]:
    """The exceptions file: (environment, vulnerability, package) to the reason it is accepted."""
    loaded: dict[tuple[str, str, str], str] = {}
    for entry in tomllib.loads(text).get("exception", []):
        reason = str(entry.get("reason", "")).strip()
        key = (entry.get("environment", ""), entry.get("vulnerability", ""), normalize(entry.get("package", "")))
        if not all(key) or not reason:
            raise ValueError(f"an exception needs environment, vulnerability, package and a reason: {entry}")
        loaded[key] = reason
    return loaded


@dataclass
class Comparison:
    """How the two documents' findings line up for one environment."""

    agree: set[Finding]
    syft_only: set[Finding]
    excepted: set[Finding]
    pixi_only: set[Finding]


def compare(environment: str, syft: set[Finding], pixi: set[Finding], exceptions: dict) -> Comparison:
    """Line syft's findings up against pixi-sbom's. A finding is the same when the vulnerability, the
    package name and its version are."""
    missing = syft - pixi
    excepted = {f for f in missing if (environment, f.vulnerability, f.package) in exceptions}
    return Comparison(agree=syft & pixi, syft_only=missing - excepted, excepted=excepted, pixi_only=pixi - syft)


def default_gap(recommended: set[Finding], default: set[Finding]) -> set[Finding]:
    """Findings the recommended flags give that a document with default flags does not: what
    leaving `--primary-purl` at `conda` costs a scanner."""
    return recommended - default


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command, failing loudly with its output."""
    result = subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"{' '.join(command[:4])} ... exited {result.returncode}:\n{result.stderr[-2000:]}")
    return result


def install(name: str, project: str, how: str, work: Path) -> Path:
    """Install one corpus environment under `work` and return its prefix."""
    if how == "pixi":
        copy = work / name
        shutil.copytree(ROOT / project, copy, ignore=shutil.ignore_patterns(".pixi"))
        run(["pixi", "install", "--locked", "--manifest-path", str(copy / "pixi.toml")])
        return copy / ".pixi" / "envs" / "default"
    venv = work / name
    run(["pixi", "exec", "--spec", "python=3.12", "python", "-m", "venv", str(venv)])
    pip = venv / ("Scripts" if os.name == "nt" else "bin") / "pip"
    run([str(pip), "install", "--quiet", "--no-deps", "-r", str(ROOT / project)])
    return venv


def grype(sbom: Path, db: Path) -> dict:
    """Grype's findings for a document, as JSON."""
    env = {**os.environ, "GRYPE_DB_CACHE_DIR": str(db), "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    result = run(["pixi", "exec", "--spec", GRYPE, "grype", f"sbom:{sbom}", "-q", "-o", "json"], env=env)
    return json.loads(result.stdout)


def main(argv: list[str] | None = None) -> int:
    """Run the comparison over the corpus and report it."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", action="append", help="run only these corpus environments")
    parser.add_argument("--work", type=Path, default=ROOT / "target" / "grype-compare")
    parser.add_argument("--pixi-sbom", type=Path, default=ROOT / "target" / "debug" / "pixi-sbom")
    parser.add_argument("--db", type=Path, default=ROOT / "target" / "grype-db", help="Grype's database cache")
    args = parser.parse_args(argv)
    exceptions = load_exceptions(EXCEPTIONS.read_text(encoding="utf-8"))
    corpus = [c for c in CORPUS if not args.only or c[0] in args.only]
    if not corpus:
        sys.stderr.write(f"error: no corpus environment named {args.only}\n")
        return 1
    shutil.rmtree(args.work, ignore_errors=True)
    args.work.mkdir(parents=True)
    db = args.db
    unexplained = 0
    for name, project, how in corpus:
        prefix = install(name, project, how, args.work)
        syft_sbom = args.work / f"{name}.syft.json"
        pixi_sbom = args.work / f"{name}.cdx.json"
        default_sbom = args.work / f"{name}.default.cdx.json"
        run(["pixi", "exec", "--spec", SYFT, "syft", "scan", f"dir:{prefix}", "-q", "-o", f"syft-json={syft_sbom}"])
        # Offline: everything pixi-sbom needs to be matched is on disk or in its own tables.
        run(
            [str(args.pixi_sbom), "--prefix", str(prefix), "--primary-purl", "pypi", "--embedded-sboms",
             "--output", str(pixi_sbom), "-q"],
            env={**os.environ, "PIXI_SBOM_OFFLINE": "1"},
        )
        run(
            [str(args.pixi_sbom), "--prefix", str(prefix), "--embedded-sboms", "--output", str(default_sbom), "-q"],
            env={**os.environ, "PIXI_SBOM_OFFLINE": "1"},
        )
        recommended = findings(grype(pixi_sbom, db))
        result = compare(name, findings(grype(syft_sbom, db), COMPARED_TYPES), recommended, exceptions)
        lost = default_gap(recommended, findings(grype(default_sbom, db)))
        sys.stderr.write(
            f"{name}: {len(result.agree)} agree, {len(result.syft_only)} syft-only, "
            f"{len(result.excepted)} excepted, {len(result.pixi_only)} pixi-sbom-only; "
            f"{len(lost)} lost with default flags (without --primary-purl pypi)\n"
        )
        for finding in sorted(result.syft_only):
            sys.stderr.write(f"  FAIL syft-only: {finding.vulnerability} {finding.package} {finding.version}\n")
        for finding in sorted(result.pixi_only):
            sys.stderr.write(f"  pixi-sbom-only: {finding.vulnerability} {finding.package} {finding.version}\n")
        unexplained += len(result.syft_only)
    env = {**os.environ, "GRYPE_DB_CACHE_DIR": str(db), "GRYPE_CHECK_FOR_APP_UPDATE": "false"}
    status = run(["pixi", "exec", "--spec", GRYPE, "grype", "db", "status", "-o", "json"], env=env)
    sys.stderr.write(f"Grype database built {json.loads(status.stdout).get('built', 'unknown')}\n")
    if unexplained:
        sys.stderr.write(f"{unexplained} syft-only finding(s): fix pixi-sbom or add an exception with a reason\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
