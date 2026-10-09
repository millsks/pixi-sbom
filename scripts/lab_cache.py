"""Record examples/lab-cache: the online answers the training lab (docs/lab.md) is replayed from.

Run it as `pixi run lab-cache`. It builds the release binary, runs every `pixi sbom` line in the lab
online, from a scratch copy of the examples, with the cache pointed at a fresh examples/lab-cache, then
stamps the date into the lab and the cache's README. The lab and its test then run offline against
what was recorded, so a classroom gets the same answers as the test did.

Re-record when the lab's commands change. The answers will have moved since the last recording (new
advisories, new EPSS scores), so update the lab's expected-output blocks to match; the test says which.

The standard library only, like the other scripts here.
"""

from __future__ import annotations

import datetime
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "docs" / "lab.md"
CACHE = ROOT / "examples" / "lab-cache"
DATE_PATTERN = re.compile(r"(recorded into `examples/lab-cache/` on )([^,]+?)(,)")


def lab_commands(text: str) -> list[list[str]]:
    """The arguments of every `pixi sbom` line in the lab's shell blocks, comments dropped."""
    commands = []
    in_shell = False
    for line in text.splitlines():
        if line.startswith("```"):
            in_shell = line == "```sh"
            continue
        if in_shell and line.startswith("pixi sbom "):
            command = line.split(" # ", 1)[0]
            commands.append(command.split()[2:])
    return commands


def stamp(text: str, date: str) -> str:
    """The lab with its capture date replaced by `date`."""
    stamped, count = DATE_PATTERN.subn(lambda m: f"{m.group(1)}{date}{m.group(3)}", text)
    if count != 1:
        raise SystemExit("docs/lab.md no longer says when the cache was recorded; restore that sentence")
    return stamped


def readme(date: str, count: int) -> str:
    return (
        "# Lab cache\n\n"
        "What the online services answered when the [training lab](../../docs/lab.md)'s commands were run on "
        f"{date}: OSV advisories, the CISA KEV catalog, FIRST EPSS scores and PyPI release metadata for the "
        f"packages its {count} commands look up. The lab sets `PIXI_SBOM_OFFLINE=1` and points "
        "`PIXI_SBOM_CACHE_DIR` here, so everyone who takes it gets these answers.\n\n"
        "Recorded by `pixi run lab-cache` (`scripts/lab_cache.py`). It is generated: do not edit it by hand.\n"
    )


def main() -> int:
    subprocess.run(["cargo", "build", "--release", "-q"], cwd=ROOT, check=True)
    binary = ROOT / "target" / "release" / ("pixi-sbom.exe" if os.name == "nt" else "pixi-sbom")
    commands = lab_commands(LAB.read_text())
    if CACHE.exists():
        shutil.rmtree(CACHE)
    CACHE.mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if k != "PIXI_SBOM_OFFLINE"}
    env["PIXI_SBOM_CACHE_DIR"] = str(CACHE)
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        shutil.copytree(ROOT / "examples", work / "examples", ignore=shutil.ignore_patterns("lab-cache"))
        env["PIXI_CACHE_DIR"] = str(work / "empty-package-cache")
        for args in commands:
            sys.stderr.write(f"  $ pixi sbom {' '.join(args)}\n")
            # Gates are expected to trip; what matters is that the lookups land in the cache.
            subprocess.run([str(binary), "-q", *args], cwd=work, env=env, stdout=subprocess.DEVNULL, check=False)
    date = datetime.date.today().isoformat()
    LAB.write_text(stamp(LAB.read_text(), date))
    (CACHE / "README.md").write_text(readme(date, len(commands)))
    sys.stderr.write(f"recorded {len(commands)} commands into {CACHE.relative_to(ROOT)} on {date}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
