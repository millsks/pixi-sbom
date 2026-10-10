"""Tab completion in real shells: pixi-sbom's own, and `pixi sbom` through the documented snippets.

Each shell loads pixi's completion, pixi-sbom's registration and docs/completion/pixi-sbom.<ext>,
then is asked what Tab offers for a line (tests/completion/probe.*). fish, bash and PowerShell come
from conda-forge through `pixi exec`; zsh is the system's, because conda-forge's has no zsh/zpty.

    pixi run completion-e2e
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBES = ROOT / "tests" / "completion"

CASES: list[tuple[str, set[str], bool]] = [
    # line, expected candidates, whether they must be all that is offered
    ("pixi-sbom --form", {"--format"}, True),
    ("pixi-sbom --format ", {"cyclonedx", "spdx"}, True),
    ("pixi-sbom --report v", {"vulnerabilities"}, True),
    ("pixi sbom --form", {"--format"}, True),
    ("pixi sbom --format ", {"cyclonedx", "spdx"}, True),
    ("pixi sbom --report v", {"vulnerabilities"}, True),
    ("pixi ins", {"install"}, False),
]


def shells() -> dict[str, list[str]]:
    """Return the command that runs each shell's probe, given the line as the last argument."""
    found = {
        "fish": ["pixi", "exec", "--spec", "fish", "fish", "--no-config", str(PROBES / "probe.fish")],
        "bash": ["pixi", "exec", "--spec", "bash", "bash", "--noprofile", "--norc", str(PROBES / "probe.bash")],
        "powershell": [
            "pixi", "exec", "--spec", "powershell", "pwsh", "-NoProfile", "-NonInteractive",
            "-File", str(PROBES / "probe.ps1"),
        ],
    }
    zsh = shutil.which("zsh")
    if zsh:
        found["zsh"] = [zsh, "-f", str(PROBES / "probe.zsh")]
    return found


def offered(command: list[str], line: str) -> set[str]:
    """Return the candidates a shell offers for a line."""
    result = subprocess.run(
        [*command, line], cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"exit {result.returncode}: {result.stderr.strip()}")
    return {candidate.strip() for candidate in result.stdout.splitlines() if candidate.strip()}


def main() -> int:
    """Run every case in every shell and report the ones that do not complete as expected."""
    binary = shutil.which("pixi-sbom", path=os.environ.get("PATH"))
    if binary is None:
        sys.stderr.write("error: pixi-sbom is not on PATH; build it and put target/debug first\n")
        return 1
    available = shells()
    missing = {"fish", "bash", "powershell", "zsh"} - available.keys()
    if missing:
        sys.stderr.write(f"error: no {', '.join(sorted(missing))} to test with\n")
        return 1
    failures = 0
    for shell, command in available.items():
        for line, expected, exact in CASES:
            try:
                got = offered(command, line)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                sys.stderr.write(f"FAIL {shell}: {line!r}: {error}\n")
                failures += 1
                continue
            ok = got == expected if exact else expected <= got
            sys.stderr.write(f"{'ok  ' if ok else 'FAIL'} {shell}: {line!r} -> {sorted(got)}\n")
            failures += not ok
    sys.stderr.write(f"{failures} failure(s) in {len(available) * len(CASES)} checks with {binary}\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
