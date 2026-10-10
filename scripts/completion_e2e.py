"""Tab completion in real shells: pixi-sbom's own, and `pixi sbom` through the documented snippets.

Each shell loads pixi's completion, pixi-sbom's registration and docs/completion/pixi-sbom.<ext>,
then is asked what Tab offers for a line (tests/completion/probe.*). fish, bash and PowerShell 7 come
from conda-forge through `pixi exec`; on macOS bash also runs as the system's 3.2; zsh is the system's, because conda-forge's has no zsh/zpty, and
Windows PowerShell 5.1 is the one Windows ships.

    pixi run completion-e2e                 # every shell this OS has
    pixi run completion-e2e --shells powershell
"""

from __future__ import annotations

import argparse
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
    ("pixi-sbom --format ", {"cyclonedx", "spdx", "github"}, True),
    ("pixi-sbom --report v", {"vulnerabilities"}, True),
    ("pixi sbom --form", {"--format"}, True),
    ("pixi sbom --format ", {"cyclonedx", "spdx", "github"}, True),
    ("pixi sbom --report v", {"vulnerabilities"}, True),
    ("pixi ins", {"install"}, False),
]


if os.name == "nt":
    DEFAULT_SHELLS = ["powershell", "windows-powershell"]
elif sys.platform == "darwin":
    DEFAULT_SHELLS = ["fish", "bash", "macos-bash", "powershell", "zsh"]
else:
    DEFAULT_SHELLS = ["fish", "bash", "powershell", "zsh"]


def shells() -> dict[str, list[str]]:
    """Return the command that runs each available shell's probe, given the line as the last argument."""
    found = {
        "fish": ["pixi", "exec", "--spec", "fish", "fish", "--no-config", str(PROBES / "probe.fish")],
        "bash": ["pixi", "exec", "--spec", "bash", "bash", "--noprofile", "--norc", str(PROBES / "probe.bash")],
        "powershell": [
            "pixi", "exec", "--spec", "powershell", "pwsh", "-NoProfile", "-NonInteractive",
            "-File", str(PROBES / "probe.ps1"),
        ],
    }
    # The bash 3.2 that macOS ships as /bin/bash, beside conda-forge's 5.2.
    if sys.platform == "darwin" and Path("/bin/bash").exists():
        found["macos-bash"] = ["/bin/bash", "--noprofile", "--norc", str(PROBES / "probe.bash")]
    zsh = shutil.which("zsh")
    if zsh:
        found["zsh"] = [zsh, "-f", str(PROBES / "probe.zsh")]
    windows_powershell = shutil.which("powershell") if os.name == "nt" else None
    if windows_powershell:
        found["windows-powershell"] = [
            windows_powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", str(PROBES / "probe.ps1"),
        ]
    return found


def offered(command: list[str], line: str) -> set[str]:
    """Return the candidates a shell offers for a line."""
    result = subprocess.run(
        [*command, line], cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"exit {result.returncode}: {result.stderr.strip()}")
    return {candidate.strip() for candidate in result.stdout.splitlines() if candidate.strip()}


def main(argv: list[str] | None = None) -> int:
    """Run every case in every requested shell and report the ones that do not complete as expected."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--shells", default=",".join(DEFAULT_SHELLS), help="comma-separated shells to test")
    args = parser.parse_args(argv)
    wanted = [shell for shell in args.shells.split(",") if shell]
    # The freshly built binary, first on PATH for this process and every shell it starts.
    os.environ["PATH"] = str(ROOT / "target" / "debug") + os.pathsep + os.environ.get("PATH", "")
    binary = shutil.which("pixi-sbom")
    if binary is None:
        sys.stderr.write("error: no pixi-sbom in target/debug; run cargo build first\n")
        return 1
    found = shells()
    missing = [shell for shell in wanted if shell not in found]
    if missing:
        sys.stderr.write(f"error: no {', '.join(missing)} to test with\n")
        return 1
    available = {shell: found[shell] for shell in wanted}
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
