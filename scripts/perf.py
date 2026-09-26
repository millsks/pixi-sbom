"""Measure what a release binary costs to run, on every platform one is built for.

Three numbers per scenario: wall time, peak resident memory and, once per run, the size of the
binary itself. They are gathered the same way on Linux, macOS and Windows so the five release
targets can be compared with each other and, more usefully, with themselves over time.

Run it against a built binary:

    pixi run perf --binary target/release/pixi-sbom --out head.json

and compare two of those:

    pixi run perf --compare base.json head.json --summary $GITHUB_STEP_SUMMARY

Wall time on a shared CI runner is noise as an absolute number; it is only worth reading as the
difference between two binaries measured on the same machine minutes apart, which is what the
compare mode is for. Binary size is exact everywhere. Peak memory is steady to within a few
percent, so it is worth gating on with room to spare.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# How many times each scenario runs. The best of these is reported: the fastest run is the one
# least interrupted by whatever else the runner was doing, and on a shared machine that is the
# closest thing to the cost of the work itself.
RUNS = 5

# Lockfiles generated for the measurement, by package count. The same two sizes the benchmark
# page reports, and large enough that the numbers are not swamped by process startup: at a few
# hundred packages the run is short enough that a scheduler hiccup is most of the measurement.
SIZES = (2000, 10000)


def generate_lockfile(packages: int, path: Path) -> None:
    """Write a lockfile with `packages` conda packages in one linux-64 environment.

    Generated rather than committed so the measurement can be resized without a fixture, and
    deterministic so two runs of this script describe the same work.
    """
    listed: list[str] = []
    entries: list[str] = []
    for index in range(packages):
        name = f"pkg-{index:05}"
        url = f"https://conda.anaconda.org/conda-forge/linux-64/{name}-1.{index}.0-h0_0.conda"
        listed.append(f"      - conda: {url}")
        # A few edges back, so the dependency graph has the shape of an environment rather
        # than a list, without becoming quadratic to build.
        depends = [f"  - pkg-{index - back:05} >=1.{index - back}.0" for back in (1, 2, 3, 4) if index - back >= 0]
        entry = [
            f"- conda: {url}",
            f"  build_number: {index % 8}",
            # Quoted: an all-digit digest is a number to YAML, and a 64-digit one overflows
            # into a float that never reaches the digest parser as text.
            f'  sha256: "{index + 1:064x}"',
            f'  md5: "{index + 1:032x}"',
            "  depends: []" if not depends else "  depends:\n" + "\n".join(depends),
            # A mix of expressions, so license normalization has real work to do.
            "  license: " + ("MIT", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause OR GPL-2.0-only", "LGPL-2.1-or-later")[index % 4],
            "  purls: []",
            f"  size: {10_000 + index}",
            "  timestamp: 1770939786096",
        ]
        entries.append("\n".join(entry))
    path.write_text(
        "version: 7\n"
        "platforms:\n"
        "- name: linux-64\n"
        "environments:\n"
        "  default:\n"
        "    channels:\n"
        "    - url: https://conda.anaconda.org/conda-forge/\n"
        "    packages:\n"
        "      linux-64:\n" + "\n".join(listed) + "\npackages:\n" + "\n".join(entries) + "\n",
        encoding="utf-8",
    )


def _peak_rss_windows(process: subprocess.Popen[bytes]) -> int:
    """Peak working set of a finished child, in bytes.

    The handle a parent holds on a child it started stays valid after the child exits, and the
    kernel keeps the process's final counters against it, so this is the true peak rather than
    whatever a poller happened to catch.
    """
    import ctypes
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    handle = int(process._handle)  # noqa: SLF001 - the started child's handle, still open
    if not ctypes.windll.psapi.GetProcessMemoryInfo(
        wintypes.HANDLE(handle), ctypes.byref(counters), counters.cb
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
    return int(counters.PeakWorkingSetSize)


def run_once(command: list[str]) -> tuple[float, int]:
    """Run `command` to completion; return its wall time in seconds and peak RSS in bytes."""
    started = time.perf_counter()
    if os.name == "nt":
        process = subprocess.Popen(  # noqa: S603 - built here, not taken from input
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        code = process.wait()
        elapsed = time.perf_counter() - started
        peak = _peak_rss_windows(process)
    else:
        # posix_spawn rather than subprocess, which forks: a forked child inherits the
        # parent's page tables, and Linux counts those pages in the child's peak RSS. That
        # reported this script's own footprint (~36 MiB of Python) as the binary's peak,
        # identically, for every scenario smaller than it.
        quiet = [
            (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0o666),
            (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0o666),
        ]
        pid = os.posix_spawn(command[0], command, os.environ, file_actions=quiet)
        # wait4 gives this child's own usage; getrusage(RUSAGE_CHILDREN) would give the
        # high-water mark across every child so far, which grows monotonically over a run and
        # would report the largest scenario's peak for all of them.
        _, status, usage = os.wait4(pid, 0)
        elapsed = time.perf_counter() - started
        code = os.waitstatus_to_exitcode(status)
        # ru_maxrss is kilobytes on Linux and bytes on macOS.
        peak = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    if code != 0:
        raise SystemExit(f"{' '.join(command)} exited {code}")
    return elapsed, peak


def _own_rss_bytes() -> int:
    """This script's own resident size, kept beside the results as a contamination check.

    Zero on Windows, which starts processes without forking and so cannot lend its own pages
    to the thing it is measuring.
    """
    if os.name == "nt":
        return 0
    import resource

    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return usage if sys.platform == "darwin" else usage * 1024


def measure(binary: Path, workdir: Path) -> dict[str, object]:
    """Every scenario, on this machine, with this binary."""
    scenarios: list[tuple[str, list[str]]] = []
    for packages in SIZES:
        lock = workdir / f"lock-{packages}"
        lock.mkdir(parents=True, exist_ok=True)
        generate_lockfile(packages, lock / "pixi.lock")
        for label, args in (
            ("cyclonedx", ["--format", "cyclonedx"]),
            ("spdx", ["--format", "spdx"]),
            ("report-packages", ["--report", "packages", "--report-format", "json"]),
        ):
            scenarios.append((f"{label}-{packages}", [
                str(binary),
                "--lockfile",
                str(lock / "pixi.lock"),
                "-p",
                "linux-64",
                "-q",
                *args,
                *(["--output", os.devnull] if label != "report-packages" else []),
            ]))
    scenarios.append(("startup", [str(binary), "--version"]))

    results: dict[str, dict[str, float]] = {}
    for name, command in scenarios:
        times: list[float] = []
        peaks: list[int] = []
        for _ in range(RUNS):
            elapsed, peak = run_once(command)
            times.append(elapsed)
            peaks.append(peak)
        results[name] = {
            # The fastest run: the one least interrupted by whatever else shares the runner.
            "seconds": min(times),
            "seconds_median": statistics.median(times),
            # The largest peak, which is the one that has to fit in the machine.
            "peak_rss_bytes": max(peaks),
        }

    return {
        "binary_bytes": binary.stat().st_size,
        # If a scenario's peak ever equals this, the measurement is reporting the measurer.
        "measurer_rss_bytes": _own_rss_bytes(),
        "platform": f"{platform.system()}-{platform.machine()}",
        "runs": RUNS,
        "scenarios": results,
    }


def _percent(base: float, head: float) -> float:
    return ((head - base) / base * 100.0) if base else 0.0


def _mib(value: float) -> str:
    return f"{value / 1048576:.2f} MiB"


# A growth has to be both a large enough share and a large enough amount to count. A
# percentage on its own fails a build over mimalloc's arena appearing in a 2.5 MiB startup
# footprint, which is 0.38 MiB and nobody's problem; an amount on its own ignores a small
# scenario doubling. Both, and the gate only fires on something worth looking at.
MEMORY_FLOOR_BYTES = 8 * 1024 * 1024
SIZE_FLOOR_BYTES = 256 * 1024

# The binary is byte-exact, so a small share of it means something.
SIZE_LIMIT_PERCENT = 5.0

# Peak memory is steady within one allocator and moves by tens of percent across a change of
# allocator. 0.9.5 to 0.10.0 is one such change: mimalloc took peak memory up by as much as
# 45.4% on Linux, Windows and aarch64, deliberately, to buy 25-35% off the run, and
# docs/benchmarks.md records the trade. A limit tight enough to catch that fails every
# comparison spanning the change, so this one is set above it with room for a noisy runner,
# and catches what nobody would choose: something approaching a doubling.
#
# Worth bringing back towards 15% once 0.10.0 is the baseline every comparison starts from.
# Within one allocator the real numbers are single digits, so it costs nothing then.
MEMORY_LIMIT_PERCENT = 60.0


def compare(base: dict, head: dict, size_limit: float, memory_limit: float) -> tuple[list[str], list[str]]:
    """A markdown report of head against base, and the regressions worth failing over."""
    lines = [
        f"### Performance — {head.get('platform', 'unknown')}",
        "",
        f"Best of {head.get('runs', '?')} runs. Wall time on a shared runner is only meaningful as the",
        "difference between two binaries measured minutes apart on the same machine, which is what this is.",
        "",
        "| | base | head | change |",
        "|---|---:|---:|---:|",
    ]
    failures: list[str] = []

    base_size, head_size = base["binary_bytes"], head["binary_bytes"]
    size_change = _percent(base_size, head_size)
    lines.append(f"| binary | {_mib(base_size)} | {_mib(head_size)} | {size_change:+.2f}% |")
    if size_change > size_limit and head_size - base_size > SIZE_FLOOR_BYTES:
        failures.append(
            f"the binary grew {size_change:+.2f}% ({_mib(head_size - base_size)}), "
            f"over the {size_limit:.0f}% allowed"
        )

    for name, head_result in head["scenarios"].items():
        base_result = base["scenarios"].get(name)
        if base_result is None:
            lines.append(f"| {name} | — | {head_result['seconds'] * 1000:.1f} ms | new |")
            continue
        time_change = _percent(base_result["seconds"], head_result["seconds"])
        memory_change = _percent(base_result["peak_rss_bytes"], head_result["peak_rss_bytes"])
        lines.append(
            f"| {name} | {base_result['seconds'] * 1000:.1f} ms | "
            f"{head_result['seconds'] * 1000:.1f} ms | {time_change:+.1f}% |"
        )
        lines.append(
            f"| {name} peak | {_mib(base_result['peak_rss_bytes'])} | "
            f"{_mib(head_result['peak_rss_bytes'])} | {memory_change:+.1f}% |"
        )
        grew_by = head_result["peak_rss_bytes"] - base_result["peak_rss_bytes"]
        if memory_change > memory_limit and grew_by > MEMORY_FLOOR_BYTES:
            failures.append(
                f"{name} peak memory grew {memory_change:+.1f}% ({_mib(grew_by)}), "
                f"over the {memory_limit:.0f}% allowed"
            )

    lines += [
        "",
        f"Gated: binary size (+{size_limit:.0f}% and more than {_mib(SIZE_FLOOR_BYTES)}) and peak memory",
        f"(+{memory_limit:.0f}% and more than {_mib(MEMORY_FLOOR_BYTES)}), both steady enough to mean something.",
        "A share alone would fail over a fraction of a megabyte on a small baseline; an amount alone would miss a",
        "small scenario doubling. Wall time is reported and never fails the job.",
    ]
    return lines, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, help="the binary to measure")
    parser.add_argument("--out", type=Path, help="where to write the measurements as JSON")
    parser.add_argument("--compare", nargs=2, type=Path, metavar=("BASE", "HEAD"), help="two measurement files")
    parser.add_argument("--summary", type=Path, help="append the markdown report here as well as to stdout")
    parser.add_argument("--size-limit", type=float, default=SIZE_LIMIT_PERCENT, help="percent the binary may grow")
    parser.add_argument("--memory-limit", type=float, default=MEMORY_LIMIT_PERCENT, help="percent peak memory may grow")
    args = parser.parse_args()

    if args.compare:
        base = json.loads(args.compare[0].read_text(encoding="utf-8"))
        head = json.loads(args.compare[1].read_text(encoding="utf-8"))
        lines, failures = compare(base, head, args.size_limit, args.memory_limit)
        report = "\n".join(lines)
        sys.stdout.write(report + "\n")
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as summary:
                summary.write(report + "\n\n")
                if failures:
                    summary.write("**Regressions:**\n\n" + "".join(f"- {line}\n" for line in failures) + "\n")
        for failure in failures:
            sys.stderr.write(f"::error::{failure}\n")
        return 1 if failures else 0

    binary = args.binary or Path("target/release/pixi-sbom" + (".exe" if os.name == "nt" else ""))
    if not binary.is_file():
        raise SystemExit(f"{binary} is not there; build it first with `pixi run build`")

    workdir = Path(tempfile.mkdtemp(prefix="pixi-sbom-perf-"))
    try:
        measurements = measure(binary.resolve(), workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    text = json.dumps(measurements, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
