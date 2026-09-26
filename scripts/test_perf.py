"""Tests for the performance comparison, which decides whether a build fails.

Run with `pixi run perf-test`. The standard library only: this is one helper script beside a
Rust project, and a test framework for it would be heavier than the thing it tests.

The gate has been wrong twice — once reporting the measuring script's own memory as the
binary's, once failing a build over 0.38 MiB — so what it does with a given pair of numbers is
worth pinning down.
"""

from __future__ import annotations

import unittest

import perf


def measurement(binary_bytes: int, scenarios: dict[str, tuple[float, int]]) -> dict:
    """A measurement file's shape, from seconds and peak bytes per scenario."""
    return {
        "binary_bytes": binary_bytes,
        "platform": "Test-x86_64",
        "runs": 5,
        "scenarios": {
            name: {"seconds": seconds, "seconds_median": seconds, "peak_rss_bytes": peak}
            for name, (seconds, peak) in scenarios.items()
        },
    }


MIB = 1024 * 1024


class CompareTest(unittest.TestCase):
    def test_nothing_changed_is_not_a_failure(self) -> None:
        one = measurement(8 * MIB, {"write": (0.1, 100 * MIB)})
        lines, failures = perf.compare(one, one, size_limit=5.0, memory_limit=15.0)
        self.assertEqual(failures, [])
        self.assertTrue(any("+0.00%" in line for line in lines), lines)

    def test_a_real_memory_regression_fails(self) -> None:
        base = measurement(8 * MIB, {"write": (0.1, 90 * MIB)})
        head = measurement(8 * MIB, {"write": (0.1, 127 * MIB)})
        _, failures = perf.compare(base, head, size_limit=5.0, memory_limit=15.0)
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("write peak memory grew", failures[0])
        self.assertIn("MiB", failures[0], "the amount is named, not only the share")

    def test_a_large_share_of_a_small_baseline_does_not(self) -> None:
        # What failed the osx-64 job: startup memory 2.51 -> 2.89 MiB, which is +15.2% and
        # 0.38 MiB, and is mimalloc reserving an arena rather than anything going wrong.
        base = measurement(8 * MIB, {"startup": (0.002, 2_631_680)})
        head = measurement(8 * MIB, {"startup": (0.002, 3_030_384)})
        _, failures = perf.compare(base, head, size_limit=5.0, memory_limit=15.0)
        self.assertEqual(failures, [], "a fraction of a megabyte is nobody's problem")

    def test_a_large_amount_that_is_a_small_share_does_not_either(self) -> None:
        # Ten percent of a gigabyte is a hundred megabytes, and still only ten percent.
        base = measurement(8 * MIB, {"huge": (1.0, 1000 * MIB)})
        head = measurement(8 * MIB, {"huge": (1.0, 1100 * MIB)})
        _, failures = perf.compare(base, head, size_limit=5.0, memory_limit=15.0)
        self.assertEqual(failures, [])

    def test_the_binary_growing_fails_on_share_and_amount_together(self) -> None:
        base = measurement(8 * MIB, {})
        self.assertEqual(perf.compare(base, measurement(9 * MIB, {}), 5.0, 15.0)[1] != [], True)
        # Under the floor: a quarter of a megabyte on a two megabyte binary is 12%, and still
        # a quarter of a megabyte.
        small = measurement(2 * MIB, {})
        grown = measurement(2 * MIB + 200 * 1024, {})
        self.assertEqual(perf.compare(small, grown, 5.0, 15.0)[1], [])

    def test_time_is_reported_and_never_fails(self) -> None:
        base = measurement(8 * MIB, {"write": (0.1, 50 * MIB)})
        head = measurement(8 * MIB, {"write": (10.0, 50 * MIB)})
        lines, failures = perf.compare(base, head, size_limit=5.0, memory_limit=15.0)
        self.assertEqual(failures, [], "a hundred times slower still only gets reported")
        self.assertTrue(any("+9900.0%" in line for line in lines), lines)

    def test_a_scenario_the_base_never_ran_is_shown_as_new(self) -> None:
        base = measurement(8 * MIB, {})
        head = measurement(8 * MIB, {"added-later": (0.1, 50 * MIB)})
        lines, failures = perf.compare(base, head, size_limit=5.0, memory_limit=15.0)
        self.assertEqual(failures, [])
        self.assertTrue(any("new" in line for line in lines), lines)


class LockfileTest(unittest.TestCase):
    def test_the_generated_lockfile_is_the_size_it_says(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pixi.lock"
            perf.generate_lockfile(25, path)
            text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count("- conda: https://"), 50, "listed once per environment and once per package")
        # Quoted, because an all-digit digest is a number to YAML and a 64-digit one overflows
        # into a float that never reaches the digest parser as text.
        self.assertIn('sha256: "', text)
        self.assertIn("depends: []", text, "the first package depends on nothing")
        self.assertIn("  - pkg-00000 >=1.0.0", text, "and later ones depend on earlier ones")


if __name__ == "__main__":
    unittest.main()
