"""Tests for scripts/action-version.sh, which picks the binary the GitHub Action installs.

Run with `pixi run action-test`. The GitHub API is replaced by fixture files served over `file://`, so what a
floating `@v0` resolves to is checked without a network or a real tag.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("action-version.sh")

RELEASES = [
    {"tag_name": "v1.0.0-rc.1"},
    {"tag_name": "v1.0.0"},
    {"tag_name": "v0.12.0"},
    {"tag_name": "v0.9.5"},
    {"tag_name": "v0.10.1"},
    {"tag_name": "v0.13.0-rc.1"},
]


class ActionVersionTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        # curl drops the `?per_page=100` query from a file:// URL, so this is what the list request reads.
        (root / "releases").write_text(json.dumps(RELEASES, indent=2))
        self.api = f"file://{root}/releases"

    def resolve(self, **env: str) -> subprocess.CompletedProcess[str]:
        full = {"PATH": os.environ["PATH"], "RELEASES_API": self.api, **env}
        return subprocess.run(["bash", str(SCRIPT)], env=full, capture_output=True, text=True, check=False)

    def version(self, **env: str) -> str:
        result = self.resolve(**env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_input_wins_over_ref(self) -> None:
        self.assertEqual(self.version(INPUT_VERSION="v0.9.5", ACTION_REF="v0"), "0.9.5")

    def test_exact_tag_pins_that_release(self) -> None:
        self.assertEqual(self.version(ACTION_REF="v0.12.0"), "0.12.0")

    def test_major_tag_resolves_within_its_major(self) -> None:
        # Newest by version, not by list order, and never a pre-release or a v1.
        self.assertEqual(self.version(ACTION_REF="v0"), "0.12.0")

    def test_the_next_major_tag_resolves_within_its_own_major(self) -> None:
        # The case that matters once 1.0 ships: `@v1` must follow 1.x and not fall back to the
        # newest release overall, which is how a v1 user would end up with a v2 binary behind v1's
        # inputs. Nothing in the script is hardcoded to a major, and this is what says so.
        self.assertEqual(self.version(ACTION_REF="v1"), "1.0.0")

    def test_branch_takes_latest(self) -> None:
        self.assertEqual(self.version(ACTION_REF="main"), "1.0.0")

    def test_local_action_takes_latest(self) -> None:
        self.assertEqual(self.version(), "1.0.0")

    def test_major_without_a_release_falls_back_to_latest(self) -> None:
        self.assertEqual(self.version(ACTION_REF="v7"), "1.0.0")

    def test_unreachable_api_is_an_error(self) -> None:
        result = self.resolve(ACTION_REF="main", RELEASES_API="file:///nonexistent/releases")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
