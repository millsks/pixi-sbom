"""Tests for the What's new release step. Run with `pixi run whats-new-test`."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import whats_new

PAGE = """# What's new since 1.0

## The short version

- A summary.

## Unreleased

**Tab completion.** It completes.

## 1.8.2

**A fix.**
"""


class WhatsNewTest(unittest.TestCase):
    def test_release_renames_the_unreleased_section_and_nothing_else(self) -> None:
        out = whats_new.release(PAGE, "1.9.0")
        self.assertEqual(out, PAGE.replace("## Unreleased", "## 1.9.0"))
        self.assertTrue(out.endswith("\n"))

    def test_a_missing_section_stops_the_release(self) -> None:
        with self.assertRaisesRegex(whats_new.WhatsNewError, "no '## Unreleased' section"):
            whats_new.check(PAGE.replace("## Unreleased\n\n**Tab completion.** It completes.\n\n", ""), "1.9.0")

    def test_an_empty_section_stops_the_release(self) -> None:
        with self.assertRaisesRegex(whats_new.WhatsNewError, "is empty"):
            whats_new.check(PAGE.replace("**Tab completion.** It completes.\n", ""), "1.9.0")

    def test_a_section_below_a_release_stops_the_release(self) -> None:
        text = PAGE.replace("## Unreleased\n\n**Tab completion.** It completes.\n\n", "") + (
            "\n## Unreleased\n\nLate.\n"
        )
        with self.assertRaisesRegex(whats_new.WhatsNewError, "below a release"):
            whats_new.check(text, "1.9.0")

    def test_two_sections_stop_the_release(self) -> None:
        with self.assertRaisesRegex(whats_new.WhatsNewError, "2 '## Unreleased' sections"):
            whats_new.check(PAGE + "\n## Unreleased\n\nMore.\n", "1.9.0")

    def test_a_version_that_already_has_a_section_stops_the_release(self) -> None:
        with self.assertRaisesRegex(whats_new.WhatsNewError, "already has a section for 1.8.2"):
            whats_new.check(PAGE, "1.8.2")

    def test_the_command_line_writes_the_page_and_skips_release_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            page = Path(tmp) / "whats-new.md"
            page.write_text(PAGE, encoding="utf-8")
            self.assertEqual(whats_new.main(["release", "1.9.0-rc.1", "--page", str(page)]), 0)
            self.assertEqual(page.read_text(encoding="utf-8"), PAGE)
            self.assertEqual(whats_new.main(["check", "1.9.0", "--page", str(page)]), 0)
            self.assertEqual(page.read_text(encoding="utf-8"), PAGE)
            self.assertEqual(whats_new.main(["release", "1.9.0", "--page", str(page)]), 0)
            self.assertIn("## 1.9.0\n", page.read_text(encoding="utf-8"))
            self.assertEqual(whats_new.main(["check", "2.0.0", "--page", str(page)]), 1)


if __name__ == "__main__":
    unittest.main()
