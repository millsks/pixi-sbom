"""Tests for the lab-cache recorder. Run with `pixi run lab-cache-test`."""

from __future__ import annotations

import unittest

import lab_cache

PAGE = """Intro.

```sh
git clone https://example.invalid/repo
pixi sbom --lockfile a.lock --report packages
```

```text
Summary: 3 packages
```

```sh
pixi sbom --lockfile b.txt --output -   # exit 1
```

The answers were recorded into `examples/lab-cache/` on 2000-01-01, so a classroom gets them.
"""


class LabCacheTest(unittest.TestCase):
    def test_only_pixi_sbom_lines_in_shell_blocks_are_commands(self) -> None:
        self.assertEqual(
            lab_cache.lab_commands(PAGE),
            [["--lockfile", "a.lock", "--report", "packages"], ["--lockfile", "b.txt", "--output", "-"]],
        )

    def test_the_date_is_stamped_once(self) -> None:
        stamped = lab_cache.stamp(PAGE, "2026-10-09")
        self.assertIn("recorded into `examples/lab-cache/` on 2026-10-09, so", stamped)
        self.assertNotIn("2000-01-01", stamped)

    def test_a_page_without_the_sentence_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            lab_cache.stamp("no date here", "2026-10-09")

    def test_the_readme_says_when_and_how_many(self) -> None:
        text = lab_cache.readme("2026-10-09", 15)
        self.assertIn("commands were run on 2026-10-09", text)
        self.assertIn("its 15 commands", text)


if __name__ == "__main__":
    unittest.main()
