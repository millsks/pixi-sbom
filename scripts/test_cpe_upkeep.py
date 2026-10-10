"""Tests for the CPE table upkeep. Run with `pixi run cpe-upkeep-test`."""

from __future__ import annotations

import unittest

import cpe_upkeep as u


def product(name: str, deprecated: bool = False, by: str | None = None) -> dict:
    cpe: dict = {"cpeName": name, "deprecated": deprecated}
    if by:
        cpe["deprecatedBy"] = [{"cpeName": by}]
    return {"cpe": cpe}


class CpeUpkeepTest(unittest.TestCase):
    def test_the_shipped_files_load(self) -> None:
        entries = u.table(u.TABLE.read_text(encoding="utf-8"))
        self.assertEqual(entries["openssl"], ("openssl", "openssl"))
        skip = u.reviewed(u.REVIEWED.read_text(encoding="utf-8"))
        self.assertIn("tzdata", skip)
        self.assertFalse(set(skip) & set(entries), "a package is either in the table or reviewed out")

    def test_a_reviewed_package_needs_a_reason(self) -> None:
        with self.assertRaisesRegex(ValueError, "reason"):
            u.reviewed('[reviewed]\ntzdata = ""\n')

    def test_nvd_answers_unknown_current_or_deprecated(self) -> None:
        self.assertFalse(u.nvd_status({"products": []}).known)
        current = u.nvd_status({"products": [product("cpe:2.3:a:haxx:curl:8.0.0:*:*:*:*:*:*:*")]})
        self.assertTrue(current.known)
        self.assertIsNone(current.replacement)
        self.assertEqual(current.versions, ["8.0.0"])
        moved = u.nvd_status({"products": [
            product("cpe:2.3:a:old:lib:1.0:*:*:*:*:*:*:*", True, "cpe:2.3:a:new:lib:1.0:*:*:*:*:*:*:*"),
            product("cpe:2.3:a:old:lib:1.1:*:*:*:*:*:*:*", True, "cpe:2.3:a:new:lib:1.1:*:*:*:*:*:*:*"),
        ]})
        self.assertEqual(moved.replacement, ("new", "lib"))
        partly = u.nvd_status({"products": [
            product("cpe:2.3:a:old:lib:1.0:*:*:*:*:*:*:*", True, "cpe:2.3:a:new:lib:1.0:*:*:*:*:*:*:*"),
            product("cpe:2.3:a:old:lib:2.0:*:*:*:*:*:*:*"),
        ]})
        self.assertIsNone(partly.replacement, "deprecated only when every CPE is")

    def test_version_spellings_unlike_nvds_are_flagged(self) -> None:
        self.assertFalse(u.version_mismatch("3.5.2", ["3.0.0", "3.5.1"]))
        self.assertFalse(u.version_mismatch("1.1.1w", ["1.1.1a", "1.1.1k"]))
        self.assertTrue(u.version_mismatch("7.1.1_39", ["7.1.1-38", "7.1.1-39"]))
        self.assertFalse(u.version_mismatch("1.0", []), "nothing to compare with, nothing flagged")

    def test_candidates_are_native_packages_with_no_cpe_no_pypi_purl_and_no_review(self) -> None:
        doc = {"components": [
            {"name": "libfoo", "purl": "pkg:conda/libfoo@1.0"},
            {"name": "openssl", "purl": "pkg:conda/openssl@3.5.2", "cpe": "cpe:2.3:a:openssl:openssl:3.5.2:*:*:*:*:*:*:*"},
            {"name": "numpy", "purl": "pkg:conda/numpy@2.0", "properties": [{"name": "pixi:purl", "value": "pkg:pypi/numpy@2.0"}]},
            {"name": "tzdata", "purl": "pkg:conda/tzdata@2026a"},
            {"name": "six", "purl": "pkg:pypi/six@1.17.0"},
        ]}
        found = u.candidates([doc, doc], {"openssl"}, {"tzdata"})
        self.assertEqual(dict(found), {"libfoo": 2})

    def test_apply_renames_an_entry_and_keeps_the_rest_of_the_file(self) -> None:
        text = "# a comment\n[cpe]\nlibfoo = \"old:foo\"\nlibbar = \"old:bar\"\n"
        self.assertEqual(
            u.apply(text, {"libfoo": ("new", "foo")}),
            "# a comment\n[cpe]\nlibfoo = \"new:foo\"\nlibbar = \"old:bar\"\n",
        )

    def test_the_report_has_every_section(self) -> None:
        text = u.report({"libfoo": ("old:foo", ("new", "foo"))}, ["libbar"], {}, u.Counter({"libbaz": 3}), True, ["libqux"])
        for expected in ("`libfoo`: `old:foo` is now `new:foo`", "A pull request applies these", "- `libbar`", "- `libbaz` (3)", "## Not a conda-forge package", "- `libqux`"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
