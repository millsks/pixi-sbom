"""Tests for the Grype comparison. Run with `pixi run grype-compare-test`."""

from __future__ import annotations

import unittest

import grype_compare as g


def match(vulnerability: str, name: str, version: str, kind: str = "python") -> dict:
    return {"vulnerability": {"id": vulnerability}, "artifact": {"name": name, "version": version, "type": kind}}


class GrypeCompareTest(unittest.TestCase):
    def test_names_are_compared_as_both_tools_spell_them(self) -> None:
        self.assertEqual(g.normalize("Typing_Extensions"), "typing-extensions")
        self.assertEqual(g.normalize("zope.interface"), "zope-interface")

    def test_findings_are_read_and_filtered_by_artifact_type(self) -> None:
        output = {"matches": [match("CVE-1", "Django", "3.2.12"), match("GHSA-2", "left-pad", "1.0", "npm")]}
        self.assertEqual(g.findings(output), {g.Finding("CVE-1", "django", "3.2.12"), g.Finding("GHSA-2", "left-pad", "1.0")})
        self.assertEqual(g.findings(output, {"python"}), {g.Finding("CVE-1", "django", "3.2.12")})

    def test_a_syft_only_finding_fails_unless_excepted_and_extra_findings_are_reported(self) -> None:
        syft = {g.Finding("CVE-1", "django", "3.2.12"), g.Finding("CVE-2", "libtiff", "4.5.1")}
        pixi = {g.Finding("CVE-1", "django", "3.2.12"), g.Finding("CVE-3", "python", "3.11.4")}
        result = g.compare("django", syft, pixi, {})
        self.assertEqual(result.agree, {g.Finding("CVE-1", "django", "3.2.12")})
        self.assertEqual(result.syft_only, {g.Finding("CVE-2", "libtiff", "4.5.1")})
        self.assertEqual(result.pixi_only, {g.Finding("CVE-3", "python", "3.11.4")})
        excepted = g.compare("django", syft, pixi, {("django", "CVE-2", "libtiff"): "a reason"})
        self.assertEqual(excepted.syft_only, set())
        self.assertEqual(excepted.excepted, {g.Finding("CVE-2", "libtiff", "4.5.1")})
        other = g.compare("data-analysis", syft, pixi, {("django", "CVE-2", "libtiff"): "a reason"})
        self.assertEqual(len(other.syft_only), 1, "an exception is for one environment")

    def test_every_exception_needs_a_reason(self) -> None:
        good = '[[exception]]\nenvironment = "django"\nvulnerability = "CVE-1"\npackage = "Lib_X"\nreason = "why"\n'
        self.assertEqual(g.load_exceptions(good), {("django", "CVE-1", "lib-x"): "why"})
        with self.assertRaisesRegex(ValueError, "reason"):
            g.load_exceptions('[[exception]]\nenvironment = "django"\nvulnerability = "CVE-1"\npackage = "x"\n')
        self.assertEqual(g.load_exceptions(g.EXCEPTIONS.read_text(encoding="utf-8")), {}, "the shipped file loads")


if __name__ == "__main__":
    unittest.main()
