"""Tests for scripts/cran_table.py."""

from __future__ import annotations

import tomllib
import unittest

import cran_table as c


class CranTableTest(unittest.TestCase):
    def test_names_come_from_the_package_list_and_the_archive(self) -> None:
        packages = "Package: Rcpp\nVersion: 1.0\n\nPackage: ggplot2\nVersion: 3.5\n"
        archive = '<a href="assertive/">assertive/</a> <a href="Rcpp/">Rcpp/</a>'
        self.assertEqual(c.cran_names(packages, archive), {"rcpp": "Rcpp", "ggplot2": "ggplot2", "assertive": "assertive"})

    def test_only_the_exceptions_are_listed(self) -> None:
        cran = {"rcpp": "Rcpp", "ggplot2": "ggplot2", "data.table": "data.table"}
        conda = ["r-rcpp", "r-ggplot2", "r-data.table", "r-base", "python"]
        renamed, not_cran = c.table(conda, cran)
        self.assertEqual(renamed, {"r-rcpp": "Rcpp"})
        self.assertEqual(not_cran, ["r-base"], "a non-r package is not considered")

    def test_the_file_is_valid_toml_in_the_shape_the_binary_reads(self) -> None:
        loaded = tomllib.loads(c.render({"r-rcpp": "Rcpp"}, ["r-base"]))
        self.assertEqual(loaded, {"renamed": {"r-rcpp": "Rcpp"}, "not-cran": {"names": ["r-base"]}})

    def test_the_shipped_table_loads(self) -> None:
        loaded = tomllib.loads(c.TABLE.read_text(encoding="utf-8"))
        self.assertIn("r-base", loaded["not-cran"]["names"])
        self.assertEqual(loaded["renamed"].get("r-rcpp"), "Rcpp")


if __name__ == "__main__":
    unittest.main()
