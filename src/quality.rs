//! `--report quality` and `--min-quality`: how complete a document is, which matters most for
//! one somebody else wrote (`--from-sbom`). A vendor document without purls or a dependency graph
//! passes a vulnerability gate by having nothing to match, so before gating on it, grade it.
//!
//! The grade is the seven NTIA minimum elements (supplier, name, version, unique identifier,
//! dependency relationships, author, timestamp) and two coverages a consumer relies on (license,
//! hash), each 0 to 100: per-package elements are the share of packages that have it, document
//! elements are all or nothing. The overall score is their mean.

use crate::model::Sbom;

/// Exit code for `--min-quality` when the document scores below the threshold.
pub const QUALITY_EXIT_CODE: i32 = 10;

/// One graded element.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Element {
    pub element: &'static str,
    /// 0 to 100.
    pub score: u8,
    /// What the score counts, e.g. `812 of 820 packages`.
    pub detail: String,
    /// One of the NTIA minimum elements.
    pub ntia: bool,
    /// Shown, but not part of the score, so adding it did not move anyone's `--min-quality`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub informational: bool,
}

/// The grade of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grade {
    pub elements: Vec<Element>,
    /// The mean of every element.
    pub overall: u8,
    /// The mean of the NTIA minimum elements alone.
    pub ntia: u8,
}

/// Grade `sbom` as it would be written.
pub fn assess(sbom: &Sbom) -> Grade {
    let total = sbom.packages.len();
    let share = |element: &'static str, ntia: bool, have: usize, what: &str| Element {
        element,
        score: percent(have, total),
        detail: format!("{have} of {total} packages {what}"),
        ntia,
        informational: false,
    };
    let whole = |element: &'static str, ntia: bool, present: bool, yes: &str, no: &str| Element {
        element,
        score: if present { 100 } else { 0 },
        detail: if present { yes.to_string() } else { no.to_string() },
        ntia,
        informational: false,
    };
    let count = |test: &dyn Fn(&crate::model::Package) -> bool| sbom.packages.iter().filter(|p| test(p)).count();

    // A package is in the graph when it depends on something or something depends on it; the
    // root's own edges are not counted, since every input has those.
    let mut in_graph: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for package in &sbom.packages {
        if !package.dependencies.is_empty() {
            in_graph.insert(package.id.as_str());
            in_graph.extend(package.dependencies.iter().map(String::as_str));
        }
    }
    let graphed = sbom
        .packages
        .iter()
        .filter(|p| in_graph.contains(p.id.as_str()))
        .count();

    // A scanner matches a package by its purl or its CPE. A channel's conda package with no PyPI
    // purl (openssl, libtiff) has only a `pkg:conda` purl, which no advisory database indexes, so
    // it is matchable only through a CPE from the curated table.
    let native: Vec<&crate::model::Package> = sbom
        .packages
        .iter()
        .filter(|p| p.kind == crate::model::PackageKind::CondaBinary)
        .filter(|p| {
            !p.extra_purls
                .iter()
                .any(|purl| purl.starts_with("pkg:pypi/") || purl.starts_with("pkg:cran/"))
        })
        .collect();
    let unmatched = native.iter().filter(|p| crate::cpe::for_package(p).is_none()).count();
    let scanner = Element {
        element: "scanner identity",
        score: if native.is_empty() {
            100
        } else {
            percent(native.len() - unmatched, native.len())
        },
        detail: format!(
            "{unmatched} of {} native conda packages lack a CPE or matchable purl (not scored)",
            native.len()
        ),
        ntia: false,
        informational: true,
    };

    // A conda Python package whose PyPI purl is only an extra reference: scanners read the primary
    // purl alone, so they miss its advisories (#449).
    let python = count(&|p| {
        p.kind != crate::model::PackageKind::Pypi
            && p.extra_purls
                .iter()
                .chain([&p.purl])
                .any(|purl| purl.starts_with("pkg:pypi/"))
    });
    let hidden = crate::mapping::hidden_pypi_identities(sbom);
    let pypi_identity = Element {
        element: "PyPI identity",
        score: if python == 0 {
            100
        } else {
            percent(python - hidden, python)
        },
        detail: format!("{hidden} of {python} conda Python packages: PyPI purl not primary (not scored)"),
        ntia: false,
        informational: true,
    };

    let mut elements = vec![
        share("supplier", true, count(&|p| p.supplier.is_some()), "name a supplier"),
        share("name", true, count(&|p| !p.name.trim().is_empty()), "have a name"),
        share("version", true, count(&|p| p.version.is_some()), "have a version"),
        // NTIA accepts a purl, a CPE or a SWID tag as the unique identifier; a document from another
        // tool may give some packages only a CPE.
        share(
            "unique identifier",
            true,
            count(&|p| p.purl.starts_with("pkg:") || crate::cpe::for_package(p).is_some()),
            &format!(
                "have a purl or a CPE ({} a purl)",
                count(&|p| p.purl.starts_with("pkg:"))
            ),
        ),
        share("dependency relationships", true, graphed, "are in the dependency graph"),
        whole(
            "author",
            true,
            !sbom.root.authors.is_empty(),
            "the document names its authors",
            "the document names no author (the generating tool is recorded)",
        ),
        whole("timestamp", true, true, "written when the document is", ""),
        share("license", false, count(&|p| p.license.is_some()), "have a license"),
        share(
            "hash",
            false,
            count(&|p| p.sha256.is_some() || p.md5.is_some()),
            "have a hash",
        ),
    ];
    let all: Vec<u8> = elements.iter().map(|e| e.score).collect();
    let ntia: Vec<u8> = elements.iter().filter(|e| e.ntia).map(|e| e.score).collect();
    elements.push(scanner);
    elements.push(pypi_identity);
    let mean = |scores: &[u8]| {
        let total: u32 = scores.iter().map(|s| u32::from(*s)).sum();
        total.checked_div(scores.len() as u32).unwrap_or(0) as u8
    };
    Grade {
        overall: mean(&all),
        ntia: mean(&ntia),
        elements,
    }
}

/// `have` of `total` as a whole percentage, rounded down; nothing of nothing is 0.
fn percent(have: usize, total: usize) -> u8 {
    (have * 100).checked_div(total).unwrap_or(0) as u8
}

/// The weakest elements, worst first, as `name (score)`, for the gate's message.
pub fn weakest(grade: &Grade, count: usize) -> Vec<String> {
    let mut elements: Vec<&Element> = grade
        .elements
        .iter()
        .filter(|e| e.score < 100 && !e.informational)
        .collect();
    elements.sort_by_key(|e| e.score);
    elements
        .into_iter()
        .take(count)
        .map(|e| format!("{} ({})", e.element, e.score))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    fn score(grade: &Grade, element: &str) -> u8 {
        grade.elements.iter().find(|e| e.element == element).unwrap().score
    }

    /// Native conda packages are counted for whether a scanner can match them; the count is shown
    /// but not scored, so a document's grade and the `--min-quality` gate do not move.
    #[test]
    fn native_conda_packages_without_a_cpe_are_counted_but_not_scored() {
        use crate::model::PackageKind;
        let mut sbom = sample_sbom();
        let mut native = sbom.packages[0].clone();
        native.kind = PackageKind::CondaBinary;
        native.extra_purls.clear();
        native.name = "openssl".into();
        native.version = Some("3.5.2".into());
        let mut unknown = native.clone();
        unknown.name = "some-unmapped-lib".into();
        sbom.packages = vec![native, unknown];
        let grade = assess(&sbom);
        let scanner = grade.elements.iter().find(|e| e.element == "scanner identity").unwrap();
        assert!(scanner.informational && !scanner.ntia);
        assert_eq!(scanner.score, 50);
        assert!(
            scanner.detail.starts_with("1 of 2 native conda packages lack"),
            "{}",
            scanner.detail
        );
        let scored: Vec<u8> = grade
            .elements
            .iter()
            .filter(|e| !e.informational)
            .map(|e| e.score)
            .collect();
        let mean = scored.iter().map(|s| u32::from(*s)).sum::<u32>() / scored.len() as u32;
        assert_eq!(
            u32::from(grade.overall),
            mean,
            "the informational row is not in the mean"
        );
        assert!(!weakest(&grade, 10).iter().any(|w| w.starts_with("scanner identity")));
    }

    /// A conda package whose PyPI purl is not primary is invisible to a scanner; counted, not scored.
    #[test]
    fn conda_python_packages_with_a_hidden_pypi_purl_are_counted_but_not_scored() {
        use crate::model::PackageKind;
        let mut sbom = sample_sbom();
        let mut hidden = sbom.packages[0].clone();
        hidden.kind = PackageKind::CondaBinary;
        hidden.name = "django".into();
        hidden.purl = "pkg:conda/conda-forge/django@3.2.12".into();
        hidden.extra_purls = vec!["pkg:pypi/django@3.2.12".into()];
        let mut primary = hidden.clone();
        primary.name = "numpy".into();
        primary.purl = "pkg:pypi/numpy@2.3.1".into();
        primary.extra_purls = vec!["pkg:conda/conda-forge/numpy@2.3.1".into()];
        sbom.packages = vec![hidden, primary];
        let before = assess(&sbom).overall;
        let grade = assess(&sbom);
        let row = grade.elements.iter().find(|e| e.element == "PyPI identity").unwrap();
        assert!(row.informational && !row.ntia);
        assert_eq!(row.score, 50);
        assert!(row.detail.starts_with("1 of 2 conda Python packages"), "{}", row.detail);
        assert!(!weakest(&grade, 20).iter().any(|w| w.starts_with("PyPI identity")));
        crate::mapping::prefer_pypi_purl(&mut sbom);
        let after = assess(&sbom);
        assert_eq!(
            after
                .elements
                .iter()
                .find(|e| e.element == "PyPI identity")
                .unwrap()
                .score,
            100
        );
        assert_eq!(after.overall, before, "the row does not move the score");
    }

    #[test]
    fn a_complete_document_scores_high_and_a_sparse_one_low() {
        let complete = assess(&sample_sbom());
        assert_eq!(complete.elements.len(), 11);
        assert_eq!(complete.elements.iter().filter(|e| e.informational).count(), 2);
        assert_eq!(complete.elements.iter().filter(|e| e.ntia).count(), 7);
        assert_eq!(score(&complete, "timestamp"), 100);
        assert_eq!(score(&complete, "name"), 100);
        assert!(score(&complete, "dependency relationships") > 0, "the sample has edges");

        // A vendor document: names and versions, nothing else.
        let mut sparse = sample_sbom();
        sparse.root.authors.clear();
        for package in &mut sparse.packages {
            // Not a channel's conda package either, or the CPE table would identify it.
            package.kind = crate::model::PackageKind::External;
            package.purl = format!("{}@x", package.name);
            package.supplier = None;
            package.license = None;
            package.sha256 = None;
            package.md5 = None;
            package.dependencies.clear();
        }
        let sparse = assess(&sparse);
        for element in [
            "supplier",
            "unique identifier",
            "dependency relationships",
            "author",
            "license",
            "hash",
        ] {
            assert_eq!(score(&sparse, element), 0, "{element}");
        }
        assert!(sparse.overall < complete.overall);
        assert!(sparse.ntia < 50, "{}", sparse.ntia);
        let weakest = weakest(&sparse, 3);
        assert_eq!(weakest.len(), 3);
        assert!(weakest.iter().all(|w| w.ends_with("(0)")), "{weakest:?}");
    }

    #[test]
    fn shares_round_down_and_nothing_scores_nothing() {
        assert_eq!(percent(2, 3), 66);
        assert_eq!(percent(0, 0), 0);
        let mut empty = sample_sbom();
        empty.packages.clear();
        let grade = assess(&empty);
        assert_eq!(score(&grade, "version"), 0);
        assert_eq!(score(&grade, "timestamp"), 100);
    }
}
