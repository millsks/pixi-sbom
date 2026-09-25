//! Human-readable reports printed to the terminal instead of an SBOM document.
//!
//! Reports are built from the same [`Sbom`] model the writers consume, after the same
//! selection and enrichment, so what is displayed is exactly what a document would contain.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::SystemTime;

use clap::ValueEnum;
use comfy_table::Row as TableRow;
use comfy_table::{Cell, ColumnConstraint, ContentArrangement, LineStyle, Table, TableStyle, Width};
use serde::Serialize;

use crate::license::{self, License};
use crate::model::{Package, Sbom, Severity, Vulnerability};
use crate::style::{Palette, Role};

/// Which report to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportKind {
    /// Inventory: one row per package with kind, source, license and purl.
    Packages,
    /// Licenses: one row per package with license, family, source and files, plus a summary.
    Licenses,
    /// Vulnerabilities: one row per finding and affected package, worst first, plus a summary
    /// by severity. Requires --vulnerabilities.
    Vulnerabilities,
    /// Diff: what changed since the document given with --against (added, removed, version
    /// and license changes).
    Diff,
    /// Outdated: how far behind its index each package is.
    Outdated,
}

/// How to render a report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// Aligned columns for a terminal.
    #[default]
    Table,
    /// A GitHub-flavoured Markdown table.
    Markdown,
    /// RFC 4180 CSV with a header row.
    Csv,
    /// JSON: an object per document, or an array of them in batch mode.
    Json,
    /// SARIF 2.1.0 for the vulnerabilities report: one run per document, one result per
    /// finding and affected package, for GitHub code scanning and other SARIF consumers.
    Sarif,
}

/// Terminal width used to fit the `table` format: `COLUMNS` when set, else this.
const DEFAULT_WIDTH: usize = 120;

/// One package as a report sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub name: String,
    pub version: String,
    pub kind: &'static str,
    /// Channel or index the package came from.
    pub source: String,
    /// Normalized license expression or text; `None` when the package declares none.
    pub license: Option<String>,
    /// Whether `license` is a valid SPDX expression.
    pub spdx: bool,
    /// Why it is not, when it is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spdx_reason: Option<String>,
    pub license_family: Option<String>,
    /// Where the license came from: `lockfile`, `package-cache`, `pypi`, or `None`.
    pub license_source: Option<String>,
    pub license_files: Vec<String>,
    pub purl: String,
    /// `Some(reason)` when the index has yanked this release (PEP 592); the reason may be
    /// empty when the index gives none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yanked: Option<String>,
}

/// Summary of the licenses in one document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LicenseSummary {
    /// Packages per license, most common first.
    pub by_license: Vec<(String, usize)>,
    /// Packages that declare no license.
    pub unlicensed: Vec<String>,
    /// Packages whose license is not a valid SPDX expression, with the parser's reason.
    pub non_spdx: Vec<String>,
}

/// One package as the outdated report sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OutdatedRow {
    pub name: String,
    pub kind: &'static str,
    pub version: String,
    /// When the pinned version was published, and how long ago in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_days: Option<i64>,
    /// The newest release the index offers, and when it appeared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_published: Option<String>,
    /// Releases in between, and the size of the step.
    pub behind: usize,
    pub step: &'static str,
}

/// Summary of how current one document's packages are.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OutdatedSummary {
    /// Packages the indexes answered for.
    pub checked: usize,
    /// Packages behind their newest release, by step.
    pub by_step: Vec<(String, usize)>,
    /// Packages no index could be asked about (private channels, source packages).
    pub unknown: Vec<String>,
}

/// One finding for one affected package, as the vulnerabilities report sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VulnerabilityRow {
    pub package: String,
    pub version: String,
    pub purl: String,
    pub severity: &'static str,
    /// The highest CVSS base score among the ratings, when any vector was scored.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    pub id: String,
    pub aliases: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub url: String,
    /// The analysis state when the finding was accepted with `--ignore-vuln`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignored: Option<String>,
    /// The justification given with `--ignore-vuln`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// The CISA KEV entry, with `--kev`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev: Option<KevCell>,
}

/// The KEV facts a report row carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KevCell {
    pub cve_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    pub ransomware: bool,
}

/// Summary of the findings in one document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct VulnerabilitySummary {
    /// Distinct findings (a finding affecting two packages is listed twice but counted once).
    pub findings: usize,
    /// Findings per severity, worst first; only severities that occur.
    pub by_severity: Vec<(String, usize)>,
    /// Distinct packages with at least one finding that is not ignored.
    pub affected_packages: usize,
    /// Findings accepted with `--ignore-vuln`, as `id (state): justification`.
    pub ignored: Vec<String>,
    /// Open findings in CISA's KEV catalog, as `id (CVE, due date)`.
    pub known_exploited: Vec<String>,
    /// Packages with no purl the vulnerability database can answer (conda-only identities).
    pub without_identity: Vec<String>,
}

/// A complete report for one document.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub report: &'static str,
    pub workspace: String,
    pub environment: String,
    pub platform: String,
    /// The lockfile the document describes, relative to the workspace (SARIF's location).
    #[serde(skip)]
    pub lockfile: String,
    /// Package rows (the packages and licenses reports).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packages: Option<Vec<Row>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<LicenseSummary>,
    /// Finding rows (the vulnerabilities report).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<Vec<VulnerabilityRow>>,
    #[serde(rename = "summary", skip_serializing_if = "Option::is_none")]
    pub vulnerability_summary: Option<VulnerabilitySummary>,
    /// The comparison (the diff report).
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub diff: Option<crate::diff::Diff>,
    /// Rows of the outdated report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outdated: Option<Vec<OutdatedRow>>,
    #[serde(rename = "summary", skip_serializing_if = "Option::is_none")]
    pub outdated_summary: Option<OutdatedSummary>,
}

impl Report {
    /// The diff report for `sbom` against a previous document.
    pub fn diff(sbom: &Sbom, diff: crate::diff::Diff) -> Self {
        let mut report = Self::new(ReportKind::Diff, sbom);
        report.diff = Some(diff);
        report
    }

    /// Build the report for `sbom` (for [`ReportKind::Diff`] use [`Report::diff`]).
    pub fn new(kind: ReportKind, sbom: &Sbom) -> Self {
        let mut report = Self {
            report: match kind {
                ReportKind::Packages => "packages",
                ReportKind::Licenses => "licenses",
                ReportKind::Vulnerabilities => "vulnerabilities",
                ReportKind::Diff => "diff",
                ReportKind::Outdated => "outdated",
            },
            workspace: sbom.root.name.clone(),
            environment: sbom.environment.clone(),
            platform: sbom.platform.clone(),
            // SARIF locates results at the lockfile; an installed environment has none, so its
            // name stands in.
            lockfile: sbom.prefix.clone().unwrap_or_else(|| sbom.lockfile.clone()),
            packages: None,
            summary: None,
            vulnerabilities: None,
            vulnerability_summary: None,
            diff: None,
            outdated: None,
            outdated_summary: None,
        };
        match kind {
            ReportKind::Packages => report.packages = Some(sbom.packages.iter().map(row).collect()),
            ReportKind::Licenses => {
                let packages: Vec<Row> = sbom.packages.iter().map(row).collect();
                report.summary = Some(summarize(&packages));
                report.packages = Some(packages);
            }
            ReportKind::Vulnerabilities => {
                // Ignored findings go last, so the table reads worst-open first.
                let rows: Vec<VulnerabilityRow> = sbom
                    .vulnerabilities
                    .iter()
                    .filter(|v| v.analysis.is_none())
                    .chain(sbom.vulnerabilities.iter().filter(|v| v.analysis.is_some()))
                    .flat_map(|v| vulnerability_rows(v, sbom))
                    .collect();
                report.vulnerability_summary = Some(summarize_vulnerabilities(&rows, sbom));
                report.vulnerabilities = Some(rows);
            }
            ReportKind::Diff | ReportKind::Outdated => {}
        }
        report
    }

    /// Drop the rows that are not at least `only` behind.
    pub fn keep_outdated(&mut self, only: crate::cli::OutdatedOnly) {
        use crate::cli::OutdatedOnly;
        let wanted = |step: &str| match only {
            OutdatedOnly::Patch => true,
            OutdatedOnly::Minor => step == "minor" || step == "major",
            OutdatedOnly::Major => step == "major",
        };
        if let Some(rows) = &mut self.outdated {
            rows.retain(|row| row.behind > 0 && wanted(row.step));
        }
    }

    /// The outdated report for `sbom`, given what each index said (by package position).
    pub fn outdated(sbom: &Sbom, statuses: &[Option<crate::outdated::Status>], now: SystemTime) -> Self {
        let mut report = Self::new(ReportKind::Outdated, sbom);
        let mut rows = Vec::new();
        let mut unknown = Vec::new();
        let mut by_step: BTreeMap<&str, usize> = BTreeMap::new();
        for (package, status) in sbom
            .packages
            .iter()
            .zip(statuses.iter().chain(std::iter::repeat(&None)))
        {
            let Some(status) = status else {
                unknown.push(package.name.clone());
                continue;
            };
            if status.behind > 0 {
                *by_step.entry(status.step.name()).or_default() += 1;
            }
            rows.push(OutdatedRow {
                name: package.name.clone(),
                kind: package.kind.name(),
                version: package.version.clone().unwrap_or_else(|| "-".into()),
                age_days: status
                    .current_published
                    .as_deref()
                    .and_then(|published| crate::outdated::age_in_days(published, now)),
                published: status.current_published.clone(),
                latest: status.latest.clone(),
                latest_published: status.latest_published.clone(),
                behind: status.behind,
                step: status.step.name(),
            });
        }
        // Furthest behind first, then oldest, then by name.
        rows.sort_by(|a, b| {
            b.behind
                .cmp(&a.behind)
                .then_with(|| b.age_days.unwrap_or(0).cmp(&a.age_days.unwrap_or(0)))
                .then_with(|| a.name.cmp(&b.name))
        });
        report.outdated_summary = Some(OutdatedSummary {
            checked: rows.len(),
            by_step: ["major", "minor", "patch", "-"]
                .into_iter()
                .filter_map(|step| by_step.get(step).map(|count| (step.to_string(), *count)))
                .collect(),
            unknown,
        });
        report.outdated = Some(rows);
        report
    }

    fn kind(&self) -> ReportKind {
        match self.report {
            "licenses" => ReportKind::Licenses,
            "vulnerabilities" => ReportKind::Vulnerabilities,
            "diff" => ReportKind::Diff,
            "outdated" => ReportKind::Outdated,
            _ => ReportKind::Packages,
        }
    }

    fn columns(&self) -> Vec<&'static str> {
        match self.kind() {
            ReportKind::Packages => vec!["Name", "Version", "Kind", "Source", "License", "Yanked", "Purl"],
            ReportKind::Licenses => vec!["Name", "Version", "Kind", "License", "Family", "Source", "Files"],
            ReportKind::Vulnerabilities => vec![
                "Package", "Version", "Severity", "Score", "KEV", "ID", "Aliases", "Fixed", "Status", "Summary",
            ],
            ReportKind::Diff => vec!["Change", "Package", "Kind", "Before", "After"],
            ReportKind::Outdated => vec![
                "Package", "Kind", "Version", "Age", "Latest", "Released", "Behind", "Step",
            ],
        }
    }

    /// The body rows in display form.
    fn rows(&self) -> Vec<Vec<String>> {
        match self.kind() {
            ReportKind::Diff => self.diff.as_ref().map(diff_rows).unwrap_or_default(),
            ReportKind::Outdated => self.outdated.iter().flatten().map(outdated_cells).collect(),
            ReportKind::Vulnerabilities => self.vulnerabilities.iter().flatten().map(vulnerability_cells).collect(),
            _ => self.packages.iter().flatten().map(|r| self.cells(r)).collect(),
        }
    }

    /// The role of each column of this report's rows, so the palette can style the cells that
    /// carry meaning and leave the rest alone.
    fn roles(&self) -> Vec<Role> {
        use Role::{Change, Muted, NonSpdx, Plain, Severity, Status};
        match self.kind() {
            // Package, Version, Severity, Score, KEV, ID, Aliases, Fixed, Status, Summary
            ReportKind::Vulnerabilities => vec![
                Plain, Plain, Severity, Plain, Status, Plain, Plain, Plain, Status, Plain,
            ],
            // Change, Package, Kind, Before, After
            ReportKind::Diff => vec![Change, Plain, Plain, Plain, Plain],
            // Package, Kind, Version, Age, Latest, Released, Behind, Step
            ReportKind::Outdated => vec![Plain, Plain, Plain, Plain, Plain, Plain, Plain, Change],
            // Name, Version, Kind, License, Family, Source, Files
            ReportKind::Licenses => vec![Plain, Plain, Plain, NonSpdx, Plain, Plain, Plain],
            // Name, Version, Kind, Source, License, Yanked, Purl
            ReportKind::Packages => vec![Plain, Plain, Plain, Plain, NonSpdx, Status, Muted],
        }
    }

    /// Turn a rendered row into styled cells. A `-` placeholder is always muted, and a
    /// `NonSpdx` column is only coloured when the package's license really is not SPDX.
    fn paint(&self, row: &[String], palette: &Palette) -> Vec<Cell> {
        let roles = self.roles();
        let spdx = |name: &str| {
            self.packages
                .iter()
                .flatten()
                .find(|r| r.name == name)
                .is_none_or(|r| r.spdx)
        };
        row.iter()
            .enumerate()
            .map(|(i, text)| {
                let role = match roles.get(i).copied().unwrap_or(Role::Plain) {
                    _ if text == "-" => Role::Muted,
                    Role::NonSpdx if spdx(&row[0]) => Role::Plain,
                    role => role,
                };
                palette.cell(role, text)
            })
            .collect()
    }

    fn cells(&self, row: &Row) -> Vec<String> {
        let dash = || "-".to_string();
        match self.kind() {
            ReportKind::Licenses => vec![
                row.name.clone(),
                row.version.clone(),
                row.kind.to_string(),
                row.license.clone().unwrap_or_else(dash),
                row.license_family.clone().unwrap_or_else(dash),
                row.license_source.clone().unwrap_or_else(dash),
                row.license_files.len().to_string(),
            ],
            _ => vec![
                row.name.clone(),
                row.version.clone(),
                row.kind.to_string(),
                row.source.clone(),
                row.license.clone().unwrap_or_else(dash),
                match &row.yanked {
                    Some(reason) if !reason.is_empty() => format!("yes: {reason}"),
                    Some(_) => "yes".into(),
                    None => dash(),
                },
                row.purl.clone(),
            ],
        }
    }
}

/// Rows of unstyled cells, for the summary tables that carry no meaning per column.
fn plain_cells(rows: &[Vec<String>]) -> Vec<Vec<Cell>> {
    rows.iter().map(|row| row.iter().map(Cell::new).collect()).collect()
}

/// One outdated row as cells.
fn outdated_cells(row: &OutdatedRow) -> Vec<String> {
    let dash = || "-".to_string();
    vec![
        row.name.clone(),
        row.kind.to_string(),
        row.version.clone(),
        row.age_days.map(|days| format!("{days}d")).unwrap_or_else(dash),
        row.latest.clone().unwrap_or_else(dash),
        row.latest_published
            .as_deref()
            .map(|p| p.split('T').next().unwrap_or(p).to_string())
            .unwrap_or_else(dash),
        if row.behind == 0 {
            dash()
        } else {
            row.behind.to_string()
        },
        if row.behind == 0 {
            "current".into()
        } else {
            row.step.to_string()
        },
    ]
}

/// The diff as rows: additions, removals, version changes, license changes, in that order.
fn diff_rows(diff: &crate::diff::Diff) -> Vec<Vec<String>> {
    let dash = || "-".to_string();
    let mut rows = Vec::new();
    for p in &diff.added {
        rows.push(vec![
            "added".into(),
            p.name.clone(),
            p.kind.clone(),
            dash(),
            p.version.clone().unwrap_or_else(dash),
        ]);
    }
    for p in &diff.removed {
        rows.push(vec![
            "removed".into(),
            p.name.clone(),
            p.kind.clone(),
            p.version.clone().unwrap_or_else(dash),
            dash(),
        ]);
    }
    for c in &diff.version_changed {
        rows.push(vec![
            "version".into(),
            c.name.clone(),
            c.kind.clone(),
            c.old_version.clone().unwrap_or_else(dash),
            c.new_version.clone().unwrap_or_else(dash),
        ]);
    }
    for c in &diff.license_changed {
        rows.push(vec![
            "license".into(),
            c.name.clone(),
            c.kind.clone(),
            c.old_license.clone().unwrap_or_else(dash),
            c.new_license.clone().unwrap_or_else(dash),
        ]);
    }
    rows
}

fn vulnerability_cells(row: &VulnerabilityRow) -> Vec<String> {
    let dash = || "-".to_string();
    vec![
        row.package.clone(),
        row.version.clone(),
        row.severity.to_string(),
        row.score.map(|s| format!("{s:.1}")).unwrap_or_else(dash),
        match &row.kev {
            Some(kev) if kev.ransomware => "ransomware".into(),
            Some(_) => "yes".into(),
            None => dash(),
        },
        row.id.clone(),
        if row.aliases.is_empty() {
            dash()
        } else {
            row.aliases.join(", ")
        },
        row.fixed_version.clone().unwrap_or_else(dash),
        if row.ignored.is_some() { "ignored" } else { "open" }.to_string(),
        row.summary.clone().unwrap_or_else(dash),
    ]
}

/// One row per affected package of a finding.
fn vulnerability_rows(vuln: &Vulnerability, sbom: &Sbom) -> Vec<VulnerabilityRow> {
    let score = vuln
        .ratings
        .iter()
        .filter_map(|r| r.score)
        .fold(None, |best: Option<f64>, s| Some(best.map_or(s, |b| b.max(s))));
    vuln.affects
        .iter()
        .map(|affected| {
            let package = sbom.packages.iter().find(|p| p.id == affected.package_id);
            VulnerabilityRow {
                package: package
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| affected.package_id.clone()),
                version: package.and_then(|p| p.version.clone()).unwrap_or_else(|| "-".into()),
                purl: affected.purl.clone(),
                severity: vuln.severity.name(),
                score,
                id: vuln.id.clone(),
                aliases: vuln.aliases.clone(),
                fixed_version: affected.fixed_version.clone(),
                // A record without a summary usually still has details; its first line will do.
                summary: vuln.summary.clone().or_else(|| {
                    vuln.details
                        .as_deref()
                        .and_then(|d| d.lines().find(|l| !l.trim().is_empty()))
                        .map(|l| l.trim().to_string())
                }),
                url: vuln.url.clone(),
                ignored: vuln.analysis.as_ref().map(|a| a.state.to_string()),
                justification: vuln.analysis.as_ref().and_then(|a| a.detail.clone()),
                kev: vuln.kev.as_ref().map(|k| KevCell {
                    cve_id: k.cve_id.clone(),
                    date_added: k.date_added.clone(),
                    due_date: k.due_date.clone(),
                    ransomware: k.ransomware,
                }),
            }
        })
        .collect()
}

fn summarize_vulnerabilities(rows: &[VulnerabilityRow], sbom: &Sbom) -> VulnerabilitySummary {
    let mut by_severity = Vec::new();
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::None,
        Severity::Unknown,
    ] {
        let count = sbom
            .vulnerabilities
            .iter()
            .filter(|v| v.analysis.is_none() && v.severity == severity)
            .count();
        if count > 0 {
            by_severity.push((severity.name().to_string(), count));
        }
    }
    let affected_packages = rows
        .iter()
        .filter(|r| r.ignored.is_none())
        .map(|r| &r.purl)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    let without_identity = sbom
        .packages
        .iter()
        .filter(|p| {
            !std::iter::once(&p.purl)
                .chain(&p.extra_purls)
                .any(|purl| crate::osv::queryable_purl(purl).is_some())
        })
        .map(|p| p.name.clone())
        .collect();
    VulnerabilitySummary {
        findings: sbom.vulnerabilities.iter().filter(|v| v.analysis.is_none()).count(),
        by_severity,
        affected_packages,
        ignored: sbom
            .vulnerabilities
            .iter()
            .filter_map(|v| {
                let analysis = v.analysis.as_ref()?;
                Some(match &analysis.detail {
                    Some(detail) => format!("{} ({}): {detail}", v.id, analysis.state),
                    None => format!("{} ({})", v.id, analysis.state),
                })
            })
            .collect(),
        known_exploited: sbom
            .vulnerabilities
            .iter()
            .filter(|v| v.analysis.is_none())
            .filter_map(|v| {
                let kev = v.kev.as_ref()?;
                Some(match &kev.due_date {
                    Some(due) => format!("{} ({}, due {due})", v.id, kev.cve_id),
                    None => format!("{} ({})", v.id, kev.cve_id),
                })
            })
            .collect(),
        without_identity,
    }
}

fn row(package: &Package) -> Row {
    let (license, spdx) = match package.license.as_deref().map(license::normalize) {
        Some(License::Expression(expression)) => (Some(expression), true),
        Some(License::Text(text)) if !text.is_empty() => (Some(text), false),
        _ => (None, false),
    };
    let spdx_reason = match (&license, spdx) {
        (Some(_), false) => package.license.as_deref().and_then(license::rejection_reason),
        _ => None,
    };
    let license_source = package
        .properties
        .get("pixi:license-source")
        .cloned()
        .or_else(|| license.as_ref().map(|_| "lockfile".to_string()));
    Row {
        name: package.name.clone(),
        version: package.version.clone().unwrap_or_else(|| "-".into()),
        kind: package.kind.name(),
        source: package
            .supplier
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "-".into()),
        license,
        spdx,
        spdx_reason,
        license_family: package.properties.get("pixi:license-family").cloned(),
        license_source,
        license_files: package.license_files.iter().map(|f| f.name.clone()).collect(),
        purl: package.purl.clone(),
        yanked: package.yanked.as_ref().map(|y| y.reason.clone().unwrap_or_default()),
    }
}

fn summarize(rows: &[Row]) -> LicenseSummary {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut summary = LicenseSummary::default();
    for row in rows {
        match &row.license {
            Some(license) => {
                *counts.entry(license).or_default() += 1;
                if !row.spdx {
                    summary.non_spdx.push(match &row.spdx_reason {
                        Some(reason) => format!("{} ({reason})", row.name),
                        None => row.name.clone(),
                    });
                }
            }
            None => summary.unlicensed.push(row.name.clone()),
        }
    }
    let mut by_license: Vec<(String, usize)> = counts.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    by_license.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    summary.by_license = by_license;
    summary
}

/// Render `reports` (one per document) in `format` to `out`, fitting tables to the terminal
/// and colouring them when `palette` says so.
pub fn render(reports: &[Report], format: ReportFormat, palette: Palette, out: &mut dyn Write) -> io::Result<()> {
    render_with_width(reports, format, terminal_width(), palette, out)
}

/// [`render`] with an explicit table width instead of the terminal's.
pub fn render_with_width(
    reports: &[Report],
    format: ReportFormat,
    width: usize,
    palette: Palette,
    out: &mut dyn Write,
) -> io::Result<()> {
    match format {
        ReportFormat::Json if reports.len() == 1 => writeln!(out, "{}", serde_json::to_string_pretty(&reports[0])?),
        ReportFormat::Json => writeln!(out, "{}", serde_json::to_string_pretty(reports)?),
        ReportFormat::Csv => render_csv(reports, out),
        ReportFormat::Sarif => writeln!(out, "{}", serde_json::to_string_pretty(&sarif(reports))?),
        ReportFormat::Table | ReportFormat::Markdown => {
            // Colour is for the terminal only; markdown is data someone pastes elsewhere.
            let palette = if format == ReportFormat::Markdown {
                Palette::new(false)
            } else {
                palette
            };
            for (i, report) in reports.iter().enumerate() {
                if i > 0 {
                    writeln!(out)?;
                }
                if reports.len() > 1 || format == ReportFormat::Markdown {
                    let heading = palette.header(&format!(
                        "{} ({}, environment {}, platform {})",
                        report.report, report.workspace, report.environment, report.platform
                    ));
                    match format {
                        ReportFormat::Markdown => writeln!(out, "## {heading}\n")?,
                        _ => writeln!(out, "{heading}\n")?,
                    }
                }
                let columns = report.columns();
                let rows = report.rows();
                match format {
                    ReportFormat::Markdown => render_markdown(&columns, &rows, out)?,
                    _ => {
                        let cells: Vec<Vec<Cell>> = rows.iter().map(|row| report.paint(row, &palette)).collect();
                        render_table(&columns, cells, width, &palette, out)?;
                    }
                }
                if let Some(summary) = &report.summary {
                    render_summary(summary, rows.len(), format, &palette, out)?;
                }
                if let Some(summary) = &report.vulnerability_summary {
                    render_vulnerability_summary(summary, format, &palette, out)?;
                }
                if let Some(summary) = &report.outdated_summary {
                    writeln!(out)?;
                    let behind: usize = summary.by_step.iter().map(|(_, count)| count).sum();
                    let heading = palette.header(&format!(
                        "Summary: {behind} of {} packages behind their index",
                        summary.checked
                    ));
                    match format {
                        ReportFormat::Markdown => writeln!(out, "### {heading}\n")?,
                        _ => writeln!(out, "{heading}")?,
                    }
                    if !summary.by_step.is_empty() {
                        let plain: Vec<Vec<String>> = summary
                            .by_step
                            .iter()
                            .map(|(step, count)| vec![step.clone(), count.to_string()])
                            .collect();
                        let rows: Vec<Vec<Cell>> = summary
                            .by_step
                            .iter()
                            .map(|(step, count)| vec![palette.cell(Role::Change, step), Cell::new(count.to_string())])
                            .collect();
                        match format {
                            ReportFormat::Markdown => render_markdown(&["Step", "Packages"], &plain, out)?,
                            _ => render_table(&["Step", "Packages"], rows, usize::MAX, &palette, out)?,
                        }
                    }
                    writeln!(out)?;
                    if summary.unknown.is_empty() {
                        writeln!(out, "{}", palette.dim("No index to ask: none"))?;
                    } else {
                        writeln!(
                            out,
                            "No index to ask ({}): {}",
                            summary.unknown.len(),
                            summary.unknown.join(", ")
                        )?;
                    }
                }
                if let Some(diff) = &report.diff {
                    writeln!(out)?;
                    let line = if diff.is_empty() {
                        format!(
                            "No changes against {} ({}); {} packages unchanged",
                            diff.against, diff.against_format, diff.unchanged
                        )
                    } else {
                        format!(
                            "Against {} ({}): {} added, {} removed, {} version changes, {} license changes, {} unchanged",
                            diff.against,
                            diff.against_format,
                            diff.added.len(),
                            diff.removed.len(),
                            diff.version_changed.len(),
                            diff.license_changed.len(),
                            diff.unchanged
                        )
                    };
                    writeln!(out, "{line}")?;
                }
            }
            Ok(())
        }
    }
}

fn terminal_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|w: &usize| *w >= 40)
        .unwrap_or(DEFAULT_WIDTH)
}

/// A table fitted to `width`: columns are sized to their content and the widest ones wrap
/// rather than truncate, so nothing is silently lost.
fn render_table(
    columns: &[&str],
    rows: Vec<Vec<Cell>>,
    width: usize,
    palette: &Palette,
    out: &mut dyn Write,
) -> io::Result<()> {
    // Column-wide dashes under the header and nothing else, which is how these reports have
    // always looked.
    let style = TableStyle::new().header_separator(LineStyle::none().fill('-').junction('-'));
    // Columns whose widest cell is short (versions, severities, ids) are kept at their
    // content width so the prose columns absorb a narrow terminal instead of identifiers
    // being broken apart -- but only while the prose columns still have room to live in.
    const SHORT: u16 = 24;
    const PROSE_MINIMUM: u16 = 12;
    let widest_of = |i: usize| -> u16 {
        rows.iter()
            .filter_map(|row| row.get(i))
            .map(|cell| cell.content().chars().count())
            .chain(std::iter::once(columns[i].chars().count()))
            .max()
            .unwrap_or(0) as u16
    };
    let mut short_column_widths: BTreeMap<usize, u16> = (0..columns.len())
        .map(|i| (i, widest_of(i)))
        .filter(|(_, widest)| *widest <= SHORT)
        .collect();
    let short_total: u16 = short_column_widths.values().map(|w| w + 1).sum();
    let prose_columns = (columns.len() - short_column_widths.len()) as u16;
    if short_total + prose_columns * PROSE_MINIMUM > width.min(u16::MAX as usize) as u16 {
        short_column_widths.clear();
    }

    let mut table = Table::new();
    table
        .load_style(style)
        .set_content_arrangement(ContentArrangement::Dynamic)
        // Narrower than 40 columns is not a terminal anyone reads a table in; the reports
        // have always assumed at least that much (see `terminal_width`).
        .set_width(width.clamp(40, u16::MAX as usize) as u16)
        .set_header(TableRow::from(
            columns
                .iter()
                .map(|c| palette.cell(Role::Header, c))
                .collect::<Vec<_>>(),
        ));
    // comfy-table decides styling from the stream it thinks it writes to; we decide.
    if palette.is_enabled() {
        table.enforce_styling();
    } else {
        table.force_no_tty();
    }
    for row in rows {
        table.add_row(TableRow::from(row));
    }
    // Two spaces between columns and none at the line's start, as the reports have always
    // looked; comfy-table's default padding would indent every line by one.
    let last = columns.len().saturating_sub(1);
    for (i, column) in table.column_iter_mut().enumerate() {
        // comfy-table keeps one space between columns for the separator, so one of padding
        // gives the two-space gap these reports have always had.
        column.set_padding(if i == last { (0, 0) } else { (0, 1) });
        // Short columns (versions, severities, ids) keep their content width so the prose
        // columns absorb the squeeze instead of identifiers being broken apart. The boundary
        // counts the padding, hence the extra column for the separator.
        if let Some(needed) = short_column_widths.get(&i) {
            let padding = u16::from(i != last);
            column.set_constraint(ColumnConstraint::LowerBoundary(Width::Fixed(needed + padding)));
        }
    }
    for line in table.to_string().lines() {
        writeln!(out, "{}", line.trim_end())?;
    }
    Ok(())
}

fn render_markdown(columns: &[&str], rows: &[Vec<String>], out: &mut dyn Write) -> io::Result<()> {
    let escape = |cell: &str| cell.replace('|', "\\|");
    writeln!(out, "| {} |", columns.join(" | "))?;
    writeln!(out, "|{}|", columns.iter().map(|_| "---").collect::<Vec<_>>().join("|"))?;
    for row in rows {
        writeln!(
            out,
            "| {} |",
            row.iter().map(|c| escape(c)).collect::<Vec<_>>().join(" | ")
        )?;
    }
    Ok(())
}

fn render_summary(
    summary: &LicenseSummary,
    total: usize,
    format: ReportFormat,
    palette: &Palette,
    out: &mut dyn Write,
) -> io::Result<()> {
    writeln!(out)?;
    let heading = palette.header(&format!(
        "Summary: {total} packages, {} distinct licenses",
        summary.by_license.len()
    ));
    match format {
        ReportFormat::Markdown => writeln!(out, "### {heading}\n")?,
        _ => writeln!(out, "{heading}")?,
    }
    let rows: Vec<Vec<String>> = summary
        .by_license
        .iter()
        .map(|(license, count)| vec![license.clone(), count.to_string()])
        .collect();
    match format {
        ReportFormat::Markdown => render_markdown(&["License", "Packages"], &rows, out)?,
        _ => render_table(&["License", "Packages"], plain_cells(&rows), usize::MAX, palette, out)?,
    }
    let list = |label: &str, names: &[String]| -> String {
        if names.is_empty() {
            format!("{label}: none")
        } else {
            format!("{label} ({}): {}", names.len(), names.join(", "))
        }
    };
    writeln!(out)?;
    let muted = |line: String| {
        if line.ends_with(": none") {
            palette.dim(&line)
        } else {
            line
        }
    };
    writeln!(out, "{}", muted(list("No license", &summary.unlicensed)))?;
    writeln!(out, "{}", muted(list("Not an SPDX expression", &summary.non_spdx)))?;
    Ok(())
}

fn render_vulnerability_summary(
    summary: &VulnerabilitySummary,
    format: ReportFormat,
    palette: &Palette,
    out: &mut dyn Write,
) -> io::Result<()> {
    writeln!(out)?;
    let heading = if !summary.ignored.is_empty() {
        palette.header(&format!(
            "Summary: {} open findings in {} packages, {} ignored",
            summary.findings,
            summary.affected_packages,
            summary.ignored.len()
        ))
    } else {
        palette.header(&format!(
            "Summary: {} findings in {} packages",
            summary.findings, summary.affected_packages
        ))
    };
    match format {
        ReportFormat::Markdown => writeln!(out, "### {heading}\n")?,
        _ => writeln!(out, "{heading}")?,
    }
    if !summary.by_severity.is_empty() {
        let plain: Vec<Vec<String>> = summary
            .by_severity
            .iter()
            .map(|(severity, count)| vec![severity.clone(), count.to_string()])
            .collect();
        let rows: Vec<Vec<Cell>> = summary
            .by_severity
            .iter()
            .map(|(severity, count)| vec![palette.cell(Role::Severity, severity), Cell::new(count.to_string())])
            .collect();
        match format {
            ReportFormat::Markdown => render_markdown(&["Severity", "Findings"], &plain, out)?,
            _ => render_table(&["Severity", "Findings"], rows, usize::MAX, palette, out)?,
        }
    }
    writeln!(out)?;
    if !summary.known_exploited.is_empty() {
        writeln!(
            out,
            "{}",
            palette.severity(&format!(
                "Known exploited (CISA KEV) ({}):",
                summary.known_exploited.len()
            ))
        )?;
        for line in &summary.known_exploited {
            writeln!(out, "  {line}")?;
        }
    }
    if !summary.ignored.is_empty() {
        writeln!(out, "Ignored ({}):", summary.ignored.len())?;
        for line in &summary.ignored {
            writeln!(out, "  {line}")?;
        }
    }
    if summary.without_identity.is_empty() {
        writeln!(out, "{}", palette.dim("No queryable identity: none"))?;
    } else {
        writeln!(
            out,
            "No queryable identity ({}): {}",
            summary.without_identity.len(),
            summary.without_identity.join(", ")
        )?;
    }
    Ok(())
}

fn render_csv(reports: &[Report], out: &mut dyn Write) -> io::Result<()> {
    let kind = reports.first().map(Report::kind).unwrap_or(ReportKind::Packages);
    if kind == ReportKind::Vulnerabilities {
        return render_vulnerabilities_csv(reports, out);
    }
    if kind == ReportKind::Outdated {
        writeln!(
            out,
            "environment,platform,package,kind,version,published,age_days,latest,latest_published,behind,step"
        )?;
        for report in reports {
            for row in report.outdated.iter().flatten() {
                let cells = [
                    report.environment.clone(),
                    report.platform.clone(),
                    row.name.clone(),
                    row.kind.to_string(),
                    row.version.clone(),
                    row.published.clone().unwrap_or_default(),
                    row.age_days.map(|d| d.to_string()).unwrap_or_default(),
                    row.latest.clone().unwrap_or_default(),
                    row.latest_published.clone().unwrap_or_default(),
                    row.behind.to_string(),
                    row.step.to_string(),
                ];
                writeln!(
                    out,
                    "{}",
                    cells.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(",")
                )?;
            }
        }
        return Ok(());
    }
    if kind == ReportKind::Diff {
        writeln!(out, "environment,platform,change,package,kind,before,after")?;
        for report in reports {
            for row in report.diff.as_ref().map(diff_rows).unwrap_or_default() {
                let mut cells = vec![report.environment.clone(), report.platform.clone()];
                cells.extend(row);
                writeln!(
                    out,
                    "{}",
                    cells.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(",")
                )?;
            }
        }
        return Ok(());
    }
    let mut columns = vec!["environment", "platform"];
    columns.extend(match kind {
        ReportKind::Packages | ReportKind::Vulnerabilities | ReportKind::Diff | ReportKind::Outdated => {
            vec![
                "name",
                "version",
                "kind",
                "source",
                "license",
                "yanked",
                "yanked_reason",
                "purl",
            ]
        }
        ReportKind::Licenses => vec![
            "name",
            "version",
            "kind",
            "license",
            "spdx",
            "spdx_reason",
            "license_family",
            "license_source",
            "license_files",
            "purl",
        ],
    });
    writeln!(out, "{}", columns.join(","))?;
    for report in reports {
        for row in report.packages.iter().flatten() {
            let mut cells = vec![report.environment.clone(), report.platform.clone()];
            cells.extend(match kind {
                ReportKind::Packages | ReportKind::Vulnerabilities | ReportKind::Diff | ReportKind::Outdated => vec![
                    row.name.clone(),
                    row.version.clone(),
                    row.kind.to_string(),
                    row.source.clone(),
                    row.license.clone().unwrap_or_default(),
                    if row.yanked.is_some() { "true" } else { "false" }.to_string(),
                    row.yanked.clone().unwrap_or_default(),
                    row.purl.clone(),
                ],
                ReportKind::Licenses => vec![
                    row.name.clone(),
                    row.version.clone(),
                    row.kind.to_string(),
                    row.license.clone().unwrap_or_default(),
                    row.spdx.to_string(),
                    row.spdx_reason.clone().unwrap_or_default(),
                    row.license_family.clone().unwrap_or_default(),
                    row.license_source.clone().unwrap_or_default(),
                    row.license_files.join(";"),
                    row.purl.clone(),
                ],
            });
            writeln!(
                out,
                "{}",
                cells.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(",")
            )?;
        }
    }
    Ok(())
}

/// GitHub's `security-severity` score for a finding: its CVSS score, 10 for known exploited,
/// else a representative value for the severity word.
fn security_severity(row: &VulnerabilityRow) -> Option<f64> {
    if row.kev.is_some() {
        return Some(10.0);
    }
    row.score.or(match row.severity {
        "critical" => Some(9.5),
        "high" => Some(8.0),
        "medium" => Some(5.5),
        "low" => Some(2.5),
        "none" => Some(0.0),
        _ => None,
    })
}

/// The SARIF 2.1.0 log for the vulnerabilities reports: one run per document, one rule per
/// advisory, one result per finding and affected package, located at the lockfile.
fn sarif(reports: &[Report]) -> serde_json::Value {
    use serde_json::json;
    let runs: Vec<serde_json::Value> = reports
        .iter()
        .map(|report| {
            let rows = report.vulnerabilities.as_deref().unwrap_or(&[]);
            let mut rules: Vec<serde_json::Value> = Vec::new();
            let mut rule_index: BTreeMap<&str, usize> = BTreeMap::new();
            let mut results = Vec::new();
            for row in rows {
                let index = *rule_index.entry(&row.id).or_insert_with(|| {
                    let mut tags = vec!["security".to_string(), "vulnerability".to_string()];
                    tags.push(row.severity.to_string());
                    if row.kev.is_some() {
                        tags.push("known-exploited".into());
                    }
                    let mut properties = json!({ "tags": tags });
                    if let Some(score) = security_severity(row) {
                        properties["security-severity"] = json!(format!("{score:.1}"));
                    }
                    let title = row
                        .summary
                        .clone()
                        .unwrap_or_else(|| format!("{} in {}", row.id, row.package));
                    let mut help = format!(
                        "{}\n\nSeverity: {}",
                        row.summary.as_deref().unwrap_or(&row.id),
                        row.severity
                    );
                    if !row.aliases.is_empty() {
                        help.push_str(&format!("\nAliases: {}", row.aliases.join(", ")));
                    }
                    if let Some(kev) = &row.kev {
                        help.push_str(&format!(
                            "\nCISA KEV: {} (due {})",
                            kev.cve_id,
                            kev.due_date.as_deref().unwrap_or("-")
                        ));
                    }
                    help.push_str(&format!("\n{}", row.url));
                    rules.push(json!({
                        "id": row.id,
                        "name": row.id.replace('-', ""),
                        "shortDescription": { "text": title },
                        "fullDescription": { "text": help.lines().next().unwrap_or(&row.id) },
                        "helpUri": row.url,
                        "help": { "text": help, "markdown": help.replace('\n', "  \n") },
                        "properties": properties,
                    }));
                    rules.len() - 1
                });
                let mut message = format!(
                    "{} {} is affected by {} ({})",
                    row.package, row.version, row.id, row.severity
                );
                if let Some(summary) = &row.summary {
                    message.push_str(&format!(": {}", summary.trim_end_matches('.')));
                }
                match &row.fixed_version {
                    Some(fixed) => message.push_str(&format!(". Upgrade to {fixed}.")),
                    None => message.push('.'),
                }
                let level = match (row.ignored.is_some(), row.severity) {
                    (true, _) => "note",
                    (_, "critical" | "high") => "error",
                    (_, "medium") => "warning",
                    _ => "note",
                };
                let mut result = json!({
                    "ruleId": row.id,
                    "ruleIndex": index,
                    "level": level,
                    "message": { "text": message },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": report.lockfile, "uriBaseId": "%SRCROOT%" }
                        },
                        "logicalLocations": [{ "name": row.purl, "kind": "package" }]
                    }],
                    "partialFingerprints": {
                        "pixi-sbom/purl": row.purl,
                        "pixi-sbom/environment": report.environment,
                        "pixi-sbom/platform": report.platform
                    },
                    "properties": {
                        "package": row.package,
                        "version": row.version,
                        "purl": row.purl,
                        "severity": row.severity,
                        "aliases": row.aliases,
                    }
                });
                if let Some(score) = row.score {
                    result["properties"]["score"] = json!(score);
                }
                if let Some(fixed) = &row.fixed_version {
                    result["properties"]["fixedVersion"] = json!(fixed);
                }
                if let Some(kev) = &row.kev {
                    result["properties"]["kev"] = json!({
                        "cveId": kev.cve_id,
                        "dateAdded": kev.date_added,
                        "dueDate": kev.due_date,
                        "knownRansomwareCampaignUse": kev.ransomware,
                    });
                }
                if let Some(state) = &row.ignored {
                    let mut suppression = json!({ "kind": "external", "status": "accepted" });
                    let justification = match &row.justification {
                        Some(text) => format!("{state}: {text}"),
                        None => state.clone(),
                    };
                    suppression["justification"] = json!(justification);
                    result["suppressions"] = json!([suppression]);
                }
                results.push(result);
            }
            json!({
                "tool": {
                    "driver": {
                        "name": "pixi-sbom",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://millsks.github.io/pixi-sbom/",
                        "rules": rules,
                    }
                },
                "automationDetails": {
                    "id": format!("pixi-sbom/{}/{}", report.environment, report.platform)
                },
                "results": results,
                "properties": {
                    "workspace": report.workspace,
                    "environment": report.environment,
                    "platform": report.platform,
                    "summary": report.vulnerability_summary,
                }
            })
        })
        .collect();
    json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    })
}

fn render_vulnerabilities_csv(reports: &[Report], out: &mut dyn Write) -> io::Result<()> {
    writeln!(
        out,
        "environment,platform,package,version,purl,severity,score,kev,kev_due_date,id,aliases,fixed_version,status,summary,url"
    )?;
    for report in reports {
        for row in report.vulnerabilities.iter().flatten() {
            let cells = [
                report.environment.clone(),
                report.platform.clone(),
                row.package.clone(),
                row.version.clone(),
                row.purl.clone(),
                row.severity.to_string(),
                row.score.map(|s| format!("{s:.1}")).unwrap_or_default(),
                match &row.kev {
                    Some(kev) if kev.ransomware => "ransomware".into(),
                    Some(_) => "yes".into(),
                    None => String::new(),
                },
                row.kev.as_ref().and_then(|k| k.due_date.clone()).unwrap_or_default(),
                row.id.clone(),
                row.aliases.join(";"),
                row.fixed_version.clone().unwrap_or_default(),
                row.ignored
                    .as_deref()
                    .map(|s| format!("ignored ({s})"))
                    .unwrap_or_else(|| "open".into()),
                row.summary.clone().unwrap_or_default(),
                row.url.clone(),
            ];
            writeln!(
                out,
                "{}",
                cells.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(",")
            )?;
        }
    }
    Ok(())
}

fn csv_field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::testing::sample_sbom;

    /// Renders at a fixed width so snapshots do not depend on the terminal running the tests.
    fn render_string(kind: ReportKind, format: ReportFormat, sboms: &[Sbom]) -> String {
        let reports: Vec<Report> = sboms.iter().map(|s| Report::new(kind, s)).collect();
        let mut out = Vec::new();
        render_with_width(&reports, format, DEFAULT_WIDTH, Palette::new(false), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn rows_carry_normalized_license_source_and_files() {
        let report = Report::new(ReportKind::Licenses, &sample_sbom());
        let packages = report.packages.as_ref().unwrap();
        let by_name = |name: &str| packages.iter().find(|r| r.name == name).unwrap();
        assert_eq!(by_name("zlib").license.as_deref(), Some("MIT OR Apache-2.0"));
        assert!(by_name("zlib").spdx);
        assert_eq!(by_name("zlib").license_source.as_deref(), Some("lockfile"));
        assert_eq!(by_name("zlib").license_files, ["LICENSE-APACHE", "LICENSE-MIT"]);
        assert_eq!(by_name("mylib").license.as_deref(), Some("Proprietary"));
        assert!(!by_name("mylib").spdx);
        assert_eq!(by_name("mylib").version, "-");
        assert_eq!(by_name("mylib").source, "-");
        assert_eq!(by_name("six").license, None);
        assert_eq!(by_name("six").license_source, None);
        assert_eq!(by_name("six").source, "pypi.org");
        let summary = report.summary.unwrap();
        assert_eq!(
            summary.by_license,
            [
                ("MIT OR Apache-2.0".to_string(), 1),
                ("Proprietary".to_string(), 1),
                ("Zlib".to_string(), 1)
            ]
        );
        assert_eq!(summary.unlicensed, ["six"]);
        assert_eq!(summary.non_spdx.len(), 1);
        assert!(summary.non_spdx[0].starts_with("mylib ("), "{:?}", summary.non_spdx);
        assert!(by_name("mylib").spdx_reason.as_deref().unwrap().contains("Proprietary"));
        assert_eq!(by_name("zlib").spdx_reason, None);
    }

    #[test]
    fn license_source_property_wins_over_lockfile_default() {
        let mut sbom = sample_sbom();
        sbom.packages[0]
            .properties
            .insert("pixi:license-source".into(), "package-cache".into());
        let report = Report::new(ReportKind::Packages, &sbom);
        assert_eq!(
            report.packages.as_ref().unwrap()[0].license_source.as_deref(),
            Some("package-cache")
        );
        assert!(report.summary.is_none());
    }

    #[test]
    fn table_snapshot() {
        insta::assert_snapshot!(render_string(
            ReportKind::Packages,
            ReportFormat::Table,
            &[sample_sbom()]
        ));
    }

    #[test]
    fn licenses_table_snapshot() {
        insta::assert_snapshot!(render_string(
            ReportKind::Licenses,
            ReportFormat::Table,
            &[sample_sbom()]
        ));
    }

    #[test]
    fn markdown_snapshot() {
        insta::assert_snapshot!(render_string(
            ReportKind::Licenses,
            ReportFormat::Markdown,
            &[sample_sbom()]
        ));
    }

    #[test]
    fn csv_snapshot() {
        insta::assert_snapshot!(render_string(ReportKind::Licenses, ReportFormat::Csv, &[sample_sbom()]));
    }

    #[test]
    fn json_is_an_object_or_an_array_in_batch_mode() {
        let one = render_string(ReportKind::Packages, ReportFormat::Json, &[sample_sbom()]);
        let value: serde_json::Value = serde_json::from_str(&one).unwrap();
        assert_eq!(value["report"], "packages");
        assert_eq!(value["packages"].as_array().unwrap().len(), 4);
        assert!(value.get("summary").is_none());

        let mut other = sample_sbom();
        other.environment = "prod".into();
        let two = render_string(ReportKind::Licenses, ReportFormat::Json, &[sample_sbom(), other]);
        let value: serde_json::Value = serde_json::from_str(&two).unwrap();
        assert_eq!(value.as_array().unwrap().len(), 2);
        assert_eq!(value[1]["environment"], "prod");
        assert_eq!(value[1]["summary"]["unlicensed"][0], "six");
    }

    #[test]
    fn batch_table_has_headings_and_csv_has_environment_columns() {
        let mut other = sample_sbom();
        other.platform = "osx-arm64".into();
        let text = render_string(ReportKind::Packages, ReportFormat::Table, &[sample_sbom(), other]);
        assert!(text.contains("packages (demo, environment default, platform linux-64)"));
        assert!(text.contains("packages (demo, environment default, platform osx-arm64)"));
        let csv = render_string(ReportKind::Packages, ReportFormat::Csv, &[sample_sbom()]);
        assert!(csv.starts_with("environment,platform,name,version,kind,source,license,yanked,yanked_reason,purl\n"));
        assert!(csv.contains("default,linux-64,zlib,1.3.1,conda,conda-forge,MIT OR Apache-2.0,false,,pkg:conda/zlib"));
    }

    #[test]
    fn a_wide_cell_wraps_within_the_width_instead_of_being_truncated() {
        let mut out = Vec::new();
        let wide = "word ".repeat(12);
        render_table(
            &["A", "B"],
            plain_cells(&[vec!["short".into(), wide.trim().into()]]),
            40,
            &Palette::new(false),
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.lines().all(|l| l.chars().count() <= 40),
            "every line fits: {text:?}"
        );
        // Nothing is lost: every word of the wide cell is still there.
        let words = text.matches("word").count();
        assert_eq!(words, 12, "{text:?}");
        // The header still has a rule under it, spanning the columns.
        let mut lines = text.lines();
        assert!(lines.next().unwrap().contains('A'));
        let rule = lines.next().unwrap();
        assert!(
            rule.starts_with('-') && rule.chars().all(|c| c == '-' || c == ' '),
            "{rule:?}"
        );
    }

    #[test]
    fn colour_paints_only_the_table_format_and_only_meaningful_cells() {
        let reports = [Report::new(ReportKind::Vulnerabilities, &vulnerable_sbom())];
        let paint = |format| {
            let mut out = Vec::new();
            render_with_width(&reports, format, 200, Palette::new(true), &mut out).unwrap();
            String::from_utf8(out).unwrap()
        };
        let table = paint(ReportFormat::Table);
        assert!(table.contains('\u{1b}'), "the table is coloured");
        // The severity and status words are styled; the package name and version are not.
        let line = table.lines().find(|l| l.contains("GHSA-q2q7-5pp4-w6pg")).unwrap();
        assert!(line.starts_with("six      1.17.0"), "{line:?}");
        for word in ["high", "open"] {
            let at = line.find(word).unwrap();
            assert!(line[..at].ends_with('m'), "{word} is styled: {line:?}");
        }
        // The text itself survives the styling, which is what makes the widths right.
        assert!(line.contains("Catastrophic backtracking"), "{line:?}");
        assert!(
            !paint(ReportFormat::Markdown).contains('\u{1b}'),
            "markdown stays plain"
        );
        assert!(!paint(ReportFormat::Csv).contains('\u{1b}'));
        assert!(!paint(ReportFormat::Json).contains('\u{1b}'));
        assert!(!paint(ReportFormat::Sarif).contains('\u{1b}'));
        // A plain palette leaves the table free of escapes, which is what the snapshots pin.
        let mut out = Vec::new();
        render_with_width(&reports, ReportFormat::Table, 200, Palette::new(false), &mut out).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains('\u{1b}'));
    }

    #[test]
    fn csv_fields_are_quoted_when_needed() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("multi\nline"), "\"multi\nline\"");
    }

    #[test]
    fn terminal_width_falls_back_when_columns_is_unusable() {
        // COLUMNS is process-global; only assert the invariant that holds either way.
        let width = terminal_width();
        assert!(width >= 40);
        // render() itself uses the terminal width: with a huge COLUMNS nothing is truncated.
        let reports = [Report::new(ReportKind::Packages, &sample_sbom())];
        let mut out = Vec::new();
        render_with_width(&reports, ReportFormat::Table, usize::MAX, Palette::new(false), &mut out).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains('…'));
    }

    /// The sample with two findings: one high affecting six (fixed), one unknown affecting zlib
    /// through its PyPI purl and six again.
    fn vulnerable_sbom() -> Sbom {
        use crate::model::{Affected, Rating, Vulnerability};
        let mut sbom = sample_sbom();
        sbom.vulnerabilities = vec![
            Vulnerability {
                id: "GHSA-q2q7-5pp4-w6pg".into(),
                source: "OSV".into(),
                url: "https://osv.dev/vulnerability/GHSA-q2q7-5pp4-w6pg".into(),
                aliases: vec!["CVE-2021-33503".into(), "PYSEC-2021-108".into()],
                summary: Some("Catastrophic backtracking in URL authority parser".into()),
                details: None,
                severity: Severity::High,
                ratings: vec![
                    Rating {
                        source: "GitHub Advisory Database".into(),
                        score: None,
                        severity: Severity::High,
                        method: "other",
                        vector: None,
                    },
                    Rating {
                        source: "OSV".into(),
                        score: Some(7.5),
                        severity: Severity::High,
                        method: "CVSSv31",
                        vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".into()),
                    },
                ],
                cwes: vec![400],
                references: vec![],
                published: None,
                modified: None,
                affects: vec![Affected {
                    package_id: "pkg:pypi/six@1.17.0".into(),
                    purl: "pkg:pypi/six@1.17.0".into(),
                    fixed_version: Some("1.26.5".into()),
                }],
                analysis: None,
                kev: Some(crate::model::Kev {
                    cve_id: "CVE-2021-33503".into(),
                    name: None,
                    date_added: Some("2026-09-01".into()),
                    due_date: Some("2026-09-22".into()),
                    ransomware: false,
                    required_action: None,
                }),
            },
            Vulnerability {
                id: "PYSEC-2099-1".into(),
                source: "OSV".into(),
                url: "https://osv.dev/vulnerability/PYSEC-2099-1".into(),
                aliases: vec![],
                summary: None,
                details: None,
                severity: Severity::Unknown,
                ratings: vec![],
                cwes: vec![],
                references: vec![],
                published: None,
                modified: None,
                affects: vec![
                    Affected {
                        package_id: "pkg:conda/zlib@1.3.1?build=h1&channel=conda-forge&subdir=linux-64&type=conda"
                            .into(),
                        purl: "pkg:pypi/zlib@1.3.1".into(),
                        fixed_version: None,
                    },
                    Affected {
                        package_id: "pkg:pypi/six@1.17.0".into(),
                        purl: "pkg:pypi/six@1.17.0".into(),
                        fixed_version: None,
                    },
                ],
                analysis: Some(crate::model::Analysis {
                    state: "false_positive",
                    detail: Some("not the same zlib".into()),
                }),
                kev: None,
            },
        ];
        sbom
    }

    #[test]
    fn vulnerability_rows_and_summary() {
        let report = Report::new(ReportKind::Vulnerabilities, &vulnerable_sbom());
        assert!(report.packages.is_none());
        let rows = report.vulnerabilities.as_ref().unwrap();
        assert_eq!(rows.len(), 3, "one row per finding and affected package");
        assert_eq!(rows[0].ignored, None);
        assert_eq!(rows[1].ignored.as_deref(), Some("false_positive"));
        assert_eq!(rows[0].package, "six");
        assert_eq!(rows[0].version, "1.17.0");
        assert_eq!(rows[0].severity, "high");
        assert_eq!(rows[0].score, Some(7.5));
        assert_eq!(rows[0].fixed_version.as_deref(), Some("1.26.5"));
        assert_eq!(rows[1].package, "zlib", "a conda package matched through its PyPI purl");
        assert_eq!(rows[1].purl, "pkg:pypi/zlib@1.3.1");
        assert_eq!(rows[1].severity, "unknown");
        assert_eq!(rows[1].score, None);
        let summary = report.vulnerability_summary.as_ref().unwrap();
        assert_eq!(
            summary.by_severity,
            [("high".to_string(), 1)],
            "ignored findings are not counted"
        );
        assert_eq!(summary.findings, 1);
        assert_eq!(summary.ignored, ["PYSEC-2099-1 (false_positive): not the same zlib"]);
        assert_eq!(
            summary.known_exploited,
            ["GHSA-q2q7-5pp4-w6pg (CVE-2021-33503, due 2026-09-22)"]
        );
        assert_eq!(rows[0].kev.as_ref().unwrap().due_date.as_deref(), Some("2026-09-22"));
        assert_eq!(rows[1].justification.as_deref(), Some("not the same zlib"));
        assert_eq!(summary.affected_packages, 1);
        assert_eq!(summary.without_identity, ["libzlib", "mylib"]);
    }

    #[test]
    fn vulnerabilities_table_snapshot() {
        insta::assert_snapshot!(render_string(
            ReportKind::Vulnerabilities,
            ReportFormat::Table,
            &[vulnerable_sbom()]
        ));
    }

    #[test]
    fn vulnerabilities_markdown_snapshot() {
        insta::assert_snapshot!(render_string(
            ReportKind::Vulnerabilities,
            ReportFormat::Markdown,
            &[vulnerable_sbom()]
        ));
    }

    #[test]
    fn vulnerabilities_csv_snapshot() {
        insta::assert_snapshot!(render_string(
            ReportKind::Vulnerabilities,
            ReportFormat::Csv,
            &[vulnerable_sbom()]
        ));
    }

    #[test]
    fn sarif_has_a_run_per_document_with_rules_results_and_suppressions() {
        let mut other = vulnerable_sbom();
        other.platform = "osx-arm64".into();
        let text = render_string(
            ReportKind::Vulnerabilities,
            ReportFormat::Sarif,
            &[vulnerable_sbom(), other],
        );
        let log: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(log["version"], "2.1.0");
        let runs = log["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 2);
        let run = &runs[0];
        assert_eq!(run["tool"]["driver"]["name"], "pixi-sbom");
        assert_eq!(run["automationDetails"]["id"], "pixi-sbom/default/linux-64");
        let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2, "one rule per advisory, not per affected package");
        assert_eq!(rules[0]["id"], "GHSA-q2q7-5pp4-w6pg");
        assert_eq!(
            rules[0]["properties"]["security-severity"], "10.0",
            "known exploited scores 10"
        );
        assert!(
            rules[0]["properties"]["tags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t == "known-exploited")
        );
        assert!(
            rules[1]["properties"].get("security-severity").is_none(),
            "unknown severity has no score"
        );
        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[0]["ruleIndex"], 0);
        assert!(
            results[0]["message"]["text"]
                .as_str()
                .unwrap()
                .starts_with("six 1.17.0 is affected by GHSA-q2q7-5pp4-w6pg (high): Catastrophic")
        );
        assert!(
            results[0]["message"]["text"]
                .as_str()
                .unwrap()
                .ends_with("Upgrade to 1.26.5.")
        );
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "pixi.lock"
        );
        assert_eq!(
            results[0]["partialFingerprints"]["pixi-sbom/purl"],
            "pkg:pypi/six@1.17.0"
        );
        assert_eq!(results[0]["properties"]["kev"]["cveId"], "CVE-2021-33503");
        assert!(results[0].get("suppressions").is_none());
        // Ignored findings are notes with a suppression carrying the justification.
        assert_eq!(results[1]["level"], "note");
        assert_eq!(results[1]["suppressions"][0]["kind"], "external");
        assert_eq!(
            results[1]["suppressions"][0]["justification"],
            "false_positive: not the same zlib"
        );
        assert_eq!(runs[1]["automationDetails"]["id"], "pixi-sbom/default/osx-arm64");
    }

    fn diffed() -> Report {
        use crate::diff::{Change, Diff, Presence};
        Report::diff(
            &sample_sbom(),
            Diff {
                against: "old.cdx.json".into(),
                against_format: "CycloneDX 1.6".into(),
                added: vec![Presence {
                    name: "requests".into(),
                    kind: "pypi".into(),
                    version: Some("2.32.4".into()),
                    license: Some("Apache-2.0".into()),
                    purl: Some("pkg:pypi/requests@2.32.4".into()),
                }],
                removed: vec![Presence {
                    name: "mylib".into(),
                    kind: "conda".into(),
                    version: None,
                    license: None,
                    purl: None,
                }],
                version_changed: vec![Change {
                    name: "zlib".into(),
                    kind: "conda".into(),
                    old_version: Some("1.3.1".into()),
                    new_version: Some("1.3.2".into()),
                    old_license: Some("Zlib".into()),
                    new_license: Some("Zlib".into()),
                }],
                license_changed: vec![Change {
                    name: "libzlib".into(),
                    kind: "conda".into(),
                    old_version: Some("1.3.1".into()),
                    new_version: Some("1.3.1".into()),
                    old_license: Some("Zlib".into()),
                    new_license: Some("MIT".into()),
                }],
                unchanged: 1,
            },
        )
    }

    #[test]
    fn diff_table_snapshot() {
        let mut out = Vec::new();
        render_with_width(
            &[diffed()],
            ReportFormat::Table,
            DEFAULT_WIDTH,
            Palette::new(false),
            &mut out,
        )
        .unwrap();
        insta::assert_snapshot!(String::from_utf8(out).unwrap());
    }

    #[test]
    fn diff_markdown_snapshot() {
        let mut out = Vec::new();
        render_with_width(
            &[diffed()],
            ReportFormat::Markdown,
            DEFAULT_WIDTH,
            Palette::new(false),
            &mut out,
        )
        .unwrap();
        insta::assert_snapshot!(String::from_utf8(out).unwrap());
    }

    #[test]
    fn diff_csv_and_json() {
        let mut out = Vec::new();
        render_with_width(
            &[diffed()],
            ReportFormat::Csv,
            DEFAULT_WIDTH,
            Palette::new(false),
            &mut out,
        )
        .unwrap();
        let csv = String::from_utf8(out).unwrap();
        assert!(csv.starts_with("environment,platform,change,package,kind,before,after\n"));
        assert!(csv.contains("default,linux-64,version,zlib,conda,1.3.1,1.3.2\n"));
        assert!(csv.contains("default,linux-64,license,libzlib,conda,Zlib,MIT\n"));
        assert_eq!(csv.lines().count(), 5);

        let mut out = Vec::new();
        render_with_width(
            &[diffed()],
            ReportFormat::Json,
            DEFAULT_WIDTH,
            Palette::new(false),
            &mut out,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["report"], "diff");
        assert_eq!(value["against"], "old.cdx.json");
        assert_eq!(value["added"][0]["name"], "requests");
        assert_eq!(value["removed"][0]["name"], "mylib");
        assert_eq!(value["version_changed"][0]["new_version"], "1.3.2");
        assert_eq!(value["license_changed"][0]["new_license"], "MIT");
        assert_eq!(value["unchanged"], 1);
        assert!(value.get("packages").is_none());

        // Nothing changed reads as such.
        let mut same = diffed();
        same.diff = Some(crate::diff::Diff {
            against: "old.cdx.json".into(),
            against_format: "CycloneDX 1.6".into(),
            unchanged: 4,
            ..Default::default()
        });
        let mut out = Vec::new();
        render_with_width(
            &[same],
            ReportFormat::Table,
            DEFAULT_WIDTH,
            Palette::new(false),
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("No changes against old.cdx.json (CycloneDX 1.6); 4 packages unchanged"),
            "{text}"
        );
    }

    fn outdated_report() -> Report {
        use crate::outdated::{Status, Step};
        let sbom = sample_sbom();
        let status = |behind, step, published: &str, latest: &str| {
            Some(Status {
                current_published: Some(published.into()),
                latest: Some(latest.into()),
                latest_published: Some("2026-09-15T19:29:34Z".into()),
                behind,
                step,
            })
        };
        let statuses = vec![
            status(1, Step::Patch, "2024-01-01T00:00:00Z", "1.3.2"),
            status(12, Step::Major, "2021-03-15T00:00:00Z", "2.8.0"),
            None,
            status(0, Step::Patch, "2026-09-01T00:00:00Z", "1.17.0"),
        ];
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000);
        Report::outdated(&sbom, &statuses, now)
    }

    #[test]
    fn outdated_rows_sort_by_how_far_behind_and_summarise_by_step() {
        let report = outdated_report();
        let rows = report.outdated.as_ref().unwrap();
        assert_eq!(rows.len(), 3, "the source package has no row");
        assert_eq!(rows[0].name, "zlib", "furthest behind first");
        assert_eq!(rows[0].behind, 12);
        assert_eq!(rows[0].step, "major");
        assert!(rows[0].age_days.unwrap() > 1500);
        assert_eq!(rows[2].name, "six");
        assert_eq!(rows[2].behind, 0);
        let summary = report.outdated_summary.as_ref().unwrap();
        assert_eq!(summary.checked, 3);
        assert_eq!(summary.by_step, [("major".to_string(), 1), ("patch".to_string(), 1)]);
        assert_eq!(summary.unknown, ["mylib"]);
    }

    #[test]
    fn outdated_only_keeps_the_bigger_steps() {
        let mut report = outdated_report();
        report.keep_outdated(crate::cli::OutdatedOnly::Major);
        let names: Vec<&str> = report
            .outdated
            .as_ref()
            .unwrap()
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(names, ["zlib"]);

        let mut report = outdated_report();
        report.keep_outdated(crate::cli::OutdatedOnly::Patch);
        assert_eq!(report.outdated.as_ref().unwrap().len(), 2, "current packages drop out");
    }

    #[test]
    fn outdated_table_snapshot() {
        let mut out = Vec::new();
        render_with_width(
            &[outdated_report()],
            ReportFormat::Table,
            DEFAULT_WIDTH,
            Palette::new(false),
            &mut out,
        )
        .unwrap();
        insta::assert_snapshot!(String::from_utf8(out).unwrap());
    }

    #[test]
    fn outdated_csv_and_json() {
        let mut out = Vec::new();
        render_with_width(
            &[outdated_report()],
            ReportFormat::Csv,
            DEFAULT_WIDTH,
            Palette::new(false),
            &mut out,
        )
        .unwrap();
        let csv = String::from_utf8(out).unwrap();
        assert!(csv.starts_with(
            "environment,platform,package,kind,version,published,age_days,latest,latest_published,behind,step\n"
        ));
        assert!(csv.contains("default,linux-64,zlib,conda,1.3.1,2021-03-15T00:00:00Z,"));

        let mut out = Vec::new();
        render_with_width(
            &[outdated_report()],
            ReportFormat::Json,
            DEFAULT_WIDTH,
            Palette::new(false),
            &mut out,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(value["report"], "outdated");
        assert_eq!(value["outdated"][0]["name"], "zlib");
        assert_eq!(value["outdated"][0]["behind"], 12);
        assert_eq!(value["summary"]["unknown"][0], "mylib");
        assert!(value.get("packages").is_none());
    }

    #[test]
    fn vulnerabilities_json_has_rows_and_summary_and_no_packages() {
        let text = render_string(ReportKind::Vulnerabilities, ReportFormat::Json, &[vulnerable_sbom()]);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["report"], "vulnerabilities");
        assert!(value.get("packages").is_none());
        assert_eq!(value["vulnerabilities"].as_array().unwrap().len(), 3);
        assert_eq!(value["vulnerabilities"][0]["aliases"][0], "CVE-2021-33503");
        assert_eq!(value["summary"]["affected_packages"], 1);
        assert_eq!(value["summary"]["ignored"].as_array().unwrap().len(), 1);
        assert_eq!(value["vulnerabilities"][1]["ignored"], "false_positive");
        assert_eq!(value["summary"]["by_severity"][0][0], "high");

        // No findings at all still renders a summary.
        let text = render_string(ReportKind::Vulnerabilities, ReportFormat::Table, &[sample_sbom()]);
        assert!(text.contains("Summary: 0 findings in 0 packages"));
        assert!(text.contains("No queryable identity (2): libzlib, mylib"));
    }
}
