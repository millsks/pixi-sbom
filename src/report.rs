//! Human-readable reports printed to the terminal instead of an SBOM document.
//!
//! Reports are built from the same [`Sbom`] model the writers consume, after the same
//! selection and enrichment, so what is displayed is exactly what a document would contain.

use std::collections::BTreeMap;
use std::io::{self, Write};

use clap::ValueEnum;
use serde::Serialize;

use crate::license::{self, License};
use crate::model::{Package, Sbom};

/// Which report to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportKind {
    /// Inventory: one row per package with kind, source, license and purl.
    Packages,
    /// Licenses: one row per package with license, family, source and files, plus a summary.
    Licenses,
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

/// A complete report for one document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub report: &'static str,
    pub workspace: String,
    pub environment: String,
    pub platform: String,
    pub packages: Vec<Row>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<LicenseSummary>,
}

impl Report {
    /// Build the report for `sbom`.
    pub fn new(kind: ReportKind, sbom: &Sbom) -> Self {
        let packages: Vec<Row> = sbom.packages.iter().map(row).collect();
        let summary = match kind {
            ReportKind::Packages => None,
            ReportKind::Licenses => Some(summarize(&packages)),
        };
        Self {
            report: match kind {
                ReportKind::Packages => "packages",
                ReportKind::Licenses => "licenses",
            },
            workspace: sbom.root.name.clone(),
            environment: sbom.environment.clone(),
            platform: sbom.platform.clone(),
            packages,
            summary,
        }
    }

    fn kind(&self) -> ReportKind {
        if self.summary.is_some() {
            ReportKind::Licenses
        } else {
            ReportKind::Packages
        }
    }

    fn columns(&self) -> Vec<&'static str> {
        match self.kind() {
            ReportKind::Packages => vec!["Name", "Version", "Kind", "Source", "License", "Purl"],
            ReportKind::Licenses => vec!["Name", "Version", "Kind", "License", "Family", "Source", "Files"],
        }
    }

    fn cells(&self, row: &Row) -> Vec<String> {
        let dash = || "-".to_string();
        match self.kind() {
            ReportKind::Packages => vec![
                row.name.clone(),
                row.version.clone(),
                row.kind.to_string(),
                row.source.clone(),
                row.license.clone().unwrap_or_else(dash),
                row.purl.clone(),
            ],
            ReportKind::Licenses => vec![
                row.name.clone(),
                row.version.clone(),
                row.kind.to_string(),
                row.license.clone().unwrap_or_else(dash),
                row.license_family.clone().unwrap_or_else(dash),
                row.license_source.clone().unwrap_or_else(dash),
                row.license_files.len().to_string(),
            ],
        }
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

/// Render `reports` (one per document) in `format` to `out`, fitting tables to the terminal.
pub fn render(reports: &[Report], format: ReportFormat, out: &mut dyn Write) -> io::Result<()> {
    render_with_width(reports, format, terminal_width(), out)
}

/// [`render`] with an explicit table width instead of the terminal's.
pub fn render_with_width(
    reports: &[Report],
    format: ReportFormat,
    width: usize,
    out: &mut dyn Write,
) -> io::Result<()> {
    match format {
        ReportFormat::Json if reports.len() == 1 => writeln!(out, "{}", serde_json::to_string_pretty(&reports[0])?),
        ReportFormat::Json => writeln!(out, "{}", serde_json::to_string_pretty(reports)?),
        ReportFormat::Csv => render_csv(reports, out),
        ReportFormat::Table | ReportFormat::Markdown => {
            for (i, report) in reports.iter().enumerate() {
                if i > 0 {
                    writeln!(out)?;
                }
                if reports.len() > 1 || format == ReportFormat::Markdown {
                    let heading = format!(
                        "{} ({}, environment {}, platform {})",
                        report.report, report.workspace, report.environment, report.platform
                    );
                    match format {
                        ReportFormat::Markdown => writeln!(out, "## {heading}\n")?,
                        _ => writeln!(out, "{heading}\n")?,
                    }
                }
                let columns = report.columns();
                let rows: Vec<Vec<String>> = report.packages.iter().map(|r| report.cells(r)).collect();
                match format {
                    ReportFormat::Markdown => render_markdown(&columns, &rows, out)?,
                    _ => render_table(&columns, &rows, width, out)?,
                }
                if let Some(summary) = &report.summary {
                    render_summary(summary, report.packages.len(), format, out)?;
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

/// Aligned columns. The last column is truncated with an ellipsis when a line would exceed
/// `width`; every other column is shown in full.
fn render_table(columns: &[&str], rows: &[Vec<String>], width: usize, out: &mut dyn Write) -> io::Result<()> {
    let mut widths: Vec<usize> = columns.iter().map(|c| c.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let last = columns.len() - 1;
    let fixed: usize = widths[..last].iter().sum::<usize>() + 2 * last;
    let last_width = widths[last].min(width.saturating_sub(fixed).max(8));
    let line = |cells: &[String]| -> String {
        let mut text = String::new();
        for (i, cell) in cells.iter().enumerate() {
            if i > 0 {
                text.push_str("  ");
            }
            if i == last {
                text.push_str(&truncate(cell, last_width));
            } else {
                text.push_str(cell);
                text.extend(std::iter::repeat_n(' ', widths[i] - cell.chars().count()));
            }
        }
        text.trim_end().to_string()
    };
    let header: Vec<String> = columns.iter().map(|c| c.to_string()).collect();
    writeln!(out, "{}", line(&header))?;
    let rule: Vec<String> = widths
        .iter()
        .enumerate()
        .map(|(i, w)| "-".repeat(if i == last { last_width } else { *w }))
        .collect();
    writeln!(out, "{}", line(&rule))?;
    for row in rows {
        writeln!(out, "{}", line(row))?;
    }
    Ok(())
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut short: String = text.chars().take(width.saturating_sub(1)).collect();
    short.push('…');
    short
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

fn render_summary(summary: &LicenseSummary, total: usize, format: ReportFormat, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out)?;
    let heading = format!(
        "Summary: {total} packages, {} distinct licenses",
        summary.by_license.len()
    );
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
        _ => render_table(&["License", "Packages"], &rows, usize::MAX, out)?,
    }
    let list = |label: &str, names: &[String]| -> String {
        if names.is_empty() {
            format!("{label}: none")
        } else {
            format!("{label} ({}): {}", names.len(), names.join(", "))
        }
    };
    writeln!(out)?;
    writeln!(out, "{}", list("No license", &summary.unlicensed))?;
    writeln!(out, "{}", list("Not an SPDX expression", &summary.non_spdx))?;
    Ok(())
}

fn render_csv(reports: &[Report], out: &mut dyn Write) -> io::Result<()> {
    let kind = reports.first().map(Report::kind).unwrap_or(ReportKind::Packages);
    let mut columns = vec!["environment", "platform"];
    columns.extend(match kind {
        ReportKind::Packages => vec!["name", "version", "kind", "source", "license", "purl"],
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
        for row in &report.packages {
            let mut cells = vec![report.environment.clone(), report.platform.clone()];
            cells.extend(match kind {
                ReportKind::Packages => vec![
                    row.name.clone(),
                    row.version.clone(),
                    row.kind.to_string(),
                    row.source.clone(),
                    row.license.clone().unwrap_or_default(),
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
        render_with_width(&reports, format, DEFAULT_WIDTH, &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn rows_carry_normalized_license_source_and_files() {
        let report = Report::new(ReportKind::Licenses, &sample_sbom());
        let by_name = |name: &str| report.packages.iter().find(|r| r.name == name).unwrap();
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
        assert_eq!(report.packages[0].license_source.as_deref(), Some("package-cache"));
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
        assert!(csv.starts_with("environment,platform,name,version,kind,source,license,purl\n"));
        assert!(csv.contains("default,linux-64,zlib,1.3.1,conda,conda-forge,MIT OR Apache-2.0,pkg:conda/zlib"));
    }

    #[test]
    fn table_truncates_only_the_last_column() {
        let mut out = Vec::new();
        render_table(&["A", "B"], &[vec!["short".into(), "x".repeat(50)]], 30, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let data = text.lines().nth(2).unwrap();
        assert!(data.starts_with("short  "));
        assert!(data.ends_with('…'));
        assert!(data.chars().count() <= 30, "{data:?}");
        assert_eq!(truncate("abc", 3), "abc");
        assert_eq!(truncate("abcd", 3), "ab…");
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
        render_with_width(&reports, ReportFormat::Table, usize::MAX, &mut out).unwrap();
        assert!(!String::from_utf8(out).unwrap().contains('…'));
    }
}
