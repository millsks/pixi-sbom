//! Colour for the terminal reports: whether to use it, and which style a cell gets.
//!
//! Colour is applied only to the `table` format; markdown, CSV, JSON and SARIF are data and
//! stay plain. `--color auto` (the default) follows the usual rules: `NO_COLOR` off,
//! `CLICOLOR_FORCE` on, otherwise only when stdout is a terminal.

use std::io::IsTerminal;

use anstyle::{AnsiColor, Style};
use clap::ValueEnum;
use comfy_table::{Attribute, Cell, Color};

/// When to colour the output.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum ColorChoice {
    /// Colour when stdout is a terminal and the environment does not forbid it.
    #[default]
    Auto,
    /// Always colour, even when redirected (useful for `less -R` and CI logs).
    Always,
    /// Never colour.
    Never,
}

impl ColorChoice {
    /// Resolve the choice against the environment and the output stream.
    pub fn enabled(self) -> bool {
        self.enabled_with(
            |name| std::env::var_os(name).map(|v| v.to_string_lossy().into_owned()),
            std::io::stdout().is_terminal(),
        )
    }

    fn enabled_with(self, env: impl Fn(&str) -> Option<String>, is_terminal: bool) -> bool {
        match self {
            ColorChoice::Never => false,
            ColorChoice::Always => true,
            ColorChoice::Auto => {
                // https://no-color.org and https://bixense.com/clicolors: any non-empty value
                // of NO_COLOR forbids colour, CLICOLOR_FORCE overrides the terminal check.
                if env("NO_COLOR").is_some_and(|v| !v.is_empty()) {
                    return false;
                }
                if env("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0") {
                    return true;
                }
                if env("TERM").is_some_and(|v| v == "dumb") {
                    return false;
                }
                is_terminal
            }
        }
    }
}

/// The styles the reports use, or all-plain when colour is off.
///
/// Table cells are styled through comfy-table (it measures the unstyled text, so wrapping
/// stays correct); the plain lines around the tables are styled with `anstyle`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Palette {
    enabled: bool,
}

/// What a cell means, which decides how it is painted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A column header.
    Header,
    /// A `-` placeholder or anything that needs no attention.
    Muted,
    /// A vulnerability severity word.
    Severity,
    /// A finding's status (`open`, `ignored`) or a KEV marker (`yes`, `ransomware`).
    Status,
    /// A diff change kind (`added`, `removed`, `version`, `license`).
    Change,
    /// A license expression that is not valid SPDX.
    NonSpdx,
    /// Anything else.
    Plain,
}

impl Palette {
    /// A palette that colours, or not.
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Whether this palette colours at all.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Wrap `text` in `style`, or leave it alone when colour is off. For the plain lines
    /// around the tables.
    pub fn paint(&self, style: Style, text: &str) -> String {
        if !self.enabled || text.is_empty() {
            return text.to_string();
        }
        format!("{style}{text}{style:#}")
    }

    /// Bold, for headings and totals.
    pub fn header(&self, text: &str) -> String {
        self.paint(Style::new().bold(), text)
    }

    /// Dim, for things that need no attention.
    pub fn dim(&self, text: &str) -> String {
        self.paint(Style::new().dimmed(), text)
    }

    /// A severity word on a plain line.
    pub fn severity(&self, severity: &str) -> String {
        self.paint(anstyle_for(Role::Severity, severity), severity)
    }

    /// The comfy-table cell for `text` in `role`.
    pub fn cell(&self, role: Role, text: &str) -> Cell {
        let cell = Cell::new(text);
        if !self.enabled || text.is_empty() {
            return cell;
        }
        let (color, attributes) = table_style_for(role, text);
        let cell = match color {
            Some(color) => cell.fg(color),
            None => cell,
        };
        attributes
            .into_iter()
            .fold(cell, |cell, attribute| cell.add_attribute(attribute))
    }
}

/// The comfy-table colour and attributes of a cell.
fn table_style_for(role: Role, text: &str) -> (Option<Color>, Vec<Attribute>) {
    match role {
        Role::Header => (None, vec![Attribute::Bold]),
        Role::Muted => (None, vec![Attribute::Dim]),
        Role::NonSpdx => (Some(Color::Yellow), vec![]),
        Role::Severity => match text {
            "critical" => (Some(Color::Red), vec![Attribute::Bold]),
            "high" => (Some(Color::Red), vec![]),
            "medium" => (Some(Color::Yellow), vec![]),
            "low" => (Some(Color::Blue), vec![]),
            "none" | "unknown" => (None, vec![Attribute::Dim]),
            _ => (None, vec![]),
        },
        Role::Status => match text {
            _ if text.starts_with("yes: ") => (Some(Color::Red), vec![]),
            "open" => (Some(Color::Yellow), vec![]),
            "ignored" => (None, vec![Attribute::Dim]),
            "yes" => (Some(Color::Red), vec![]),
            "ransomware" => (Some(Color::Red), vec![Attribute::Bold]),
            _ => (None, vec![]),
        },
        Role::Change => match text {
            "added" => (Some(Color::Green), vec![]),
            "removed" => (Some(Color::Red), vec![]),
            "version" => (Some(Color::Cyan), vec![]),
            "license" => (Some(Color::Magenta), vec![]),
            _ => (None, vec![]),
        },
        Role::Plain => (None, vec![]),
    }
}

/// The same decisions as [`table_style_for`], for text outside a table.
fn anstyle_for(role: Role, text: &str) -> Style {
    let (color, attributes) = table_style_for(role, text);
    let mut style = match color {
        Some(Color::Red) => Style::new().fg_color(Some(AnsiColor::Red.into())),
        Some(Color::Yellow) => Style::new().fg_color(Some(AnsiColor::Yellow.into())),
        Some(Color::Blue) => Style::new().fg_color(Some(AnsiColor::Blue.into())),
        Some(Color::Green) => Style::new().fg_color(Some(AnsiColor::Green.into())),
        Some(Color::Cyan) => Style::new().fg_color(Some(AnsiColor::Cyan.into())),
        Some(Color::Magenta) => Style::new().fg_color(Some(AnsiColor::Magenta.into())),
        _ => Style::new(),
    };
    for attribute in attributes {
        style = match attribute {
            Attribute::Bold => style.bold(),
            Attribute::Dim => style.dimmed(),
            _ => style,
        };
    }
    style
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| (*v).to_string())
    }

    #[test]
    fn auto_follows_the_terminal_and_the_environment() {
        let none = env_of(&[]);
        assert!(ColorChoice::Auto.enabled_with(&none, true));
        assert!(!ColorChoice::Auto.enabled_with(&none, false));
        assert!(!ColorChoice::Auto.enabled_with(env_of(&[("NO_COLOR", "1")]), true));
        // An empty NO_COLOR does not count, per the spec.
        assert!(ColorChoice::Auto.enabled_with(env_of(&[("NO_COLOR", "")]), true));
        assert!(ColorChoice::Auto.enabled_with(env_of(&[("CLICOLOR_FORCE", "1")]), false));
        assert!(!ColorChoice::Auto.enabled_with(env_of(&[("CLICOLOR_FORCE", "0")]), false));
        assert!(!ColorChoice::Auto.enabled_with(env_of(&[("TERM", "dumb")]), true));
        // NO_COLOR wins over CLICOLOR_FORCE.
        assert!(!ColorChoice::Auto.enabled_with(env_of(&[("NO_COLOR", "1"), ("CLICOLOR_FORCE", "1")]), true));
    }

    #[test]
    fn always_and_never_ignore_everything_else() {
        let forbidding = env_of(&[("NO_COLOR", "1"), ("TERM", "dumb")]);
        assert!(ColorChoice::Always.enabled_with(&forbidding, false));
        assert!(!ColorChoice::Never.enabled_with(env_of(&[("CLICOLOR_FORCE", "1")]), true));
    }

    /// Render one styled cell the way the reports do, so the assertions see what a terminal
    /// would: comfy-table owns the table styling and measures the unstyled content.
    fn rendered(palette: &Palette, role: Role, text: &str) -> String {
        let mut table = comfy_table::Table::new();
        if palette.is_enabled() {
            table.enforce_styling();
        } else {
            table.force_no_tty();
        }
        table.add_row(comfy_table::Row::from(vec![palette.cell(role, text)]));
        table.to_string()
    }

    #[test]
    fn a_plain_palette_returns_the_text_unchanged() {
        let plain = Palette::new(false);
        assert_eq!(plain.severity("critical"), "critical");
        assert_eq!(plain.dim("-"), "-");
        assert_eq!(plain.header("Name"), "Name");
        assert!(!plain.is_enabled());
        let table = rendered(&plain, Role::Severity, "critical");
        assert!(!table.contains('\u{1b}'), "{table:?}");
        assert!(table.contains("critical"));
    }

    #[test]
    fn a_colouring_palette_wraps_plain_text_and_styles_cells() {
        let colour = Palette::new(true);
        // Plain lines around the tables are painted with anstyle.
        let critical = colour.severity("critical");
        assert!(critical.starts_with('\u{1b}'), "{critical:?}");
        assert!(critical.ends_with("\u{1b}[0m"), "{critical:?}");
        assert!(critical.contains("critical"));
        assert_ne!(colour.severity("critical"), colour.severity("low"));
        assert_eq!(colour.severity(""), "", "empty text is never painted");

        // Table cells carry the styling comfy-table emits, and differ by meaning.
        let critical = rendered(&colour, Role::Severity, "critical");
        assert!(critical.contains('\u{1b}'), "{critical:?}");
        assert!(critical.contains("critical"), "the text is intact: {critical:?}");
        assert_ne!(critical, rendered(&colour, Role::Severity, "low"));
        assert_ne!(
            rendered(&colour, Role::Change, "added"),
            rendered(&colour, Role::Change, "removed")
        );
        // Red for a high severity, and the same red for a removal.
        assert!(rendered(&colour, Role::Severity, "high").contains("\u{1b}[38;5;9m"));
        assert!(rendered(&colour, Role::Status, "open").contains("\u{1b}[38;5;11m"));
        // Unknown severities and placeholders are dim, not coloured.
        assert!(rendered(&colour, Role::Severity, "unknown").contains("\u{1b}[2m"));
        assert!(rendered(&colour, Role::Muted, "-").contains("\u{1b}[2m"));
        // An empty cell gets no styling at all, so widths stay predictable.
        assert!(!rendered(&colour, Role::Severity, "").contains('\u{1b}'));
    }
}
