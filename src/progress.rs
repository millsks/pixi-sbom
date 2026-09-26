//! Progress bars for the enrichment fetches, which otherwise leave the terminal silent for
//! seconds over a hundred packages.
//!
//! Bars are drawn on stderr and only when it is a terminal, the run is not quiet and the log
//! level would not overwrite them anyway. Everything else (CI logs, pipes, `-q`, `-v`) sees
//! exactly what it saw before: nothing.

use std::io::IsTerminal;
use std::sync::OnceLock;
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};

/// The one place bars are drawn, so a log line written through [`suspend`] can hide every bar
/// that happens to be live rather than only the one it knows about.
static BARS: OnceLock<MultiProgress> = OnceLock::new();

fn bars() -> &'static MultiProgress {
    BARS.get_or_init(MultiProgress::new)
}

/// Run `f` with every live bar hidden, so its output lands on a clean line. Cheap and correct
/// when no bar is drawing.
pub fn suspend<T>(f: impl FnOnce() -> T) -> T {
    match BARS.get() {
        Some(bars) => bars.suspend(f),
        None => f(),
    }
}

/// Whether bars are drawn at all, decided once per run.
#[derive(Debug, Clone, Copy, Default)]
pub struct Progress {
    enabled: bool,
}

/// How often the bar is redrawn; often enough to feel live, rarely enough to be cheap.
const TICK: Duration = Duration::from_millis(100);

impl Progress {
    /// Decide from the environment: a terminal on stderr, not quiet, no debug logging to tear
    /// the bars apart, and not a structured log, which nothing human is reading.
    pub fn resolve(verbose: bool, quiet: bool, structured_log: bool) -> Self {
        Self::resolve_with(
            std::io::stderr().is_terminal(),
            verbose,
            quiet,
            structured_log,
            |name| std::env::var_os(name).map(|v| v.to_string_lossy().into_owned()),
        )
    }

    fn resolve_with(
        is_terminal: bool,
        verbose: bool,
        quiet: bool,
        structured_log: bool,
        env: impl Fn(&str) -> Option<String>,
    ) -> Self {
        let forbidden = env("TERM").is_some_and(|v| v == "dumb")
            || env("CI").is_some_and(|v| !v.is_empty() && v != "0" && v != "false")
            || env("PIXI_SBOM_NO_PROGRESS").is_some_and(|v| !v.is_empty() && v != "0");
        Self {
            enabled: is_terminal && !verbose && !quiet && !structured_log && !forbidden,
        }
    }

    /// A progress bar counting `total` items, labelled with their plural noun (`"packages"`,
    /// `"advisories"`), or a hidden one when progress is off.
    pub fn bar(&self, what: &str, total: usize) -> Bar {
        if !self.enabled || total == 0 {
            return Bar {
                bar: ProgressBar::hidden(),
            };
        }
        let bar = bars().add(ProgressBar::with_draw_target(
            Some(total as u64),
            ProgressDrawTarget::stderr(),
        ));
        bar.set_style(
            ProgressStyle::with_template(&format!("{{spinner}} {what} {{pos}}/{{len}} {{wide_msg}} {{elapsed}}"))
                .expect("a valid template")
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ "),
        );
        bar.enable_steady_tick(TICK);
        Bar { bar }
    }
}

/// One progress bar. Dropping it clears the line.
pub struct Bar {
    bar: ProgressBar,
}

impl Bar {
    /// Count one finished item, naming what is being worked on next.
    pub fn advance(&self, message: &str) {
        self.bar.set_message(message.to_string());
        self.bar.inc(1);
    }

    /// Take the bar off the terminal, leaving the line clean for the log line that follows.
    pub fn finish(self) {
        self.bar.finish_and_clear();
        bars().remove(&self.bar);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| (*v).to_string())
    }

    #[test]
    fn progress_is_for_interactive_runs_only() {
        let none = env_of(&[]);
        assert!(Progress::resolve_with(true, false, false, false, &none).enabled);
        assert!(
            !Progress::resolve_with(false, false, false, false, &none).enabled,
            "a pipe"
        );
        assert!(
            !Progress::resolve_with(true, true, false, false, &none).enabled,
            "-v tears bars"
        );
        assert!(
            !Progress::resolve_with(true, false, true, false, &none).enabled,
            "-q asked for quiet"
        );
        assert!(!Progress::resolve_with(true, false, false, false, env_of(&[("TERM", "dumb")])).enabled);
        assert!(!Progress::resolve_with(true, false, false, false, env_of(&[("CI", "true")])).enabled);
        assert!(Progress::resolve_with(true, false, false, false, env_of(&[("CI", "")])).enabled);
        assert!(!Progress::resolve_with(true, false, false, false, env_of(&[("PIXI_SBOM_NO_PROGRESS", "1")])).enabled);
        assert!(
            !Progress::resolve_with(true, false, false, true, &none).enabled,
            "--log-format json: nothing reading the output is watching a bar"
        );
    }

    #[test]
    fn suspending_without_any_bar_just_runs_the_work() {
        assert_eq!(suspend(|| 7), 7);
    }

    #[test]
    fn a_hidden_bar_counts_without_drawing() {
        let off = Progress::default();
        let bar = off.bar("packages", 3);
        bar.advance("one");
        bar.advance("two");
        bar.finish();

        // Zero items never draws, even when progress is on.
        let on = Progress { enabled: true };
        let empty = on.bar("packages", 0);
        empty.advance("nothing");
        empty.finish();
    }
}
