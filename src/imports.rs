//! Which top-level modules the workspace's own Python sources import, found by reading the
//! files rather than by running or fully parsing them.
//!
//! An import statement is the one Python construct that is unambiguous line by line, so a
//! tokenizer over the lines is enough and costs no dependency: `import a.b`, `from a.b import
//! c`, aliases, parenthesized lists and continuations all put the module on the line the
//! statement starts on. Docstrings are tracked so a code sample inside one is not mistaken
//! for code, and relative imports (`from . import x`) name nothing outside the workspace.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Directories that never hold the workspace's own sources: environments, build output,
/// caches, and anything hidden.
const SKIPPED_DIRS: &[&str] = &[
    "site-packages",
    "build",
    "dist",
    "node_modules",
    "__pycache__",
    "target",
    "venv",
];

/// What a scan of the sources found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Imports {
    /// Top-level module name to the files that import it, relative to the scan root and
    /// sorted.
    pub by_module: BTreeMap<String, Vec<String>>,
    /// Modules the workspace itself provides: a top-level package or module in its own
    /// sources, which no distribution has to supply.
    pub local: BTreeSet<String>,
    /// How many Python files were read.
    pub files: usize,
}

/// Read every `.py` file under `roots` and collect what it imports. Unreadable files are
/// logged and skipped: a source tree is not required to be complete for an SBOM to be useful.
pub fn scan(roots: &[PathBuf]) -> Imports {
    let mut imports = Imports::default();
    for root in roots {
        walk(root, root, false, &mut imports);
    }
    imports
}

/// Walk one directory. `inside_package` says whether the directory itself is part of a
/// package, which decides whether what it holds is top level.
fn walk(root: &Path, dir: &Path, inside_package: bool, imports: &mut Imports) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            tracing::debug!(path = %dir.display(), %err, "cannot read directory; skipped");
            return;
        }
    };
    let mut children = Vec::new();
    for entry in entries.flatten() {
        children.push(entry.path());
    }
    children.sort();
    for path in children {
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if path.is_dir() {
            if name.starts_with('.') || SKIPPED_DIRS.contains(&name.as_str()) {
                continue;
            }
            let is_package = path.join("__init__.py").is_file();
            if is_package && !inside_package && is_identifier(&name) {
                imports.local.insert(name);
            }
            walk(root, &path, is_package, imports);
        } else if path.extension().is_some_and(|e| e == "py") {
            if !inside_package
                && let Some(stem) = path.file_stem().map(|s| s.to_string_lossy().into_owned())
                && is_identifier(&stem)
            {
                imports.local.insert(stem);
            }
            read_file(root, &path, imports);
        }
    }
}

fn read_file(root: &Path, path: &Path, imports: &mut Imports) {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            tracing::debug!(path = %path.display(), %err, "cannot read source file; skipped");
            return;
        }
    };
    imports.files += 1;
    let shown = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    for module in modules_of(&text) {
        let files = imports.by_module.entry(module).or_default();
        if !files.contains(&shown) {
            files.push(shown.clone());
        }
    }
}

/// The top-level modules one source file imports, in the order they appear, deduplicated.
pub fn modules_of(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut in_docstring: Option<&str> = None;
    let mut pending = String::new();
    for raw in source.lines() {
        // A statement continued with a backslash puts the rest on the next line.
        let line = if pending.is_empty() {
            raw.to_string()
        } else {
            std::mem::take(&mut pending) + raw.trim_start()
        };
        if let Some(delimiter) = in_docstring {
            if line.contains(delimiter) {
                in_docstring = None;
            }
            continue;
        }
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some(delimiter) = opens_docstring(trimmed) {
            in_docstring = Some(delimiter);
            continue;
        }
        if let Some(rest) = line.strip_suffix('\\') {
            pending = rest.to_string();
            continue;
        }
        for module in statement_modules(trimmed) {
            if !found.contains(&module) {
                found.push(module);
            }
        }
    }
    found
}

/// The delimiter of a triple-quoted string this line opens and does not close.
fn opens_docstring(line: &str) -> Option<&'static str> {
    for delimiter in ["\"\"\"", "'''"] {
        if let Some(rest) = line.find(delimiter).map(|at| &line[at + 3..])
            && !rest.contains(delimiter)
        {
            return Some(delimiter);
        }
    }
    None
}

/// The modules one `import` / `from ... import ...` statement names.
fn statement_modules(line: &str) -> Vec<String> {
    if let Some(rest) = line.strip_prefix("from ") {
        let module = rest.split_whitespace().next().unwrap_or_default();
        // `from . import x` and `from .pkg import y` stay inside the workspace.
        return top_level(module).into_iter().collect();
    }
    let Some(rest) = line.strip_prefix("import ") else {
        return Vec::new();
    };
    rest.split(',')
        .map(|part| part.split_whitespace().next().unwrap_or_default())
        .filter_map(top_level)
        .collect()
}

/// The first segment of a dotted module path, when it is a name a distribution could provide.
fn top_level(module: &str) -> Option<String> {
    let first = module.trim().split('.').next().unwrap_or_default();
    is_identifier(first).then(|| first.to_string())
}

fn is_identifier(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shape_of_import_statement() {
        let source = concat!(
            "\"\"\"Module docstring.\n",
            "\n",
            "    import notcode\n",
            "\"\"\"\n",
            "from __future__ import annotations\n",
            "import os\n",
            "import os.path\n",
            "import numpy as np, pandas\n",
            "from requests.adapters import HTTPAdapter\n",
            "from . import sibling\n",
            "from .relative import thing\n",
            "# import commented\n",
            "import \\\n",
            "    yaml\n",
            "if TYPE_CHECKING:\n",
            "    import attrs\n",
            "from typing import (\n",
            "    Any,\n",
            ")\n",
            "import 9lives\n",
        );
        assert_eq!(
            modules_of(source),
            [
                "__future__",
                "os",
                "numpy",
                "pandas",
                "requests",
                "yaml",
                "attrs",
                "typing"
            ]
        );
    }

    #[test]
    fn a_docstring_that_closes_on_its_own_line_is_not_a_docstring() {
        let source = "x = \"\"\"one line\"\"\"\nimport six\n";
        assert_eq!(modules_of(source), ["six"]);
    }

    #[test]
    fn scanning_finds_local_packages_and_skips_environments() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let write = |path: &str, text: &str| {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("src/mypkg/__init__.py", "import requests\n");
        write("src/mypkg/inner/__init__.py", "");
        write("src/mypkg/inner/deep.py", "import mypkg\nimport requests\n");
        write("conftest.py", "import pytest\n");
        write(".pixi/envs/default/lib/x.py", "import shouldnotbeseen\n");
        write("build/generated.py", "import alsonot\n");
        write("docs/notes.md", "import notpython\n");

        let scanned = scan(std::slice::from_ref(&root.to_path_buf()));
        assert_eq!(scanned.files, 4, "{scanned:?}");
        assert_eq!(scanned.local, ["conftest".to_string(), "mypkg".to_string()].into());
        assert_eq!(
            scanned.by_module.keys().collect::<Vec<_>>(),
            ["mypkg", "pytest", "requests"]
        );
        // The importing files are recorded relative to the root, deduplicated.
        assert_eq!(
            scanned.by_module["requests"],
            ["src/mypkg/__init__.py", "src/mypkg/inner/deep.py"]
        );
    }
}
