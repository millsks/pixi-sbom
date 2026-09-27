"""MkDocs hooks: publish repository root Markdown files as site pages.

CHANGELOG.md and SECURITY.md have to live at the repository root — GitHub looks for them there,
and the "Report a vulnerability" button depends on it. They are also pages the site should carry,
so they are added to the build from where they are rather than copied into docs/ and left to drift.
"""

from pathlib import Path

from mkdocs.structure.files import File, Files

ROOT = Path(__file__).parent

# Repository file -> the page it becomes on the site.
PAGES = {
    "CHANGELOG.md": "changelog.md",
    "SECURITY.md": "security.md",
}


def on_files(files: Files, config) -> Files:
    """Add the repository's root Markdown pages to the site without copying them into docs/."""
    for source, page in PAGES.items():
        content = (ROOT / source).read_text(encoding="utf-8")
        files.append(File.generated(config, page, content=content))
    return files
