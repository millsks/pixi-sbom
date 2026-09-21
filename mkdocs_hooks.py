"""MkDocs hooks: publish the repository CHANGELOG.md as the site's changelog page."""

from pathlib import Path

from mkdocs.structure.files import File, Files

CHANGELOG = Path(__file__).parent / "CHANGELOG.md"


def on_files(files: Files, config) -> Files:
    """Add CHANGELOG.md to the site as `changelog.md` without copying it into docs/."""
    content = CHANGELOG.read_text(encoding="utf-8")
    files.append(File.generated(config, "changelog.md", content=content))
    return files
