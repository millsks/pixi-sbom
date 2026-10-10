"""Turn the What's new page's `## Unreleased` section into a release's section.

The release workflow runs `check` before it tags anything and `release` when it writes the
changelog, so the notes land in the same commit as the version. Release candidates are skipped:
only a final release gets a section.

    pixi run whats-new check 1.9.0
    pixi run whats-new release 1.9.0
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "docs" / "whats-new.md"
UNRELEASED = "## Unreleased"
RELEASE = re.compile(r"^## \d+\.\d+\.\d+\s*$")


class WhatsNewError(Exception):
    """The page is not ready to be released."""


def is_candidate(version: str) -> bool:
    """Return whether the version is a pre-release, which gets no section of its own."""
    return "-" in version


def check(text: str, version: str) -> None:
    """Raise WhatsNewError unless the page has one non-empty Unreleased section above every release."""
    lines = text.splitlines()
    if any(line.strip() == f"## {version}" for line in lines):
        raise WhatsNewError(f"docs/whats-new.md already has a section for {version}")
    headings = [i for i, line in enumerate(lines) if line.rstrip() == UNRELEASED]
    if not headings:
        raise WhatsNewError(
            f"docs/whats-new.md has no '{UNRELEASED}' section: write what {version} means for someone "
            "using the tool there before releasing it"
        )
    if len(headings) > 1:
        raise WhatsNewError(f"docs/whats-new.md has {len(headings)} '{UNRELEASED}' sections")
    start = headings[0]
    first_release = next((i for i, line in enumerate(lines) if RELEASE.match(line)), len(lines))
    if start > first_release:
        raise WhatsNewError(f"'{UNRELEASED}' in docs/whats-new.md is below a release's section")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    if not any(line.strip() for line in lines[start + 1 : end]):
        raise WhatsNewError(f"'{UNRELEASED}' in docs/whats-new.md is empty")


def release(text: str, version: str) -> str:
    """Return the page with its Unreleased section renamed to the version."""
    check(text, version)
    return "\n".join(f"## {version}" if line.rstrip() == UNRELEASED else line for line in text.split("\n"))


def main(argv: list[str] | None = None) -> int:
    """Run the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=["check", "release"])
    parser.add_argument("version")
    parser.add_argument("--page", type=Path, default=PAGE)
    args = parser.parse_args(argv)
    if is_candidate(args.version):
        sys.stderr.write(f"{args.version} is a pre-release: docs/whats-new.md is left as it is\n")
        return 0
    text = args.page.read_text(encoding="utf-8")
    try:
        if args.command == "check":
            check(text, args.version)
        else:
            args.page.write_text(release(text, args.version), encoding="utf-8")
    except WhatsNewError as error:
        sys.stderr.write(f"error: {error}\n")
        return 1
    done = "is ready to become" if args.command == "check" else "is now"
    sys.stderr.write(f"docs/whats-new.md: '{UNRELEASED}' {done} '## {args.version}'\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
