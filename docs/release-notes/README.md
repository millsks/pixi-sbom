# Release note preambles

One optional file per release, named for its tag: `v1.0.0.md`. When `release-artifacts.yml` finds
`docs/release-notes/<tag>.md` it puts that text at the top of the GitHub release, above the section
git-cliff generates from the commit log.

It exists because git-cliff rewrites `CHANGELOG.md` wholesale from the commits on every release, so
there is nowhere in that file a hand-written paragraph survives. Most releases need nothing here —
the commit list *is* the story. A release where it is not, like 1.0.0, gets a file.

These are excluded from the documentation site (`exclude_docs` in `mkdocs.yml`): they are release
copy, and the site already carries the changelog.

The account of every release that *is* on the site, in prose, is [What's new](../whats-new.md). A
preamble here is for the GitHub release page; it is not a substitute for that section.
