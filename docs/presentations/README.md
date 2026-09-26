# Presentations

Two decks making the case for pixi-sbom, to two different rooms. The slide sources live here so the numbers in
them can be corrected when the numbers change, which they will.

| Deck | Audience | Slides |
|---|---|---|
| `engineering-management/` | Engineering management, plus people who already know what an SBOM is | 12 |
| `executive/` | C-suite: the decision, what it costs, what happens if it is wrong | 9 |

They are not two versions of one deck. The engineering deck argues from capability — what the tool does, what it
refuses to claim, what a team gets. The executive deck argues from consequence — what we cannot answer today, what
that costs, and what the downside of saying yes is. Slides that matter to one room are absent from the other on
purpose.

## Fill these in before presenting

Both decks carry bracketed placeholders. An audience reads a placeholder as a case that was not finished.

**Engineering management:** `[Presenter]`, `[Date]`.

**Executive:** `[Presenter]`, `[date]` (twice), `[name]` of whoever maintains this, `[$___]` for the loaded cost of
two weeks of part-time engineering, and three `[__]` figures on the cost slide — engineer-days a quarter spent on
security questionnaires, deals delayed by a compliance review, and hours to answer "are we exposed?" the last time
it came up. The deal desk has the first two; whoever ran the last incident has the third.

Both decks also carry a note to **check the current regulatory timelines** before presenting. Do that, then delete
the note. The US and EU positions are summarized from memory of the public instruments, and deadlines have moved
before.

## Where the numbers come from

Every figure on a slide that is not a placeholder traces to something in this repository:

| Claim | Source |
|---|---|
| 7.6 MB binary, five platforms | the 0.10.1 release |
| Under a second per build, 72-package environment | [benchmarks.md](../benchmarks.md) |
| Exit codes 3, 4, 6, 8 | [cli.md](../cli.md#exit-codes-and-errors) |
| CycloneDX 1.6/1.7, SPDX 2.3/3.0.1 | [output-format.md](../output-format.md) |

If a number here stops matching its source, the slide is wrong, not the source.

## Editing and exporting

The sources are the slide format of the Slides artifact type: one `deck.json` index naming the order, and one
HTML file per slide, each holding a single `<section>` with inline styles and an `<aside>` of speaker notes.

They render, and export to PowerPoint and PDF, from the artifact each deck was published to. To change a deck,
edit the files here and publish them back, or edit in the artifact and copy the files back into this directory so
the two do not drift.

These files are excluded from the documentation site (`exclude_docs` in `mkdocs.yml`). They are internal sales
material with placeholders in them, not documentation, and a half-filled pitch deck on a public site helps nobody.
