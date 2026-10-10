# Presentations

Two decks making the case for pixi-sbom, to two different rooms, and a public talk. The slide sources live here so the numbers in
them can be corrected when the numbers change, which they will.

| Deck | Audience | Slides |
|---|---|---|
| `engineering-management/` | Engineering management, plus people who already know what an SBOM is | 12 |
| `executive/` | C-suite: the decision, what it costs, what happens if it is wrong | 10 |
| `talk/` | A public, technical audience: a conference, a meetup, a community call | 12 |

They are not two versions of one deck. The engineering deck argues from capability — what the tool does, what it
refuses to claim, what a team gets. The executive deck argues from consequence — what we cannot answer today, what
that costs, and what the downside of saying yes is. Slides that matter to one room are absent from the other on
purpose.

## The public talk

`talk/` is "The Hole in Your SBOM": why a conda or pixi environment's SBOM can be valid and still unsearchable, the
evidence from [the paper](../papers/package-identity-sbom-matching.md), and a live demo on `examples/`. It runs 13
minutes 30 seconds, and the speaker notes on every slide give its place in the full talk and in a 5-minute cut for
a community call.

Unlike the two decks below, it has no placeholders and no sales argument, so it can be shown and shared as it is.

[`talk/demo-script.md`](talk/demo-script.md) is the live part: the setup, both timed running orders, each command
with what it prints, a fallback recording for each step, and where every number on a slide comes from. The demo
runs offline against `examples/lab-cache`, so the counts on the slides are the counts on stage. A test runs every
command in the script and checks every output line on the demo slides against what the command printed, so the
slides cannot drift from the tool. Export as `pixi-sbom-talk.*`.

## Fill these in before presenting

Both decks carry bracketed placeholders. An audience reads a placeholder as a case that was not finished.

**Engineering management:** `[Presenter]`, `[Date]`.

**Executive:** `[Presenter]`, `[date]` (twice), `[name]` of whoever maintains this, `[$___]` for the loaded cost of
two weeks of part-time engineering, and three `[__]` figures on the cost slide — engineer-days a quarter spent on
security questionnaires, deals delayed by a compliance review, and hours to answer "are we exposed?" the last time
it came up. The deal desk has the first two; whoever ran the last incident has the third.

Both decks have a slide of the rules that ask for this inventory: PCI DSS 4.0, EU DORA, the EU Cyber Resilience Act
and US Executive Order 14028, each with who it covers and when it took effect, and the instruments cited in the
footer. The speaker notes give the requirement wording. Neither financial rule uses the word "SBOM"; both require a
component inventory, and the slides say exactly that. Have compliance confirm which rows apply before presenting.
The executive deck's "true today" slide still carries a note to **check the current regulatory timelines**; do
that, then delete the note.

## Where the numbers come from

Every figure on a slide that is not a placeholder traces to something in this repository, except the regulatory dates:

| Claim | Source |
|---|---|
| 12 MB binary, five platforms | the 1.8.1 release: 12.2 MB unpacked on linux-64, the largest; 9.1 MB on osx-arm64 |
| Under a second per build, 72-package environment | [benchmarks.md](../benchmarks.md) |
| Exit codes 3, 4, 6, 8, 10 | [cli.md](../cli.md#exit-codes-and-errors) |
| PCI DSS 4.0 Req. 6.3.2 (31 March 2025), DORA RTS (EU) 2024/1774 Art. 10(2)(d) (17 January 2025), CRA (EU) 2024/2847 (11 December 2027) | the instruments themselves, cited on the slide; not this repository |
| CycloneDX 1.6/1.7, SPDX 2.3/3.0.1 | [output-format.md](../output-format.md) |

If a number here stops matching its source, the slide is wrong, not the source.

## The exported decks

Each deck is here in three forms, exported from the artifact it lives on:

| | Use it for |
|---|---|
| `.pptx` | Editing. Text stays editable, so it can be pasted into a corporate template. |
| `.pdf` | Sending. Renders identically for someone who will not open a deck they cannot preview. |
| `.html` | Presenting anywhere. One self-contained file, opens in a browser, needs no PowerPoint. |

Named `pixi-sbom-engineering.*`, `pixi-sbom-executive.*` and `pixi-sbom-talk.*` in their respective directories.

**The two pitch decks are templates, not finished decks.** All three forms still carry the bracketed placeholders — open one,
fill them in, and save your own copy. Presenting straight from this directory means presenting `[Presenter]` on
the title slide, and `[__]` where the cost figures should be.

The two typefaces are free from Google Fonts (IBM Plex Sans, JetBrains Mono). The PDF and the HTML carry their own
rendering, but PowerPoint substitutes if the fonts are not installed locally, and the spacing shifts when it does.

**Re-export after changing a slide.** These files are a snapshot. Nothing checks that they match the sources
beside them, so a stale export is the most likely way this directory starts lying — if you change a number in a
slide, export all three again in the same sitting.

## Editing and exporting

The sources are the slide format of the Slides artifact type: one `deck.json` index naming the order, and one
HTML file per slide, each holding a single `<section>` with inline styles and an `<aside>` of speaker notes.

They render, and export to PowerPoint and PDF, from the artifact each deck was published to. To change a deck,
edit the files here and publish them back, or edit in the artifact and copy the files back into this directory so
the two do not drift.

These files are excluded from the documentation site (`exclude_docs` in `mkdocs.yml`). They are internal sales
material with placeholders in them, not documentation, and a half-filled pitch deck on a public site helps nobody.
