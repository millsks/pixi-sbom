---
name: feedback-minimal-defaults
description: User wants enrichment defaults minimal (license type only); bulky data like license texts must be opt-in flags
metadata:
  type: feedback
---

When adding enrichment to the SBOM, the default output should carry only the identifying fact (e.g. the license
expression); bulky payloads such as full license texts are an explicit opt-in (`--license-texts`), never the default
with an opt-out. Given 2026-09-20 while reviewing `--fetch-licenses`.

**Why:** documents are consumed by scanners and diffed in CI; size and noise matter more than completeness by default.
**How to apply:** for any new fetched detail, ask "is this the fact or the payload?"; payloads get their own flag.
See [[roadmap]].
