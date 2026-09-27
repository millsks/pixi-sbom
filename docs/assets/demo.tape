# The README recording: a lockfile in, documents out, and the gate that fails a build.
#
#   pixi global install vhs      # once
#   pixi run demo                # regenerates docs/assets/demo.gif
#
# Every line of output is the real binary's. Only the input is staged — see
# scripts/demo-workspace.sh. Keep it near 20s: it autoplays at the top of the README and a reader
# gives it one loop. `-e web -p linux-64` is on each command because that environment is the one
# carrying a vulnerable urllib3, and the gate is the whole point of the last step.

Output "docs/assets/demo.gif"

Require pixi-sbom

Set Shell bash
Set FontSize 15
Set Width 1260
Set Height 750
Set Padding 18
Set Margin 12
Set BorderRadius 8
Set WindowBar Colorful
Set WindowBarSize 32
Set TypingSpeed 28ms
Set Framerate 24

# A plain prompt, so the recording does not carry whoever made it. Inside Hide so the setup is
# not part of the film; the Ctrl+L afterwards clears what Hide still leaves on screen.
Hide
Type `PS1='$ '` Enter
Type "clear" Enter
Ctrl+L
Show

Sleep 500ms

# --- A pixi workspace. Nothing in it but a manifest and a lockfile. ---------------------------
Type "ls" Sleep 200ms Enter
Sleep 700ms

# --- The whole point: lockfile in, CycloneDX out. ---------------------------------------------
Type "pixi sbom -e web -p linux-64 --output sbom.cdx.json" Sleep 200ms Enter
Sleep 1800ms

# --- The same lockfile as SPDX 3.0.1. ---------------------------------------------------------
Type "pixi sbom -e web -p linux-64 --format spdx --spec-version 3.0 --output sbom.spdx.json" Sleep 200ms Enter
Sleep 1800ms

# --- A terminal report rather than a document. Not piped: the tool turns colour off when its
# --- output is not a terminal, so `| head` would have filmed a monochrome table.
Type "pixi sbom -e web -p linux-64 -q --report python" Sleep 200ms Enter
Sleep 2400ms

# --- And why it belongs in CI: a gate with an exit code. ---------------------------------------
Type "pixi sbom -e web -p linux-64 -q --vulnerabilities osv --kev --fail-on-severity high" Sleep 200ms Enter
Sleep 2400ms
Type "echo exit=$?" Sleep 200ms Enter
Sleep 1600ms
