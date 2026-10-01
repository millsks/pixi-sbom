# How far behind the locked environment is, against the real indexes.
#
# **This one needs the network.** Its report asks a live service, and the responses are far too
# large to commit as a fixture — the anaconda.org project documents behind `--report outdated`
# alone are 19 MB. The GIF is the committed artifact, not the cache, so that only costs
# connectivity at re-record time; what it shows was true on the day it was recorded, the way any
# screenshot of live data is.
#
# The hidden block runs the command once before filming, so the network wait happens off camera
# and what is filmed is a warm run — which is also what the second run of anything looks like.

Output "docs/assets/report-outdated.gif"
Source "docs/assets/_common.tape"
Set Height 810

Hide
Type `cd "$DEMO_WORKSPACE" && unset PIXI_SBOM_OFFLINE && PS1='$ '` Enter
Type "pixi sbom -e web -p linux-64 -q --report outdated > /dev/null 2>&1" Enter
Sleep 20s
Type "clear" Enter
Ctrl+L
Show

Sleep 400ms
Type "pixi sbom -e web -p linux-64 -q --report outdated" Sleep 200ms Enter
Sleep 2600ms
