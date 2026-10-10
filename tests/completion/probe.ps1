# Load pixi-sbom's completion and the `pixi sbom` snippet (which loads pixi's), then print what
# Tab offers for the line in the first argument, one candidate per line.
param([string]$Line)
$env:PIXI_SBOM_COMPLETE = "powershell"; pixi-sbom | Out-String | Invoke-Expression; Remove-Item Env:\PIXI_SBOM_COMPLETE
. ./docs/completion/pixi-sbom.ps1
(TabExpansion2 -inputScript $Line -cursorColumn $Line.Length).CompletionMatches | ForEach-Object { $_.CompletionText }
