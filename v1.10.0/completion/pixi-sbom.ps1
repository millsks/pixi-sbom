# Complete `pixi sbom ...` with pixi-sbom's own completion. Replaces the usual
# `pixi completion --shell powershell | Out-String | Invoke-Expression` line, because a command
# has one native completer: pixi's is kept and called for everything that is not `pixi sbom`.
$s = (pixi completion --shell powershell | Out-String) -replace "Register-ArgumentCompleter -Native -CommandName 'pixi' -ScriptBlock", '$global:PixiCompleter ='
Invoke-Expression $s
Register-ArgumentCompleter -Native -CommandName pixi -ScriptBlock {
  param($w, $ast, $pos)
  $e = $ast.CommandElements
  if ($e.Count -ge 2 -and $e[1].Extent.Text -eq 'sbom' -and $pos -gt $e[1].Extent.EndOffset) {
    $o = $ast.Extent.StartOffset
    $line = $ast.Extent.Text.Substring(0, [math]::Min($pos - $o, $ast.Extent.Text.Length)).PadRight($pos - $o)
    $inner = 'pixi-sbom' + $line.Substring($e[1].Extent.EndOffset - $o)
    (TabExpansion2 -inputScript $inner -cursorColumn $inner.Length).CompletionMatches
  } else { & $global:PixiCompleter $w $ast $pos }
}
