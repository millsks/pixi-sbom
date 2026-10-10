# Load pixi's completion, pixi-sbom's and the `pixi sbom` snippet, then print what Tab offers
# for the line in $argv[1], one candidate per line.
pixi completion --shell fish | source
PIXI_SBOM_COMPLETE=fish pixi-sbom | source
source docs/completion/pixi-sbom.fish
complete -C "$argv[1]" | string replace -r '\t.*' ''
