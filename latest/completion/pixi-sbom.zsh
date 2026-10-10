# Complete `pixi sbom ...` with pixi-sbom's own completion. Load after pixi's and pixi-sbom's.
_pixi_with_sbom() {
  if (( CURRENT > 2 )) && [[ ${words[2]} == sbom ]]; then
    shift words; (( CURRENT-- )); words[1]=pixi-sbom; _normal
  else
    _pixi "$@"
  fi
}
compdef _pixi_with_sbom pixi
