# Complete `pixi sbom ...` with pixi-sbom's own completion. Load after pixi's and pixi-sbom's.
_pixi_with_sbom() {
  if (( COMP_CWORD >= 2 )) && [[ ${COMP_WORDS[1]} == sbom ]]; then
    local spec fn old=${#COMP_LINE}
    spec=$(complete -p pixi-sbom 2>/dev/null) || return 0
    fn=${spec##*-F }; fn=${fn%% *}
    COMP_WORDS=(pixi-sbom "${COMP_WORDS[@]:2}"); (( COMP_CWORD-- ))
    COMP_LINE="pixi-sbom ${COMP_LINE#*sbom }"; (( COMP_POINT -= old - ${#COMP_LINE} ))
    "$fn" pixi-sbom "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
  else
    _pixi "$@"
  fi
}
complete -o bashdefault -o default -o nosort -F _pixi_with_sbom pixi
