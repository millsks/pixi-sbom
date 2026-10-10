# Load pixi's completion, pixi-sbom's and the `pixi sbom` snippet, then print what Tab offers
# for the line in $1, one candidate per line. Bash only completes inside readline, so the
# variables it would set are set here and the registered function is called directly.
# Loaded with eval, as docs/installation.md says: `source <(...)` reads nothing in bash 3.2.
eval "$(pixi completion --shell bash)"
eval "$(PIXI_SBOM_COMPLETE=bash pixi-sbom)"
source docs/completion/pixi-sbom.bash
COMP_LINE=$1
COMP_POINT=${#COMP_LINE}
COMP_TYPE=9
read -r -a COMP_WORDS <<< "$COMP_LINE"
[[ $COMP_LINE == *" " ]] && COMP_WORDS+=("")
COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
spec=$(complete -p "${COMP_WORDS[0]}")
fn=${spec##*-F }; fn=${fn%% *}
COMPREPLY=()
"$fn" "${COMP_WORDS[0]}" "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
printf '%s\n' "${COMPREPLY[@]}" | sed -E 's/[[:space:]]+$//'
