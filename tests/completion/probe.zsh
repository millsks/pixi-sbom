# Load pixi's completion, pixi-sbom's and the `pixi sbom` snippet in an interactive zsh, type the
# line in $1 followed by Tab, and print what the completion system offers, one candidate per line.
# zsh completes only inside its line editor, so the shell runs in a pseudo-terminal (zpty) and
# compadd is wrapped to print each match between two NUL-marked lines.
zmodload zsh/zpty || { print -u2 'error: no zsh/zpty'; exit 1 }
setopt rcquotes
zpty z zsh -f -i
init=$(mktemp)
<<< '
PROMPT=
autoload -Uz compinit
compinit -u -d '"${init}"'.dump
eval "$(pixi completion --shell zsh)"
source <(PIXI_SBOM_COMPLETE=zsh pixi-sbom)
source docs/completion/pixi-sbom.zsh
bindkey ''^I'' complete-word
null-line () { print -r -- $''\0'' }
compprefuncs=( null-line )
comppostfuncs=( null-line exit )
zstyle '':completion:*'' list-grouped false
compadd () {
  if [[ ${@[1,(i)(-|--)]} == *-(O|A|D)\ * ]]; then
    builtin compadd "$@"
    return $?
  fi
  typeset -a __hits
  builtin compadd -A __hits "$@"
  local hit
  for hit in $__hits; do print -r -- $hit; done
}
print ok' > $init
zpty -w z "source $init"
repeat 8; do
  zpty -r z line
  [[ $line == ok* ]] && break
done
zpty -w z "$1"$'\t'
integer seen=0
while zpty -r z line; do
  line=${line%$'\r'}
  if [[ $line == *$'\0'* ]]; then
    (( seen++ )) && break || continue
  fi
  (( seen )) && print -r -- $line
done
rm -f $init $init.dump
