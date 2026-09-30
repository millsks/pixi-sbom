#!/usr/bin/env bash
set -euo pipefail
src="$1"; out="$2"
{ printf '<!doctype html><html lang="en"><head><meta charset="utf-8">\n'
  printf '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,wght@0,400;0,600;1,400&family=IBM+Plex+Sans:wght@400;600&family=JetBrains+Mono:wght@400&display=swap">\n'
  printf '<title>$title$</title><style>\n'; cat paper.css; printf '\n</style></head><body>\n'
  printf '<h1 class="title">$title$</h1>\n'
  printf '$if(subtitle)$<p class="subtitle">$subtitle$</p>$endif$\n'
  printf '$if(author)$<p class="author">$for(author)$$author$$sep$, $endfor$</p>$endif$\n'
  printf '$if(date)$<p class="date">$date$</p>$endif$\n'
  printf '$if(abstract)$<div id="abstract"><h2>Abstract</h2>$abstract$</div>$endif$\n'
  printf '$body$\n</body></html>\n'
} > tpl.html
pandoc "$src" --standalone --from markdown --to html5 --template=tpl.html -o "$out.html"
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless --disable-gpu --no-pdf-header-footer \
  --print-to-pdf="$out.pdf" "file://$PWD/$out.html" 2>/dev/null
