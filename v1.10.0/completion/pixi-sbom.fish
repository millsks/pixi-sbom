# Complete `pixi sbom ...` with pixi-sbom's own completion.
complete -c pixi -n 'test (count (commandline -opc)) -ge 2; and test (commandline -opc)[2] = sbom' -f \
    -a '(complete -C "pixi-sbom "(string replace -r "^\s*\S+\s+sbom\s+" "" -- (commandline -cp)))'
