#!/bin/zsh

xnLinkFinder -i all-scripts-export.txt -sf ../target-domains.txt

# TODO: grep for all schemes, not only http(s)
cat output.txt | sort -u | sed -e 's/^\.\{1,2\}//g' | grep -E '^http' | anew full-urls.txt
cat output.txt | sort -u | sed -e 's/^\.\{1,2\}//g' | grep -E '^/' | anew paths.txt

jsluice secrets --unique all-scripts-export.txt | anew jsluice-secrets.txt
jsluice urls --unique all-scripts-export.txt | anew jsluice-urls.txt