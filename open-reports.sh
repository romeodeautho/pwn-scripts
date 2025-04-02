#!/bin/zsh

/usr/bin/find . -name "*.html" ! -name "*ffuf*" ! -path "*ffuf-output*" -exec /usr/bin/firefox {} \; 2>/dev/null