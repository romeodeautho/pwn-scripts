#!/bin/zsh

/usr/bin/chromium &; disown
/usr/bin/find . -name "*.html" ! -path "*ffuf-output*" ! -path "*scans*" ! -path "*autorecon*" \
-exec /usr/bin/chromium {} \; 2>/dev/null