#!/bin/zsh

/usr/bin/chromium &;
sleep 3
/usr/bin/find . -name "*.html" ! -path "*ffuf-output*" ! -path "*scans*" ! -path "*autorecon*" ! -path "*waymore*" -exec /usr/bin/chromium {} \; 2>/dev/null