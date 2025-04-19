#!/bin/zsh

/home/shyngys/Downloads/firefox/firefox
/usr/bin/find . -name "*.html" ! -name "*ffuf*" ! -path "*ffuf-output*" ! -path "*scans*"\
 -exec /home/shyngys/Downloads/firefox/firefox {} \; 2>/dev/null