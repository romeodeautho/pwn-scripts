#!/bin/zsh
target=$1

if [[ $target =~ ^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$ ]]; then
targetType='ip-url';
elif [[ $target =~ ^https?://([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}(:[0-9]+)?$ ]]; then
targetType='domain-url';
else echo "ERROR: Not a valid target.";
exit 1;
fi

vared -p "[*] Run through replay proxy 127.0.0.1:8080?[y]" -c replayProxy
if [ $replayProxy = 'y' ]; then
ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u $target/FUZZ -o ffuf-ds-$(date '+%d-%m-%Y-%s').html -of html -or
ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $target/FUZZ -o ffuf-common-$(date '+%d-%m-%Y-%s').html -of html -or; 
else 
ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u $target/FUZZ -o ffuf-ds-`date '+%d-%m-%Y-%s'`.html -of html -or
ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $target/FUZZ -o $(pwd)/ffuf-common-`date '+%d-%m-%Y-%s'`.html -of html -or;
fi

vared -p "[*] Run with directory list?[y]" -c useDirlist
if [ $useDirlist = 'y' ]; then
ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u $target/FUZZ/ -o ffuf-dirmed-`date '+%d-%m-%Y-%s'`.html -of html -or;
fi

vared -p "[*] Open reports in a browser?[y]" -c openReports
if [ $openReports = 'y' ]; then
/usr/bin/firefox ./ffuf*.html
fi
