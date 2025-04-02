#!/bin/zsh

trap ' ' INT

target=$1
if [[ ! $target =~ ^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$ && ! $target =~ ^https?://([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}(:[0-9]+)?$ ]]; then
echo "ERROR: Not a valid target.";
exit 1;
fi

outputDir='ffuf-output'
if [[ ! -d ${outputDir} ]]; then mkdir $outputDir; fi

vared -p "[*] Run through replay proxy 127.0.0.1:8080?[y]" -c replayProxy
if [ $replayProxy = 'y' ]; then
/usr/bin/ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u $target/FUZZ -o ${outputDir}/ffuf-ds-$(date '+%d-%m-%Y-%s').html -of html
/usr/bin/ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $target/FUZZ -o ${outputDir}/ffuf-common-$(date '+%d-%m-%Y-%s').html -of html; 
else 
/usr/bin/ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u $target/FUZZ -o ${outputDir}/ffuf-ds-`date '+%d-%m-%Y-%s'`.html -of html
/usr/bin/ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $target/FUZZ -o ${outputDir}/ffuf-common-`date '+%d-%m-%Y-%s'`.html -of html;
fi

vared -p "[*] Run with directory list?[y]" -c useDirlist
if [ $useDirlist = 'y' ]; then
/usr/bin/ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u $target/FUZZ/ -o ${outputDir}/ffuf-dirmed-`date '+%d-%m-%Y-%s'`.html -of html;
fi

vared -p "[*] Open reports in a browser?[y]" -c openReports
if [ $openReports = 'y' ]; then
/usr/bin/firefox ${outputDir}/*.html
fi
