#!/bin/zsh

trap ' ' INT

if [[ -z $1 ]]; then
echo "[*] Usage: $0 <URL>"
exit 1;
fi

target=$1
if [[ ! $target =~ ^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$ && ! $target =~ ^https?://([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}(:[0-9]+)?$ ]]; then
echo "ERROR: Not a valid target.";
exit 1;
fi

outputDir='ffuf-output'
if [[ ! -d ${outputDir} ]]; then mkdir $outputDir; fi

vared -p "[*] Run through Burp?[y]" -c replayProxy
if [ $replayProxy = 'y' ]; then
replayProxyOption="-replay-proxy http://127.0.0.1:8080";
else
replayProxyOption="";
fi

echo "/usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u $target/FUZZ $replayProxyOption -o ${outputDir}/ffuf-ds-$(date '+%d-%m-%Y-%s').html -of html;" | zsh
echo "/usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $target/FUZZ $replayProxyOption -o ${outputDir}/ffuf-common-$(date '+%d-%m-%Y-%s').html -of html;" | zsh
echo "/usr/bin/ffuf -sf -v -ic -r -ac -w /usr/share/seclists/Discovery/Web-Content/trickest-robots-disallowed-wordlists/top-100.txt -u $target/FUZZ $replayProxyOption -o ${outputDir}/ffuf-common-$(date '+%d-%m-%Y-%s').html -of html;" | zsh

vared -p "[*] Run with directory list?[y]" -c useDirlist
if [ $useDirlist = 'y' ]; then
echo "/usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u $target/FUZZ/ $replayProxyOption -o ${outputDir}/ffuf-dirmed-`date '+%d-%m-%Y-%s'`.html -of html;" | zsh
fi

vared -p "[*] Open reports in a browser?[y]" -c openReports
if [ $openReports = 'y' ]; then
/home/shyngys/Downloads/firefox/firefox ${outputDir}/*.html
fi
