#!/bin/zsh

trap ' ' INT

targetList=$1
if [[ ! -f $targetList ]]; then
echo "ERROR: file not found.";
exit 1;
fi

outputDir='ffuf-output'
if [[ ! -d ${outputDir} ]]; then mkdir $outputDir; fi

cat $targetList | while read url; do
    if [[ (! $url =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$ && ! $url =~ ([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}(:[0-9]+)?$) ]]; then echo "not a valid target"; continue; fi
    /usr/bin/ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u $url/FUZZ -o ${outputDir}/ffuf-ds-`date '+%d-%m-%Y-%s'`.html -of html;
    /usr/bin/ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $url/FUZZ -o ${outputDir}/ffuf-common-`date '+%d-%m-%Y-%s'`.html -of html;
    /usr/bin/ffuf -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u $url/FUZZ/ -o ${outputDir}/ffuf-dirmed-`date '+%d-%m-%Y-%s'`.html -of html;
done
