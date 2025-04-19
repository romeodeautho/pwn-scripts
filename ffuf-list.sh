#!/bin/zsh

trap ' ' INT

targetList=$1
if [[ ! -f $targetList ]]; then
echo "ERROR: file not found.";
exit 1;
fi

outputDir='ffuf-output'
if [[ ! -d ${outputDir} ]]; then mkdir $outputDir; fi

vared -p "[*]Want to use directory wordlist (raft-large-directories)?[y]" -c dirWordlist
if [[ $dirWordlist == 'y' ]]; then
directoryWordlistCMD="/usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u $url/FUZZ/ -o ${outputDir}/ffuf-dirmed-`date '+%d-%m-%Y'`-$url.html -of html;"
else directoryWordlistCMD='';
fi

cat $targetList | while read url; do
    # TODO: extract domain name from target URL
    #domainURLRegex='^https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$';
    #ipURLRegex='^https?://([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}(:[0-9]+)?$)';
    #if [[ (! $url =~ $domainRegex && ! $url =~ $ipURLRegex) ]]; then
    #echo "not a valid target"; continue;
    #fi
    #if [[ $url=$domainURLRegex ]]; then
    #domainName=$(echo $url | sed ')
    /usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u $url/FUZZ -o ${outputDir}/ffuf-ds-`date '+%d-%m-%Y'`-$url.html -of html;
    /usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u $url/FUZZ -o ${outputDir}/ffuf-common-`date '+%d-%m-%Y'`-$url.html -of html;
    /usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/trickest-robots-disallowed-wordlists/top-100.txt -u $url/FUZZ/ -o ${outputDir}/ffuf-robots-top100-`date '+%d-%m-%Y'`-$url.html -of html;
    $directoryWordlistCMD
done
