#!/bin/zsh

HELP="This script runs Httpx tool to probe running http services. Needs a list of URLS (http:// or https://).
    Usage: $0 [-h] [-H] [-C] [-t]
    Options:
      -h show help
      -t target(s) for Wayback Machine search (domain name, IP address, file with a list of targets)"

# HTTPX: validate and fingerprint http services from domain list
echo "[*] Fingerprinting applications with httpx..."
/home/shyngys/go/bin/httpx -l target-urls-for-probe.txt -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o httpx.log -oa -srd httpx-output
/usr/bin/chromium &
sleep 4
/usr/bin/chromium file://`pwd`/httpx-output/screenshot/screenshot.html

# extract valid URLs from httpx log
awk -F ' ' -e '$2 ~ /404]$/ {print $1}' httpx.log | grep -v -E '^https://.*:80$' | tee httpx-404-urls.txt
cat httpx.log | cut -d ' ' -f 1 | grep -v -E '^https://.*:80$' | grep -v -E '^http://.*:443$' | sort -u | tee httpx-valid-urls.txt
cat httpx.log | awk -F'[' '{print $1,"["$5,"["$4}' | sort -u | anew httpx-ip-asn.txt

if [[ -s httpx-valid-urls.txt ]]; then  
    /home/shyngys/go/bin/gowitness scan file -f httpx-valid-urls.txt --write-db --write-screenshots --write-jsonl --threads 20
    cat httpx-valid-urls.txt | python3 ~/Tools/FavFreak/favfreak.py -o favfreak-output.txt
fi
