#!/bin/zsh

HELP="This script runs httpx tool to probe running http services. Needs a list of URLS (http(s)://).
    Usage: $0 [-h] [-H] [-C] [-t]
    Options:
      -h show help
      -p use proxychains"

while getopts ":hp" opt; do
  case $OPTARG in
   -*) echo "ERROR: Incorrect arguments."
  exit 1;;
  esac
  case $opt in
    h) echo $HELP;
    exit 1;
    ;;
    p) useProxychains='1';
    ;;
    "?") echo "Invalid option: '$OPTARG'.\nTry '$0 -h' for usage information." >&2
    exit 1;;
    ":") echo "Error: empty value for the argument -$OPTARG"
    exit 1;;
  esac
done

# HTTPX: validate and fingerprint http services from domain list
echo "[*] Fingerprinting applications with httpx..."

if [[ $useProxychains == '1' ]]; then
proxychains4 /home/shyngys/go/bin/httpx -l target-urls-for-probe.txt -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o httpx.log -oa -srd httpx-output;
else
/home/shyngys/go/bin/httpx -l target-urls-for-probe.txt -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o httpx.log -oa -srd httpx-output;
fi
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
