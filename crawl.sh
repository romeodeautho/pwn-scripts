#!/usr/bin/zsh
#vared -p "[*]Enter cookie key/value pair for authenticated spidering or leave empty:\n" -c authCookie
#if [ ! -z ${authCookie} ]; then
#export cookieHeader="-H 'Cookie: ${authCookie}'"
# crawl and filter for paths and GET parameter names
HELP="This script runs web crawling tools against a list of URLs from httpx-valid-urls.txt file.
    Usage: $0 [-h] [-a] [-H] [-C] [-t]
    Options:
      -h show help
      -a run katana against the targets (default: OFF. Only passive URL discover)
      -t target(s) for Wayback Machine search (domain name, IP address or a file with a list of targets)
    
    [+]For an authenticated crawl you can set custom cookies or headers:
      -H HEADER
      -C COOKIE"

while getopts ":aH:C:t:h" opt; do
    case $OPTARG in
    -*) echo "ERROR: Incorrect arguments."
    exit 1;;
    esac
    case $opt in
      h) echo $HELP;
      exit 1;
      ;;
      a) active='1'
      ;;
      H) header="$OPTARG"
      ;;
      C) cookie="$OPTARG"
      ;;
      t) waybackTarget=$OPTARG
      ;;
      "?") echo "Invalid option: '$OPTARG'.\nTry '$0 -h' for usage information." >&2
      exit 1
      ;;
      ":") echo "Error: empty value for the argument -$OPTARG"
      exit 1
      ;;
    esac
done

function extract_and_filter {
    filename=$1
    basename=`echo $filename | awk '{sub(/\.[^.]*$/, ""); print}'`
    cat $filename | urless | sort | tee $basename-urless-filtered.txt
    cat $basename-urless-filtered.txt | unfurl -u paths | sort | anew $basename-paths.txt
    cat $basename-urless-filtered.txt| unfurl -u keys | sort | anew $basename-params.txt
    cat $filename | uro --filters vuln | sort | anew $basename-uro-vuln.txt
}

if [[ ! -z ${header} ]]; then
headerOption="-H '${header}'";
fi
if [[ ! -z ${cookie} ]]; then
cookieOption="-H 'Cookie: ${cookie}'";
fi


if [[ $active == '1' ]]; then
    # live spidering a target with Katana (include full URLs, URLs with path, GET parameter keys)
    echo "${HOME}/go/bin/katana -rl 30 -list httpx-valid-urls.txt -f url,path,key -o katana.log $headerOption $cookieOption" | zsh

    # extracting parameters, directories and full urls from kanata output
    cat katana.log | /usr/bin/grep -Ev '^/' | /usr/bin/grep -Ev '^[a-z]+://' | sort -u | anew katana-params.txt
    /usr/bin/grep -E '^/' katana.log | cut -d / -f2 | sed -e 's/^/\//' | /usr/bin/grep -Ev '\.' | sort -u | anew katana-paths.txt
    /usr/bin/grep -E '^https?://' katana.log | sort -u | anew katana-urls.txt
    cat katana-urls.txt | awk -F/ '{print $1"/"$2"/"$3"/"$4}' | sort -u | anew katana-urls-path-onelevel.txt
fi

if [[ -s target-hostnames.txt ]]; then
    echo "[*] Getting historical URLs from Web Archive..."
    cat root-domains.txt | gau -v -t 5 | anew -q gau-output-alldomains.log
    cat gau-output-alldomains.log | urless | sort | anew gau-urless-filtered.txt
    cat gau-urless-filtered.txt | unfurl -u paths | sort | anew gau-paths.txt
    cat gau-urless-filtered.txt| unfurl -u keys | sort | anew gau-params.txt
    cat gau-output-alldomains.log | uro --filters vuln | sort | anew gau-uro-vuln.txt
fi

#jsluice urls $file | jq .url | sort -u | tr -d '"' | tee jsluice-urls.txt
#jsluice secrets $file | tee jsluice-secrets.txt

urlfinder -d root-domains.txt -o urlfinder-output.txt -all
cat urlfinder-output.txt | urless | sort | tee urlfinder-urless-filtered.txt
cat urlfinder-urless-filtered.txt | unfurl -u paths | sort | anew urlfinder-paths.txt
cat urlfinder-urless-filtered.txt| unfurl -u keys | sort | tee urlfinder-params.txt
cat urlfinder-output.txt | uro --filters vuln | sort | tee urlfinder-uro-vuln.txt

# find URLs and download HTTP responses from Wayback Machine
waymore -i $waybackTarget -oU waymore_urls_${waybackTarget}.txt -oR waymore_responses_${waybackTarget}

cat waymore_urls_${waybackTarget}.txt | urless | sort | tee waymore-urless-filtered.txt
cat waymore-urless-filtered.txt | unfurl -u paths | sort | anew waymore-paths.txt
cat waymore-urless-filtered.txt| unfurl -u keys | sort | tee waymore-params.txt
cat waymore_urls_${waybackTarget}.txt | uro --filters vuln | sort | tee waymore-uro-vuln.txt

cat gau-urless-filtered.txt urlfinder-urless-filtered.txt | awk -F/ '{print $1"/"$2"/"$3"/"$4}' \
| grep -E '^http' | sort -u | tee urls-paths-level-1.txt

#parse downloaded resposes and JS files for links
xnLinkFinder -i waymore_responses_${waybackTarget} -sf $waybackTarget

# creating custom wordlist from website content
cat httpx-valid-urls.txt | while read url; do
    cewl $url --header "Cookie: ${cookie}" -d 2 -m 4 --write cewl-wordlist.txt
done
