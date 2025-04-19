#!/usr/bin/zsh
#vared -p "[*]Enter cookie key/value pair for authenticated spidering or leave empty:\n" -c authCookie
#if [ ! -z ${authCookie} ]; then
#export cookieHeader="-H 'Cookie: ${authCookie}'"
# crawl and filter for paths and GET parameter names
while getopts ":h:" opt; do
  case $opt in
    H) header="$OPTARG"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2
    exit 1
    ;;
  esac

  case $OPTARG in
    -*) echo "Option $opt needs a valid argument"
    exit 1
    ;;
  esac
done

if [[ ! -z ${header} ]]; then
export cookieOption="-H 'Cookie: ${header}'";
fi
${HOME}/go/bin/katana -list httpx-valid-urls.txt -f url,path,key -o katana.log $cookieOption  

# sorting parameters, directories and full urls
cat katana.log | grep -Ev '^/' | grep -Ev '^[a-z]+://' | sort -u | tee katana-params-get.txt
grep -E '^/' katana.log | cut -d / -f2 | sed -e 's/^/\//' | grep -Ev '\.' | sort -u | tee katana-paths.txt
grep -E '^https?://' katana.log | sort -u | tee katana-urls.txt
cat katana-urls.txt | awk -F/ '{print $1"/"$2"/"$3"/"$4}' | sort -u > katana-urls-path-onelevel.txt

# find URLs and download HTTP responses from Wayback Machine
vared -p "[*]Enter root domain for wayback machine search: " -c targetDomain
waymore -i ${targetDomain} -oU waymore_urls_${targetDomain}.txt -oR waymore_responses_${targetDomain}

#parse downloaded resposes and JS files for endpoints
xnLinkFinder -i waymore_responses_${targetDomain} -sf ${targetDomain}
jsluice urls ${file} | jq .url | sort -u | tr -d '"' | tee jsluice-urls.txt

# search for secrets
jsluice secrets $file | tee jsluice-secrets.txt