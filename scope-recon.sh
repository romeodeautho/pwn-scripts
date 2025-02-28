#!/bin/zsh

#analyze scope list and extract wildcard domain names
grep '*' scope.txt | sed 's/\*\.//g' > wildcard-domains.txt
grep -v '*' scope.txt > target-domains.txt
cat wildcard-domains.txt | tee -a target-domains.txt

# find subdomains for wildcard domains
cat wildcard-domains.txt | /home/shyngys/go/bin/subfinder -active >> target-domains.txt

# export asnmap api key
export PDCP_API_KEY=b8656edb-65c5-41cb-8f3d-bcfc47340ea3

# validate and fingerprint domain list
/home/shyngys/go/bin/httpx -l ./target-domains.txt -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o httpx.log -oa  


python -c 'with open("httpx-ips.txt","r") as f, open("httpx.log", "r") as g: ips = [line.rstrip("\n") for line in f]; httpx_rows = [line.rstrip("\n") for line in g]; for ip in ips: host_file = open(f"{ip}-domains.txt", "a"); for row in httpx_rows: if ip in row: url = row.split(" ")[0]; host_file.write(url + "\n"); host_file.close()'


#extract IP addresses
cat httpx.log | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' --only-matching | sort -u | tee httpx-ips.txt
cat httpx.log | cut -d ' ' -f 1 | tee httpx-urls.txt
/usr/bin/firefox file://`pwd`/output/screenshot/screenshot.html
cat target-domains.txt | dnsx -nc -asn -recon -e axfr | tee dnsx.log
cat dnsx.log | grep '\[A\]' | grep -v cloudflare | cut -d ' ' -f3 | tr -d "[]" | sort -u | tee dnsx-ips.txt
cat dnsx-ips.txt httpx-ips.txt | sort -u | tee ips-all.txt
echo "IP addresses in scope:"
/usr/bin/cat ips-all.txt
/usr/bin/sleep 2

#nmap scan of the IP range
sudo /usr/bin/nmap -T4 -sS -sV -O --top-ports=30000 -vv -iL ips-all.txt -oA nmap-all-ports-tcp-`date '+%d-%m-%Y'`
echo "[*] Creating html report from nmap scan..."
/usr/bin/xsltproc $(ls -Art *.xml | tail -n 1) -o nmap-all-ports-tcp-`date '+%d-%m-%Y'`.html
vared -p "[*] Open html report?[y]" -c open_report
if [ $open_report = 'y' ]; then /usr/bin/firefox file://`pwd`/nmap-all-ports-tcp-`date '+%d-%m-%Y'`.html; fi
