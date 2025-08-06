#!/bin/zsh
dnsxOutputDir=dnsx-output/

if ! [ -d ${dnsxOutputDir} ]; then mkdir ${dnsxOutputDir}; fi

echo "Starting aggressive subdomain enumeration..."

trap ' ' INT

# bruteforcing level 3 subdomains with NOERROR technique
dnsx -nc -a -resp -v -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt\
    -d root-domains.txt -rcode noerror > ${dnsxOutputDir}dnsx-subs-brute-noerror.log;
cat ${dnsxOutputDir}dnsx-subs-brute-noerror.log | cut -d ' ' -f 1 > ${dnsxOutputDir}dnsx-brute-subs-list.txt;
cat ${dnsxOutputDir}dnsx-brute-subs-list.txt | dnsx -nc -asn -recon -e axfr > ${dnsxOutputDir}dnsx-brute-resolve.log;
cat ${dnsxOutputDir}dnsx-brute-resolve.log | grep '\[A\]' | cut -d ' ' -f3 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${dnsxOutputDir}dnsx-brute-ips.txt;
cat ${dnsxOutputDir}dnsx-brute-resolve.log | grep '\[A\]' | cut -d ' ' -f1 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${dnsxOutputDir}dnsx-subs-bruted-resolved-to-a.txt

# select only subdomains with NOERROR response code and without a Resource Record
grep -F -x -v -f ${dnsxOutputDir}dnsx-subs-bruted-resolved-to-a.txt ${dnsxOutputDir}dnsx-brute-subs-list.txt | tee ${dnsxOutputDir}dnsx-subs-bruted-no-rr.txt;

vared -p "[*] Run puredns for subdomain bruteforce? (WARNING: can be extremely stressful for a network!)[y]" -c purednsRun
if [ $purednsRun = 'y' ]; then
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt;
puredns bruteforce /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -d root-domains.txt -r resolvers.txt -w pure-subs.txt;
fi

echo "[*] Following subdomains were found during DNS enumeration:"
cat pure-subs.txt ${dnsxOutputDir}dnsx-brute-subs-list.txt

vared -p "Append those to the main target list?[y]" -c mergeBrutedSubs
if [[ $mergeBrutedSubs = 'y' ]]; then
cat pure-subs.txt ${dnsxOutputDir}dnsx-brute-subs-list.txt | sort -u | anew -t target-hostnames.txt;
fi

# recursive bruteforcing
# sorting discovered hostnames by levels
export sub_level=3
while true; do
    dsieve -f ${sub_level} -if target-hostnames.txt -o target-hostnames-level-${sub_level}.txt
    if [[ ! -s target-hostnames-level-${sub_level}.txt ]]; then break; fi
    cat target-hostnames-level-${sub_level}.txt | dnsgen - > dnsgen-level-${sub_level}.txt
    (( sub_level += 1 ))
done


# TODO:
# bruteforce 4,5,6 level domain names
# include permutations DNSGEN + puredns resovling
