#!/bin/zsh

# setting up working directory for the script
if [[ -z $1 ]]; then export workingDir="$(pwd)/"; else
if [[ -d $1 ]]; then
if [[ $1 =~ .*/$ ]]; then export workingDir=$1; else export workingDir="$1/"; fi
else echo "Directory does not exist. Check the path."; exit 1
fi
fi

trap ' ' INT

# analyze scope list and extract root domain names
if [[ ! -f ${workingDir}scope.txt ]];
 then echo "scope.txt not found in the program directory"; exit 1;
fi
grep '*' ${workingDir}scope.txt | sed 's/\*\.//g' > ${workingDir}root-domains.txt
grep -v '*' ${workingDir}scope.txt | sed 's/\*\.//g' > ${workingDir}target-domains.txt
cat ${workingDir}root-domains.txt >> ${workingDir}target-domains.txt
sed -e 's/\./\\./g' -e 's/\*\\\./\(.*\\.\)?/' ${workingDir}scope.txt > ${workingDir}scope-regex.txt

# SUBFINDER: find subdomains for root domains
cat ${workingDir}root-domains.txt | /home/shyngys/go/bin/subfinder >> ${workingDir}target-domains.txt

# import asnmap api key
export PDCP_API_KEY=`cat /home/shyngys/Documents/.chaos-token`

# subdomain bruteforce
vared -p "[*] Run subdomain bruteforce?[y]" -c subbrute
if [ $subbrute = 'y' ]; then dnsx -nc -a -resp -v \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt\
    -d ${workingDir}root-domains.txt -rcode noerror | tee ${workingDir}dnsx-subs-brute-noerror.log;
  cat ${workingDir}dnsx-subs-brute-noerror.log | cut -d ' ' -f 1 > ${workingDir}dnsx-brute-subs-list.txt;
  cat ${workingDir}dnsx-brute-subs-list.txt | dnsx -nc -asn -recon -e axfr | tee ${workingDir}dnsx-brute-resolve.log;
  cat ${workingDir}dnsx-brute-resolve.log | grep '\[A\]' | cut -d ' ' -f3 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${workingDir}dnsx-brute-ips.txt;
  cat ${workingDir}dnsx-brute-resolve.log | grep '\[A\]' | cut -d ' ' -f1 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${workingDir}dnsx-subs-bruted-resolved-to-a.txt

  # select only subdomains with NOERROR response code and without a Resource Record
  grep -F -x -v -f ${workingDir}dnsx-subs-bruted-resolved-to-a.txt ${workingDir}dnsx-brute-subs-list.txt | tee ${workingDir}dnsx-subs-bruted-no-rr.txt;
  
  vared -p "[*] Run puredns for subdomain bruteforce? (can be very stressful for a network)[y]" -c purednsRun
  if [ $purednsRun = 'y' ]; then
  wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt;
  puredns bruteforce /usr/share/seclists/Discovery/DNS/combined_subdomains.txt\
   -d ${workingDir}root-domains.txt -r ${workingDir}resolvers.txt -w ${workingDir}pure-subs.txt;
  fi
  echo "[*] Following subdomains were found during DNS enumeration:"
  cat ${workingDir}pure-subs.txt ${workingDir}dnsx-brute-subs-list.txt | sort -u | anew -t -d target-domains.txt
  vared -p "Append them to the main target list?[y]" -c mergeBrutedSubs
  if [[ $mergeBrutedSubs = 'y' ]]; then
  cat ${workingDir}pure-subs.txt ${workingDir}dnsx-brute-subs-list.txt | sort -u | anew -t target-domains.txt
  fi
fi

cat ${workingDir}root-domains.txt | while read line; do
puncia subdomain $line | tee ${workingDir}puncia-subs-$line.txt;
done
cat ${workingDir}puncia-subs-* | tr -d ', []"' | sed '/^$/d' |\
 grep -E '^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}(:[0-9]+)?$' |\
  sort -u | anew -d ${workingDir}target-domains.txt

# GITHUB-SUBDOMAINS: search subdomains on Github and validate
githubToken=`cat /home/shyngys/intel/.token`
while read -r line; do github-subdomains -d $line -t $githubToken\
 -o ${workingDir}github-subdomains-$line.txt;
done < ${workingDir}root-domains.txt


# DNSX: run DNS resolving on a domain list
cat ${workingDir}target-domains.txt | dnsx -nc -asn -recon -e axfr > ${workingDir}dnsx-resolve.log
# extract NS server domains from dnsx log
cat ${workingDir}dnsx-resolve.log | grep 'NS\|SOA' | cut -d ' ' -f 3 | tr -d '[]' | sort -u > ${workingDir}ns.txt

# extract IP addresses from dnsx.log
cat ${workingDir}dnsx-resolve.log | grep '\[A\]' | cut -d ' ' -f3 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${workingDir}ips.txt
echo "IP addresses in scope:"
/usr/bin/cat ${workingDir}ips.txt
/usr/bin/sleep 2

# DNSX PTR resolve
echo "[*] Resolving IP addresses to PTR records..."
dnsx -l ${workingDir}ips.txt -nc -ptr -resp | cut -d ' ' -f3 | tr -d '[]' | tee ${workingDir}dnsx-ptr.txt

# NMAP scan against the IP address list
portscan() {
    nmapOutputBasename=nmap-3000-ports-tcp-`date '+%d-%m-%Y-%H:%M'`
    sudo /usr/bin/nmap -T4 -sS -sV --top-ports=3000 -vv -iL ips.txt -oA ${workingDir}$nmapOutputBasename
    echo "[*] Creating html report from nmap scan..."
    /usr/bin/xsltproc $(ls -Art ${workingDir}*.xml | tail -n 1) -o ${workingDir}$nmapOutputBasename.html
    /home/shyngys/Downloads/firefox/firefox file://${workingDir}$nmapOutputBasename.html
}

portscan

# extract HTTP port numbers from nmap output for each host
echo "[*] Analyzing nmap report. Generating url list for scanning..."
[[ ! -d ${workingDir}http-ports-by-host ]] && mkdir ${workingDir}http-ports-by-host;\
 cat ${workingDir}ips.txt | while read line; do grep $line ${workingDir}$nmapOutputBasename.gnmap | grep Ports | awk '{for (i=4;i<=NF;i++) {split($i,a,"/");if (a[5] ~ /(ssl|)?http.*/) print a[1];}}' |\
  tee ${workingDir}http-ports-by-host/$line-http-ports.txt; done

# extract domain names for each host (for vhosts enumeration)
#/usr/bin/python3 /home/shyngys/scripts/httpx-domains.py
[[ ! -d ${workingDir}domains-by-host ]] && mkdir ${workingDir}domains-by-host; cat ${workingDir}ips.txt | while read -r line; do domains=`grep $line ${workingDir}dnsx-resolve.log | cut -d ' ' -f1`; echo "$domains" > ${workingDir}domains-by-host/$line-domains.txt;done

# generate list in format <DOMAIN:PORT> from 3 lists: IPs, domains, ports for further validating
cat ${workingDir}ips.txt | while read line;\
 do cat ${workingDir}domains-by-host/$line-domains.txt | while read domain;\
  do cat ${workingDir}http-ports-by-host/$line-http-ports.txt | while read port;\
   do echo $domain:$port | anew ${workingDir}target-domains-ports-raw.txt; done ; done; done
cat ${workingDir}target-domains-ports-raw.txt | while read host; do
    if [[ $host =~ ':80$' ]]; then echo $host | sed -e 's/:80//' -e 's/^/http:\/\//' >> target-domains-ports.txt
    elif [[ $host =~ ':443$' ]]; then echo $host | sed -e 's/:443//' -e 's/^/https:\/\//' >> target-domains-ports.txt
    else echo $host | sed -e 's/^/http:\/\//' >> target-domains-ports.txt
    fi
done
    
# HTTPX: validate and fingerprint http services from domain list
echo "[*] Fingerprinting applications with httpx..."
/home/shyngys/go/bin/httpx -l ${workingDir}target-domains-ports.txt -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o ${workingDir}httpx.log -oa -srd ${workingDir}httpx-output
/home/shyngys/Downloads/firefox/firefox file://${workingDir}httpx-output/screenshot/screenshot.html 

# extract valid URLs from httpx log
awk -F ' ' -e '$2 ~ /404]$/ {print $1}' ${workingDir}httpx.log | grep -v -E '^https://.*:80$' | tee ${workingDir}httpx-404-urls.txt
cat ${workingDir}httpx.log | cut -d ' ' -f 1 | grep -v -E '^https://.*:80$' | grep -v -E '^http://.*:443$' | sort -u | tee ${workingDir}httpx-valid-urls.txt

/home/shyngys/go/bin/gowitness scan file -f ${workingDir}httpx-valid-urls.txt --write-db --write-screenshots --write-jsonl --threads 20 --chrome-proxy http://127.0.0.1:8080

cat ${workingDir}httpx-valid-urls.txt | python3 ~/Tools/FavFreak/favfreak.py -o favfreak-output.txt

echo "[*] Getting historical URLs from Web Archive..."
cat ${workingDir}target-domains.txt | gau -t 5 > ${workingDir}gau-output-alldomains.log

searchsploit --nmap ${workingDir}$nmapOutputBasename.xml | tee ${workingDir}searchsploit-tcp.log

# GITDORKS: Github dork attack
vared -p "[*] Please enter a target for git gorks search: " -c git_target
if [ ! -z ${git_target} ]; then /usr/bin/gitdorks -target $git_target -nws 20 -ew 3\
 -token $githubToken -gd /home/shyngys/Tools/gitdorks_go/Dorks/smalldorks.txt | tee ${workingDir}gitdorks-$git_target.log;
fi

#NUCLEI : scan for common vulns
vared -p "[*] Run nuclei?[y]" -c nucleiAnswer
if [ $nucleiAnswer = 'y' ]; then /home/shyngys/.pdtm/go/bin/nuclei -tags cve,panel,exposure,osint,misconfig -l ${workingDir}ips.txt
fi

# NMAP rerun with all-ports config
vared -p "[*] Rerun Nmap scanning against all TCP ports?[y]" -c nmapRerun
if [ $nmapRerun = 'y' ]; then
    nmapOutputBasenameRepeat=nmap-all-ports-tcp-`date '+%d-%m-%Y-%H:%M'`
    sudo /usr/bin/nmap -T4 -sS -sV --script="(default or discovery) and not broadcast and not http*" -p- -vv -iL ${workingDir}ips.txt -oA ${workingDir}$nmapOutputBasenameRepeat
    sudo /usr/bin/nmap -T4 -sU -sV --top-ports=100 -vv -iL ${workingDir}ips.txt -oA ${workingDir}$nmapOutputBasenameRepeat-udp
    echo "[*] Creating html report from nmap scan..."
    /usr/bin/xsltproc ${workingDir}$nmapOutputBasenameRepeat.xml -o ${workingDir}$nmapOutputBasenameRepeat.html
    /usr/bin/xsltproc ${workingDir}$nmapOutputBasenameRepeat-udp.xml -o ${workingDir}$nmapOutputBasenameRepeat-udp.html
    vared -p "[*] Open html reports?[y]" -c open_report
    if [ $open_report = 'y' ]; then /home/shyngys/Downloads/firefox/firefox file://${workingDir}$nmapOutputBasenameRepeat*.html; fi

    # extract additional HTTP port numbers from nmap output for each host ip address
    echo "[*] Analyzing nmap report. Generating url list for scanning..."
    [[ ! -d ${workingDir}http-ports-by-host ]] && mkdir ${workingDir}http-ports-by-host;\
    cat ${workingDir}ips.txt | while read line;\
      do grep $line ${workingDir}$nmapOutputBasenameRepeat.gnmap | grep Ports |\
      awk '{for (i=4;i<=NF;i++) {split($i,a,"/");if (a[5] ~ /(ssl|)?http.*/) print a[1];}}' >> ${workingDir}http-ports-by-host/$line-http-ports-extended.txt;
      done

    # regenerate list in format <http(s)://DOMAIN:PORT> from 3 lists: IPs, domains, ports for further validating
    cat ${workingDir}ips.txt | while read line;\
    do cat ${workingDir}domains-by-host/$line-domains.txt | while read domain;\
      do cat ${workingDir}http-ports-by-host/$line-http-ports-extended.txt | while read port;\
      do echo $domain:$port >> ${workingDir}target-domains-ports-extended-raw.txt;\ 
      done;
      done;
    done
    cat ${workingDir}target-domains-ports-extended-raw.txt | while read host; do
        if [[ $host =~ ':80$' ]]; then echo $host | sed -e 's/:80//' -e 's/^/http:\/\//' >> ${workingDir}target-domains-ports-extended.txt
        elif [[ $host =~ ':443$' ]]; then echo $host | sed -e 's/:443//' -e 's/^/https:\/\//' >> ${workingDir}target-domains-ports-extended.txt
        else echo $host | sed -e 's/^/http:\/\//' >> ${workingDir}target-domains-ports-extended.txt
        fi
    done
        
    # HTTPX: validate and fingerprint http services from domain list
    echo "[*] Fingerprinting applications with httpx..."
    /home/shyngys/go/bin/httpx -l ${workingDir}target-domains-ports-extended.txt -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o ${workingDir}httpx-extended.log -oa -srd ${workingDir}httpx-output-extended
    /home/shyngys/Downloads/firefox/firefox file://${workingDir}httpx-output-extended/screenshot/screenshot.html 

    # extract valid URLs from httpx log
    awk -F ' ' -e '$2 ~ /404]$/ {print $1}' ${workingDir}httpx-extended.log | grep -v -E '^https://.*:80$' | tee ${workingDir}httpx-404-urls-extended.txt
    cat ${workingDir}httpx-extended.log | cut -d ' ' -f 1 | grep -v -E '^https://.*:80$' | grep -v -E '^http://.*:443$' | tee ${workingDir}httpx-urls-extended.txt
fi