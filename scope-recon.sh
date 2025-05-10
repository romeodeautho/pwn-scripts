#!/bin/zsh

while getopts ":d:p:ben" opt; do
  case $OPTARG in
   -*) echo "ERROR: Incorrect arguments."
  exit 1;;
  esac
  case $opt in
    d) dirOption=$OPTARG
    ;;
    p) if [ $OPTARG -gt 0 ] && [ $OPTARG -lt 65536 ]; then topPorts=$OPTARG;
    else echo "ERROR: Invalid port range. Maximum amount of TCP ports to scan is 65535.";
    exit 1; fi
    ;;
    b) dnsBruteforceFlag='true'
    ;;
    e) extendedScansFlag='true'
    ;;
    n) nucleiScanFlag='true'
    ;;
    "?") echo "Invalid option: -$OPTARG. Use -h to get help." >&2
    exit 1
    ;;
    ":") echo "Error: empty value for the argument -$OPTARG"
    exit 1
    ;;
  esac
done

######################################################################################################
# ---------------------------------------------Functions---------------------------------------------#
######################################################################################################

function passive_DNS_recon() {
    # SUBFINDER: find subdomains for root domains
    cat ${workingDir}root-domains.txt | /home/shyngys/go/bin/subfinder >> ${workingDir}target-domains.txt

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
}

function subdomainBrute() {
  dnsx -nc -a -resp -v -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt\
    -d ${dnsxOutputDir}root-domains.txt -rcode noerror > ${dnsxOutputDir}dnsx-subs-brute-noerror.log;
  cat ${dnsxOutputDir}dnsx-subs-brute-noerror.log | cut -d ' ' -f 1 > ${dnsxOutputDir}dnsx-brute-subs-list.txt;
  cat ${dnsxOutputDir}dnsx-brute-subs-list.txt | dnsx -nc -asn -recon -e axfr > ${dnsxOutputDir}dnsx-brute-resolve.log;
  cat ${dnsxOutputDir}dnsx-brute-resolve.log | grep '\[A\]' | cut -d ' ' -f3 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${dnsxOutputDir}dnsx-brute-ips.txt;
  cat ${dnsxOutputDir}dnsx-brute-resolve.log | grep '\[A\]' | cut -d ' ' -f1 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${dnsxOutputDir}dnsx-subs-bruted-resolved-to-a.txt

  # select only subdomains with NOERROR response code and without a Resource Record
  grep -F -x -v -f ${dnsxOutputDir}dnsx-subs-bruted-resolved-to-a.txt ${workingDir}dnsx-brute-subs-list.txt | tee ${workingDir}dnsx-subs-bruted-no-rr.txt;
  
  vared -p "[*] Run puredns for subdomain bruteforce? (can be very stressful for a network)[y]" -c purednsRun
  if [ $purednsRun = 'y' ]; then
  wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt;
  puredns bruteforce /usr/share/seclists/Discovery/DNS/combined_subdomains.txt\
   -d ${workingDir}root-domains.txt -r ${workingDir}resolvers.txt -w ${workingDir}pure-subs.txt;
  fi

  echo "[*] Following subdomains were found during DNS enumeration:"
  
  vared -p "Append them to the main target list?[y]" -c mergeBrutedSubs
  if [[ $mergeBrutedSubs = 'y' ]]; then
  cat ${workingDir}pure-subs.txt ${dnsxOutputDir}dnsx-brute-subs-list.txt | sort -u | anew -t ${workingDir}target-domains.txt
  fi
}

function dnsxRun() {
    # DNSX: run DNS resolving on a domain list
    if ! [ -d ${dnsxOutputDir} ]; then mkdir ${dnsxOutputDir}; fi
    cat ${workingDir}target-domains.txt | dnsx -nc -asn -recon -e axfr > ${dnsxOutputDir}dnsx-resolve.log
    # extract NS server domains from dnsx log
    cat ${dnsxOutputDir}dnsx-resolve.log | grep 'NS\|SOA' | cut -d ' ' -f 3 | tr -d '[]' | sort -u > ${workingDir}ns.txt

    # extract IP addresses from dnsx.log
    cat ${dnsxOutputDir}dnsx-resolve.log | grep '\[A\]' | cut -d ' ' -f3 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${workingDir}ips.txt
    # DNSX PTR resolve
    echo "[*] Resolving IP addresses to PTR records..."
    dnsx -l ${workingDir}ips.txt -nc -ptr -resp | cut -d ' ' -f3 | tr -d '[]' > ${dnsxOutputDir}dnsx-ptr.txt
}

function portscan() {
    # NMAP scan against the IP address list
    if ! [ -d ${nmapOutputDir} ]; then mkdir ${nmapOutputDir}; fi
    
    nmapOutputBasename=nmap-${topPorts}-ports-tcp-`date '+%d-%m-%Y-%H:%M'`
    sudo /usr/bin/nmap -T4 -sS -sV --top-ports=${topPorts} --script=asn-query -vv -iL ips.txt -oA ${nmapOutputDir}$nmapOutputBasename
    
    echo "[*] Creating html report from nmap scan..."
    
    /usr/bin/xsltproc ${nmapOutputDir}$nmapOutputBasename.xml -o ${nmapOutputDir}$nmapOutputBasename.html
    /home/shyngys/Downloads/firefox/firefox file://${nmapOutputDir}$nmapOutputBasename.html
    
    searchsploit --nmap ${nmapOutputDir}$nmapOutputBasename.xml | tee ${workingDir}searchsploit-tcp.log
}

function extendedNmap() {
    nmapOutputBasenameRepeat=nmap-all-ports-tcp-`date '+%d-%m-%Y-%H:%M'`
    sudo /usr/bin/nmap -T4 -sS -sV --script="(default or discovery) and not broadcast and not http*" -p- -vv -iL ${workingDir}ips.txt -oA ${nmapOutputDir}$nmapOutputBasenameRepeat
    sudo /usr/bin/nmap -T4 -sU -sV --top-ports=100 -vv -iL ${workingDir}ips.txt -oA ${nmapOutputDir}$nmapOutputBasenameRepeat-udp
    
    echo "[*] Creating html report from nmap scan..."
    
    /usr/bin/xsltproc ${nmapOutputDir}$nmapOutputBasenameRepeat.xml -o ${nmapOutputDir}$nmapOutputBasenameRepeat.html
    /usr/bin/xsltproc ${nmapOutputDir}$nmapOutputBasenameRepeat-udp.xml -o ${nmapOutputDir}$nmapOutputBasenameRepeat-udp.html
    
    vared -p "[*] Open html reports?[y]" -c open_report
    if [ $open_report = 'y' ]; then /home/shyngys/Downloads/firefox/firefox file://${nmapOutputDir}${nmapOutputBasenameRepeat}*.html; fi

    # extract additional HTTP port numbers from nmap output for each host (ip address)
    echo "[*] Analyzing nmap report. Generating url list for scanning..."
    [[ ! -d ${workingDir}http-ports-by-host ]] && mkdir ${workingDir}http-ports-by-host;\
    cat ${workingDir}ips.txt | while read line;\
      do grep $line ${nmapOutputDir}$nmapOutputBasenameRepeat.gnmap | grep Ports |\
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
    # creating URL list from DOMAIN:PORT list and prepending scheme
    cat ${workingDir}target-domains-ports-extended-raw.txt | while read host; do
        if [[ $host =~ ':80$' ]]; then echo $host | sed -e 's/:80$//' -e 's/^/http:\/\//' >> ${workingDir}target-urls-for-probe-extended.txt
        elif [[ $host =~ ':443$' ]]; then echo $host | sed -e 's/:443$//' -e 's/^/https:\/\//' >> ${workingDir}target-urls-for-probe-extended.txt
        else echo $host | sed -e 's/^/http:\/\//' >> ${workingDir}target-urls-for-probe-extended.txt
        fi
    done
        
    # HTTPX: validate and fingerprint http services from URL list
    echo "[*] Fingerprinting applications with httpx..."
    /home/shyngys/go/bin/httpx -l ${workingDir}target-urls-for-probe-extended.txt -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o ${workingDir}httpx-extended.log -oa -srd ${workingDir}httpx-output-extended
    /home/shyngys/Downloads/firefox/firefox file://${workingDir}httpx-output-extended/screenshot/screenshot.html 

    # extract valid URLs from httpx log
    awk -F ' ' -e '$2 ~ /404]$/ {print $1}' ${workingDir}httpx-extended.log | grep -v -E '^https://.*:80$' | tee ${workingDir}httpx-404-urls-extended.txt
    cat ${workingDir}httpx-404-urls-extended.txt | anew ${workingDir}httpx-404-urls.txt
    cat ${workingDir}httpx-extended.log | cut -d ' ' -f 1 | grep -v -E '^https://.*:80$' | grep -v -E '^http://.*:443$' | tee ${workingDir}httpx-valid-urls-extended.txt
    cat ${workingDir}httpx-extended.log | awk -F'[' '{print $1,"["$5,"["$4}' | sort -u | anew httpx-extended-ip-asn.txt
    cat ${workingDir}httpx-urls-extended.txt | anew ${workingDir}httpx-valid-urls.txt
}

function parseNmapOutput() {
    echo "[*] Analyzing nmap report. Generating url list for probing..."
    
    [[ ! -d ${workingDir}http-ports-by-host ]] && mkdir ${workingDir}http-ports-by-host;\
    cat ${workingDir}ips.txt | while read line; do grep $line ${nmapOutputDir}$nmapOutputBasename.gnmap |\
      grep Ports | awk '{for (i=4;i<=NF;i++) {split($i,a,"/");if (a[5] ~ /(ssl|)?http.*/) print a[1];}}' |\
      tee ${workingDir}http-ports-by-host/$line-http-ports.txt; done

    # extract domain names associated with each IP address (for vhosts enumeration)
    #/usr/bin/python3 /home/shyngys/scripts/httpx-domains.py
    [[ ! -d ${workingDir}domains-by-host ]] && mkdir ${workingDir}domains-by-host; cat ${workingDir}ips.txt |\
    while read -r line; do domains=`grep $line ${dnsxOutputDir}dnsx-resolve.log |\
      cut -d ' ' -f1`; echo "$domains" > ${workingDir}domains-by-host/$line-domains.txt;done

    # generate list in format <DOMAIN:PORT> from 3 lists: IPs, domains, ports for further validating
    cat ${workingDir}ips.txt | while read line;\
    do cat ${workingDir}domains-by-host/$line-domains.txt | while read domain;\
      do cat ${workingDir}http-ports-by-host/$line-http-ports.txt | while read port;\
      do echo $domain:$port | anew ${workingDir}target-domains-ports-raw.txt; done ; done; done
    cat ${workingDir}target-domains-ports-raw.txt | while read host; do
        if [[ $host =~ ':80$' ]]; then echo $host | sed -e 's/:80//' -e 's/^/http:\/\//' >> target-urls-for-probe.txt
        elif [[ $host =~ ':443$' ]]; then echo $host | sed -e 's/:443//' -e 's/^/https:\/\//' >> target-urls-for-probe.txt
        else echo $host | sed -e 's/^/http:\/\//' >> target-urls-for-probe.txt
        fi
    done
}

function nucleiScan() {
    /home/shyngys/.pdtm/go/bin/nuclei -tags cve,panel,exposure,osint,misconfig -l ${workingDir}ips.txt
}

function httpProbe() {
    # HTTPX: validate and fingerprint http services from domain list
    echo "[*] Fingerprinting applications with httpx..."
    /home/shyngys/go/bin/httpx -l ${workingDir}target-urls-for-probe.txt -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o ${workingDir}httpx.log -oa -srd ${workingDir}httpx-output
    /home/shyngys/Downloads/firefox/firefox file://${workingDir}httpx-output/screenshot/screenshot.html

    # extract valid URLs from httpx log
    awk -F ' ' -e '$2 ~ /404]$/ {print $1}' ${workingDir}httpx.log | grep -v -E '^https://.*:80$' | tee ${workingDir}httpx-404-urls.txt
    cat ${workingDir}httpx.log | cut -d ' ' -f 1 | grep -v -E '^https://.*:80$' | grep -v -E '^http://.*:443$' | sort -u | tee ${workingDir}httpx-valid-urls.txt
    cat ${workingDir}httpx.log | awk -F'[' '{print $1,"["$5,"["$4}' | sort -u | anew ${workingDir}httpx-ip-asn.txt

    if [[ -s ${workingDir}httpx-valid-urls.txt ]]; then  
        /home/shyngys/go/bin/gowitness scan file -f ${workingDir}httpx-valid-urls.txt --write-db --write-screenshots --write-jsonl --threads 20 --chrome-proxy http://127.0.0.1:8080
        cat ${workingDir}httpx-valid-urls.txt | python3 ~/Tools/FavFreak/favfreak.py -o favfreak-output.txt
    fi
}

function githubDorks () {
    # GITDORKS: Github dork attack
    vared -p "[*] Please enter a target for git gorks search: " -c git_target
    if [ ! -z ${git_target} ]; then /usr/bin/gitdorks -target $git_target -nws 20 -ew 3\
    -token $githubToken -gd /home/shyngys/Tools/gitdorks_go/Dorks/smalldorks.txt | tee ${workingDir}gitdorks-$git_target.log;
    fi
}

#######################################################################################################
#######################################################################################################

# setting up a working directory option for the script
if [[ -z $dirOption ]]; then workingDir="$(pwd)/"; else
    if [[ -d $dirOption ]]; then
        if [[ $dirOption =~ .*/$ ]]; then workingDir=$dirOption;  
        else workingDir="${dirOption}/"; 
        fi
    else echo "Directory does not exist. Check the path."; exit 1
    fi
fi

nmapOutputDir="${workingDir}nmap-output/"
dnsxOutputDir="${workingDir}dnsx-output/"
export PDCP_API_KEY=`cat /home/shyngys/Documents/.chaos-token`


if [ ! -z $dnsBruteforceFlag ] && [ $dnsBruteforceFlag = 'true' ]; then 
echo "[*] DNS bruteforce: ON."; else 
echo "[*] DNS bruteforce: OFF."
fi

if [ ! -z $extendedScansFlag ] && [ $extendedScansFlag = 'true' ]; 
then echo "[*] Extended scans: ON."; 
else echo "[*] Extended scans: OFF."; 
fi

if [ ! -z $topPorts ]; then
echo "[*] Nmap will scan $topPorts ports.";
fi

echo "The scan is ready to start. Press any key to proceed or Ctrl+C to abort."
read -krs

trap ' ' INT

# analyze scope list and extract root domain names
if [[ ! -f ${workingDir}scope.txt ]];
     then echo "scope.txt not found in the program directory"; exit 1;
fi
grep -E '\*\.' ${workingDir}scope.txt | sed 's/\*\.//g' > ${workingDir}root-domains.txt
cat ${workingDir}scope.txt | grep -v '*' | grep -vE '^https?' | sed 's/\*\.//g' > ${workingDir}target-domains.txt
cat ${workingDir}scope.txt | grep -Ev '\*\.' | grep -E '^https?://' > ${workingDir}target-urls-for-probe.txt
cat ${workingDir}root-domains.txt >> ${workingDir}target-domains.txt

# make a regex version of scope list for BurpSuite
sed -e 's/\./\\./g' -e 's/\*\\\./\(.*\\.\)?/' -re 's/(^[^\(])/^\1/' -e 's/$/$/'  ${workingDir}scope.txt > ${workingDir}scope-regex.txt

if [[ -s ${workingDir}root-domains.txt ]]; then
passive_DNS_recon
fi

if [ ! -z $dnsBruteforceFlag ] && [ $dnsBruteforceFlag = 'true' ]; then
subdomainBrute;
fi

if [[ -s ${workingDir}target-domains.txt ]]; then
    dnsxRun
fi

if [[ -s ${workingDir}ips.txt ]]; then
    echo "IP addresses in scope:"
    /usr/bin/cat ${workingDir}ips.txt
    echo "Press any key to proceed"
    read -krs
    portscan
    parseNmapOutput
fi

if [[ -s ${workingDir}target-urls-for-probe.txt ]]; then
    httpProbe;
fi

if [[ -s ${workingDir}target-domains.txt ]]; then
    echo "[*] Getting historical URLs from Web Archive..."
    cat ${workingDir}target-domains.txt | gau -t 5 > ${workingDir}gau-output-alldomains.log
fi

if [ ! -z $nucleiScanFlag ] && [ $nucleiScanFlag = 'true' ]; then
nucleiScan;
fi

if ! [ -z $extendedScansFlag ] && [ $extendedScansFlag='true' ]; then
extendedNmap;
fi