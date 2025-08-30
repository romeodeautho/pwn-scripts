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
    else echo "ERROR: Invalid port range. Enter a number between 1 and 65535.";
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

currdate=`date '+%d-%m-%Y-%H:%M'`
new_hosts_filename="new-hosts-$currdate.txt"
new_hosts_bruted_filename="new-hosts-bruted-$currdate.txt"

################################################################################################################
# -------------------------------------------------------Functions---------------------------------------------#
################################################################################################################

function passive_DNS_recon() {
    # SUBFINDER: find subdomains for root domains
        cat ${workingDir}root-domains.txt | subfinder | anew ${workingDir}target-hostnames.txt | tee ${workingDir}$new_hosts_filename
    
    # PUNCIA: find subdomains for root domains
    cat ${workingDir}root-domains.txt | while read line; do
    puncia subdomain $line > ${workingDir}puncia-subs-$line.txt;
    done
    cat ${workingDir}puncia-subs-* | tr -d ', []"' | sed '/^$/d' |\
    grep -E '^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}(:[0-9]+)?$' |\
      sort -u | anew -d ${workingDir}target-hostnames.txt | tee -a ${workingDir}$new_hosts_filename
 
    # GITHUB-SUBDOMAINS: search subdomains on Github and validate
    githubToken=`cat /home/shyngys/intel/.token`
    while read -r line; do github-subdomains -d $line -t $githubToken\
    -o ${workingDir}github-subdomains-$line.txt;
    done < ${workingDir}root-domains.txt
}

function subdomainBrute() {
    if ! [ -d ${dnsxOutputDir} ]; then mkdir ${dnsxOutputDir}; fi
    
    echo "Starting active subdomain enumeration..."
    
    # bruteforcing subdomains with NOERROR technique
    dnsx -nc -a -resp -v -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt\
      -d ${workingDir}root-domains.txt -rcode noerror > ${dnsxOutputDir}dnsx-subs-brute-noerror.log;
    cat ${dnsxOutputDir}dnsx-subs-brute-noerror.log | cut -d ' ' -f 1 > ${dnsxOutputDir}dnsx-brute-subs-list.txt;
    cat ${dnsxOutputDir}dnsx-brute-subs-list.txt | dnsx -nc -asn -recon -e axfr > ${dnsxOutputDir}dnsx-brute-resolve.log;
    cat ${dnsxOutputDir}dnsx-brute-resolve.log | grep '\[A\]' | cut -d ' ' -f3 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${dnsxOutputDir}dnsx-brute-ips.txt;
    cat ${dnsxOutputDir}dnsx-brute-resolve.log | grep '\[A\]' | cut -d ' ' -f1 | tr -d "[]" | sort -u | grep -v '127.0.0.1' > ${dnsxOutputDir}dnsx-subs-bruted-resolved-to-a.txt

    # select only subdomains with NOERROR response code and without a Resource Record
    grep -F -x -v -f ${dnsxOutputDir}dnsx-subs-bruted-resolved-to-a.txt ${dnsxOutputDir}dnsx-brute-subs-list.txt | tee ${dnsxOutputDir}dnsx-subs-bruted-no-rr.txt;
    
    vared -p "[*] Run puredns for subdomain bruteforce? (WARNING: can be extremely stressful for a network!)[y]" -c purednsRun
    if [ $purednsRun = 'y' ]; then
    wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt;
    puredns bruteforce /usr/share/seclists/Discovery/DNS/combined_subdomains.txt\
    -d ${workingDir}root-domains.txt -r ${workingDir}resolvers.txt -w ${workingDir}pure-subs.txt;
    fi

    echo "[*] Following subdomains were found during DNS enumeration:"
    cat ${workingDir}pure-subs.txt ${dnsxOutputDir}dnsx-subs-bruted-resolved-to-a.txt
    
    vared -p "Append them to the main target list?[y]" -c mergeBrutedSubs
    if [[ $mergeBrutedSubs = 'y' ]]; then
    cat ${workingDir}pure-subs.txt ${dnsxOutputDir}dnsx-subs-bruted-resolved-to-a.txt | sort -u | anew -q ${workingDir}target-hostnames.txt | tee $new_hosts_bruted_filename;
    fi
}

function dnsxRun() {
    # DNSX: run DNS resolving on a domain list
    if ! [ -d ${dnsxOutputDir} ]; then mkdir ${dnsxOutputDir}; fi
    cat ${workingDir}target-hostnames.txt | dnsx -nc -asn -recon -e axfr | anew -q ${dnsxOutputDir}dnsx-resolve.log
    
    # extract NS server domains from dnsx log
    cat ${dnsxOutputDir}dnsx-resolve.log | grep 'NS\|SOA' | cut -d ' ' -f 3 | tr -d '[]' | sort -u | anew -q ${workingDir}ns.txt

    # extract IP addresses from dnsx.log
    cat ${dnsxOutputDir}dnsx-resolve.log | grep '\[A\]' | cut -d ' ' -f3 | tr -d "[]" | sort -u | grep -v '127.0.0.1' | anew -q ${workingDir}ips.txt
    
    grep '\[A\]' ${dnsxOutputDir}dnsx-resolve.log | awk -F '[' 'BEGIN {OFS = FS}  {print $3,"| ",$1,"| ",$4}' | tr -d '[]' | sort -u > ${dnsxOutputDir}basic-resolve-list.txt

    # DNSX PTR resolve
    echo "[*] Resolving IP addresses to PTR records..."
    dnsx -l ${workingDir}ips.txt -nc -ptr -resp | cut -d ' ' -f3 | tr -d '[]' | anew -q ${dnsxOutputDir}dnsx-ptr.txt
}

function portscan() {
    if ! [ -d ${nmapOutputDir} ]; then mkdir ${nmapOutputDir}; fi
    if [[ -z {$topPorts} ]]; then topPorts='4000'; fi
    nmapOutputBasename=nmap-${topPorts}-ports-tcp-$currdate
    smapOutputBasename=smap-$currdate
    sudo /usr/bin/nmap -T4 -sS -sV --top-ports=${topPorts} --script=asn-query -vv -iL ips.txt -oA ${nmapOutputDir}$nmapOutputBasename
    smap -iL ips.txt -oA ${nmapOutputDir}$smapOutputBasename

    echo "[*] Creating html report from nmap and smap scan logs..."
    
    /usr/bin/xsltproc ${nmapOutputDir}$nmapOutputBasename.xml -o ${nmapOutputDir}$nmapOutputBasename.html
    /usr/bin/xsltproc ${nmapOutputDir}$smapOutputBasename.xml -o ${nmapOutputDir}$smapOutputBasename.html

    /usr/bin/chromium &;
    sleep 3
    /usr/bin/chromium file://${nmapOutputDir}$nmapOutputBasename.html
    /usr/bin/chromium file://${nmapOutputDir}$smapOutputBasename.html
    
    searchsploit --nmap ${nmapOutputDir}$nmapOutputBasename.xml | tee -a ${workingDir}searchsploit-tcp.log
    searchsploit --nmap ${nmapOutputDir}$smapOutputBasename.xml | tee -a ${workingDir}searchsploit-smap.log
}

function extendedPortscan() {
    if ! [ -d ${nmapOutputDir} ]; then mkdir ${nmapOutputDir}; fi
    sudo /usr/bin/nmap -T4 -sS -sV --script="(default or discovery) and not broadcast and not http*" -p- -vv -iL ${workingDir}ips.txt -oA ${nmapOutputDir}$nmapOutputBasenameRepeat
    sudo /usr/bin/nmap -T4 -sU -sV --top-ports=100 -vv -iL ${workingDir}ips.txt -oA ${nmapOutputDir}$nmapOutputBasenameRepeat-udp
    
    echo "[*] Creating html report from nmap scan..."
    
    /usr/bin/xsltproc ${nmapOutputDir}$nmapOutputBasenameRepeat.xml -o ${nmapOutputDir}$nmapOutputBasenameRepeat.html
    /usr/bin/xsltproc ${nmapOutputDir}$nmapOutputBasenameRepeat-udp.xml -o ${nmapOutputDir}$nmapOutputBasenameRepeat-udp.html
    
    /usr/bin/chromium file://${nmapOutputDir}${nmapOutputBasenameRepeat}*.html
    
    searchsploit --nmap ${nmapOutputDir}$nmapOutputBasenameRepeat.xml | tee -a ${workingDir}searchsploit-tcp-extended.log   
    searchsploit --nmap ${nmapOutputDir}$nmapOutputBasenameRepeat-udp.xml | tee -a ${workingDir}searchsploit-tcp-extended-udp.log
}

function parseNmapOutput() {
    # FUNCTION REQUIRES A .GNMAP FILE AS AN ARGUMENT
    
    echo "[*] Analyzing nmap report. Generating url list for probing..."
    
    grep "Up$" ${1} | awk '{print $2}' > ${workingDir}ips-alive.txt

    # extract HTTP port numbers from nmap output for each host (ip address)
    [[ ! -d ${workingDir}http-ports-by-host ]] && mkdir ${workingDir}http-ports-by-host;\
    cat ${workingDir}ips.txt | while read line; do
        grep $line ${1} |\
        grep Ports | awk '{for (i=4;i<=NF;i++) {split($i,a,"/");if (a[5] ~ /(ssl|)?http.*|tcpwrapped/) print a[1];}}' |\
        anew -q ${workingDir}http-ports-by-host/$line-http-ports.txt; done

    # extract domain names associated with each IP address (for vhosts enumeration) and put them in separate files
    [[ ! -d ${workingDir}domains-by-host ]] && mkdir ${workingDir}domains-by-host; cat ${workingDir}ips.txt |\
    while read -r line; do                                          # LOOKS LAME, NEED TO REFACTOR!!!
        domains=`grep $line ${dnsxOutputDir}dnsx-resolve.log | cut -d ' ' -f1`;
        if [[ ! -z ${domains} ]]; then echo "${domains}"; fi | anew -q ${workingDir}domains-by-host/$line-domains.txt;
    done

    # generate list in format <HOSTNAME:PORT> from 3 lists: IPs, domains, ports for further validating
    cat ${workingDir}ips.txt | \
    while read line; do
        cat ${workingDir}domains-by-host/$line-domains.txt | \
        while read domain; do 
            cat ${workingDir}http-ports-by-host/$line-http-ports.txt | \
            while read port; do 
            echo $domain:$port | anew -q ${workingDir}target-domains-ports-raw.txt; 
            done; 
        done; 
    done
    
    # creating URL list from HOSTNAME:PORT list and prepending URL scheme
    cat ${workingDir}target-domains-ports-raw.txt | while read host; do
        if [[ $host =~ ':80$' ]]; then echo $host | sed -e 's/:80//' -e 's/^/http:\/\//' | anew -q target-urls-for-probe.txt
        elif [[ $host =~ ':443$' ]]; then echo $host | sed -e 's/:443//' -e 's/^/https:\/\//' | anew -q target-urls-for-probe.txt
        else echo $host | sed -e 's/^/http:\/\//' | anew -q target-urls-for-probe.txt
        fi
    done
}

function nucleiScan() {
#    /home/shyngys/.pdtm/go/bin/nuclei -tags panel,exposure,osint,misconfig -no-httpx -stats -o ${workingDir}nuclei-${currdate}.log -l ${workingDir}ips-alive.txt
    /home/shyngys/.pdtm/go/bin/nuclei -t network -etags intrusive,c2,honeypot -no-httpx -stats -o ${workingDir}nuclei-${currdate}.log -l ${workingDir}ips-alive.txt
}

function httpProbe() {
    # HTTPX: validate and fingerprint http services from domain list
    echo "[*] Fingerprinting applications with httpx..."
    
    /home/shyngys/.pdtm/go/bin/httpx -l ${workingDir}target-urls-for-probe.txt \
    -td -server -efqdn -cname -cdn -asn -ip -sc -ss -nc -fr -o ${workingDir}httpx.log -oa -srd ${workingDir}httpx-output
    /usr/bin/chromium file://${workingDir}httpx-output/screenshot/screenshot.html

    # extract valid URLs from httpx log
    awk -F ' ' -e '$2 ~ /404]$/ {print $1}' ${workingDir}httpx.log | grep -v -E '^https://.*:80$' | anew ${workingDir}httpx-404-urls.txt
    cat ${workingDir}httpx.log | cut -d ' ' -f 1 | grep -v -E '^https://.*:80$' | grep -v -E '^http://.*:443$' | sort -u | anew ${workingDir}httpx-valid-urls.txt | tee ${workingDir}httpx-new-valid-urls-${currdate}.txt
    cat ${workingDir}httpx.log | awk -F'[' '{print $1,"["$5,"["$4}' | sort -u | anew ${workingDir}httpx-ip-asn.txt

    if [[ -s ${workingDir}httpx-valid-urls.txt ]]; then  
        /home/shyngys/go/bin/gowitness scan file -f ${workingDir}httpx-valid-urls.txt --write-db --write-screenshots --write-jsonl --threads 20 --chrome-proxy http://127.0.0.1:8080
        source ${HOME}/Tools/FavFreak/venv/bin/activate
        cat ${workingDir}httpx-valid-urls.txt | python3 ~/Tools/FavFreak/favfreak.py -o ${workingDir}favfreak-output.txt
        deactivate
    fi
}

function githubDorks () {
    # GITDORKS: Github dork attack
    vared -p "[*] Please enter a target for git gorks search: " -c git_target
    
    if [[ ! -z ${git_target} ]]; then /usr/bin/gitdorks -target $git_target -nws 20 -ew 3\
    -token $githubToken -gd /home/shyngys/Tools/gitdorks_go/Dorks/medium_dorks.txt | tee ${workingDir}gitdorks-$git_target.log;
    fi
}
##############################################################################################################
##########                                     END FUNCTIONS                                        ##########
##############################################################################################################

# setting up a working directory for the script
if [[ -z $dirOption ]]; then workingDir="$(pwd)/"; else
    if [[ -d $dirOption ]]; then
        if [[ $dirOption =~ /$ ]]; then workingDir=$dirOption;  
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

if [[ ! -f ${workingDir}scope.txt ]];
     then echo "scope.txt not found in the program directory"; exit 1;
fi

if ! [ -d ${nmapOutputDir} ]; then mkdir ${nmapOutputDir}; fi

# extract second level domains from wildcard entries
grep -E '\*\.' ${workingDir}scope.txt | sed 's/\*\.//g' | anew -q ${workingDir}root-domains.txt
cat ${workingDir}root-domains.txt | anew -q ${workingDir}target-hostnames.txt

# extract non-wildcard domain entries without scheme
cat ${workingDir}scope.txt | grep -v '*' | grep -Ev '^https?' | \
grep -Ev '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]{1,2}$' | anew -q ${workingDir}target-hostnames.txt

# extract HTTP URLs
cat ${workingDir}scope.txt | grep -Ev '\*\.' | grep -E '^https?://' | anew -q ${workingDir}target-urls-for-probe.txt

# extract only IP addresses
cat ${workingDir}scope.txt | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[:/0-9]*$' | anew -q ${workingDir}ip-scope.txt
cat ${workingDir}ip-scope.txt | anew -q ${workingDir}ips.txt

grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]{1,2}$' ${workingDir}scope.txt | anew -q ${workingDir}cidr-scope.txt
/usr/bin/python3 /home/shyngys/pwn-scripts/cidr_to_list_convert.py ${workingDir}cidr-scope.txt
cat ${workingDir}ip_list.txt | anew -q ${workingDir}ips.txt

# make a regex version of scope list for BurpSuite
sed -e 's/\./\\./g' -e 's/\*\\\./\(.*\\.\)?/' -re 's/(^[^\(])/^\1/' \
-e 's/$/\(:[0-9]+\)?$/'  ${workingDir}scope.txt | anew -q ${workingDir}scope-regex.txt

# passively enumerate subdomains for root domains
if [[ -s ${workingDir}root-domains.txt ]]; then
    passive_DNS_recon
fi

if [ ! -z $dnsBruteforceFlag ] && [[ $dnsBruteforceFlag == 'true' ]]; then
    subdomainBrute
fi

# DNSX recon against target domains
if [[ -s ${workingDir}target-hostnames.txt ]]; then
    dnsxRun
fi

if [[ -s ${workingDir}ips.txt ]]; then
    echo "IP addresses in scope:"
    /usr/bin/cat ${workingDir}ips.txt
    echo "Press any key to proceed"
    read -krs
    portscan
fi

# create list of URLs for http probes
if [[ -s ${nmapOutputDir}${nmapOutputBasename}.gnmap ]]; then
    parseNmapOutput ${nmapOutputDir}${nmapOutputBasename}.gnmap
fi

# run http probes against a target list
if [[ -s ${workingDir}target-urls-for-probe.txt ]]; then
    httpProbe
fi

#if [[ -s ${workingDir}target-hostnames.txt ]]; then
#    echo "[*] Getting historical URLs from Web Archive..."
#    cat ${workingDir}target-hostnames.txt | gau -v -t 5 > ${workingDir}gau-output-alldomains.log
#fi

if [ ! -z $nucleiScanFlag ] && [[ $nucleiScanFlag == 'true' ]]; then
nucleiScan
fi

# rerun portscanning and http probes with all-ports config
if [ ! -z $extendedScansFlag ] && [[ $extendedScansFlag == 'true' ]]; then
    nmapOutputBasenameRepeat=nmap-all-ports-tcp-`date '+%d-%m-%Y-%H:%M'`
    extendedPortscan
    parseNmapOutput ${nmapOutputDir}${nmapOutputBasenameRepeat}.gnmap
    httpProbe
fi