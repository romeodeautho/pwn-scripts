#!/bin/zsh

HELP="This script automates basic reconnaissance against common CTF machines.
    Usage: $0 [-h] -t [-p] [-U] [-P] [-n] [-x]
    Options:
      -h show help
      -t target (domain name, IP address, file with a list of targets) [required]
      -p number of ports to scan with Nmap
      -U username for Active Directory authentication
      -P password for Active Directory authentication
      -n Nmap gnmap output file to parse
      -x Nmap XML output file to parse
    
    If both gnmap and XML files are specified, portscan stage will be skipped."

while getopts ":p:t:U:P:n:x:h" opt; do
  case $OPTARG in
   -*) echo "ERROR: Incorrect arguments."
  exit 1;;
  esac
  case $opt in
    h) echo $HELP;
    exit 1;
    ;;
    p) topPorts=$OPTARG
    ;;
    t) target=$OPTARG
    #[[ -n $target ]] && echo "Please specify a target with -t." && exit 1;
    ;;
    U) username=$OPTARG
    ;;
    P) password=$OPTARG
    ;;
    n) gnmapFile=$OPTARG
    ;;
    x) xmlNmapFile=$OPTARG
    ;;
    "?") echo "Invalid option: '$OPTARG'.\nTry '$0 -h' for usage information." >&2
    exit 1
    ;;
    ":") echo "Error: empty value for the argument -$OPTARG"
    exit 1
    ;;
  esac
done

########################################################################################################################
##############################---------------------------FUNCTIONS---------------------------###########################
########################################################################################################################
function waitForAnyKey() {
    echo "Press any key to continue..."
    read -krs
}

function portscan () {
    while true; do
    vared -p "Select Nmap scan mode:
    1) Simple TCP
    2) TCP -sV -sC
    3) TCP -p- -sC -sV -O
    4) TCP --top-ports ${topPorts} -sV -sC -O + UDP (100 ports)
    5) TCP -p- -sV --script=extended -O + UDP (100 ports)
    6) Skip
    " -c nmapType

    nmapLogBaseName=nmap-$(date "+%d-%m-%Y-%H-%M");
    nmapLogNameGnmap=nmap-$(date "+%d-%m-%Y-%H-%M").gnmap;
    nmapLogNameXML=nmap-$(date "+%d-%m-%Y-%H-%M").xml;
    nmapLogBaseNameUDP=nmap-$(date "+%d-%m-%Y-%H-%M")-udp;
    nmapLogNameGnmapUDP=nmap-$(date "+%d-%m-%Y-%H-%M")-udp.gnmap;
    nmapLogNameXMLUDP=nmap-$(date "+%d-%m-%Y-%H-%M")-udp.xml; 

    case $nmapType in
    '1') 
    echo "Performing standard nmap enumeration..."
    nmap -vv -oA $nmapLogBaseName -Pn --disable-arp-ping -iL $nmapTarget
    break
    ;;
    '2') 
    echo "Performing nmap scan with service detection and default scripts..."
    nmap -sV -sC -vv -oA $nmapLogBaseName -Pn --disable-arp-ping -iL $nmapTarget
    break
    ;;
    '3') 
    echo "Performing all-ports TCP scan with OS fingerprint and default scripts..."
    nmap -sV -sC -p- -vv -oA $nmapLogBaseName -Pn -O --disable-arp-ping -iL $nmapTarget
    break
    ;;
    '4') 
    echo "Performing basic TCP + UDP scan..."
    nmap -sV -sT --script="(default or discovery) and not broadcast and not http*" --top-ports $topPorts -vv -oA $nmapLogBaseName -Pn --disable-arp-ping -iL $nmapTarget
    vared -p "Scan UDP ports?[y]" -c udpAnswer
    [[ $udpAnswer == "y" ]] && nmap -sU -sV --top-ports=150 -vv -oA $nmapLogBaseNameUDP -Pn --disable-arp-ping -iL $nmapTarget;
    break
    ;;
    '5')
    echo "Performing all-ports TCP and basic UDP scan with OS fingerprint and safe scripts..."
    nmap -p- -sT -sV --script="(default or discovery) and not broadcast and not http*" -vv -oA $nmapLogBaseName -Pn -O --disable-arp-ping -iL $nmapTarget
    vared -p "Scan UDP ports?[y]" -c udpAnswer
    [[ $udpAnswer == "y" ]] && nmap -sU -sV --top-ports=150 -vv --disable-arp-ping -oA $nmapLogBaseNameUDP -Pn -iL $nmapTarget;
    break
    ;;
    '6' )
    break
    ;;
    *)
    echo "Wrong answer."
    ;;
    esac
    done
}

function nmapOutputToHTML() {
    [[ -f ${nmapLogNameXML} ]] && /usr/bin/xsltproc $nmapLogNameXML -o $nmapLogBaseName.html
    [[ -f ${nmapLogNameXMLUDP} ]] && /usr/bin/xsltproc $nmapLogNameXMLUDP -o $nmapLogBaseNameUDP.html
}

function searchsploitRun() {
    if [[ -f "${nmapLogNameXML}" ]]; then
    searchsploit --nmap $nmapLogNameXML | tee searchsploit-tcp.log
    fi
    if [[ -f "${nmapLogNameXMLUDP}" ]]; then
    searchsploit --nmap $nmapLogNameXMLUDP | tee searchsploit-udp.log
    fi
}

function parseForPorts() {
    openPorts=()
    openPorts+=($(cat $nmapLogNameGnmap | \
        awk '{for (i=4;i<=NF;i++) {
            split($i,a,"/");
            if (a[2]=="open") print a[1];}
        }'))

    #parsing open port numbers from nmap output file and creating a string
    openPortsList=$(cat $nmapLogNameGnmap | awk '{for (i=4;i<=NF;i++) {
        split($i,a,"/");
        if (a[2]=="open") printf ",%s",a[1];}}' | sed -e 's/,//')

    #parsing open http port numbers from nmap output file and creating an array
    openHttpPorts=()
    openHttpPorts+=($(cat $nmapLogNameGnmap | awk '{for (i=4;i<=NF;i++) {
        split($i,a,"/");
        if (a[5] ~ /(ssl|)?http.*/) print a[1];}
        }'))
}

function generate_url_list {
    echo "Generating URL list for HTTPX..."
    for port in $openPorts; echo "http://$1:${port}" | anew -q target-with-ports.txt;
    for port in $openPorts; echo "https://$1:${port}" | anew -q target-with-ports.txt;
}

function httpxRun() {
    echo "Following URLs will be tested with httpx: "
    cat target-with-ports.txt
    waitForAnyKey
    clear
    httpx -l target-with-ports.txt -nc -sc -server -td -location -ss -fr -o httpx.log -oa -srd httpx-output
    /home/shyngys/Downloads/firefox/firefox file://`pwd`/httpx-output/screenshot/screenshot.html
}

function ffufRun() {
    ffufOutputDir='ffuf-output'
    if [[ ! -d ${ffufOutputDir} ]]; then mkdir $ffufOutputDir; fi

    vared -p "[*] Run ffuf through Burp?[y]" -c replayProxy
    if [[ $replayProxy == 'y' ]]; then
    replayProxyOption="-replay-proxy http://127.0.0.1:8080";
    else
    replayProxyOption="";
    fi
    
    trap ' ' INT

    cat httpx-valid-urls.txt | \
    while read line; do
        hostname=`echo $line | awk -F '//' '{print $2}' | awk -F ':' '{print $1}'`
        echo "/usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt \
        -u ${line}/FUZZ $replayProxyOption -o ${ffufOutputDir}/ffuf-${hostname}-ds-$(date '+%d-%m-%Y-%s').html -of html;" | zsh
        echo "/usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/common.txt \
        -u ${line}/FUZZ $replayProxyOption -o ${ffufOutputDir}/ffuf-${hostname}-common-$(date '+%d-%m-%Y-%s').html -of html;" | zsh
        echo "/usr/bin/ffuf -sf -v -ic -r -ac -w /usr/share/seclists/Discovery/Web-Content/trickest-robots-disallowed-wordlists/top-100.txt \
        -u ${line}/FUZZ $replayProxyOption -o ${ffufOutputDir}/ffuf-${hostname}-common-$(date '+%d-%m-%Y-%s').html -of html;" | zsh
        vared -p "[*] Run with a directory list?[y]" -c useDirlist
        if [[ $useDirlist == 'y' ]]; then
        echo "/usr/bin/ffuf -sf -v -ic -r -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
        -u ${line}/FUZZ/ $replayProxyOption -o ${ffufOutputDir}/ffuf-dirmed-${hostname}-`date '+%d-%m-%Y-%s'`.html -of html;" | zsh
        fi
    done

    vared -p "[*] Open ffuf reports in a browser?[y]" -c openReports
    if [[ $openReports == 'y' ]]; then
    /home/shyngys/Downloads/firefox/firefox ${ffufOutputDir}/*.html &
    fi
}

function nucleiRun() {
    trap ' ' INT
    vared -p "[*] Run Nuclei?[y]" -c run_nuclei
    if [[ $run_nuclei == 'y' ]]; then
    while true; do
        vared -p "What type of nuclei scan do you want?
        1) Full, all tags
        2) Standard without wordpress
        3) Standard without client-side(XSS)
        4) Standard without wordpress and client-side(XSS)
        5) Include custom tags
        " -c nucleiChoice

        nucleiLogName=nuclei-$(date "+%d-%m-%Y-%H-%M").log

        case $nucleiChoice in
        "1") echo "nuclei $nucleiTarget -stats -o $nucleiLogName" | zsh
        break
        ;;
        "2") echo "nuclei $nucleiTarget -etags wordpress,wp-plugin,wpscan -stats -o $nucleiLogName" | zsh
        break
        ;;
        "3") echo "nuclei $nucleiTarget -etags xss -stats -o $nucleiLogName" | zsh
        break
        ;;
        "4") echo "nuclei $nucleiTarget -etags wordpress,wp-plugin,wpscan,xss -stats -o $nucleiLogName" | zsh
        break
        ;;
        "5") read -p "[*] Specify tags to include, comma separated: " tags_line
        [[ ! -z $tags_line ]] && echo "nuclei $nucleiTarget -tags $tags_line -stats -o $nucleiLogName" | zsh
        break
        ;;
        esac
    done 
    fi
    waitForAnyKey
}

function ADRecon() {
    if [[ $(echo ${openPorts[@]} | grep -E '88') ]]; then
        echo "The target machine seems to be a Domain Controller."
        vared -p "Want to run a basic Active Directory enumeration?" -c ADenumAnswer
    fi

    if [[ $ADenumAnswer == 'y' ]]; then
        echo "[*] Running enum4linux..."
        enum4linux-ng -A $target -u "$username" -p "$password" | tee enum4linux-$target-$username.log
        
        echo "[*] Running basic SMB enum..."
        nxc smb $target -u "$username" -p "$password" --users --shares --pass-pol --loggedon-users | tee smb_basic_enum_$username.log
        
        nxc smb $target -u "$username" -p "$password" --rid-brute 8000 | grep SidTypeUser | awk '{print $6}' | cut -d '\' -f2 | \
        grep -E '^[0-9A-Za-z\._\$]+$' --only-match | grep -v -i "administrator\|krbtgt\|guest" | tee rid-brute-$username.log
        
        nxc smb $target -u "$username" -p "$password" --users | awk '{print $5}' | grep -E '^[0-9A-Za-z\._]+$' --only-match | \
        grep -v -i "administrator\|krbtgt\|guest" | tee domain_users_$username.txt
        
        echo "[*] Spidering shares..."
        nxc smb $target -u "$username" -p "$password" -M spider_plus -o DOWNLOAD_FLAG=1 OUTPUT_FOLDER=`pwd` | tee -a smb_basic_enum_$username.log
        
        echo "[*] Checking for GPP passwords and autologon info..."
        nxc smb $target -u "$username" -p "$password" -M gpp_autologin | tee -a smb_basic_enum_$username.log
        nxc smb $target -u "$username" -p "$password" -M gpp_password | tee -a smb_basic_enum_$username.log
        
        echo "[*] Enumerating Certificate authorities..."
        nxc smb $target -u "$username" -p "$password" -M enum_ca | tee -a smb_basic_enum_$username.log
        
        echo "[*] Checking if spooler service is running on the target..."
        nxc smb $target -u "$username" -p "$password" -M spooler | tee -a smb_basic_enum_$username.log
        
        echo "[*] Checking if the target is vulnerable to ceorcing attacks..."
        nxc smb $target -u "$username" -p "$password" -M coerce_plus | tee -a smb_basic_enum_$username.log
        
        echo "[*] Testing for Zerologon..."
        nxc smb $target -u "$username" -p "$password" -M zerologon | tee -a smb_basic_enum_$username.log
        
        echo "[*] Running basic LDAP enum..."
        nxc ldap $target -u "$username" -p "$password" --users --get-sid --trusted-for-delegation --gmsa | tee ldap_basic_enum_$username.log
        nxc ldap $target -u "$username" -p "$password" --gmsa | tee -a ldap_basic_enum_$username.log
    fi
}

# check target type
if [[ -s $target ]]; then
    targetType='list';
    elif [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    targetType='ip';
    elif [[ $target =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$ ]]; then
    targetType='domain';
    else echo "ERROR: Not a valid target.\nUsage: $0 -t <IP>|<hostname> [-U] [-P] [-n] [-x] [-h].";
    exit 1; 
fi

# check gnmap log file argument
if ! [ -z $gnmapFile ]; then 
    if (! [[ -f $gnmapFile ]] || ! [[ $gnmapFile =~ '.*\.gnmap' ]]); then 
    echo "Invalid grepable nmap log. Check filenames."
    exit 1;
    else gnmap_exist=1;
    fi
fi

# check XML log file argument
if ! [ -z $xmlNmapFile ]; then 
    if (! [[ -f $xmlNmapFile ]] || ! [[ $xmlNmapFile =~ '.*\.xml' ]]); then 
    echo "Invalid XML nmap log. Check filenames."
    exit 1;
    else xml_nmap_exist=1;
    fi
fi

if [[ -v $gnmap_exist ]] && [[ $gnmap_exist=1 ]]; then
    skip_port_scan=1
    echo "Nmap output files provided. Skipping portscanning...";
    else
    skip_port_scan=0;
fi

if ! [[ $targetType == 'list' ]]; then
    echo $target > target-hosts.txt
    nmapTarget="target-hosts.txt"
    nucleiTarget="-u ${target}"

    echo "*****************************"
    echo "Checking if target host is live..."
    echo
    echo "*****************************"
    ping -c 4 $target

    echo "********************************************************"
    vared -p "Enter a name of a machine to pwn: " -c machineName
    [[ -z "$machineName" ]] && machineName=$target                                  #machineName=ip address
else
    nmapTarget=${target}
    nucleiTarget="-l ${target}"    
fi

if [[ -z $topPorts ]]; then
topPorts='4000';
fi

if [[ $skip_port_scan == 0 ]]; then
    portscan
    waitForAnyKey
    nmapOutputToHTML
    searchsploitRun
    waitForAnyKey
    parseForPorts
elif [[ $skip_port_scan == 1 ]]; then
    nmapLogNameGnmap=${gnmapFile}
    parseForPorts
fi

# HTTPX
# search for HTTP services on open TCP ports
if [[ $targetType == 'list' ]]; then
    cat $target | while read line; do
        generate_url_list $line;
        done
else
    generate_url_list $target
fi

httpxRun

# search for 301 and 302 status codes in httpx output and update target
redirectionStatusCodes=`awk -F ' ' -e '$2 ~ /.*30[12].*]$/' httpx.log`
if [ ! -z $redirectionStatusCodes ]; then 
    echo
    echo 'Seems like HTTP redirections occured on some ports!';
    echo 'Possible new locations are:'
	awk -F ' ' -e '$2 ~ /.*30[12].*]$/ {print}' httpx.log | tr -d '[]';
    vared -p "Update target?[y]" -c updateTargetAnswer;
fi

if [[ $updateTargetAnswer == 'y' ]]; then
    vared -p "Enter a new target for scans manually:" -c newTarget
    vared -p "Please confirm the new target hostname: $newTarget [y/n]" -c newTargetConfirm
    while ! [[ $newTargetConfirm == 'y' ]]; do
        vared -p "Enter a new target for scans:" -c newTarget;
        vared -p "Please confirm the new target hostname: $newTarget [y/n]" -c newTargetConfirm;
    done    
    while true; do
        if [[ $newTarget =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        targetType='ip'; 
        target=$newTarget;
        break;
        elif [[ $newTarget =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$ ]]; then
        targetType='domain'; 
        ipTarget=$target;
        target=$newTarget;
        break;
        else echo "ERROR: Not a valid target.";
        vared -p "Please enter a target again:" -c newTarget;
        fi;
    done
    echo $target > target-hosts.txt
    updatedTarget='1';
fi

if [[ $updatedTarget == '1' ]]; then
    /bin/mv target-with-ports.txt target-with-ports.txt.old;
	/bin/mv httpx-output httpx-output-old;
    httpxRun
fi

/usr/bin/cat httpx.log | cut -d ' ' -f1 > httpx-valid-urls.txt

# GOBUSTER
#enumerate vhosts for every valid URL
if [[ $targetType == 'domain' ]]; then
    echo "Bruteforcing virtual hosts on the target web server..."
    
    trap ' ' INT
    
    cat httpx-valid-urls.txt | \
    while read line; do
        scheme=`echo $line | awk -F ':' '{print $1}'`
        hostname=`echo $line | awk -F '//' '{print $2}' | awk -F ':' '{print $1}'`
        port=`echo $line | awk -F '//' '{print $2}' | awk -F ':' '{print $2}'`
        if [ -z $port ]; then
            gobusterOutFile="gobuster-vhost-output-${hostname}.txt";
            else
            gobusterOutFile="gobuster-vhost-output-${hostname}-${port}.txt";
        fi
        gobuster vhost -q -u $line --append-domain -w /usr/share/seclists/Discovery/DNS/fierce-hostlist.txt \
        -v -r --random-agent --no-color -o $gobusterOutFile
        # making a list of URLs with new found vhosts
        cat $gobusterOutFile | grep -v "Missed" | grep -Ev "Status: [400|429]" | cut -d ' ' -f2 | \
        while read vhostName; do
            echo "${scheme}://${vhostName}:${port}" | anew gobuster-bruted-urls.txt
        done;
    done;
fi

if [[ -s gobuster-bruted-urls.txt ]]; then
    echo "Following virtual hosts were found during scan:"
    cat gobuster-bruted-urls.txt
    vared -p "Want to append these to the list of valid urls?[y]" -c brutedVhostAppend
fi
if [[ $brutedVhostAppend == 'y' ]]; then
    cat gobuster-bruted-urls.txt | anew httpx-valid-urls.txt
fi

# FFUF
#directory busting
ffufRun
#NUCLEI
nucleiRun

# CMSeek
/usr/bin/python3 /home/shyngys/Tools/CMSeeK/cmseek.py -l httpx-valid-urls.txt

if ! [[ $targetType == 'list' ]]; then
ADRecon
fi
