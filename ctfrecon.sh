#!/bin/zsh

target=$1

if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
targetType='ip';
elif [[ $target =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$ ]]; then
targetType='domain';
else echo "ERROR: Not a valid target.";
exit 1; 
fi

echo "*****************************"
echo "Checking if target is live..."
echo
echo "*****************************"
ping -c 4 $target


echo "********************************************************"
vared -p "Enter a name of a machine to pwn: " -c machineName
[[ -z "$machineName" ]] && machineName=$target                                  #machineName=ip address


#nmap
while true; do
vared -p "Select Nmap scan mode:
1) Simple TCP
2) TCP -sV -sC
3) TCP -p- -sC -sV -O
4) TCP -sV -sC + UDP (100 ports)
5) TCP -p- -sV --script=extended -O + UDP (100 ports)
6) Skip
" -c nmapType

logFilenameBase=$machineName-$(date '+%d-%m-%Y')

case $nmapType in
'1') 
echo "Performing standard nmap enumeration..."
nmap -vv -oA $logFilenameBase $target  
break
;;
'2') 
echo "Performing nmap scan with service detection and default scripts..."
nmap -sV -sC -vv -oA $logFilenameBase $target -Pn
break
;;
'3') 
echo "Performing all-ports TCP scan with OS fingerprint and default scripts..."
nmap -sV -sC -p- -vv -oA $logFilenameBase $target -Pn -O
break
;;
'4') 
echo "Performing basic TCP + UDP scan..."
nmap -sV -sT -sC -vv -oA $logFilenameBase $target -Pn
vared -p "Scan UDP ports?[y]" -c udpAnswer
[[ $udpAnswer == "y" ]] && nmap -sU -sV --top-ports=100 -vv -oN $logFilenameBase-udp -Pn $target;
break
;;
'5')
echo "Performing all-ports TCP and basic UDP scan with OS fingerprint and safe scripts..."
nmap -p- -sT -sV --script="(default or discovery) and not broadcast and not http*" -vv -oA $logFilenameBase $target -Pn -O
vared -p "Scan UDP ports?[y]" -c udpAnswer
[[ $udpAnswer == "y" ]] && nmap -sU -sV --top-ports=100 -vv -oN $logFilenameBase-udp -Pn $target;
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

lastXMLLogFile=`(find . -name '*.xml' -printf '%T@ %p\n' | sort -n | cut -d' ' -f 2- | tail -n 1)`
lastXMLLogFileUDP=`(find . -name '*-udp.xml' -printf '%T@ %p\n' | sort -n | cut -d' ' -f 2- | tail -n 1)`


xsltproc $lastXMLLogFile -o $logFilenameBase.html
xsltproc $lastXMLLogFileUDP -o $logFilenameBase-udp.html


if [[ -f $lastXMLLogFile ]]; then
searchsploit --nmap $lastXMLLogFile | tee searchsploit-tcp.log
fi

if [[ -f $lastXMLLogFileUDP ]]; then
searchsploit --nmap $lastXMLLogFileUDP | tee searchsploit-udp.log
fi

vared -p "[*] Run Nuclei?[y]" -c run_nuclei
if [ $run_nuclei = 'y' ]; then
while true; do
vared -p "What type of nuclei scan do you want?
1) Full, all tags
2) Standard without wordpress
3) Standard without client-side(XSS)
4) Standard without wordpress and client-side(XSS)
5) Include custom tags
" -c nucleiChoice

case $nucleiChoice in
"1") nuclei -u $target -stats
break
;;
"2") nuclei -u $target -etags wordpress,wp-plugin,wpscan -stats
break
;;
"3") nuclei -u $target -etags xss -stats
break
;;
"4") nuclei -u $target -etags wordpress,wp-plugin,wpscan,xss -stats -o $logFilenameBase-nuclei.log
break
;;
"5") read -p "[*] Specify tags to include: " tags_line
[[ ! -z $tags_line ]] && nuclei -u $target -tags $tags_line -stats
break
;;
esac
done 
fi

lastGnmapFile=`(find . -name '*.gnmap' -printf '%T@ %p\n' | sort -n | cut -d' ' -f 2- | tail -n 1)`

#parsing open port numbers from nmap output file and creating an array
openPorts=()
openPorts+=($(cat $lastGnmapFile | awk '{for (i=4;i<=NF;i++) {
 split($i,a,"/");
 if (a[2]=="open") print a[1];}}'))

#parsing open port numbers from nmap output file and creating a string
openPortsList=$(cat $lastGnmapFile | awk '{for (i=4;i<=NF;i++) {
        split($i,a,"/");
        if (a[2]=="open") printf ",%s",a[1];}}' | sed -e 's/,//')

#parsing open http port numbers from nmap output file and creating an array
openHttpPorts=()
openHttpPorts+=($(cat $lastGnmapFile |awk '{for (i=4;i<=NF;i++) {
 split($i,a,"/");
 if (a[5] ~ /(ssl|)?http.*/) print a[1];}}'))

#web services discovery
if [ ! ${#openHttpPorts[@]} -eq 0 ]; then 
#webPorts=(80 443 8000 8009 8080 8081 8089 8100 8443 8888 10000)
#if [[ $(echo ${openPorts[@]} | grep -E '80|443|8000|8009|8080|8081|8089|8100|8443|8888|10000') ]]; then

    echo
    echo
    echo "************************************************************************************************************************"
    echo                             "Web services discovered. Running web scans...";
    echo
    echo "************************************************************************************************************************"

    if [ $targetType = 'domain' ]; then        #if domain name given as a target
       for port in ${openHttpPorts[@]}; do         #searching for additional virtual hosts on a server
	       vared -p "Want to search vhosts on port $port?[y]" -c vhostAnswer
		   if [ $vhostAnswer = 'y' ]; then
		   case "$port" in
	       "443" )	    
	       ffuf -u https://$target -H "Host: FUZZ.$target" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o $machineName-vhosts-raw-list-port-$port.csv -of csv -mc 200
           ;;
           * )
           ffuf -u http://$target:$port -H "Host: FUZZ.$target" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o $machineName-vhosts-raw-list-port-$port.csv -of csv -mc 200       
           ;;
           esac
		   fi
       done  
    /bin/cat $machineName-vhosts-raw-list-port-*.csv > $machineName-vhosts-raw-list.csv
    awk -v target="$target" -F, "{print \$1'.'target}" <  $machineName-vhosts-raw-list.csv > $machineName-vhosts.txt
    echo $target >> $machineName-vhosts.txt
    echo
    echo "************************************************************************************************************************"
	echo
	echo "[*] Fingerprinting web services..."
	echo
	echo "************************************************************************************************************************"
	echo
	echo
	echo "************************************************************************************************************************"
	echo "[*] Running httpx..."
	echo
	echo "************************************************************************************************************************"
	echo
	/home/shyngys/go/bin/httpx -sc -title -follow-redirects -td -p $openPortsList -l $machineName-vhosts.txt
	echo
	echo
	echo "************************************************************************************************************************"
	echo "[*] Running whatweb..."
	echo
	echo "************************************************************************************************************************"
	for port in ${openHttpPorts[@]}; do
	/usr/bin/whatweb -a 3 --input-file=$machineName-vhosts.txt --url-suffix=":$port"
	done
	echo
    echo
	echo "************************************************************************************************************************"
	echo "[*] Enumerating directories..."
	echo
	echo "************************************************************************************************************************"
		
	while read -r line; do 
	   for port in ${openHttpPorts[@]}; do
	     case "$port" in
	     '443' )
	     ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u https://$line/FUZZ -o ffuf-ds-$line:$port-$(date '+%d-%m-%Y').html -of html
         ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://$target/FUZZ -o ffuf-common-$line:$port-$(date '+%d-%m-%Y').html -of html; 
	     katana -u https://$line -jc -jsl;
	     ;;
	     * )
	     ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u http://$target:$port/FUZZ -o ffuf-ds-$line:$port-$(date '+%d-%m-%Y').html -of html
         ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$target:$port/FUZZ -o ffuf-common-$line:$port-$(date '+%d-%m-%Y').html -of html; 
	     katana -u http://$line:$port -jc -jsl;
	     ;;
	     esac
	   done
	done < $machineName-vhosts.txt
	else    #if ip address given as a target
	echo "Target is ip address"
	echo "[*] Fingerprinting web services..."
	echo
	echo
	echo "[*] Running httpx..."
	echo
	for port in ${openHttpPorts[@]}; do
	    vared -p "Want to search vhosts on port $port?[y]" -c httpxPortAnswer
		   if [ $httpxPortAnswer = 'y' ]; then
	           /home/shyngys/go/bin/httpx -title -follow-redirects -sc -td -p $port -u $target
		   fi
    done
	echo "[*] Running whatweb..."
	echo
	for port in ${openHttpPorts[@]}; do
	/usr/bin/whatweb -a 3 $target --url-suffix=":$port"
	done
	echo '========================================================================================================================'
	echo '========================================================================================================================'
	echo '========================================================================================================================'
	echo
	echo

	for port in ${openHttpPorts[@]}; do
		vared -p "Want to search vhosts on port $port?[y]" -c ffufPortAnswer
		if [ $ffufPortAnswer = 'y' ]; then
		case "$port" in
		"443" )
			ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u https://$target/FUZZ -o ffuf-ds-$(date '+%d-%m-%Y').html -of html
            ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u https://$target/FUZZ -o ffuf-common-$(date '+%d-%m-%Y').html -of html; 
			katana -u https://$target -jc -jsl
		;;
		* )
			ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -u http://$target:$port/FUZZ -o ffuf-ds-$(date '+%d-%m-%Y').html -of html
            ffuf -replay-proxy http://127.0.0.1:8080 -sf -v -ic -ac -r -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://$target:$port/FUZZ -o ffuf-common-$(date '+%d-%m-%Y').html -of html; 
			katana -u http://$target:$port -jc -jsl
		;;
		esac
		fi
	done	
	fi
fi

if [[ $(echo ${openPorts[@]} | grep -E '88') ]]; then
echo "The target machine seems to be a Domain Controller."
vared -p "Want to run a basic Active Directory enumeration?" -c ADenumAnswer
if [ $ADenumAnswer = 'y' ]; then
vared -p "Enter username or leave blank: " -c domainUser
vared -p "Enter password or leave blank: " -c domainPassword
echo "[*] Running enum4linux..."
enum4linux-ng -A $target -u "$domainUser" -p "$domainPassword" | tee enum4linux-$target-$domainUser.log
echo "[*] Running basic SMB enum..."
nxc smb $target -u "$domainUser" -p "$domainPassword" --users --shares --pass-pol --loggedon-users | tee smb_basic_enum_$domainUser.log
nxc smb $target -u "$domainUser" -p "$domainPassword" --rid-brute 8000 | grep SidTypeUser | awk '{print $6}' | cut -d '\' -f2 | grep -E '^[0-9A-Za-z\._\$]+$' --only-match | grep -v -i "administrator\|krbtgt\|guest" | tee rid-brute-$domainUser.log
nxc smb $target -u "$domainUser" -p "$domainPassword" --users | awk '{print $5}' | grep -E '^[0-9A-Za-z\._]+$' --only-match | grep -v -i "administrator\|krbtgt\|guest" | tee domain_users_$domainUser.txt
echo "[*] Spidering shares..."
nxc smb $target -u "$domainUser" -p "$domainPassword" -M spider_plus -o DOWNLOAD_FLAG=1 OUTPUT_FOLDER=`pwd` | tee -a smb_basic_enum_$domainUser.log
echo "[*] Checking for GPP passwords and autologon info..."
nxc smb $target -u "$domainUser" -p "$domainPassword" -M gpp_autologin | tee -a smb_basic_enum_$domainUser.log
nxc smb $target -u "$domainUser" -p "$domainPassword" -M gpp_password | tee -a smb_basic_enum_$domainUser.log
echo "[*] Enumerating Certificate authorities..."
nxc smb $target -u "$domainUser" -p "$domainPassword" -M enum_ca | tee -a smb_basic_enum_$domainUser.log
echo "[*] Checking if spooler service is running on the target..."
nxc smb $target -u "$domainUser" -p "$domainPassword" -M spooler | tee -a smb_basic_enum_$domainUser.log
echo "[*] Checking if the target is vulnerable to ceorcing attacks..."
nxc smb $target -u "$domainUser" -p "$domainPassword" -M coerce_plus | tee -a smb_basic_enum_$domainUser.log
echo "[*] Testing for Zerologon..."
nxc smb $target -u "$domainUser" -p "$domainPassword" -M zerologon | tee -a smb_basic_enum_$domainUser.log
echo "[*] Running basic LDAP enum..."
nxc ldap $target -u "$domainUser" -p "$domainPassword" --users --get-sid --trusted-for-delegation --gmsa | tee ldap_basic_enum_$domainUser.log
nxc ldap $target -u "$domainUser" -p "$domainPassword" --gmsa | tee -a ldap_basic_enum_$domainUser.log
fi
fi