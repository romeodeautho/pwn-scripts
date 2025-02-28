#!/bin/bash

#check if valid target is set
#while true
#do
#read -p "Please enter an IP address of your target or a domain name: " target
target=$1

if [[ $target =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
targetType='ip';
break;
elif [[ $target =~ ^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$ ]]; then
targetType='domain';
break;
else echo "ERROR: Not a valid target.";
exit 1; 
fi

echo "*****************************"
echo "Checking if target is live..."
echo
echo "*****************************"
ping -c 4 $target


echo "********************************************************"
read -p "Enter a name of a machine to pwn: " machineName
[[ -z "$machineName" ]] && machineName=$target                                  #machineName=ip address


#parsing open port numbers from nmap output file and creating an array
openPorts=()
openPorts+=($(cat $machineName.gnmap | awk '{for (i=4;i<=NF;i++) {
 split($i,a,"/");
 if (a[2]=="open") print a[1];}}'))

#parsing open port numbers from nmap output file and creating a list
openPortsList=$(cat $machineName.gnmap | awk '{for (i=4;i<=NF;i++) {
        split($i,a,"/");
        if (a[2]=="open") printf ",%s",a[1];}}' | sed -e 's/,//')

#parsing open http port numbers from nmap output file and creating an array
openHttpPorts=()
openHttpPorts+=($(cat $machineName.gnmap |awk '{for (i=4;i<=NF;i++) {
 split($i,a,"/");
 if (a[5]=="http") print a[1];}}'))

#web services discovery
if [ ! ${#openHttpPorts[@]} -eq 0 ]; then 
#webPorts=(80 443 8000 8009 8080 8081 8089 8100 8443 8888 10000)
#if [[ $(echo ${openPorts[@]} | grep -E '80|443|8000|8009|8080|8081|8089|8100|8443|8888|10000') ]]; then
    echo
    echo "************************************************************************************************************************"
    echo "Web services discovered. Running web scans...";
    echo "************************************************************************************************************************"
	
	#vhost enum
#	if [ $targetType = 'domain' ]; then gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://$target --append-domain -o $machineName-vhosts-raw.txt
#    cat $machineName-vhosts-raw.txt | cut -d ' ' -f2 > $machineName-vhosts.txt

	
    
    if [ $targetType = 'domain' ]; then        #if domain name given as a target
       for port in ${openHttpPorts[@]}; do         #searching for additional virtual hosts on a server
	       case "$port" in
	       "443" )	    
	       ffuf -u https://$target -H "Host: FUZZ.$target" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o $machineName-vhosts-raw-list-port-$port.csv -of csv -mc 200
           ;;
           * )
           ffuf -u http://$target:$port -H "Host: FUZZ.$target" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -o $machineName-vhosts-raw-list-port-$port.csv -of csv -mc 200       
           ;;
           esac
       done  
    cat $machineName-vhosts-raw-list-port-*.csv > $machineName-vhosts-raw-list.csv
    awk -v target="$target" -F, "{print \$1'.'target}" <  $machineName-vhosts-raw-list.csv > $machineName-vhosts.txt
    echo $target >> $machineName-vhosts.txt
    echo
    echo "************************************************************************************************************************"
	echo "[*] Fingerprinting web services..."
	echo "************************************************************************************************************************"
	echo
	echo
	echo "************************************************************************************************************************"
	echo "[*] Running httpx..."
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
	     dirsearch -u https://$line 
	     ffuf -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -ic -replay-proxy http://127.0.0.1:8080 -u https://$line/FUZZ -r
	     ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -ic -replay-proxy http://127.0.0.1:8080 -u https://$line/FUZZ -r
	     katana -u https://$line -jc -jsl;
	     ;;
	     * )
	     dirsearch -u http://$line:$port 
	     ffuf -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -ic -replay-proxy http://127.0.0.1:8080 -u http://$line:$port/FUZZ -r
	     ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -ic -replay-proxy http://127.0.0.1:8080 -u http://$line:$port/FUZZ -r
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
	/home/shyngys/go/bin/httpx -title -follow-redirects -sc -td -p $openPortsList -u $target
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
		case "$port" in
		"443" )
			dirsearch -u https://$target
			ffuf -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -ic -replay-proxy http://127.0.0.1:8080 -u https://$target/FUZZ -r
			ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -ic -replay-proxy http://127.0.0.1:8080 -u https://$target/FUZZ -r
			katana -u https://$target -jc -jsl
		;;
		* )
			dirsearch -u http://$target:$port 
			ffuf -w /usr/share/seclists/Discovery/Web-Content/dsstorewordlist.txt -ic -replay-proxy http://127.0.0.1:8080 -u http://$target:$port/FUZZ -r
			ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -ic -replay-proxy http://127.0.0.1:8080 -u http://$target:$port/FUZZ -r
			katana -u http://$target:$port -jc -jsl
		;;
		esac
	done	
	fi
fi
