#!/usr/bin/zsh
#Nmap Targeted Full Tcp Port Scan
[[ -z $1 ]] && echo "Usage: $0 <target>" && exit 1

export t=$1

timestamp=$(date "+%d-%m-%Y-%H-%M");
nmap -p- --min-rate=1000 -T4 -v $t -oN nmap-fastscan-${timestamp}.nmap
ports=$(/bin/grep '^[0-9]' nmap-fastscan-${timestamp}.nmap | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//);

if [[ ! -z ${ports} ]]; then
echo "Discovered TCP ports: ${ports}"
nmap -p${ports} -sV --script="(default or discovery) and not broadcast and not http*" -O -Pn -n -vv --disable-arp-ping -oA nmap-full-${timestamp} $t;
xsltproc nmap-full-${timestamp}.xml -o nmap-synfull-${timestamp}.html;
vared -p "[*] Run nmap ACK TCP scan?[y]" -c ackScan
    if [ $ackScan = 'y' ]; then sudo nmap -sA -p- --min-rate=1000 -T4 -v $t;
    fi
fi