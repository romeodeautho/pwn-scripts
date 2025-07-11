#!/bin/sh
YELLOW="\e[1;33m"
NC="\e[0m"

# GUID/SUID binaries
find / -type f -perm -4000 2>/dev/null;find / -type f -perm -6000 2>/dev/null

# Find installed Linux packages
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

#for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done

# Analyze logs
for i in $(ls /var/log/* 2>/dev/null);do
    GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null);
    if [[ $GREP ]];then 
         echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;
    fi;
    done

# Search for passwords, hashes, secrets in config files:
for i in $(find / -name *.cnf -o -name *.conf -o -name "*config*" 2>/dev/null |\
 grep -Ev "^/doc|^/lib|^/snap|^/proc|^/sys|^/run|^/usr|^/var/lib");do
 echo -e "\nFile: " $i; grep -Ei "pass|user|hash|salt|secret" $i 2>/dev/null | grep -v "\#";
 done


# Search for database files and scripts:
for l in $(echo ".sql .sqlite .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -Ev "^/doc|^/lib|^/snap|^/proc|^/sys|^/run|^/usr|^/var/lib";done
for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -Ev "^/doc|^/lib|^/snap|^/proc|^/sys|^/run|^/usr|^/var/lib";done
find / ! -path "*/proc/*" -iname "*database*" -type f 2>/dev/null

# Search for documents
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# All hidden files and directories
find /home -type f -name ".*" -exec ls -l {} \; 2>/dev/null
find /home -type d -name ".*" -ls 2>/dev/null

# Backup files:
find / -type f -name "*bak" -o -name "*.old" -exec ls -l {} \; 2>/dev/null

# Search for SSH private keys
printf "${YELLOW}Searching for SSH private keys...${NC}"
grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"