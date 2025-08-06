#!/bin/zsh

sudo apt install pipx git
sudo apt install golang

pipx ensurepath

pipx install git+https://github.com/Pennyw0rth/NetExec
#pip3 install defaultcreds-cheat-sheet

go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -i katana,uncover,httpx,dnsx,subfinder,nuclei

go install -v github.com/tomnomnom/anew@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/unfurl@latest
pipx install uro
go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest

#Active Directory tools
wget https://raw.githubusercontent.com/canix1/ADACLScanner/refs/heads/master/ADACLScan.ps1 -O ~/Tools/ADACLScan.ps1
#Bloodhound new
git clone https://github.com/SpecterOps/BloodHound
sudo apt install libkrb5-dev
pip3 install powerview --break-system-packages
git clone https://github.com/ShutdownRepo/pywhisker
git clone https://github.com/dirkjanm/PKINITtools
git clone https://github.com/dirkjanm/krbrelayx
pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
pipx install bloodyAD

#sudo apt install -y nvidia-driver nvidia-cuda-toolkit
go install -v github.com/Hackmanit/TInjA@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest

git clone https://github.com/SecurityRiskAdvisors/cmd.jsp
#git clone https://github.com/maurosoria/dirsearch.git --depth 1
git clone https://github.com/patuuh/Payloads-and-wordlists.git
#git clone https://github.com/blacklanternsecurity/writehat

sudo wget https://raw.githubusercontent.com/peass-ng/PEASS-ng/master/metasploit/peass.rb -O /usr/share/metasploit-framework/modules/post/multi/gather/peass.rb
go install -v github.com/bountysecurity/gbounty/cmd/gbounty@main

#run windows executables
sudo apt install mono-devel 

#reconftw tools
git clone https://github.com/JoelGMSec/LeakSearch
git clone https://github.com/UndeadSec/SwaggerSpy.git
python3 -m pip install porch-pirate
git clone https://github.com/intigriti/misconfig-mapper.git
git clone https://github.com/Tuhinshubhra/CMSeeK
go install github.com/gwen001/github-subdomains@latest
go install github.com/trickest/enumerepo@latest
git clone https://github.com/damit5/gitdorks_go.git
git clone https://github.com/six2dez/dorks_hunter
git clone https://github.com/w9w/JSA
go install github.com/x90skysn3k/brutespray@latest
pipx install git+https://github.com/xnl-h4ck3r/waymore.git
pipx install git+https://github.com/xnl-h4ck3r/xnLinkFinder.git
go install github.com/sensepost/gowitness@latest
pipx install git+https://github.com/xnl-h4ck3r/urless.git
GO111MODULE=on go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
pipx install dnsgen

#CLI utility for Osprey Vision, Subdomain Center & Exploit Observer
pip3 install puncia

go install -v github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest

#GraphQL tools
git clone https://github.com/nicholasaleks/CrackQL
git clone https://github.com/dolevf/graphw00f

#sudo apt install bluetooth pulseaudio-module-bluetooth blueman bluez-firmware
