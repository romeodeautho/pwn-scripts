#!/bin/zsh

sudo apt install pipx git
sudo apt install golang
sudo apt install nmap searchsploit xsltproc cewl

pipx ensurepath
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -i katana,uncover,httpx,dnsx,subfinder,nuclei,urlfinder
go install github.com/d3mondev/puredns/v2@latest
go install -v github.com/tomnomnom/anew@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/unfurl@latest
pipx install git+https://github.com/xnl-h4ck3r/urless.git
pipx install uro

go install -v github.com/Hackmanit/TInjA@latest
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
git clone https://github.com/maurosoria/dirsearch.git --depth 1
git clone https://github.com/patuuh/Payloads-and-wordlists.git

#reconftw tools
git clone https://github.com/JoelGMSec/LeakSearch
git clone https://github.com/UndeadSec/SwaggerSpy.git
python3 -m pip install porch-pirate
git clone https://github.com/intigriti/misconfig-mapper.git
git clone https://github.com/Tuhinshubhra/CMSeeK
go install github.com/gwen001/github-subdomains@latest
go install github.com/trickest/enumerepo@latest
go install github.com/trickest/dsieve@latest
git clone https://github.com/damit5/gitdorks_go.git
git clone https://github.com/six2dez/dorks_hunter
git clone https://github.com/w9w/JSA
go install github.com/x90skysn3k/brutespray@latest
pipx install git+https://github.com/xnl-h4ck3r/waymore.git
pipx install git+https://github.com/xnl-h4ck3r/xnLinkFinder.git
go install github.com/sensepost/gowitness@latest

GO111MODULE=on go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
pipx install dnsgen

#CLI utility for Osprey Vision, Subdomain Center & Exploit Observer
pip3 install puncia
