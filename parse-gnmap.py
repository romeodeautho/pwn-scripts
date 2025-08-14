#!/usr/bin/python3

import re

file=open("nmap-output/nmap-4000-ports-tcp-13-05-2025-12:44.gnmap","r")
content=file.readlines()

http_ports={}
service_line_regex=re.compile(r"([a-zA-Z0-9.\-\s]*/){7}")
http_service_regex=re.compile(r"(ssl|)?http.*|tcpwrapped")

useful=[]
for line in content:
    if "Ports" in line:
        useful.append(line)

for line in useful:
    fragments=line.split(' ')
    ip=fragments[1]
    http_ports[ip]=[]
    for fragment in fragments:
        subfragments=fragment.split('/')
        if len(subfragments)>4:
            for subfragment in subfragments:
                match=re.fullmatch(http_service_regex, subfragment)
                if match:
                    http_ports[ip].append(subfragment)

print(http_ports)

file.close()
ip_file=open("ips.txt","r")
dnsx_file=open("dnsx-output/dnsx-resolve.log","r")
ips=ip_file.readlines()
resolve_lines=dnsx_file.readlines()

domains_by_host={}

for ip in ips:
    ip=ip.strip('\n')
    domains_by_host[ip]=[]
    for resolve_line in resolve_lines:
        if ip in resolve_line:
            fragments=resolve_line.split(' ')
            domain_name=fragments[0]
            domains_by_host[ip].append(domain_name)

print(domains_by_host)

ip_file.close()
dnsx_file.close()