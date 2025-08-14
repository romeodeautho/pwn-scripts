#!/usr/bin/python3
"""
This scripts converts a list of IP address blocks in CIDR notation to a simple list of IP addresses
"""

import sys, ipaddress

def converter(range):
    range=range.rstrip('\n')
    ips=ipaddress.IPv4Network(range)
    ip_list=[str(ip) for ip in ips]
    return ip_list

if len(sys.argv)<2:
    print(f"Usage: {sys.argv[0]} <file with CIDR ranges>")
    sys.exit(1)
file=sys.argv[1]

all_ips=[]

with open(file, 'r') as cidr_file:
    cidr_list=cidr_file.readlines()
    print (cidr_list)
    input("press a key")
    for range in cidr_list:
        result=converter(range)
        for ip in result:
            all_ips.append(ip)

print(all_ips)
input("press a key")
with open('ip_list.txt','w') as ip_file:
    for ip in all_ips:
        ip_file.write(ip+"\n")

