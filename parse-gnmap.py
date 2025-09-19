#!/usr/bin/env python3

from telegram import Bot, Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import os, sys, re, ipaddress, requests

def check_private_ip(ip_address_str):
    try:
        # Create an IP address object (IPv4Address or IPv6Address)
        ip_address_str=ip_address_str.strip('\n')
        ip_obj = ipaddress.ip_address(ip_address_str)
        # Use the is_private attribute to check if it's a private address
        return ip_obj.is_private
    except ipaddress.AddressValueError:
        print(f"Error: '{ip_address_str}' is not a valid IP address.")
        return False

token = os.environ['TELEGRAM_BOT_TOKEN']
app = ApplicationBuilder().token(token).build()
chat_id = '@potemkingalerts'
send_url = f"https://api.telegram.org/bot{token}/sendMessage"

file = open(sys.argv[1],"r")
ip_file = open("ips.txt","r")
dnsx_file = open("dnsx-output/dnsx-resolve.log","r")

ips_raw = ip_file.readlines()
resolve_lines = dnsx_file.readlines()
content = file.readlines()

http_service_name_regex = re.compile(r"(ssl|)?http.*|tcpwrapped")

useful=[]
for line in content:
    if "Ports" in line:
        useful.append(line)

http_ports = {}
for line in useful:
    fragments = line.split(' ')
    ip = fragments[1]
    http_ports[ip] = []
    for fragment in fragments:
        subfragments = fragment.split('/')
        if len(subfragments) > 4:
            for subfragment in subfragments:
                match = re.fullmatch(http_service_name_regex, subfragment)
                if match:
                    port = subfragments[0]
                    http_ports[ip].append(port)

#print(http_ports)
file.close()

ips = []
for ip in ips_raw:
    if not check_private_ip(ip):
        ip = ip.strip()
        ips.append(ip)

domains_by_host = {}
for ip in ips:
    domains_by_host[ip] = []
    for resolve_line in resolve_lines:
        if ip in resolve_line:
            fragments = resolve_line.split(' ')
            domain_name = fragments[0]
            domains_by_host[ip].append(domain_name)

ip_file.close()
dnsx_file.close()

hostnames_with_ports = []
for ip in ips:
    domains = domains_by_host[ip]
#    print(domains)
    try:
        ports = http_ports[ip]
    except KeyError:
        ports = ['80','443']
#    print(ports)
    for domain in domains:
        for port in ports:
            hostname = f"{domain}:{port}"
            hostnames_with_ports.append(hostname)

#print(hostnames_with_ports)
try:
    with open("hostnames-with-ports-raw-python.txt", "a") as file_raw:
        for hostname in hostnames_with_ports:
            file_raw.write(hostname + '\n')
except IOError as e:
    print(f"An error occurred while writing to the file: {e}")

text = 'all done'
resp = requests.post(send_url, json = {'chat_id':chat_id, 'text' : text})
print(resp.text)