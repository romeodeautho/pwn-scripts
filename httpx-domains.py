import re

with open('httpx-ips.txt','r') as f:
    ips=[line.rstrip('\n') for line in f]

with open('httpx.log', 'r') as f:
    httpx_rows=[line.rstrip('\n') for line in f]

for ip in ips:
    host_file=open(f"{ip}-domains.txt", 'a')
    for row in httpx_rows:
        if ip in row:
            url = row.split(' ')[0]
            print(url)
            regex = r"https?://([0-9a-z\.]+)"
            domain = re.search(regex,url).group(1)
            if domain:
                host_file.write(domain+'\n')
    host_file.close()