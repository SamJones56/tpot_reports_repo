Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T21:01:26Z
**Timeframe:** 2025-10-21T20:20:01Z to 2025-10-21T21:00:01Z
**Files Used:**
- agg_log_20251021T202001Z.json
- agg_log_20251021T204001Z.json
- agg_log_20251021T210001Z.json

**Executive Summary**
This report summarizes 15,177 events collected from the honeypot network. The majority of attacks were captured by the Honeytrap, Cowrie, and Suricata honeypots. The most prominent attack vectors involved reconnaissance and brute-force attempts against VNC and SSH services. A significant portion of the attacks originated from IP addresses `185.243.96.105` and `10.208.0.3`.

**Detailed Analysis**

***Attacks by Honeypot:***
- Honeytrap: 4220
- Cowrie: 3899
- Suricata: 3306
- Heralding: 1615
- Ciscoasa: 1677
- Sentrypeer: 158
- Mailoney: 82
- Redishoneypot: 81
- Dionaea: 32
- ConPot: 24
- Tanner: 27
- H0neytr4p: 28
- Ipphoney: 11
- Adbhoney: 6
- Dicompot: 4
- ElasticPot: 4
- Honeyaml: 3

***Top Attacking IPs:***
- 185.243.96.105
- 10.208.0.3
- 72.146.232.13
- 193.168.196.68
- 193.32.162.157
- 107.170.36.5
- 45.119.212.99
- 182.18.161.165
- 14.103.115.115
- 5.181.86.179

***Top Targeted Ports/Protocols:***
- vnc/5900
- 22
- 5903
- 5060
- TCP/1080
- 8333
- 6379
- 25
- 5901
- 4443

***Most Common CVEs:***
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012
- CVE-2001-0096
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2005-4050
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2006-2369
- CVE-2001-0414
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

***Commands Attempted by Attackers:***
- uname -s -v -n -r -m
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- whoami

***Signatures Triggered:***
- ET INFO VNC Authentication Failure
- 2002920
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- GPL INFO SOCKS Proxy attempt
- 2100615
- ET SCAN NMAP -sS window 1024
- 2009582

***Users / Login Attempts:***
- /1q2w3e4r
- /passw0rd
- /Passw0rd
- root/Asteriskmnbodega
- root/AstraQ0m123
- root/athenabras`l
- /qwertyui
- root/asterisk2015
- root/Asterisk_2013
- 345gs5662d34/345gs5662d34

***Files Uploaded/Downloaded:***
- nse.html

***HTTP User-Agents:***
- Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36

***SSH Clients and Servers:***
- No SSH clients or servers were recorded in the logs.

***Top Attacker AS Organizations:***
- No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**
- A high volume of VNC authentication failures suggests widespread scanning and brute-force attacks targeting VNC servers.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates attempts to install SSH keys for persistent access.
- The presence of the file `nse.html` suggests the use of the Nmap Scripting Engine for vulnerability scanning.
- The variety of CVEs targeted indicates that attackers are attempting to exploit a wide range of vulnerabilities.
