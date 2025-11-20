Honeypot Attack Summary Report

Report Generation Time: 2025-10-18T05:01:30Z
Timeframe: 2025-10-18T04:20:01Z to 2025-10-18T05:00:01Z
Files used to generate this report:
- agg_log_20251018T042001Z.json
- agg_log_20251018T044001Z.json
- agg_log_20251018T050001Z.json

Executive Summary:
This report summarizes 10090 attacks recorded by the honeypot network. The majority of attacks were against the Cowrie honeypot, with significant activity also observed on Honeytrap, Suricata, and Ciscoasa. The most frequent attacker IP was 72.146.232.13, and the most targeted port was 22 (SSH). Several CVEs were detected, and a variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing control.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 4285
- Honeytrap: 2511
- Suricata: 1426
- Ciscoasa: 1403
- Sentrypeer: 190
- Mailoney: 84
- Tanner: 42
- H0neytr4p: 33
- Dionaea: 31
- Adbhoney: 20
- Redishoneypot: 17
- Honeyaml: 16
- ConPot: 13
- ElasticPot: 7
- Dicompot: 8
- Heralding: 3

Top Attacking IPs:
- 72.146.232.13: 909
- 198.98.57.141: 360
- 88.210.63.16: 333
- 103.115.56.3: 269
- 106.52.44.89: 258
- 107.170.36.5: 247
- 195.96.129.45: 287
- 117.72.57.139: 191
- 14.97.117.34: 203
- 107.150.97.192: 203
- 101.36.109.130: 196
- 36.134.151.126: 125
- 103.174.114.143: 138
- 106.12.111.134: 113
- 68.183.149.135: 111
- 167.250.224.25: 105
- 159.89.121.144: 91
- 101.126.88.203: 87
- 68.183.207.213: 62
- 35.222.117.243: 60

Top Targeted Ports/Protocols:
- 22: 859
- 5903: 223
- 5060: 190
- 5901: 112
- 25: 84
- 5905: 77
- 5904: 76
- 8333: 61
- TCP/80: 36
- 80: 46
- 5908: 50
- 5909: 48
- 5907: 48
- 443: 24
- 5902: 38
- TCP/22: 20

Most Common CVEs:
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2001-0414

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- Enter new UNIX password: 
- system
- tftp; wget; /bin/busybox BZFGA

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET INFO curl User-Agent Outbound
- ET HUNTING curl User-Agent to Dotted Quad
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET INFO CURL User Agent
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 3
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 47

Users / Login Attempts:
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/123@Robert
- nobody/222
- ubnt/webmaster
- centos/passw0rd
- root/1Terr
- root/20!3Crenova
- user-backup/user-backup
- test/1q2w3e4r
- ftpuser/ftppassword
- root/Passw0rd123$
- toor/toor
- unknown/unknown2019
- ymoreno/ymoreno
- root/null
- compiler/compiler
- admin/adminpassword
- admin/admin123456789
- zeppelin/zeppelin123

Files Uploaded/Downloaded:
- wget.sh;
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- w.sh;
- c.sh;

HTTP User-Agents:
- No user agents were reported in this timeframe.

SSH Clients:
- No SSH clients were reported in this timeframe.

SSH Servers:
- No SSH servers were reported in this timeframe.

Top Attacker AS Organizations:
- No AS organizations were reported in this timeframe.

Key Observations and Anomalies:
- The attacker with IP 72.146.232.13 is particularly persistent, launching a high volume of attacks across the reporting period.
- The commands attempted suggest a focus on reconnaissance of the system's hardware and user activity, followed by attempts to establish persistent access by modifying SSH authorized_keys.
- The high number of "ET DROP Dshield Block Listed Source group 1" signatures indicates that many of the attacking IPs are already known malicious actors.
- A number of commands are related to downloading and executing shell scripts, which is a common tactic for deploying malware.
