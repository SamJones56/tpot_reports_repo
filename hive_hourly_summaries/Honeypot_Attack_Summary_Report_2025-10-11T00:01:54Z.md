Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T00:01:22Z
**Timeframe:** 2025-10-10 23:20:01Z to 2025-10-11 00:00:01Z
**Files Used:**
- agg_log_20251010T232001Z.json
- agg_log_20251010T234001Z.json
- agg_log_20251011T000001Z.json

**Executive Summary**

This report summarizes 13,725 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based attacks. A significant number of events were also logged by Honeytrap, Suricata, and Ciscoasa honeypots. Attackers were observed attempting to gain unauthorized access, enumerate system information, and download malicious files. Multiple CVEs were targeted, and a variety of credentials and commands were used.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 5122
- Honeytrap: 2698
- Suricata: 1889
- Ciscoasa: 1801
- Dionaea: 897
- Mailoney: 889
- Tanner: 157
- Sentrypeer: 146
- H0neytr4p: 50
- Adbhoney: 15
- Redishoneypot: 15
- ConPot: 14
- Honeyaml: 13
- Miniprint: 13
- ElasticPot: 6

***Top Attacking IPs***

- 196.251.88.103: 960
- 176.65.141.117: 820
- 167.250.224.25: 515
- 45.129.185.4: 498
- 119.207.254.77: 350
- 193.32.162.157: 258
- 160.187.146.255: 248
- 111.68.98.152: 194
- 5.187.44.27: 184
- 185.39.19.40: 172

***Top Targeted Ports/Protocols***

- 22: 895
- 25: 888
- TCP/21: 234
- 5903: 189
- 80: 148
- 5060: 146

***Most Common CVEs***

- CVE-2005-4050
- CVE-2022-27255
- CVE-2024-4577
- CVE-2002-0953
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2021-41773
- CVE-2021-42013
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2002-1149

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1: 382
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 195
- ET SCAN NMAP -sS window 1024: 155
- ET FTP FTP PWD command attempt without login: 117
- ET FTP FTP CWD command attempt without login: 117
- ET SCAN Sipsak SIP scan: 62

***Users / Login Attempts***

- root/7777777
- root/LeitboGi0ro
- bin/smoker666
- root/bond007
- root/superuser
- 345gs5662d34/345gs5662d34
- default/123
- ubnt/P@ssw0rd

***Files Uploaded/Downloaded***

- sh
- wget.sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- w.sh
- c.sh

***HTTP User-Agents***

- No HTTP User-Agents were logged in this period.

***SSH Clients and Servers***

- No specific SSH clients or servers were logged in this period.

***Top Attacker AS Organizations***

- No AS organizations were logged in this period.

**Key Observations and Anomalies**

- A large number of attacks originated from a small number of IP addresses, suggesting targeted attacks or botnet activity.
- The most common commands are focused on system enumeration and establishing persistent access by adding a new SSH key to `authorized_keys`.
- The downloaded files appear to be malware targeting various architectures (ARM, x86, MIPS).
- The high number of events on port 22 (SSH) and 25 (SMTP) indicates that these services are prime targets for attackers.
- The variety of CVEs targeted shows that attackers are attempting to exploit a wide range of vulnerabilities.
