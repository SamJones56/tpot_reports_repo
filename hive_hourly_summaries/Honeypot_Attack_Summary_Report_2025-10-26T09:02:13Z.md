Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T09:01:29Z
**Timeframe Covered:** 2025-10-26T08:20:01Z to 2025-10-26T09:00:01Z
**Log Files Used:**
- agg_log_20251026T082001Z.json
- agg_log_20251026T084001Z.json
- agg_log_20251026T090001Z.json

### Executive Summary
This report summarizes 19,462 events collected from the honeypot network. The majority of attacks were detected by the Cowrie and Suricata honeypots. The most frequent attacker IP was 109.205.211.9. The most targeted port was port 22 (SSH). Several CVEs were detected, with the most common being CVE-2021-3449 and CVE-2019-11500. Attackers attempted a variety of commands, primarily focused on system enumeration and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 5883
- Suricata: 5097
- Honeytrap: 4570
- Ciscoasa: 1776
- Dionaea: 984
- Sentrypeer: 773
- Adbhoney: 75
- Mailoney: 134
- ConPot: 67
- H0neytr4p: 34
- Miniprint: 24
- Tanner: 20
- Ipphoney: 11
- Redishoneypot: 9
- Dicompot: 7
- Medpot: 2
- Honeyaml: 1

**Top Attacking IPs:**
- 109.205.211.9: 4436
- 20.80.236.78: 1613
- 212.87.220.20: 1041
- 185.243.5.121: 514
- 115.113.198.245: 473
- 103.72.147.99: 346
- 40.82.214.8: 346
- 103.179.218.243: 346
- 80.94.95.238: 253
- 107.170.36.5: 250
- 193.32.162.157: 250
- 219.92.8.45: 174
- 14.34.157.138: 128
- 165.154.1.18: 188
- 167.250.224.25: 139

**Top Targeted Ports/Protocols:**
- 22: 996
- 445: 840
- 5060: 766
- 1433: 139
- 8333: 119
- 5903: 135
- 2070: 166
- 25: 134
- 5901: 119
- 23: 68
- TCP/22: 77
- TCP/80: 69
- 5905: 81
- 5904: 76
- 5909: 50
- 5908: 50
- 5907: 48
- UDP/5060: 50

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2002-0013
- CVE-2002-0012

**Commands Attempted by Attackers:**
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- Enter new UNIX password:

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 2492
- 2023753: 2492
- ET HUNTING RDP Authentication Bypass Attempt: 1152
- 2034857: 1152
- ET DROP Dshield Block Listed Source group 1: 446
- 2402000: 446
- ET SCAN NMAP -sS window 1024: 176
- 2009582: 176
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET SCAN Potential SSH Scan: 41
- 2001219: 41

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 13
- root/3245gs5662d34: 5
- root/gdmg2010: 4
- root/gdr5123: 4
- alex/alex1234: 3
- client/client@123: 3
- hadi/hadi: 2
- admin/12qwaszx: 2
- admin/3245gs5662d34: 2
- zhaoyu/zhaoyu: 2
- jenkins/Admin@123: 2
- postgres/1234qwer: 2
- root/5201314a: 2
- root/admin1234567: 2
- sa/1qaz2wsx: 5
- root/server1234: 2
- rick/rick: 2
- suresh/suresh@123: 2
- root/Vps123456: 2
- user0/123: 2

**Files Uploaded/Downloaded:**
- wget.sh;: 28
- w.sh;: 7
- c.sh;: 7
- arm.urbotnetisass;: 2
- arm.urbotnetisass: 2
- arm5.urbotnetisass;: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass;: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass;: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass;: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass;: 2
- mips.urbotnetisass: 2

**HTTP User-Agents:**
- No user agents were logged.

**SSH Clients:**
- No specific SSH clients were logged.

**SSH Servers:**
- No specific SSH servers were logged.

**Top Attacker AS Organizations:**
- No AS organizations were logged.

### Key Observations and Anomalies
- The vast majority of attacks are automated, using common usernames and passwords.
- A significant number of commands are aimed at reconnaissance and disabling security measures.
- There is a recurring attempt to add a specific SSH key to the authorized_keys file.
- Attackers frequently use `wget` and `curl` to download and execute malicious scripts.
- The most common Suricata signature is related to MS Terminal Server traffic on non-standard ports, indicating a high volume of RDP scanning activity.
- A number of commands are aimed at downloading and executing binaries with names like `arm.urbotnetisass`, suggesting an attempt to install a botnet client.
