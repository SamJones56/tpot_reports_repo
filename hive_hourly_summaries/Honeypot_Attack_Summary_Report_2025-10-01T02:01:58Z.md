Honeypot Attack Summary Report

Report Generated: 2025-10-01T02:01:34Z
Timeframe: 2025-10-01T01:20:01Z to 2025-10-01T02:00:01Z
Files Used: agg_log_20251001T012001Z.json, agg_log_20251001T014001Z.json, agg_log_20251001T020001Z.json

Executive Summary
This report summarizes 15,906 attacks recorded by honeypots over a 40-minute period. The most targeted honeypot was Cowrie, with 6,091 events. The top attacking IP address was 113.161.17.144, responsible for 3,123 attacks, primarily targeting port 445. Several CVEs were detected, including CVE-2002-0013 and CVE-2002-0012. A variety of commands were attempted, with attackers frequently trying to manipulate SSH keys and gather system information.

Detailed Analysis

Attacks by Honeypot:
- Cowrie: 6091
- Dionaea: 3185
- Honeytrap: 2208
- Mailoney: 1303
- Suricata: 1506
- Ciscoasa: 1420
- H0neytr4p: 55
- Adbhoney: 29
- Honeyaml: 29
- Tanner: 25
- ConPot: 18
- Sentrypeer: 16
- Ipphoney: 9
- Dicompot: 6
- Redishoneypot: 6

Top Attacking IPs:
- 113.161.17.144: 3123
- 164.92.85.77: 1343
- 47.242.0.187: 1311
- 92.242.166.161: 822
- 86.54.42.238: 474
- 92.191.96.115: 449
- 35.185.163.88: 430
- 152.32.172.117: 384
- 185.156.73.167: 363
- 185.156.73.166: 362
- 92.63.197.55: 356
- 92.63.197.59: 327
- 190.32.246.14: 323
- 165.154.36.71: 229
- 160.187.147.127: 254
- 185.121.0.25: 283
- 5.56.132.116: 247
- 42.51.34.15: 150
- 3.130.96.91: 84
- 79.124.56.138: 57

Top Targeted Ports/Protocols:
- 445: 3146
- 25: 1303
- 22: 989
- 8333: 86
- 443: 55
- 80: 37
- UDP/161: 31
- 2222: 25
- 2087: 21
- TCP/80: 38
- 23: 31
- TCP/22: 26
- 4443: 23
- 37777: 14
- 9020: 17
- 5672: 16

Most Common CVEs:
- CVE-2002-0013 CVE-2002-0012: 18
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 14

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 20
- lockr -ia .ssh: 20
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 20
- uname -a: 21
- cat /proc/cpuinfo | grep name | wc -l: 19
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 19
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 19
- ls -lh $(which ls): 20
- which ls: 20
- crontab -l: 20
- w: 20
- uname -m: 20
- cat /proc/cpuinfo | grep model | grep name | wc -l: 20
- top: 20
- uname: 20
- whoami: 20
- lscpu | grep Model: 20
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 20
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 10
- Enter new UNIX password: : 7

Signatures Triggered:
- ET DROP Dshield Block Listed Source group 1: 499
- ET SCAN NMAP -sS window 1024: 213
- ET INFO Reserved Internal IP Traffic: 58
- ET CINS Active Threat Intelligence Poor Reputation IP group 41: 13
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 10
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 40: 21
- GPL INFO SOCKS Proxy attempt: 10
- ET SCAN Potential SSH Scan: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 9
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 21
- ET INFO CURL User Agent: 8
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 8
- ET INFO External Oracle T3 Requests Inbound: 8
- GPL SNMP request udp: 16
- GPL SNMP public access udp: 13
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 12
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 11

Users / Login Attempts:
- 345gs5662d34/345gs5662d34: 18
- root/3245gs5662d34: 9
- root/nPSpP4PBW0: 8
- foundry/foundry: 6
- superadmin/admin123: 6
- root/2glehe5t24th1issZs: 5
- test/zhbjETuyMffoL8F: 5
- ubnt/ubnt: 5
- root/LeitboGi0ro: 6
- root/qqwweerrtt: 4
- mongodb/mongodb: 4
- sonar/sonar: 4
- elasticsearch/elasticsearch: 4
- docker/docker123: 4
- root/123: 4
- dev/dev123456: 4
- guest/guest123: 4
- root/Sy123456: 3
- root/Root@123!: 3
- administrator/Pa$$w0rd: 3

Files Uploaded/Downloaded:
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
- arm.urbotnetisass;: 3
- arm.urbotnetisass: 3
- arm5.urbotnetisass;: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass;: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass;: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass;: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass;: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass;: 3
- mipsel.urbotnetisass: 3

HTTP User-Agents:
- N/A

SSH Clients:
- N/A

SSH Servers:
- N/A

Top Attacker AS Organizations:
- N/A

Key Observations and Anomalies
- A significant amount of scanning activity was detected from the IP address 113.161.17.144, which focused on port 445 (SMB), indicating likely attempts to exploit SMB vulnerabilities.
- Attackers frequently attempted to add their own SSH keys to the authorized_keys file, a common technique for establishing persistent access.
- The command `cd /data/local/tmp/; rm *; busybox wget ...` suggests attempts to download and execute malware on Android devices.
- The presence of commands related to removing security scripts (`rm -rf /tmp/secure.sh`) indicates that attackers are aware of and attempting to disable common security measures.
- A wide variety of usernames and passwords were used in brute-force attempts, with a focus on default credentials for various services.