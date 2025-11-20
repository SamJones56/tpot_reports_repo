Honeypot Attack Summary Report

Report Generation Time: 2025-10-27T23:01:29Z
Timeframe of logs: 2025-10-27T22:20:01Z to 2025-10-27T23:00:01Z

Files used to generate this report:
- agg_log_20251027T222001Z.json
- agg_log_20251027T224001Z.json
- agg_log_20251027T230001Z.json

Executive Summary
This report summarizes 16,306 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. A significant number of events were also logged by Honeytrap, Suricata, Ciscoasa, and Sentrypeer. The most frequent attacks originated from IP address 144.172.108.231. The primary targets were ports 5060 (SIP) and 22 (SSH). Attackers were observed attempting to download and execute malicious scripts, as well as attempting to gain further access by manipulating SSH authorized_keys files.

Detailed Analysis

Attacks by honeypot:
- Cowrie: 7312
- Honeytrap: 3060
- Suricata: 1824
- Sentrypeer: 1794
- Ciscoasa: 1967
- Mailoney: 91
- Dionaea: 75
- Adbhoney: 34
- ConPot: 19
- Redishoneypot: 24
- Tanner: 48
- Honeyaml: 14
- H0neytr4p: 15
- ElasticPot: 14
- Ipphoney: 12
- Dicompot: 3

Top attacking IPs:
- 144.172.108.231: 1121
- 114.67.125.183: 514
- 113.137.40.250: 357
- 103.131.144.123: 337
- 103.193.178.68: 341
- 163.172.99.31: 336
- 185.176.94.101: 287
- 209.38.228.14: 263
- 91.229.9.84: 263
- 194.107.115.65: 246
- 116.193.191.90: 242
- 122.155.0.205: 240
- 41.59.229.33: 234
- 190.99.154.38: 231
- 185.227.152.155: 208
- 198.23.190.58: 131
- 173.249.45.217: 124

Top targeted ports/protocols:
- 5060: 1794
- 22: 900
- 5901: 297
- 2222: 74
- 80: 47
- 25: 91
- UDP/5060: 94
- TCP/22: 89
- 5903: 131
- 5904: 78
- 5905: 78
- 5908: 51
- 5909: 50
- 5907: 49
- 5902: 28
- TCP/80: 52
- 12125: 36
- 27019: 34
- 81: 19
- 8333: 17
- 27017: 15
- 9050: 49
- 58000: 25
- 8728: 15
- TCP/5432: 15
- 7001: 14
- 8081: 13

Most common CVEs:
- CVE-2005-4050: 80
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2025-57819 CVE-2025-57819: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-35394 CVE-2021-35394: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2006-2369: 1
- CVE-1999-0183: 1

Commands attempted by attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 53
- lockr -ia .ssh: 53
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 53
- cat /proc/cpuinfo | grep name | wc -l: 53
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 53
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 53
- ls -lh $(which ls): 53
- which ls: 53
- crontab -l: 53
- w: 53
- uname -m: 53
- cat /proc/cpuinfo | grep model | grep name | wc -l: 52
- top: 52
- uname: 52
- uname -a: 52
- whoami: 52
- lscpu | grep Model: 51
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 51
- Enter new UNIX password: : 42
- Enter new UNIX password:: 42

Signatures triggered:
- ET DROP Dshield Block Listed Source group 1: 365
- 2402000: 365
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 264
- 2023753: 264
- ET SCAN NMAP -sS window 1024: 194
- 2009582: 194
- ET HUNTING RDP Authentication Bypass Attempt: 100
- 2034857: 100
- ET VOIP MultiTech SIP UDP Overflow: 80
- 2003237: 80
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 25
- 2400031: 25
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 22
- 2403346: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 24
- 2403349: 24
- ET DROP Spamhaus DROP Listed Traffic Inbound group 14: 11
- 2400013: 11
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 11
- 2400040: 11

Users / login attempts:
- 345gs5662d34/345gs5662d34: 52
- root/3245gs5662d34: 9
- root/gogo1234: 5
- root/Jessica1173: 4
- root/111111aa: 4
- root/123156: 4
- root/jamesbond007: 4
- mysql/: 4
- root/jga: 4
- alix/alix: 4
- ulises/ulises: 4
- ulises/3245gs5662d34: 4
- ella/ella: 4
- ella/3245gs5662d34: 4
- etienne/etienne: 4
- etienne/3245gs5662d34: 4
- root/JH: 4
- admin/1234: 4
- root/sergio: 4

Files uploaded/downloaded:
- sh: 98
- wget.sh;: 4
- arm.uhavenobotsxd;: 2
- arm.uhavenobotsxd: 2
- arm5.uhavenobotsxd;: 2
- arm5.uhavenobotsxd: 2
- arm6.uhavenobotsxd;: 2
- arm6.uhavenobotsxd: 2
- arm7.uhavenobotsxd;: 2
- arm7.uhavenobotsxd: 2
- x86_32.uhavenobotsxd;: 2
- x86_32.uhavenobotsxd: 2
- mips.uhavenobotsxd;: 2
- mips.uhavenobotsxd: 2
- mipsel.uhavenobotsxd;: 2
- mipsel.uhavenobotsxd: 2
- irannet.mips;: 2
- irannet.mipsel;: 2
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1
- w.sh;: 1
- c.sh;: 1
- welcome.jpg): 1
- writing.jpg): 1
- tags.jpg): 1

HTTP User-Agents:
- (No data)

SSH clients:
- (No data)

SSH servers:
- (No data)

Top attacker AS organizations:
- (No data)

Key Observations and Anomalies:
- A large number of commands executed are related to system reconnaissance (checking CPU, memory, processes) and establishing persistent access (modifying SSH authorized_keys).
- Multiple attackers were observed downloading and attempting to execute shell scripts and binaries (e.g., `w.sh`, `c.sh`, `*.uhavenobotsxd`, `*.urbotnetisass`). These are likely related to botnet recruitment.
- The CVEs indicate that attackers are targeting a mix of old and more recent vulnerabilities, including those related to VoIP (SIP) and web servers.
- The high number of triggers for `ET DROP Dshield Block Listed Source` and `ET SCAN MS Terminal Server Traffic on Non-standard Port` signatures indicates that many of the attacking IPs are known bad actors and that scanning for RDP on non-standard ports is a common activity.
- The credentials attempted are a mix of common default passwords and more complex, potentially previously breached, passwords.
