Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T02:01:51Z
**Timeframe:** 2025-10-04T01:20:01Z to 2025-10-04T02:00:01Z
**Files Used:**
- agg_log_20251004T012001Z.json
- agg_log_20251004T014002Z.json
- agg_log_20251004T020001Z.json

### Executive Summary
This report summarizes 18,378 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Honeytrap, Cowrie, and Mailoney honeypots. A significant portion of the attacks originated from the IP address 45.234.176.18, which was responsible for over 5,800 events directed at the Honeytrap honeypot. The most targeted ports were 25 (SMTP), 22 (SSH), and 5060 (SIP). A number of CVEs were detected, with CVE-2016-5696 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control over the compromised system.

### Detailed Analysis

**Attacks by Honeypot:**
- Honeytrap: 6412
- Cowrie: 5276
- Mailoney: 2477
- Ciscoasa: 1882
- Suricata: 1693
- Dionaea: 222
- Sentrypeer: 191
- H0neytr4p: 74
- Adbhoney: 41
- Tanner: 26
- Redishoneypot: 20
- ConPot: 16
- Miniprint: 12
- ElasticPot: 11
- Heralding: 16
- Honeyaml: 4
- Dicompot: 4
- Ipphoney: 1

**Top Attacking IPs:**
- 45.234.176.18: 5815
- 176.65.141.117: 1640
- 86.54.42.238: 821
- 162.240.154.77: 523
- 152.32.145.111: 518
- 103.163.215.10: 518
- 36.93.247.226: 493
- 152.42.196.217: 417
- 51.222.85.63: 311
- 88.210.63.16: 280
- 185.156.73.166: 227
- 210.79.190.46: 224
- 154.221.21.168: 201
- 27.254.149.199: 188
- 27.50.25.190: 169
- 170.233.151.14: 168
- 193.203.203.7: 163
- 103.176.78.176: 154
- 46.105.87.113: 141
- 139.150.83.88: 135

**Top Targeted Ports/Protocols:**
- 25: 2477
- 22: 610
- 5060: 191
- 445: 90
- 3306: 86
- 443: 74
- 23: 47
- TCP/1080: 43
- 3388: 39
- 15672: 34
- 81: 29
- 80: 28
- 5555: 23
- 6379: 17
- TCP/22: 16
- postgresql/5432: 16
- UDP/161: 14
- TCP/80: 14
- TCP/1433: 12
- 9100: 12

**Most Common CVEs:**
- CVE-2016-5696: 32
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2021-35394 CVE-2021-35394: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2005-4050: 1

**Commands Attempted by Attackers:**
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
- Enter new UNIX password:
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- tftp; wget; /bin/busybox MKVRY

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 458
- 2402000: 458
- ET SCAN NMAP -sS window 1024: 178
- 2009582: 178
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 172
- 2023753: 172
- ET HUNTING RDP Authentication Bypass Attempt: 84
- 2034857: 84
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET EXPLOIT RST Flood With Window: 32
- 2023141: 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 22
- 2403344: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 21
- 2403345: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 68: 19
- 2403367: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 19
- 2403347: 19
- GPL INFO SOCKS Proxy attempt: 18
- 2100615: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 17
- 2403350: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 17
- 2403346: 17
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 16
- 2403348: 16
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 14
- 2403343: 14
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 12
- 2400027: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 12
- 2403342: 12

**Users / Login Attempts:**
- a2billinguser/: 82
- 345gs5662d34/345gs5662d34: 37
- root/nPSpP4PBW0: 13
- root/2glehe5t24th1issZs: 11
- root/3245gs5662d34: 13
- test/zhbjETuyMffoL8F: 12
- root/LeitboGi0ro: 11
- superadmin/admin123: 10
- user1/pass1234: 5
- root/qqqq: 5
- jules/jules: 3
- admin/default: 3
- minecraft/mc: 3
- digital/digital@123: 3
- odoo/odoo@2025: 3
- tezos/tezos: 3
- tezos/3245gs5662d34: 3
- ems/ems: 3
- root/Admin112233: 3
- geo/geo123: 3

**Files Uploaded/Downloaded:**
- UnHAnaAW.mpsl;: 8
- UnHAnaAW.arm;: 4
- UnHAnaAW.arm5;: 4
- UnHAnaAW.arm6;: 4
- UnHAnaAW.arm7;: 4
- UnHAnaAW.m68k;: 4
- UnHAnaAW.mips;: 4
- UnHAnaAW.ppc;: 4
- UnHAnaAW.sh4;: 4
- UnHAnaAW.spc;: 4
- UnHAnaAW.x86;: 4
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1

**HTTP User-Agents:**
- No data recorded.

**SSH Clients:**
- No data recorded.

**SSH Servers:**
- No data recorded.

**Top Attacker AS Organizations:**
- No data recorded.

### Key Observations and Anomalies
- The IP address 45.234.176.18 was responsible for an anomalously high number of events (5815) directed at the Honeytrap honeypot. This suggests a targeted attack or a botnet focused on a specific vulnerability that Honeytrap is designed to emulate.
- The commands attempted by attackers indicate a clear pattern of reconnaissance (e.g., `uname -a`, `cat /proc/cpuinfo`), followed by attempts to establish persistence by adding an SSH key to `authorized_keys`.
- The most common CVE, CVE-2016-5696, is a TCP vulnerability that can be used to hijack traffic. This, combined with the high number of Suricata alerts, suggests that attackers are attempting to perform man-in-the-middle attacks.
- A number of files with names like `UnHAnaAW.*` and `*.urbotnetisass` were downloaded. These are likely malicious binaries for different architectures, indicating that attackers are attempting to deploy malware on the compromised systems.
- The high number of login attempts with default or common credentials across various services (SSH, Telnet, etc.) highlights the ongoing threat of brute-force attacks.
