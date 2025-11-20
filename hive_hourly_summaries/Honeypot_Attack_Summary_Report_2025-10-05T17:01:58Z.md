Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T17:01:34Z
**Timeframe:** 2025-10-05T16:20:01Z - 2025-10-05T17:00:01Z
**Files Used:**
- agg_log_20251005T162001Z.json
- agg_log_20251005T164001Z.json
- agg_log_20251005T170001Z.json

**Executive Summary**

This report summarizes 14,236 attacks recorded across three honeypot log files. The majority of attacks targeted the Cowrie (SSH) and Mailoney (SMTP) honeypots. The most frequent attacks originated from IP addresses 86.54.42.238 and 176.65.141.117. The most targeted port was port 25 (SMTP). Several CVEs were detected, with CVE-2005-4050 being the most common. Attackers attempted a variety of commands, primarily related to enumeration and establishing persistence.

**Detailed Analysis**

**Attacks by Honeypot**
- Cowrie: 6500
- Mailoney: 3295
- Suricata: 1498
- Ciscoasa: 1419
- Sentrypeer: 623
- Honeytrap: 563
- Dionaea: 126
- H0neytr4p: 72
- Adbhoney: 56
- Tanner: 18
- Honeyaml: 17
- Ipphoney: 14
- Redishoneypot: 12
- ElasticPot: 8
- ConPot: 6
- Miniprint: 9

**Top Attacking IPs**
- 86.54.42.238: 1641
- 176.65.141.117: 1640
- 118.194.230.211: 646
- 172.86.95.98: 415
- 45.140.17.52: 287
- 51.178.43.161: 288
- 27.71.230.3: 310
- 102.88.137.80: 202
- 172.208.52.110: 253
- 14.103.118.166: 137
- 143.110.241.64: 232
- 198.12.68.114: 288
- 212.25.35.66: 209
- 119.45.40.108: 242
- 103.226.139.143: 169
- 202.143.111.141: 168

**Top Targeted Ports/Protocols**
- 25: 3295
- 22: 912
- 5060: 623
- TCP/5900: 177
- 443: 68
- UDP/5060: 119
- 1433: 43
- TCP/1433: 45
- TCP/22: 31
- 80: 26
- 23: 48
- 445: 47

**Most Common CVEs**
- CVE-2005-4050: 115
- CVE-2002-0013 CVE-2002-0012: 17
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 13
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2021-3449 CVE-2021-3449: 7
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2001-0414: 1

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 38
- lockr -ia .ssh: 38
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 38
- cat /proc/cpuinfo | grep name | wc -l: 34
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 34
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 34
- ls -lh $(which ls): 34
- which ls: 34
- crontab -l: 34
- w: 34
- uname -m: 34
- cat /proc/cpuinfo | grep model | grep name | wc -l: 33
- top: 33
- uname: 33
- uname -a: 33
- whoami: 33
- lscpu | grep Model: 34
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 34
- Enter new UNIX password: : 27
- Enter new UNIX password:": 27

**Signatures Triggered**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 166
- ET DROP Dshield Block Listed Source group 1: 270
- ET HUNTING RDP Authentication Bypass Attempt: 78
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 185
- ET SCAN NMAP -sS window 1024: 143
- ET VOIP MultiTech SIP UDP Overflow: 115
- ET SCAN Suspicious inbound to MSSQL port 1433: 30
- ET INFO Reserved Internal IP Traffic: 56
- GPL SNMP request udp: 16
- GPL SNMP public access udp: 12

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 34
- test/zhbjETuyMffoL8F: 15
- root/LeitboGi0ro: 13
- novinhost/novinhost.org: 18
- root/nPSpP4PBW0: 13
- root/2glehe5t24th1issZs: 11
- root/3245gs5662d34: 8

**Files Uploaded/Downloaded**
- wget.sh;: 16
- w.sh;: 4
- c.sh;: 4

**HTTP User-Agents**
- None observed.

**SSH Clients**
- None observed.

**SSH Servers**
- None observed.

**Top Attacker AS Organizations**
- None observed.

**Key Observations and Anomalies**

- A significant number of commands attempted by attackers involve enumeration of system information (CPU, memory, etc.) and establishing persistence by adding an SSH key to `authorized_keys`.
- The high number of attacks on port 25 (SMTP) suggests a focus on spamming or mail-related exploits.
- The most common CVE, CVE-2005-4050, is related to a vulnerability in older versions of the MultiTech modem firmware, which is often targeted in automated scans.
- No HTTP User-Agents, SSH clients/servers, or AS organizations were recorded in these logs, which might indicate that the attacks were primarily from automated scripts that do not populate these fields.
