# Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T03:01:37Z
**Timeframe:** 2025-09-30T02:20:01Z to 2025-09-30T03:00:01Z
**Files Used:**
- agg_log_20250930T022001Z.json
- agg_log_20250930T024002Z.json
- agg_log_20250930T030001Z.json

## Executive Summary

This report summarizes 20,423 events collected from multiple honeypots over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Honeytrap and Suricata. The most prominent attacker IP was 160.25.118.10, responsible for a large volume of the observed traffic. Port 22 (SSH) was the most targeted port, consistent with widespread automated attacks. Several CVEs were observed, with the most frequent being related to older vulnerabilities. A variety of commands were attempted, primarily focused on reconnaissance and establishing control of the compromised system.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 14,098
- Honeytrap: 2,615
- Suricata: 1,745
- Ciscoasa: 1,384
- Dionaea: 317
- Tanner: 60
- Redishoneypot: 50
- H0neytr4p: 43
- Adbhoney: 16
- Miniprint: 18
- ConPot: 16
- Dicompot: 12
- Mailoney: 17
- Sentrypeer: 12
- ElasticPot: 4
- Ipphoney: 9
- Heralding: 3
- Honeyaml: 4

### Top Attacking IPs
- 160.25.118.10: 8,031
- 5.129.251.145: 1,235
- 43.163.91.110: 909
- 34.128.77.56: 425
- 179.32.33.160: 414
- 156.226.176.165: 430
- 185.156.73.167: 348
- 185.156.73.166: 348
- 92.63.197.55: 347
- 92.63.197.59: 318
- 20.193.141.133: 351
- 34.132.83.158: 210
- 14.241.254.5: 282
- 185.216.117.150: 286
- 211.253.31.30: 277
- 34.12.95.116: 190
- 94.254.0.234: 208
- 36.77.99.53: 200
- 167.172.189.176: 183
- 103.113.105.228: 70

### Top Targeted Ports/Protocols
- 22: 2,506
- 3306: 203
- 8333: 95
- 5901: 88
- 445: 49
- 80: 52
- 6379: 39
- TCP/22: 85
- 443: 55
- TCP/1080: 39
- 81: 30
- 23: 25
- 7777: 25
- 2323: 15
- 9000: 15
- TCP/1433: 15
- 8728: 16
- UDP/161: 21
- 9674: 15
- 4443: 12

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 15
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2019-11500 CVE-2019-11500: 6
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2006-2369: 1
- CVE-1999-0183: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 25
- lockr -ia .ssh: 25
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 25
- cat /proc/cpuinfo | grep name | wc -l: 25
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 25
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 25
- ls -lh $(which ls): 25
- which ls: 25
- crontab -l: 25
- w: 25
- uname -m: 25
- cat /proc/cpuinfo | grep model | grep name | wc -l: 25
- top: 25
- uname: 25
- uname -a: 26
- whoami: 25
- lscpu | grep Model: 25
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 25
- Enter new UNIX password: : 11
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 10

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 650
- 2402000: 650
- ET SCAN NMAP -sS window 1024: 213
- 2009582: 213
- ET SCAN Potential SSH Scan: 56
- 2001219: 56
- ET INFO Reserved Internal IP Traffic: 54
- 2002752: 54
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 42
- 2023753: 42
- ET INFO Proxy CONNECT Request: 16
- 2001675: 16
- ET SCAN Suspicious inbound to MSSQL port 1433: 13
- 2010935: 13
- GPL SNMP request udp: 12
- 2101417: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 22
- 2403347: 22
- GPL INFO SOCKS Proxy attempt: 30
- 2100615: 30

### Users / Login Attempts
- john/: 199
- 345gs5662d34/345gs5662d34: 25
- root/3245gs5662d34: 13
- root/2glehe5t24th1issZs: 8
- root/nPSpP4PBW0: 8
- foundry/foundry: 7
- root/LeitboGi0ro: 6
- test/zhbjETuyMffoL8F: 5
- root/Tk123456: 5
- castle/castle1!: 4
- joao/joao@123: 5
- root/Hn123456@: 3
- superadmin/admin123: 3
- httpadmin/httpadmin: 3
- root/1234!@#$qwerQWER: 3
- jasmin/jasmin123: 3
- root/qaz12345: 3
- ociisstd/ociisstd123: 3
- root/1234: 3
- ubuntu/ubuntu: 3

### Files Uploaded/Downloaded
- sh: 98
- arm.urbotnetisass;: 4
- arm.urbotnetisass: 4
- arm5.urbotnetisass;: 4
- arm5.urbotnetisass: 4
- arm6.urbotnetisass;: 4
- arm6.urbotnetisass: 4
- arm7.urbotnetisass;: 4
- arm7.urbotnetisass: 4
- x86_32.urbotnetisass;: 4
- x86_32.urbotnetisass: 4
- mips.urbotnetisass;: 4
- mips.urbotnetisass: 4
- mipsel.urbotnetisass;: 4
- mipsel.urbotnetisass: 4

### HTTP User-Agents
- No HTTP User-Agents were logged during this period.

### SSH Clients
- No specific SSH clients were logged during this period.

### SSH Servers
- No specific SSH servers were logged during this period.

### Top Attacker AS Organizations
- No Attacker AS Organizations were logged during this period.

## Key Observations and Anomalies

- **High Volume from a Single IP:** The IP address 160.25.118.10 was responsible for a disproportionately large number of events, suggesting a targeted or persistent automated attack.
- **Reconnaissance and Control Commands:** The most common commands are indicative of attackers attempting to gather system information (`uname`, `lscpu`, `cat /proc/cpuinfo`) and establish persistence (`chattr`, modifying `.ssh/authorized_keys`).
- **Malware Download Attempts:** The presence of `wget` and `curl` commands attempting to download files with names like `arm.urbotnetisass` indicates attempts to deploy malware, likely for botnet recruitment.
- **Focus on SSH:** The high number of connections to port 22 and the volume of SSH-related commands and credentials highlight the ongoing threat of brute-force and credential-stuffing attacks against SSH servers.

This concludes the Honeypot Attack Summary Report.
