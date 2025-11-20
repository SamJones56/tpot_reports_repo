
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T20:01:28Z
**Timeframe:** 2025-10-13T19:20:01Z to 2025-10-13T20:00:01Z
**Files Used:**
- agg_log_20251013T192001Z.json
- agg_log_20251013T194001Z.json
- agg_log_20251013T200001Z.json

## Executive Summary

This report summarizes 19,593 events collected from the honeypot network. The majority of attacks were detected by the Cowrie honeypot. The most targeted ports were 5060 (SIP) and 22 (SSH). A significant number of attacks originated from IP addresses 45.78.192.81, 46.32.178.190, and 13.86.116.21. Several CVEs were exploited, with CVE-2022-27255 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 11393
- Sentrypeer: 3339
- Suricata: 1472
- Mailoney: 852
- Dionaea: 978
- Honeytrap: 1223
- Tanner: 189
- H0neytr4p: 35
- Adbhoney: 25
- Redishoneypot: 17
- Miniprint: 21
- Heralding: 16
- Dicompot: 10
- ElasticPot: 6
- ConPot: 5
- Honeyaml: 5
- Ciscoasa: 4
- Ipphoney: 3

### Top Attacking IPs
- 45.78.192.81: 1247
- 46.32.178.190: 1247
- 13.86.116.21: 1247
- 185.243.5.146: 1323
- 94.126.59.114: 1250
- 45.236.188.4: 921
- 185.243.5.148: 787
- 45.200.233.125: 398
- 200.247.127.242: 322
- 172.86.95.115: 387
- 172.86.95.98: 395
- 62.141.43.183: 324
- 154.221.19.152: 315
- 157.20.207.165: 174
- 45.43.55.121: 173
- 102.132.245.209: 158
- 96.92.63.243: 193

### Top Targeted Ports/Protocols
- 5060: 3339
- 22: 1853
- 445: 832
- 25: 853
- 80: 192
- 1433: 101
- 23: 158
- TCP/22: 75
- UDP/5060: 74

### Most Common CVEs
- CVE-2022-27255: 29
- CVE-2006-0189: 24
- CVE-2002-0013 CVE-2002-0012: 15
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 9
- CVE-2019-11500: 3
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
- CVE-2002-1149: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 29
- lockr -ia .ssh: 29
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 29
- cat /proc/cpuinfo | grep name | wc -l: 29
- uname -a: 31
- whoami: 30
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 29
- ls -lh $(which ls): 29
- which ls: 29
- crontab -l: 29
- w: 29
- uname -m: 29
- cat /proc/cpuinfo | grep model | grep name | wc -l: 29
- top: 29
- uname: 29
- lscpu | grep Model: 29
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 29
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 14
- Enter new UNIX password: : 13

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 394
- 2402000: 394
- ET SCAN NMAP -sS window 1024: 165
- 2009582: 165
- ET SCAN Potential SSH Scan: 64
- 2001219: 64
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 31
- 2010939: 31
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 24
- 2403349: 24
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 21
- 2038669: 21

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 29
- root/3245gs5662d34: 14
- root/Password@2025: 13
- sa/Vordruck$Verl@g1993: 10
- sa/!dESCO?2010: 10
- sa/@ebp78EBP: 10
- TrackerDbUser/Tracker@2022: 10
- sa/SageCRM#20xx: 10

### Files Uploaded/Downloaded
- Mozi.m: 4
- arm.urbotnetisass: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass: 2
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png: 2
- no_avatar-849f9c04a3a0d0cea2424ae97b27447dc64a7dbfae83c036c45b403392f0e8ba.png: 1
- &currentsetting.htm=1: 1
- ns#: 1
- sign_in: 1

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients
- No SSH clients recorded in this period.

### SSH Servers
- No SSH servers recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations recorded in this period.

## Key Observations and Anomalies

- **High-Volume Scans:** A small number of IP addresses are responsible for a large portion of the observed traffic, indicating targeted scanning campaigns against the honeypot infrastructure.
- **Consistent Command Execution:** Attackers are consistently using a set of commands to gather system information, check for running processes, and attempt to establish persistent access by modifying SSH authorized_keys.
- **Malware Download Attempts:** The presence of filenames such as "Mozi.m" and "urbotnetisass" variants indicates attempts to download and execute malware on the compromised systems.
- **Exploitation of Known Vulnerabilities:** The targeting of CVE-2022-27255 (Realtek eCos RSDK/MSDK Stack-based Buffer Overflow) suggests that attackers are actively exploiting known vulnerabilities in IoT devices.
- **Focus on SIP and SSH:** The high number of events on ports 5060 and 22 indicates a strong focus on compromising VoIP and remote administration services.
