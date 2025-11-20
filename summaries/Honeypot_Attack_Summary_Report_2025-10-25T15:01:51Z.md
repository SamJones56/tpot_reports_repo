
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T15:01:27Z
**Timeframe:** 2025-10-25T14:20:01Z to 2025-10-25T15:00:01Z
**Files Used:** 
- agg_log_20251025T142001Z.json
- agg_log_20251025T144002Z.json
- agg_log_20251025T150001Z.json

## Executive Summary

This report summarizes 14,081 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were reconnaissance and automated login attempts. The most active honeypots were Heralding, Honeytrap, and Suricata. A single IP address, 185.243.96.105, was responsible for a significant portion of the traffic, primarily targeting VNC port 5900. Several CVEs were targeted, and attackers attempted to install SSH keys and download malicious scripts.

## Detailed Analysis

### Attacks by Honeypot

- Heralding: 4130
- Honeytrap: 3552
- Suricata: 2084
- Cowrie: 1890
- Ciscoasa: 1837
- Sentrypeer: 167
- Tanner: 121
- Mailoney: 126
- Dionaea: 68
- Adbhoney: 34
- ElasticPot: 18
- H0neytr4p: 16
- Redishoneypot: 15
- Miniprint: 8
- Honeyaml: 6
- Ipphoney: 4
- Dicompot: 3
- Medpot: 2

### Top Attacking IPs

- 185.243.96.105: 4130
- 80.94.95.238: 967
- 109.205.211.9: 444
- 107.170.36.5: 247
- 90.154.46.138: 218
- 34.92.146.210: 214
- 80.94.92.13: 151
- 45.136.68.49: 136
- 91.237.163.113: 134
- 167.250.224.25: 135
- 187.62.87.27: 114
- 85.192.29.247: 117
- 190.220.188.254: 100
- 203.195.82.4: 102
- 68.183.149.135: 111
- 68.183.207.213: 94
- 217.154.1.15: 113
- 193.24.211.28: 72
- 198.23.238.154: 66
- 173.249.47.226: 71

### Top Targeted Ports/Protocols

- vnc/5900: 4130
- 22: 299
- 8333: 183
- 5060: 167
- 80: 123
- 5903: 131
- 25: 126
- 5901: 110
- TCP/22: 75
- 5905: 75
- 5904: 75
- 9001: 49
- 5908: 50
- 5909: 48
- TCP/80: 49
- 15672: 35
- 11211: 40
- 5038: 39
- UDP/161: 21
- 81: 20

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012: 20
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2021-44228 CVE-2021-44228: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2023-49103 CVE-2023-49103: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2018-2893 CVE-2018-2893 CVE-2018-2893: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2025-22457 CVE-2025-22457: 1

### Commands Attempted by Attackers

- Basic system enumeration commands (uname, whoami, lscpu, etc.)
- Attempting to add an SSH key to authorized_keys
- File system manipulation (cd, rm, mkdir)
- Checking and manipulating cron jobs
- Changing user passwords

### Signatures Triggered

- ET SCAN MS Terminal Server Traffic on Non-standard Port: 723
- 2023753: 723
- ET DROP Dshield Block Listed Source group 1: 262
- 2402000: 262
- ET SCAN NMAP -sS window 1024: 178
- 2009582: 178
- ET HUNTING RDP Authentication Bypass Attempt: 190
- 2034857: 190
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Potential SSH Scan: 43
- 2001219: 43

### Users / Login Attempts

- /Passw0rd: 29
- /passw0rd: 13
- /1q2w3e4r: 12
- 345gs5662d34/345gs5662d34: 6
- root/excel95952012a: 4
- root/Excel95952015a: 4
- root/exclusivesip1: 4
- root/exito1314: 4
- root/exito7A: 4
- /1qaz2wsx: 6
- root/Expl0r3r5: 3
- /pa55word: 3
- /testpass: 5
- /qwertyui: 8
- /pa55w0rd: 4

### Files Uploaded/Downloaded

- sh: 98
- json: 2
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1

### HTTP User-Agents
- None observed.

### SSH Clients and Servers
- None observed.

### Top Attacker AS Organizations
- None observed.

## Key Observations and Anomalies

- A significant amount of activity originated from the IP address 185.243.96.105, which exclusively targeted the VNC port 5900. This suggests a targeted scan for exposed VNC servers.
- Attackers were observed attempting to download and execute shell scripts from a specific domain (netrip.ddns.net). This indicates an attempt to install malware or backdoors on compromised systems.
- The command to add a specific SSH key to `authorized_keys` was seen multiple times. This is a common technique for attackers to maintain persistent access to a compromised machine.
- Several attempts to exploit the Log4j vulnerability (CVE-2021-44228) were observed. This continues to be a popular target for attackers.
- The presence of commands like `tftp` and `wget` followed by `/bin/busybox TORHH` suggests attempts to use BusyBox to download and execute malware.
- The wide variety of honeypots that were triggered indicates a broad-spectrum, automated attack approach, rather than a targeted attack on a specific service.
