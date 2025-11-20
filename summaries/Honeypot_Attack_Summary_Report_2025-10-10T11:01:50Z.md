
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T11:01:28Z
**Timeframe:** 2025-10-10T10:20:01Z to 2025-10-10T11:00:01Z
**Files Used:**
- agg_log_20251010T102001Z.json
- agg_log_20251010T104001Z.json
- agg_log_20251010T110001Z.json

## Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes, based on three separate log files. A total of 18,334 attacks were recorded across various honeypots. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks targeted SSH (port 22) and SMB (port 445). A significant number of brute-force login attempts and command executions were observed, primarily aimed at gaining control of the system and establishing a persistent presence. Several CVEs were also targeted.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 10175
- Honeytrap: 2957
- Suricata: 1741
- Ciscoasa: 1802
- Dionaea: 964
- Sentrypeer: 357
- Redishoneypot: 105
- Tanner: 123
- Mailoney: 51
- H0neytr4p: 22
- Honeyaml: 19
- ElasticPot: 8
- ConPot: 4
- Dicompot: 3
- Miniprint: 2
- Adbhoney: 1

### Top Attacking IPs
- 167.250.224.25: 1005
- 143.44.164.80: 767
- 51.250.65.61: 459
- 14.103.235.147: 285
- 43.224.248.187: 332
- 103.212.36.230: 218
- 112.31.108.8: 214
- 109.237.71.198: 187
- 137.184.72.181: 184
- 96.78.175.42: 163
- 150.95.190.167: 243
- 95.165.130.226: 149
- 172.190.89.127: 258
- 101.36.113.241: 134
- 43.156.66.219: 243
- 120.48.122.52: 129
- 103.147.211.2: 129
- 152.32.191.75: 223
- 201.186.40.161: 124
- 117.2.142.24: 119

### Top Targeted Ports/Protocols
- 22: 1445
- 445: 767
- 5060: 357
- 5903: 204
- 6379: 105
- 80: 117
- 1433: 100
- TCP/1433: 96
- 8333: 74
- 5908: 84
- 5909: 82
- 5901: 71
- 25: 43
- 2323: 37
- 8500: 35
- 27019: 34
- 15671: 34
- 27017: 32
- 5907: 49
- 17000: 30

### Most Common CVEs
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-1149
- CVE-1999-0183
- CVE-2021-35394 CVE-2021-35394

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 56
- lockr -ia .ssh: 56
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 56
- cat /proc/cpuinfo | grep name | wc -l: 56
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 56
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 56
- Enter new UNIX password: : 55
- Enter new UNIX password:: 55
- ls -lh $(which ls): 55
- which ls: 55
- crontab -l: 55
- w: 55
- uname -m: 55
- cat /proc/cpuinfo | grep model | grep name | wc -l: 55
- top: 55
- uname: 55
- uname -a: 55
- whoami: 55
- lscpu | grep Model: 55
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 55

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 383
- 2402000: 383
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 353
- 2023753: 353
- ET HUNTING RDP Authentication Bypass Attempt: 160
- 2034857: 160
- ET SCAN NMAP -sS window 1024: 151
- 2009582: 151
- ET SCAN Suspicious inbound to MSSQL port 1433: 90
- 2010935: 90

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 50
- vpn/vpn21: 6
- default/default12: 6
- blank/blank1234567890: 6
- root/001: 6
- unknown/unknown33: 6
- root/XSW123456!: 4
- alex/alex!: 4
- debian/temppwd: 4
- Support/55555555: 4
- root/WSX2024: 4
- root/WSX2024@: 4
- root/root!: 4
- root/WSX2024!: 4
- root/WSX2024.: 4
- github/1234: 4
- root/WSX@2024: 4
- root/WSX!2024: 4
- root/WSX.2024: 4
- nobody/nobody5: 4

### Files Uploaded/Downloaded
- blog-cover.jpg
- schema.org
- ghost-logo.svg
- blog-cover.jpg)
- svg
- hide.mpsl;
- welcome.jpg)
- writing.jpg)
- tags.jpg)

### HTTP User-Agents
- None observed

### SSH Clients
- None observed

### SSH Servers
- None observed

### Top Attacker AS Organizations
- None observed

## Key Observations and Anomalies

- A large number of commands executed are related to reconnaissance and establishing persistence, such as manipulating SSH keys and gathering system information.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` is a clear indicator of an attempt to install a persistent SSH key.
- The high volume of attacks from a small number of IPs suggests targeted or automated scanning campaigns.
- The variety of targeted ports indicates a broad scanning approach by attackers, looking for any available service to exploit.
- The presence of CVEs, even older ones, shows that attackers still try to exploit known vulnerabilities.
- No HTTP User-Agents, SSH clients/servers, or AS organizations were recorded in these logs, which might indicate that the attacks were primarily at the network level and did not result in successful higher-level protocol interactions that would be logged with this information.
