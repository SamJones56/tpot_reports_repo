## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T12:01:35Z
**Timeframe:** 2025-10-08T11:20:01Z to 2025-10-08T12:00:01Z
**Files Used:**
- agg_log_20251008T112001Z.json
- agg_log_20251008T114001Z.json
- agg_log_20251008T120001Z.json

### Executive Summary
This report summarizes 12,467 malicious events captured by the honeypot network over the last hour. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute force attempts. A significant number of attacks originated from a small cluster of IP addresses, suggesting coordinated activity. The most frequently targeted port was TCP/22 (SSH). Attackers were observed attempting to modify SSH authorized_keys files and perform system reconnaissance. Several CVEs were detected, primarily related to remote code execution vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7145
- Honeytrap: 1866
- Ciscoasa: 1675
- Suricata: 915
- Dionaea: 480
- Sentrypeer: 155
- H0neytr4p: 68
- Mailoney: 66
- Redishoneypot: 34
- Tanner: 28
- ConPot: 7
- Heralding: 6
- ElasticPot: 3
- Ipphoney: 3
- Honeyaml: 12
- ssh-rsa: 2
- Adbhoney: 2

**Top Attacking IPs:**
- 45.78.192.92: 1247
- 164.92.85.77: 1244
- 47.242.0.187: 1244
- 209.38.91.18: 1033
- 182.176.149.227: 333
- 43.143.137.138: 199
- 124.156.238.210: 263
- 43.160.204.100: 214
- 23.88.43.131: 184
- 175.126.166.172: 169
- 85.215.65.189: 114
- 101.42.248.167: 98
- 82.112.238.153: 94
- 185.228.3.9: 85
- 51.68.199.166: 115

**Top Targeted Ports/Protocols:**
- 22: 1301
- 445: 341
- 5060: 155
- 3306: 97
- 5038: 85
- 5903: 105
- 5901: 84
- 25: 66
- 443: 68
- 23: 57
- 6379: 34
- 8333: 37
- 80: 24

**Most Common CVEs:**
- CVE-2019-11500: 3
- CVE-2021-3449: 2
- CVE-2005-4050: 2
- CVE-2024-3721: 1
- CVE-2018-11776: 1

**Commands Attempted by Attackers:**
- `Enter new UNIX password:`: 9
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 8
- `lockr -ia .ssh`: 8
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 8
- `cat /proc/cpuinfo | grep name | wc -l`: 8
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 8
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 8
- `ls -lh $(which ls)`: 8
- `which ls`: 8
- `crontab -l`: 8
- `w`: 8
- `uname -m`: 8
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 6
- `top`: 6
- `uname`: 5
- `uname -a`: 5
- `whoami`: 5
- `lscpu | grep Model`: 5
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 5
- `system`: 4
- `shell`: 4
- `q`: 4
- `cat /proc/uptime 2 > /dev/null | cut -d. -f1`: 4
- `uname -s -v -n -r -m`: 3

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 278
- ET SCAN NMAP -sS window 1024: 147
- ET INFO Reserved Internal IP Traffic: 58
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 30
- ET SCAN Potential SSH Scan: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 65: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 2: 10
- ET CINS Active Threat Intelligence Poor Reputation IP group 93: 8

**Users / Login Attempts:**
- appuser/: 94
- supervisor/222222: 6
- root/R0ot: 6
- debian/debian77: 6
- config/config12: 6
- support/password@: 6
- root/deploy: 6
- root/system32: 6
- root/secret: 6
- 345gs5662d34/345gs5662d34: 5

**Files Uploaded/Downloaded:**
- No file transfer activity was observed.

**HTTP User-Agents:**
- No HTTP user-agent data was recorded.

**SSH Clients and Servers:**
- No specific SSH client or server signature data was recorded.

**Top Attacker AS Organizations:**
- No AS organization data was recorded.

### Key Observations and Anomalies
- **High-Volume SSH Activity:** The Cowrie honeypot logged over 7,000 events, the vast majority of which were SSH-based. This indicates a persistent and automated threat landscape targeting exposed SSH servers.
- **Credential Stuffing:** A wide variety of usernames and passwords were attempted, from common defaults ('root', 'admin') to more specific ones ('appuser', 'postgres'), typical of credential stuffing lists.
- **Post-Exploitation Commands:** The commands executed post-login are indicative of attackers attempting to establish persistence. The repeated use of `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` is a clear attempt to install the attacker's SSH key for future access.
- **System Reconnaissance:** Attackers frequently ran commands like `uname`, `lscpu`, `free -m`, and `cat /proc/cpuinfo` to gather information about the compromised system's architecture and resources.
- **Coordinated Scanning:** The concentration of attacks from IPs like `45.78.192.92` and `164.92.85.77` suggests these may be part of a botnet or a single actor's infrastructure dedicated to scanning and exploitation.
