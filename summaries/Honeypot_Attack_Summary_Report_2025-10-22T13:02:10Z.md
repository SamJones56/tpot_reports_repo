# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T13:01:41Z
**Timeframe:** 2025-10-22T12:20:01Z to 2025-10-22T13:00:01Z
**Files Used:**
- agg_log_20251022T122001Z.json
- agg_log_20251022T124001Z.json
- agg_log_20251022T130001Z.json

---

## Executive Summary

This report summarizes 19,468 events captured by the honeypot network over a period of approximately 40 minutes. The majority of attacks were detected by the Dionaea, Honeytrap, and Cowrie honeypots. The most prominent attacker IP was 1.9.70.82, responsible for a significant portion of the traffic. The most targeted port was 445 (SMB), indicating widespread scanning for SMB vulnerabilities. A number of CVEs were detected, with CVE-2021-3449 and CVE-2019-11500 being the most frequent. Attackers were observed attempting to modify SSH authorized_keys and gather system information.

---

## Detailed Analysis

### Attacks by Honeypot
- Dionaea: 5747
- Honeytrap: 5295
- Cowrie: 4454
- Ciscoasa: 1716
- Suricata: 1691
- Sentrypeer: 290
- Mailoney: 75
- Tanner: 92
- Redishoneypot: 31
- Adbhoney: 20
- H0neytr4p: 24

### Top Attacking IPs
- 1.9.70.82: 4466
- 129.212.177.106: 998
- 45.134.26.62: 866
- 45.134.26.20: 497
- 45.140.17.144: 388
- 45.140.17.153: 336
- 181.48.187.43: 279
- 124.226.219.166: 336
- 107.170.36.5: 251

### Top Targeted Ports/Protocols
- 445: 4900
- 22: 702
- 5060: 290
- TCP/21: 236
- 5903: 228
- 8333: 168
- TCP/445: 99
- 21: 121

### Most Common CVEs
- CVE-2021-3449: 12
- CVE-2019-11500: 10
- CVE-2002-0013: 5
- CVE-2002-0012: 5
- CVE-2024-4577: 4
- CVE-2021-41773: 4
- CVE-2021-42013: 2
- CVE-2002-0953: 2
- CVE-2006-2369: 1
- CVE-1999-0517: 1

### Commands Attempted by Attackers
- uname -a: 16
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 15
- lockr -ia .ssh: 15
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 15
- cat /proc/cpuinfo | grep name | wc -l: 15
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 15
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 15
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 7
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...: 1

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 223
- ET SCAN NMAP -sS window 1024: 169
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 208
- ET FTP FTP PWD command attempt without login: 116
- ET FTP FTP CWD command attempt without login: 112
- ET HUNTING RDP Authentication Bypass Attempt: 82
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 93
- ET SCAN Suspicious inbound to MSSQL port 1433: 69
- ET INFO Reserved Internal IP Traffic: 59

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 15
- root/3245gs5662d34: 7
- root/Bonuscred326159: 4
- root/BOrneo9001: 4
- root/Borsa5255: 4
- root/Bot42zp: 4
- root/boy2cat4: 4
- admin/admin123: 3
- root/bpo: 3

### Files Uploaded/Downloaded
- sh: 98
- wget.sh;: 8
- 11: 6
- fonts.gstatic.com: 6
- css?family=Libre+Franklin...: 6
- ie8.css?ver=1.0: 6
- html5.js?ver=3.7.3: 6
- Mozi.m: 4
- w.sh;: 2
- c.sh;: 2

### HTTP User-Agents
- No HTTP User-Agent data was available in the logs.

### SSH Clients
- No SSH client data was available in the logs.

### SSH Servers
- No SSH server data was available in the logs.

### Top Attacker AS Organizations
- No AS organization data was available in the logs.

---

## Key Observations and Anomalies

- **High Volume of SMB Scans:** The overwhelming number of events targeting port 445 suggests large-scale, automated scanning for SMB vulnerabilities like EternalBlue.
- **SSH Key Manipulation:** A significant number of commands were aimed at removing existing SSH configurations and adding a specific public key to the `authorized_keys` file. This is a common technique for attackers to maintain persistent access to a compromised machine. The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys ...` was particularly prevalent.
- **Information Gathering:** Attackers frequently ran commands to gather information about the system's CPU, memory, and running processes (`uname -a`, `cat /proc/cpuinfo`, `free -m`). This is typical post-exploitation behavior to understand the environment they have compromised.
- **Dominant Attacker:** The IP address 1.9.70.82 was the most active attacker across all three log files, indicating a persistent source of malicious traffic.
