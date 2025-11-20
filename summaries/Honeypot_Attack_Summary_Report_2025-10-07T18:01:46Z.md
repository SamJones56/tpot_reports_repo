
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T18:01:26Z
**Timeframe:** 2025-10-07T17:20:02Z to 2025-10-07T18:00:01Z
**Files Used:**
- agg_log_20251007T172002Z.json
- agg_log_20251007T174001Z.json
- agg_log_20251007T180001Z.json

## Executive Summary
This report summarizes honeypot activity over the last hour, based on three log files. A total of 14,693 attacks were recorded. The most active honeypot was Cowrie, and the most common attack vector was SSH on port 22. The top attacking IP was 106.75.131.128. Several CVEs were targeted, with CVE-2021-44228 being the most frequent. A significant number of shell commands were attempted, indicating efforts to establish control over compromised systems.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 8388
- Honeytrap: 2586
- Suricata: 1510
- Mailoney: 866
- Sentrypeer: 640
- Ciscoasa: 472
- ElasticPot: 45
- Tanner: 34
- Adbhoney: 22
- ConPot: 26
- Heralding: 19
- H0neytr4p: 20
- Dionaea: 10
- Honeyaml: 10
- Redishoneypot: 9
- Dicompot: 6
- ssh-rsa: 30

### Top Attacking IPs
- 106.75.131.128: 1234
- 86.54.42.238: 821
- 4.144.169.44: 559
- 209.38.88.14: 1045
- 104.223.122.114: 406
- 220.247.224.226: 470
- 172.208.24.217: 397
- 185.255.126.223: 558
- 20.46.54.49: 313
- 45.140.17.52: 215
- 209.141.52.88: 341

### Top Targeted Ports/Protocols
- 22: 1197
- 5060: 640
- 25: 866
- 8333: 151
- 9200: 42
- TCP/22: 76
- 5903: 94

### Most Common CVEs
- CVE-2021-44228: 26
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2023-26801: 2
- CVE-2021-35394: 1
- CVE-2005-4050: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 42
- lockr -ia .ssh: 42
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 42
- cat /proc/cpuinfo | grep name | wc -l: 42
- Enter new UNIX password: : 39
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 42
- uname -a: 42
- whoami: 42

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 322
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 160
- ET SCAN NMAP -sS window 1024: 152
- ET SCAN Potential SSH Scan: 60
- ET INFO Reserved Internal IP Traffic: 57
- ET SCAN Suspicious inbound to MSSQL port 1433: 14
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 28

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 41
- root/: 30
- steam/steam@2025: 5
- steam/3245gs5662d34: 5
- es/1234567: 4
- sysadmin/sysadmin@1: 10
- vpn/password@123: 4

### Files Uploaded/Downloaded
- wget.sh;: 12
- w.sh;: 3
- c.sh;: 3
- mips: 2
- Space.mips;: 2
- Mozi.m dlink.mips: 1

### HTTP User-Agents
- None observed.

### SSH Clients and Servers
- **Clients:** None observed.
- **Servers:** None observed.

### Top Attacker AS Organizations
- None observed.

## Key Observations and Anomalies
- The vast majority of attacks are automated, focusing on common vulnerabilities and weak credentials.
- The high number of commands related to SSH key manipulation suggests attackers are attempting to establish persistent access.
- The targeting of CVE-2021-44228 (Log4Shell) remains a popular attack vector.
- The lack of observed HTTP User-Agents, SSH clients/servers, and AS organizations might indicate limitations in the current honeypot configuration or data collection.
