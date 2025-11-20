
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T07:01:24Z
**Timeframe Covered:** 2025-10-26T06:20:01Z to 2025-10-26T07:00:01Z
**Files Used to Generate Report:**
- agg_log_20251026T062001Z.json
- agg_log_20251026T064001Z.json
- agg_log_20251026T070001Z.json

## Executive Summary

This report summarizes 17,443 malicious events captured by the honeypot network. The most engaged honeypots were Suricata, Cowrie, and Honeytrap, indicating a high volume of network intrusions, SSH/Telnet brute-force attempts, and web application attacks. The most prolific attacker IP was `109.205.211.9`. A significant portion of the traffic involved scans for MS Terminal Server and RDP authentication bypass attempts. Attackers were observed attempting to modify SSH authorized_keys and download malicious shell scripts.

## Detailed Analysis

### Attacks by Honeypot
- Suricata: 4513
- Cowrie: 4832
- Honeytrap: 4392
- Ciscoasa: 1867
- Dionaea: 831
- Sentrypeer: 601
- Mailoney: 175
- Tanner: 82
- Adbhoney: 42
- H0neytr4p: 35
- Redishoneypot: 25
- ElasticPot: 13
- Honeyaml: 13
- ConPot: 10
- Dicompot: 6
- Wordpot: 2
- Heralding: 3
- Ipphoney: 1

### Top Attacking IPs
- 109.205.211.9: 2720
- 178.128.241.191: 870
- 118.69.3.58: 751
- 88.214.50.58: 646
- 80.94.95.238: 492
- 185.243.5.121: 523
- 167.71.68.143: 455
- 196.251.71.24: 274
- 90.154.46.138: 198
- 107.170.36.5: 248
- 190.167.237.191: 194
- 132.145.213.106: 173
- 185.216.116.13: 204
- 217.160.201.135: 138
- 152.42.216.249: 128
- 172.208.24.217: 125
- 103.124.100.181: 189
- 109.91.230.1: 209
- 45.154.138.19: 225

### Top Targeted Ports/Protocols
- 22: 855
- 445: 780
- 5060: 601
- 25: 175
- 5038: 225
- 80: 66
- 8333: 121
- 2068: 156
- 5903: 133
- 5901: 119
- TCP/22: 92
- 5905: 78
- 5904: 76
- 443: 38
- TCP/80: 63
- 9443: 30
- 23: 27
- TCP/1521: 29
- UDP/5060: 33

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2010-0738: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2009-2765: 1
- CVE-2005-4050: 1
- CVE-2021-35394 CVE-2021-35394: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 12
- lockr -ia .ssh: 12
- cd ~ && rm -rf .ssh && ... authorized_keys ...: 12
- cat /proc/cpuinfo | grep name | wc -l: 11
- Enter new UNIX password: : 9
- Enter new UNIX password:": 9
- free -m | grep Mem | awk ...: 11
- uname -a: 10
- whoami: 10
- system: 2
- shell: 2

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 2054
- ET HUNTING RDP Authentication Bypass Attempt: 877
- ET DROP Dshield Block Listed Source group 1: 483
- ET SCAN NMAP -sS window 1024: 180
- ET SCAN Potential SSH Scan: 46
- ET INFO Reserved Internal IP Traffic: 60

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 10
- root/Galileo: 4
- root/galinablanka: 4
- root/Gambarotta1973: 4
- root/Garajes2015: 4
- root/gatefa123: 4
- root/gary101101: 4
- admin/12091979: 4
- admin/120887: 4
- admin/120886: 4
- admin/12081996: 4
- admin/120789: 4

### Files Uploaded/Downloaded
- sh: 98
- wget.sh;: 16
- w.sh;: 4
- c.sh;: 4
- Mozi.m: 1
- bot.mpsl;: 1

### HTTP User-Agents
- No HTTP user-agents were recorded in the logs.

### SSH Clients and Servers
- No specific SSH clients or servers were recorded in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in the logs.

## Key Observations and Anomalies

- **High RDP/Terminal Server Activity:** The most frequently triggered Suricata signature was "ET SCAN MS Terminal Server Traffic on Non-standard Port," indicating widespread scanning for remote desktop services.
- **SSH Key Manipulation:** A common pattern observed in Cowrie was the attempt to remove existing SSH configurations and add a new public key to `authorized_keys`. This is a classic technique to maintain persistent access.
- **Repetitive Reconnaissance Commands:** Attackers frequently ran commands like `uname -a`, `whoami`, and `cat /proc/cpuinfo` to gather system information, likely as part of automated scripts to profile the compromised machine.
- **Malware Download Attempts:** Multiple attempts to download shell scripts (`w.sh`, `c.sh`, `wget.sh`) and malware (`Mozi.m`) were recorded, indicating efforts to deploy second-stage payloads.
