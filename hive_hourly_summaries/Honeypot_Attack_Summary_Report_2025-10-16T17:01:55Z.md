# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T17:01:28Z
**Timeframe of Report:** 2025-10-16T16:20:01Z to 2025-10-16T17:00:01Z
**Files Used to Generate Report:**
- agg_log_20251016T162001Z.json
- agg_log_20251016T164001Z.json
- agg_log_20251016T170001Z.json

## Executive Summary

This report summarizes 21,068 events collected from the honeypot network. The primary attack vectors observed were reconnaissance and brute-force attempts targeting VNC, SSH, and SIP services. A significant number of attacks originated from a small set of IP addresses, indicating targeted activity. The most common attack patterns involved attempts to gain unauthorized access and deploy malware.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 5354
- Suricata: 4664
- Heralding: 3091
- Sentrypeer: 2583
- Honeytrap: 2483
- Dionaea: 1128
- Ciscoasa: 1538
- ElasticPot: 55
- Miniprint: 51
- Redishoneypot: 41
- Mailoney: 28
- Tanner: 19
- H0neytr4p: 17
- ConPot: 6
- Honeyaml: 5
- Adbhoney: 2
- Ipphoney: 3

### Top Attacking IPs
- 45.134.26.47: 3092
- 10.208.0.3: 2724
- 134.199.193.216: 992
- 41.94.88.219: 892
- 23.94.26.58: 855
- 134.199.204.233: 719
- 45.171.150.123: 516
- 10.140.0.3: 384
- 172.86.95.115: 484
- 185.243.5.158: 478
- 172.86.95.98: 450
- 27.79.42.90: 383
- 201.22.227.249: 555
- 171.243.149.58: 244
- 101.100.194.23: 229
- 198.12.68.114: 186
- 107.170.36.5: 251
- 190.162.113.74: 119
- 4.194.4.255: 160
- 116.99.171.126: 160

### Top Targeted Ports/Protocols
- vnc/5900: 3091
- 5060: 2583
- 445: 1076
- 22: 963
- TCP/5900: 352
- 5903: 226
- 8333: 200
- 5901: 123
- 9200: 51
- 9100: 51
- 23: 82
- 5905: 78
- 5904: 78
- 6379: 41
- 5909: 50
- 5908: 49
- 5907: 50
- UDP/5060: 44
- 5902: 35
- TCP/22: 51

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2001-0414: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-1999-0517: 1
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2006-2369: 1

### Commands Attempted by Attackers
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 8
- lockr -ia .ssh: 8
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 8
- cat /proc/cpuinfo | grep name | wc -l: 8
- Enter new UNIX password: : 6
- Enter new UNIX password:: 6
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 6
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 6
- ls -lh $(which ls): 6
- which ls: 6
- crontab -l: 6
- w: 6
- uname -m: 6
- cat /proc/cpuinfo | grep model | grep name | wc -l: 6
- top: 6
- uname: 6
- uname -a: 6
- system: 4
- shell: 4
- q: 4

### Signatures Triggered
- ET INFO VNC Authentication Failure: 3105
- 2002920: 3105
- ET DROP Dshield Block Listed Source group 1: 369
- 2402000: 369
- ET SCAN NMAP -sS window 1024: 155
- 2009582: 155
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 201
- 2400041: 201
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 165
- 2400040: 165
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 68
- 2023753: 68
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET SCAN Potential SSH Scan: 29
- 2001219: 29
- ET SCAN Sipsak SIP scan: 39
- 2008598: 39

### Users / Login Attempts
- A variety of usernames and passwords were attempted, with common default credentials such as 'root', 'admin', 'support', and 'user' being frequently used.

### Files Uploaded/Downloaded
- ): 1

### HTTP User-Agents
- No HTTP User-Agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations were identified in the logs.

## Key Observations and Anomalies
- The high volume of VNC traffic suggests a coordinated campaign targeting this service.
- The repeated use of commands to gather system information and modify SSH keys indicates attackers are attempting to establish persistent access.
- The presence of CVEs related to older vulnerabilities highlights that attackers are still exploiting legacy systems.
- The single file downloaded with the name ")" is anomalous and may indicate a malformed script or an attempt to test for vulnerabilities.
