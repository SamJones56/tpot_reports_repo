
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T16:01:37Z
**Timeframe of Report:** 2025-10-24T15:20:02Z to 2025-10-24T16:00:01Z
**Files Used:** agg_log_20251024T152002Z.json, agg_log_20251024T154001Z.json, agg_log_20251024T160001Z.json

## Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing 29,341 events from three log files. The majority of attacks targeted the Dionaea honeypot. The most prominent attacking IP address was 114.47.12.143. Port 445 (SMB) was the most targeted port. Several CVEs were detected, and a variety of commands were attempted by attackers, primarily focused on reconnaissance and establishing control.

## Detailed Analysis

### Attacks by Honeypot
* Dionaea: 11416
* Cowrie: 5362
* Suricata: 4736
* Honeytrap: 5792
* Ciscoasa: 1609
* Sentrypeer: 162
* Redishoneypot: 59
* Tanner: 54
* Mailoney: 61
* Adbhoney: 37
* H0neytr4p: 26
* Honeyaml: 11
* ElasticPot: 5
* ConPot: 7
* Heralding: 3
* Ipphoney: 1

### Top Attacking IPs
* 114.47.12.143: 11312
* 109.205.211.9: 2231
* 217.218.145.138: 1302
* 80.94.95.238: 1356
* 34.47.232.78: 1136
* 45.134.26.20: 997
* 45.134.26.62: 915
* 59.97.205.137: 406
* 45.140.17.144: 431
* 202.184.134.84: 325
* 161.132.37.62: 312
* 167.99.74.18: 272
* 193.163.72.91: 247
* 52.169.142.214: 251
* 107.170.36.5: 228
* 150.95.157.171: 222
* 94.180.217.138: 194
* 115.190.73.63: 202
* 182.42.93.139: 159
* 222.124.17.227: 128

### Top Targeted Ports/Protocols
* 445: 11330
* TCP/445: 1298
* 22: 769
* TCP/22: 53
* 5060: 162
* 5903: 122
* 5901: 103
* 6379: 56
* 80: 51
* 8333: 82
* 5905: 72
* 5904: 69
* 25: 61
* 1433: 48
* 5908: 46
* 5909: 45
* 5907: 45
* 23: 33
* 5902: 38
* TCP/5432: 12

### Most Common CVEs
* CVE-2002-0013 CVE-2002-0012
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
* CVE-2001-0414
* CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255

### Commands Attempted by Attackers
* cd ~; chattr -ia .ssh; lockr -ia .ssh: 26
* lockr -ia .ssh: 26
* cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 26
* cat /proc/cpuinfo | grep name | wc -l: 26
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 26
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 26
* ls -lh $(which ls): 26
* which ls: 26
* crontab -l: 26
* w: 26
* uname -m: 26
* cat /proc/cpuinfo | grep model | grep name | wc -l: 26
* top: 26
* uname: 26
* uname -a: 26
* whoami: 26
* lscpu | grep Model: 26
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 26
* Enter new UNIX password: : 13
* Enter new UNIX password:: 9
* rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 7

### Signatures Triggered
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 1843
* 2023753: 1843
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1296
* 2024766: 1296
* ET HUNTING RDP Authentication Bypass Attempt: 623
* 2034857: 623
* ET DROP Dshield Block Listed Source group 1: 239
* 2402000: 239
* ET SCAN NMAP -sS window 1024: 167
* 2009582: 167
* ET INFO Reserved Internal IP Traffic: 56
* 2002752: 56
* ET SCAN Potential SSH Scan: 33
* 2001219: 33
* ET INFO CURL User Agent: 16
* 2002824: 16
* ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 14
* 2400040: 14

### Users / Login Attempts
* 345gs5662d34/345gs5662d34: 24
* root/3245gs5662d34: 10
* root/Domicilios2014: 4
* root/Dominio2015: 4
* root/Domino: 4
* deploy/123qwe: 4
* office/office@123: 4
* root/Dongle2500: 4
* invite/invite: 3
* invite/3245gs5662d34: 3
* root/Aa1111: 3
* root/domidot: 3
* guest/abc123: 3
* xwang/xwang: 3
* db2fenc1/p@ssw0rd: 3
* evs/evs: 3
* root/touring: 3
* root/p@$$w0rd@2023: 3
* root/1qaz#edc: 3
* root/admin3344: 5

### Files Uploaded/Downloaded
* No files were uploaded or downloaded in this timeframe.

### HTTP User-Agents
* No HTTP user agents were recorded in this timeframe.

### SSH Clients and Servers
* No SSH clients or servers were recorded in this timeframe.

### Top Attacker AS Organizations
* No AS organizations were recorded in this timeframe.

## Key Observations and Anomalies
* The overwhelming majority of attacks were directed at port 445, indicating widespread SMB scanning and exploitation attempts.
* A single IP address, 114.47.12.143, was responsible for a significant portion of the total attack volume, primarily targeting the Dionaea honeypot on port 445.
* The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, suggesting attempts to install a persistent SSH key for backdoor access.
* The `DoublePulsar` signature was triggered a large number of times, indicating attempts to exploit the SMB vulnerability (likely related to EternalBlue).
* There were numerous brute-force login attempts with a wide variety of usernames and passwords, none of which appear to be sophisticated.
* No files were successfully transferred, and no HTTP-based attacks were recorded in detail.
