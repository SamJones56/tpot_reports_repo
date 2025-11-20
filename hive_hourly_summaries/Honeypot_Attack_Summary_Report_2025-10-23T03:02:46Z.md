
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T03:01:38Z
**Timeframe:** 2025-10-23T02:20:02Z to 2025-10-23T03:00:01Z
**Files Used:** agg_log_20251023T022002Z.json, agg_log_20251023T024001Z.json, agg_log_20251023T030001Z.json

## Executive Summary

This report summarizes 18915 events collected from the honeypot network. The majority of attacks were detected by the Cowrie, Honeytrap, and Suricata honeypots. The most frequent attacks originated from IP addresses 109.205.211.9, 156.198.249.65, and 67.220.72.44. The most targeted ports were 445 (SMB), 22 (SSH), and 5060 (SIP). A number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 5534, Honeytrap: 4678, Suricata: 3464, Dionaea: 2211, Ciscoasa: 1836, Sentrypeer: 975, Mailoney: 43, H0neytr4p: 36, Tanner: 70, Redishoneypot: 21, Miniprint: 18, ConPot: 10, Adbhoney: 9, Heralding: 3, ElasticPot: 4, ssh-rsa: 2, Honeyaml: 1

### Top Attacking IPs
- 109.205.211.9: 1934, 156.198.249.65: 1282, 67.220.72.44: 981, 103.193.178.230: 886, 180.246.121.46: 778, 68.183.4.42: 540, 103.187.147.214: 289, 103.164.63.144: 253, 14.195.83.210: 294, 123.255.46.174: 222

### Top Targeted Ports/Protocols
- 445: 2071, 22: 870, 5060: 975, 8333: 165, 2049: 189, 5903: 131, 5901: 115, 23: 97, 5905: 79, 5904: 77

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 8, CVE-2021-3449 CVE-2021-3449: 3, CVE-2019-11500 CVE-2019-11500: 2, CVE-2024-4577 CVE-2024-4577: 2, CVE-2024-4577 CVE-2002-0953: 2, CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1, CVE-2021-42013 CVE-2021-42013: 1, CVE-1999-0183: 1, CVE-2021-35394 CVE-2021-35394: 1

### Commands Attempted by Attackers
- "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'": 17, "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'": 17, "ls -lh $(which ls)": 17, "which ls": 17, "crontab -l": 17, "w": 17, "uname -m": 17, "cat /proc/cpuinfo | grep model | grep name | wc -l": 17, "top": 17, "uname": 17

### Signatures Triggered
- "ET SCAN MS Terminal Server Traffic on Non-standard Port": 1244, "2023753": 1244, "ET HUNTING RDP Authentication Bypass Attempt": 584, "2034857": 584, "ET DROP Dshield Block Listed Source group 1": 463, "2402000": 463, "ET SCAN NMAP -sS window 1024": 170, "2009582": 170, "ET INFO Reserved Internal IP Traffic": 56, "2002752": 56

### Users / Login Attempts
- "345gs5662d34/345gs5662d34": 16, "sa/!QAZ2wsx": 10, "root/3245gs5662d34": 6, "root/cardioinfantil2013": 4, "root/cariveadmin201309": 4, "root/carlosdiaz62": 4, "root/carioca2009": 4, "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36/Accept: */*": 3, "Accept-Encoding: gzip/": 3, "web/web2023": 3

### Files Uploaded/Downloaded
- "sh": 98, "wget.sh;": 4, "w.sh;": 1, "c.sh;": 1, "loader.sh|sh;#": 1

### HTTP User-Agents
- No data

### SSH Clients and Servers
- No data

### Top Attacker AS Organizations
- No data

## Key Observations and Anomalies

- A significant number of commands are related to reconnaissance of the system specifications (CPU, memory, etc.) and attempts to modify SSH authorized_keys.
- The `ET SCAN MS Terminal Server Traffic on Non-standard Port` signature was triggered the most, indicating a high volume of scanning for remote desktop services.
- There is a notable amount of brute force attempts with common and default credentials.
