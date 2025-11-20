
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T22:01:28Z
**Timeframe:** 2025-10-07T21:20:01Z to 2025-10-07T22:00:01Z
**Files Used:**
- agg_log_20251007T212001Z.json
- agg_log_20251007T214001Z.json
- agg_log_20251007T220001Z.json

---

## Executive Summary

This report summarizes 12,382 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. A significant number of attacks also targeted services monitored by Honeytrap and Ciscoasa. The most prominent attacking IP is 93.115.79.198. Most malicious activities involved reconnaissance, brute-force login attempts, and the execution of shell commands aimed at establishing persistent access.

---

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 4902
- **Honeytrap:** 2755
- **Ciscoasa:** 1642
- **Suricata:** 1375
- **Mailoney:** 928
- **Sentrypeer:** 599
- **H0neytr4p:** 40
- **Dionaea:** 37
- **Tanner:** 38
- **ElasticPot:** 21
- **Redishoneypot:** 24
- **ConPot:** 4
- **Ipphoney:** 1
- **ssh-rsa:** 2
- **Honeyaml:** 8
- **Adbhoney:** 6

### Top Attacking IPs

- 93.115.79.198
- 86.54.42.238
- 71.41.130.50
- 185.255.126.223
- 173.212.232.6
- 106.75.131.128
- 173.249.50.59
- 94.228.113.178
- 157.245.241.196
- 103.20.122.54
- 159.223.217.219
- 213.225.9.3
- 207.231.107.73
- 186.13.43.140
- 139.59.91.254

### Top Targeted Ports/Protocols

- 25
- 5060
- 22
- 8333
- 5903
- 443
- TCP/22
- 9200
- 23
- 80
- 9093

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `tftp; wget; /bin/busybox YKSHW`

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET INFO CURL User Agent

### Users / Login Attempts

- 345gs5662d34/345gs5662d34
- support/admin123
- DSL/DSL
- unknown/unknown12345
- config/config5
- root/admin123
- sysadmin/sysadmin@1
- root/root4
- supervisor/raspberry
- test/test99

### Files Uploaded/Downloaded

- Mozi.a+varcron

### HTTP User-Agents

- *No user agents recorded in this period.*

### SSH Clients and Servers

- *No specific SSH clients or servers recorded in this period.*

### Top Attacker AS Organizations

- *No AS organizations recorded in this period.*

---

## Key Observations and Anomalies

- **High Volume of Credential Stuffing:** The Cowrie honeypot recorded numerous login attempts with common and default credentials, indicating widespread automated brute-force campaigns.
- **Persistent Access Attempts:** A recurring command pattern involves modifying the `.ssh/authorized_keys` file to install a public key, granting the attacker persistent access to the compromised machine.
- **System Reconnaissance:** Attackers frequently run commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo` to gather information about the system architecture, likely to tailor subsequent payloads.
- **Malware Download Attempt:** A file named `Mozi.a+varcron` was observed in download attempts, which is associated with the Mozi botnet, a known P2P IoT botnet.

---
