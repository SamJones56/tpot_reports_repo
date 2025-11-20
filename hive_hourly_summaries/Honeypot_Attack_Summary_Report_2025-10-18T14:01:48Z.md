
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T14:01:24Z
**Timeframe:** 2025-10-18T13:20:01Z to 2025-10-18T14:00:01Z

**Files Used:**
- `agg_log_20251018T132001Z.json`
- `agg_log_20251018T134001Z.json`
- `agg_log_20251018T140001Z.json`

## Executive Summary

This report summarizes 19,684 events collected from the honeypot network. The majority of attacks were captured by the Cowrie and Mailoney honeypots. The most prominent attack vector was via SMTP (port 25), with a significant number of SSH attempts also observed. The IP address `172.245.214.35` was the most active attacker. A number of CVEs were targeted, with CVE-2022-27255 being the most frequent.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7450
- Mailoney: 7126
- Honeytrap: 2173
- Suricata: 1397
- Ciscoasa: 1211
- Sentrypeer: 152
- Dionaea: 48
- Tanner: 30
- Miniprint: 27
- H0neytr4p: 26
- Redishoneypot: 15
- ElasticPot: 13
- Dicompot: 9
- ConPot: 5
- Ipphoney: 1
- Honeyaml: 1

### Top Attacking IPs
- 172.245.214.35: 7106
- 194.50.16.73: 1795
- 157.92.145.135: 1247
- 81.19.135.103: 1246
- 72.146.232.13: 918
- 66.29.143.67: 330
- 112.196.70.142: 293
- 41.93.28.23: 278
- 107.170.36.5: 246
- 36.99.192.221: 211

### Top Targeted Ports/Protocols
- 25: 7130
- 22: 1751
- TCP/5900: 290
- 5903: 224
- 5060: 152
- 8333: 125
- 5901: 110
- TCP/22: 89
- 5905: 74
- 5904: 73

### Most Common CVEs
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-11500
- CVE-1999-0183
- CVE-2001-0414
- CVE-1999-0517

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
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
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `Enter new UNIX password:`
- `uname -s -v -n -r -m`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET HUNTING RDP Authentication Bypass Attempt
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- ET INFO Reserved Internal IP Traffic
- ET INFO CURL User Agent

### Users / Login Attempts
- A variety of username and password combinations were attempted, including common defaults like `root/root2006`, `ubnt/123123`, `guest/guest`, and many others.

### Files Uploaded/Downloaded
- `11`
- `fonts.gstatic.com`
- `css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext`
- `ie8.css?ver=1.0`
- `html5.js?ver=3.7.3`

### HTTP User-Agents
- No HTTP user-agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were identified in this period.

## Key Observations and Anomalies

- The overwhelming majority of attacks are automated and opportunistic, focusing on common ports like 25 (SMTP) and 22 (SSH).
- The commands executed by attackers on the Cowrie honeypot indicate attempts to establish persistent access by adding SSH keys to `authorized_keys` and to perform reconnaissance on the system.
- The high number of events from `172.245.214.35` targeting port 25 suggests a botnet or compromised host is being used for spam or further exploitation.
- The variety of CVEs targeted shows a broad scanning approach by attackers, looking for any available vulnerability.
