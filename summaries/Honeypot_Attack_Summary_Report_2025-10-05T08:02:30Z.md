# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T08:01:31Z
**Timeframe:** 2025-10-05T07:20:01Z to 2025-10-05T08:00:01Z
**Files Used:**
- agg_log_20251005T072001Z.json
- agg_log_20251005T074001Z.json
- agg_log_20251005T080001Z.json

## Executive Summary

This report summarizes 10,860 attacks recorded by the honeypot network. The most targeted services were SSH (Cowrie), email (Mailoney), and network services (Suricata, Ciscoasa). A significant portion of the attacks originated from IP addresses 20.2.136.52, 147.45.193.115, and 86.54.42.238. Attackers primarily targeted ports 25 (SMTP), 22 (SSH), and 445 (SMB). A number of CVEs were targeted, with CVE-2005-4050 being the most frequent.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4988
- Mailoney: 1663
- Suricata: 1485
- Ciscoasa: 1453
- Dionaea: 520
- Sentrypeer: 267
- Honeytrap: 143
- Heralding: 138
- Adbhoney: 69
- Redishoneypot: 34
- H0neytr4p: 32
- Honeyaml: 27
- Tanner: 15
- Dicompot: 14
- ElasticPot: 6
- ConPot: 6

### Top Attacking IPs
- 20.2.136.52: 1216
- 147.45.193.115: 868
- 86.54.42.238: 821
- 176.65.141.117: 820
- 103.74.228.162: 443
- 134.209.36.11: 312
- 139.59.34.255: 298
- 190.108.93.227: 288
- 111.47.56.203: 284
- 178.176.250.39: 229
- 79.61.112.234: 214
- 103.214.112.160: 212
- 198.12.68.114: 167
- 200.195.162.68: 149
- 103.248.120.6: 144
- 124.71.9.9: 139
- 138.124.186.209: 128
- 43.225.158.169: 114
- 115.84.183.242: 105
- 172.86.95.98: 63

### Top Targeted Ports/Protocols
- 25: 1663
- 22: 822
- 445: 454
- 5060: 267
- TCP/5900: 263
- TCP/1080: 173
- socks5/1080: 138
- UDP/5060: 66
- TCP/80: 50
- TCP/22: 48
- 23: 35
- 6379: 34
- 443: 27
- 80: 26
- 81: 16
- 17007: 15
- UDP/161: 14
- 1433: 13
- TCP/1433: 17
- 1883: 12

### Most Common CVEs
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-2024-3721
- CVE-2021-3449
- CVE-2006-2369
- CVE-1999-0517
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 16
- lockr -ia .ssh: 16
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 16
- cat /proc/cpuinfo | grep name | wc -l: 16
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 16
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 16
- ls -lh $(which ls): 16
- which ls: 16
- crontab -l: 16
- w: 16
- uname -m: 16
- cat /proc/cpuinfo | grep model | grep name | wc -l: 16
- top: 16
- uname: 16
- uname -a: 16
- whoami: 16
- lscpu | grep Model: 16
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 16
- Enter new UNIX password: : 12
- Enter new UNIX password:: 12

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 324
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 266
- GPL INFO SOCKS Proxy attempt: 163
- ET SCAN NMAP -sS window 1024: 101
- ET VOIP MultiTech SIP UDP Overflow: 57
- ET INFO Reserved Internal IP Traffic: 50
- ET SCAN Potential SSH Scan: 38
- ET HUNTING curl User-Agent to Dotted Quad: 18
- ET INFO curl User-Agent Outbound: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 13

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 15
- root/nPSpP4PBW0: 6
- root/LeitboGi0ro: 6
- novinhost/novinhost.org: 6
- root/2glehe5t24th1issZs: 5
- test/zhbjETuyMffoL8F: 4
- test/3245gs5662d34: 4
- admin/admin123: 3
- test/test: 2
- admin/221086: 2
- admin/22101993: 2
- admin/22091993: 2
- admin/22091980: 2
- admin/22091979: 2
- thor/thor: 2
- thor/3245gs5662d34: 2
- user02/123: 2
- anonymous/: 2
- root/3245gs5662d34: 2
- user/abc123: 2

### Files Uploaded/Downloaded
- wget.sh;: 28
- w.sh;: 7
- c.sh;: 7

### HTTP User-Agents
- No user-agent data was collected during this period.

### SSH Clients
- No SSH client data was collected during this period.

### SSH Servers
- No SSH server data was collected during this period.

### Top Attacker AS Organizations
- No attacker AS organization data was collected during this period.

## Key Observations and Anomalies

- **High Volume of Cowrie Attacks:** The Cowrie honeypot, simulating an SSH server, recorded the highest number of attacks, indicating a strong focus on compromising SSH servers.
- **Botnet-like Activity:** The repetition of identical commands across multiple sessions, such as attempts to modify SSH authorized_keys and gather system information, is indicative of automated botnet activity.
- **Targeting of Mail Servers:** The Mailoney honeypot saw a significant number of events, highlighting the ongoing threat to email servers.
- **File Downloads:** The repeated downloading of `wget.sh`, `w.sh`, and `c.sh` suggests a campaign to install malware or other malicious scripts on compromised systems.
