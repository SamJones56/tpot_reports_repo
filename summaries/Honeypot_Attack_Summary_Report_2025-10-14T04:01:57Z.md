Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T04:01:31Z
**Timeframe:** Approximately 2025-10-14T03:20:01Z to 2025-10-14T04:00:02Z
**Files Used:**
- `agg_log_20251014T032001Z.json`
- `agg_log_20251014T034001Z.json`
- `agg_log_20251014T040002Z.json`

**Executive Summary**
This report summarizes 16,124 attacks recorded across multiple honeypots. The majority of attacks were reconnaissance and automated login attempts. The most active honeypots were Cowrie, Sentrypeer, and Honeytrap. A significant number of attacks originated from IP addresses `185.243.5.146` and `42.119.232.181`. The most targeted ports were 5060 (SIP), 445 (SMB), and 25 (SMTP). Several CVEs were observed, with `CVE-2005-4050` being the most frequent.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 4087
- Sentrypeer: 3225
- Honeytrap: 2518
- Dionaea: 1869
- Ciscoasa: 1694
- Suricata: 1616
- Mailoney: 862
- ConPot: 85
- H0neytr4p: 53
- Tanner: 49
- Adbhoney: 22
- Redishoneypot: 23
- Honeyaml: 11
- Dicompot: 4
- ssh-rsa: 2
- ElasticPot: 1
- Ipphoney: 2
- Heralding: 1

**Top Attacking IPs:**
- 185.243.5.146: 1192
- 42.119.232.181: 1003
- 86.54.42.238: 821
- 171.43.135.80: 802
- 185.243.5.148: 799
- 45.236.188.4: 658
- 172.86.95.115: 376
- 172.86.95.98: 357
- 62.141.43.183: 324
- 202.152.148.2: 258
- 196.251.71.24: 200
- 81.30.162.18: 214

**Top Targeted Ports/Protocols:**
- 5060: 3225
- 445: 1029
- 25: 862
- 1433: 807
- 22: 626
- 5903: 180
- 80: 67
- 23: 68
- TCP/1433: 63
- TCP/80: 41
- UDP/5060: 72

**Most Common CVEs:**
- CVE-2005-4050: 62
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2016-20016 CVE-2016-20016: 2
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2024-3721 CVE-2024-3721: 1
- CVE-2002-1149: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 14
- `lockr -ia .ssh`: 14
- `cd ~ && rm -rf .ssh && echo ...`: 14
- `cat /proc/cpuinfo | grep name | wc -l`: 14
- `uname -a`: 15
- `Enter new UNIX password: `: 12
- `cd /data/local/tmp/; busybox wget ...`: 2

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 461
- ET SCAN NMAP -sS window 1024: 160
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 130
- ET HUNTING RDP Authentication Bypass Attempt: 61
- ET VOIP MultiTech SIP UDP Overflow: 62
- ET INFO Reserved Internal IP Traffic: 59
- ET SCAN Suspicious inbound to MSSQL port 1433: 58
- ET SCAN Potential SSH Scan: 28

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 14
- root/Password@2025: 10
- debian/alpine: 6
- nobody/11: 6
- default/default2010: 6
- guest/guest2025: 6
- supervisor/123321: 6

**Files Uploaded/Downloaded:**
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
- 11: 2
- fonts.gstatic.com: 2
- ?format=json: 2

**Key Observations and Anomalies**
- The high volume of attacks on port 5060 (SIP) suggests a focus on VoIP infrastructure.
- The commands attempted on Cowrie honeypots indicate efforts to establish persistent SSH access and gather system information.
- A notable command involved downloading and executing scripts (`w.sh`, `c.sh`, `wget.sh`) from `194.238.26.136`. These should be analyzed for malware.
- The variety of credentials used in brute-force attempts suggests the use of common password lists.
- A significant number of events are flagged by Suricata with the signature "ET DROP Dshield Block Listed Source group 1", indicating that many of the attacking IPs are already known to be malicious.
- There are no listed HTTP User-Agents, SSH clients, SSH servers, or top attacker AS organizations in these logs.
