Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T19:01:54Z
**Timeframe:** 2025-10-14T18:20:01Z to 2025-10-14T19:00:01Z
**Files Used:**
- agg_log_20251014T182001Z.json
- agg_log_20251014T184001Z.json
- agg_log_20251014T190001Z.json

### Executive Summary
This report summarizes 20,449 malicious events recorded across three log files. The most targeted honeypot was Cowrie, with 6,867 events. The most active attacking IP was 206.191.154.180. The most targeted port was 5060/UDP (SIP). Several CVEs were exploited, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted various commands, primarily for reconnaissance and establishing persistence.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6,867
- Honeytrap: 4,407
- Sentrypeer: 3,926
- Ciscoasa: 1,878
- Suricata: 1,655
- Mailoney: 924
- Dionaea: 623
- Heralding: 32
- H0neytr4p: 30
- Tanner: 27
- Redishoneypot: 22
- ElasticPot: 20
- ConPot: 14
- Adbhoney: 11
- Honeyaml: 7
- Dicompot: 3
- ssh-rsa: 2
- Ipphoney: 1

**Top Attacking IPs:**
- 206.191.154.180: 1,350
- 185.243.5.146: 1,232
- 86.54.42.238: 821
- 185.243.5.148: 862
- 193.24.123.88: 608
- 51.38.130.3: 363
- 88.210.63.16: 433
- 173.249.41.171: 370
- 172.86.95.115: 402
- 172.86.95.98: 396
- 89.117.54.101: 380
- 185.243.5.121: 275
- 95.237.254.79: 240
- 81.184.21.171: 232
- 62.141.43.183: 214
- 190.69.183.20: 168

**Top Targeted Ports/Protocols:**
- 5060: 3,926
- 22: 805
- 25: 892
- 1433: 503
- 5903: 189
- TCP/1433: 115
- 445: 65
- 23: 72
- 8333: 66
- 5908: 82
- 5909: 82
- 5901: 73
- 5907: 48
- 6379: 19
- 8728: 25

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 6
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
- CVE-2018-11776: 1

**Commands Attempted by Attackers:**
- Reconnaissance commands (e.g., `cat /proc/cpuinfo`, `uname -a`, `whoami`): 49
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 48
- `lockr -ia .ssh`: 48
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 48
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...`: 31
- `Enter new UNIX password: `: 18

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 354
- 2402000: 354
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 230
- 2023753: 230
- ET SCAN NMAP -sS window 1024: 165
- 2009582: 165
- ET HUNTING RDP Authentication Bypass Attempt: 109
- 2034857: 109
- ET SCAN Suspicious inbound to MSSQL port 1433: 114
- 2010935: 114
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 36
- 2403342: 36

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 44
- root/3245gs5662d34: 31
- root/Password@2025: 19
- root/123@@@: 17
- root/Qaz123qaz: 13
- ftpuser/ftppassword: 6

**Files Uploaded/Downloaded:**
- `arm.urbotnetisass;`: 2
- `arm.urbotnetisass`: 2
- `arm5.urbotnetisass;`: 2
- `arm5.urbotnetisass`: 2
- `arm6.urbotnetisass;`: 2
- `arm6.urbotnetisass`: 2
- `arm7.urbotnetisass;`: 2
- `arm7.urbotnetisass`: 2
- `x86_32.urbotnetisass;`: 2
- `x86_32.urbotnetisass`: 2
- `mips.urbotnetisass;`: 2
- `mips.urbotnetisass`: 2
- `mipsel.urbotnetisass;`: 2
- `mipsel.urbotnetisass`: 2
- `shadow.mips;chmod`: 2

**HTTP User-Agents:**
- No user agents recorded in this period.

**SSH Clients and Servers:**
- No specific SSH client or server versions recorded in this period.

**Top Attacker AS Organizations:**
- No AS organization data recorded in this period.

### Key Observations and Anomalies
- A significant amount of reconnaissance activity was observed, with attackers attempting to gather system information using commands like `lscpu` and `uname`.
- The `urbotnetisass` malware was repeatedly downloaded, suggesting a coordinated campaign.
- The `boatnet` malware was also downloaded, indicating multiple concurrent malware campaigns.
- The most common attack vector remains brute-force and credential stuffing attacks against SSH, as evidenced by the high number of login attempts.
- The prevalence of attacks against SIP (port 5060) and MSSQL (port 1433) suggests that these services are currently high-value targets.
- The frequent use of commands to manipulate SSH authorized_keys files indicates that attackers are attempting to establish persistent access.
