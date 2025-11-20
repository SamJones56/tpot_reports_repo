Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T23:01:31Z
**Timeframe:** 2025-10-05T22:20:01Z to 2025-10-05T23:00:01Z
**Files Used:**
- agg_log_20251005T222001Z.json
- agg_log_20251005T224001Z.json
- agg_log_20251005T230001Z.json

### Executive Summary

This report summarizes 13,386 attacks recorded by honeypot systems over the last hour. The majority of attacks were SSH brute-force attempts, with significant activity also observed in SIP and mail service scanning. Attackers frequently attempted to install SSH keys for persistent access and performed system reconnaissance.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 8076
- Suricata: 1476
- Ciscoasa: 1377
- Mailoney: 865
- Honeytrap: 740
- Sentrypeer: 570
- H0neytr4p: 55
- ConPot: 61
- Dionaea: 32
- Adbhoney: 30
- ssh-rsa: 32
- ElasticPot: 21
- Tanner: 25
- Redishoneypot: 12
- Honeyaml: 9
- Heralding: 3
- Ipphoney: 2

**Top Attacking IPs:**
- 129.212.183.147: 2137
- 176.65.141.117: 820
- 134.122.77.28: 764
- 91.237.163.114: 292
- 34.91.0.68: 253
- 198.23.190.58: 246
- 52.183.128.237: 226
- 172.86.95.98: 411
- 185.216.117.150: 342
- 118.145.189.160: 333
- 27.111.32.174: 222
- 103.189.235.65: 238
- 218.37.207.187: 212
- 167.99.74.18: 259
- 74.225.11.113: 143
- 168.121.75.209: 124

**Top Targeted Ports/Protocols:**
- 22: 1270
- 5060: 570
- 25: 865
- TCP/443: 129
- 443: 57
- 1025: 61
- UDP/5060: 134
- 80: 29
- TCP/22: 55
- 9200: 20
- 23: 15

**Most Common CVEs:**
- CVE-2022-27255 CVE-2022-27255: 18
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-2019-11500 CVE-2019-11500: 7
- CVE-2021-3449 CVE-2021-3449: 7
- CVE-2023-26801 CVE-2023-26801: 2
- CVE-1999-0183: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 37
- `lockr -ia .ssh`: 37
- `cd ~ && rm -rf .ssh && ...`: 37
- `Enter new UNIX password: `: 31
- `Enter new UNIX password:`: 31
- `cat /proc/cpuinfo ...`: 31
- `free -m ...`: 31
- `ls -lh $(which ls)`: 30
- `which ls`: 30
- `crontab -l`: 30
- `w`: 30
- `uname -m`: 30
- `top`: 30
- `uname -a`: 30
- `whoami`: 30

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 382
- 2402000: 382
- ET SCAN NMAP -sS window 1024: 155
- 2009582: 155
- ET SCAN Possible SSL Brute Force attack or Site Crawl: 124
- 2001553: 124
- ET SCAN Sipsak SIP scan: 100
- 2008598: 100
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET SCAN Potential SSH Scan: 44
- 2001219: 44

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 34
- root/: 32
- polynomial/polynomial@123: 3
- pierre/123: 3
- zmodem/123: 3
- zmodem/3245gs5662d34: 3
- net/net@123: 3
- data/data: 3
- beethoven/beethoven: 3
- mutant/mutant@123: 3
- node/node: 3

**Files Uploaded/Downloaded:**
- wget.sh;: 12
- w.sh;: 3
- c.sh;: 3

**HTTP User-Agents:**
- None observed.

**SSH Clients and Servers:**
- None observed.

**Top Attacker AS Organizations:**
- None observed.

### Key Observations and Anomalies

- **High Volume of SSH Attacks:** The Cowrie honeypot captured the vast majority of events, indicating a high volume of automated SSH brute-force and credential stuffing attacks.
- **Persistent Access Attempts:** A recurring pattern involves attackers attempting to remove existing `.ssh` directories and add their own public key to `authorized_keys`. This is a clear attempt to establish persistent access.
- **System Reconnaissance:** Attackers consistently run a series of commands to gather information about the system's hardware, memory, and running processes.
- **Malware Downloads:** Several attacks involved attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from malicious IPs. This is indicative of attempts to install malware or add the system to a botnet.
- **SIP Scanning:** A significant number of events targeted SIP services on port 5060, likely searching for vulnerable VoIP systems.

This report highlights ongoing automated attacks targeting common services. The focus on SSH and the specific commands used suggest a coordinated campaign to compromise systems for further malicious activities. Continuous monitoring is recommended.