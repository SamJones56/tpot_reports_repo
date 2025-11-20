Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T21:01:38Z
**Timeframe Covered:** 2025-10-23T20:20:01Z to 2025-10-23T21:00:01Z
**Log Files Used:**
- agg_log_20251023T202001Z.json
- agg_log_20251023T204001Z.json
- agg_log_20251023T210001Z.json

### Executive Summary
This report summarizes 5,602 malicious events recorded across the honeypot network. The most targeted services were Ciscoasa (1715 events), Cowrie (1371 events), and Honeytrap (1334 events). A significant portion of attacks originated from the IP address 147.182.205.88. Attackers primarily targeted port 5060 (SIP), likely for VoIP abuse, and port 22 (SSH) for brute-force login attempts. Multiple CVEs were exploited, and attackers attempted to install SSH keys for persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Ciscoasa: 1715
- Cowrie: 1371
- Honeytrap: 1334
- Suricata: 629
- Sentrypeer: 370
- ConPot: 29
- Redishoneypot: 30
- Dionaea: 20
- H0neytr4p: 45
- Mailoney: 22
- Tanner: 17
- Ipphoney: 6
- Dicompot: 3
- Miniprint: 3
- Adbhoney: 2
- Honeyaml: 4
- ssh-rsa: 2

**Top Attacking IPs:**
- 147.182.205.88: 693
- 107.170.36.5: 153
- 185.243.5.146: 146
- 3.14.82.245: 133
- 123.139.119.239: 128
- 185.50.38.171: 98
- 68.183.149.135: 112
- 23.94.26.58: 84
- 141.52.36.57: 91
- 198.12.68.114: 62

**Top Targeted Ports/Protocols:**
- 5060: 370
- 22: 224
- 8333: 109
- 5905: 77
- 5904: 76
- 443: 47
- 23: 42
- 5901: 45
- 5902: 39
- 5903: 39
- 25: 22
- 6379: 28

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2001-0414
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

**Commands Attempted by Attackers:**
- uname -a
- uname
- whoami
- top
- w
- crontab -l
- which ls
- ls -lh $(which ls)
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- cat /proc/cpuinfo | grep model | grep name | wc -l
- cat /proc/cpuinfo | grep name | wc -l
- echo ... | passwd
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 187
- 2402000: 187
- ET SCAN NMAP -sS window 1024: 94
- 2009582: 94
- ET INFO Reserved Internal IP Traffic: 41
- 2002752: 41
- ET VOIP MultiTech SIP UDP Overflow: 18
- 2003237: 18
- GPL TELNET Bad Login: 20
- 2101251: 20

**Users / Login Attempts:**
- A wide variety of default or common usernames such as 'root', 'admin', 'ubuntu', 'user', 'git', and 'oracle' were used in brute-force attempts with common password lists.

**Files Uploaded/Downloaded:**
- )@ubuntu:~$: 3

**HTTP User-Agents:**
- No HTTP User-Agents were recorded in this period.

**SSH Clients:**
- No specific SSH clients were recorded in this period.

**SSH Servers:**
- No specific SSH servers were recorded in this period.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in this period.

### Key Observations and Anomalies
- A recurring and sophisticated attack pattern involved attempts to modify the `.ssh` directory. The attacker attempts to remove existing SSH keys, create a new `authorized_keys` file, and add their own public SSH key. This is a clear attempt to gain persistent, passwordless access to the compromised machine.
- Several commands indicate system reconnaissance, with attackers trying to identify the system architecture (`uname`), CPU details (`/proc/cpuinfo`), and running processes (`top`, `w`).
- The targeting of Ciscoasa devices remains high, indicating ongoing campaigns against network infrastructure.
- The high volume of traffic on port 5060 suggests automated scanning for vulnerable VoIP systems.
