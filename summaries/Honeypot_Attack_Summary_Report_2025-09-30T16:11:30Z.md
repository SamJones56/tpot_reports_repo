Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T16:11:02Z
**Timeframe:** 2025-09-30T15:20:01Z - 2025-09-30T16:00:01Z
**Files Used:**
- agg_log_20250930T152001Z.json
- agg_log_20250930T154002Z.json
- agg_log_20250930T160001Z.json

**Executive Summary**
This report summarizes 8,530 attacks recorded across three honeypot log files. The majority of activity was observed on the Cowrie (SSH), Honeytrap, and Ciscoasa honeypots. A significant portion of attacks originated from the IP address 95.84.58.194, primarily targeting the Dionaea honeypot on port 445 (SMB). Attackers frequently attempted to gain access via common usernames and passwords and execute scripts to download further malware.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 2883
- Honeytrap: 1642
- Ciscoasa: 1424
- Dionaea: 1178
- Suricata: 1052
- Tanner: 197
- Adbhoney: 46
- ConPot: 36
- H0neytr4p: 23
- Mailoney: 19
- Sentrypeer: 12
- Honeyaml: 12
- Dicompot: 6
- ElasticPot: 6
- Redishoneypot: 3
- Ipphoney: 1

**Top Attacking IPs:**
- 95.84.58.194: 999
- 45.78.224.161: 393
- 96.78.175.36: 361
- 185.156.73.166: 366
- 185.156.73.167: 360
- 92.63.197.55: 352
- 163.5.79.45: 351
- 36.67.70.198: 341
- 146.190.111.235: 199
- 45.148.10.243: 181
- 172.245.177.148: 189
- 103.103.245.61: 193
- 92.63.197.59: 332
- 45.112.72.65: 135
- 20.174.162.182: 115

**Top Targeted Ports/Protocols:**
- 445: 1001
- 22: 375
- 80: 198
- 8333: 138
- 3306: 136
- TCP/1433: 43
- 23: 58
- 1433: 31
- 1025: 26
- 8728: 27

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2002-1149: 6
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
- CVE-2018-11776: 1
- CVE-2016-20016 CVE-2016-20016: 1

**Commands Attempted by Attackers:**
- A series of commands to add an SSH key to `authorized_keys` was the most common, executed 15 times. This includes:
  - `cd ~; chattr -ia .ssh; lockr -ia .ssh`
  - `lockr -ia .ssh`
  - `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys ...`
- System reconnaissance commands were also executed 15 times each:
  - `cat /proc/cpuinfo | grep name | wc -l`
  - `uname -a`
  - `whoami`
  - `w`
- Password change prompts (`Enter new UNIX password: `) appeared 10 times.
- Commands to download and execute shell scripts and binaries from external servers (e.g., `urbotnetisass`, `w.sh`, `c.sh`) were also observed.

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 279
- 2402000 (Dshield Block List): 279
- ET SCAN NMAP -sS window 1024: 189
- 2009582 (NMAP Scan): 189
- ET INFO Reserved Internal IP Traffic: 58
- 2002752 (Reserved IP Traffic): 58
- ET SCAN Suspicious inbound to MSSQL port 1433: 38
- 2010935 (MSSQL Scan): 38

**Users / Login Attempts:**
- testuser/: 134
- 345gs5662d34/345gs5662d34: 15
- root/nPSpP4PBW0: 5
- A wide variety of other common and default credentials such as root, admin, user, pi, and oracle were attempted.

**Files Uploaded/Downloaded:**
- Various payloads for different architectures (arm, mips, x86) named `*.urbotnetisass` were repeatedly downloaded.
- Shell scripts such as `wget.sh`, `w.sh`, and `c.sh` were downloaded and executed.
- Image files (`.jpg`) were noted in one of the logs, likely related to web honeypot activity.

**HTTP User-Agents:**
- No HTTP User-Agents were recorded in the logs.

**SSH Clients and Servers:**
- No specific SSH client or server versions were recorded in the logs.

**Top Attacker AS Organizations:**
- No Attacker AS Organizations were recorded in the logs.

**Key Observations and Anomalies**
- **High-Volume Scanners:** The IP address 95.84.58.194 was exceptionally active, responsible for over 11% of all recorded events, primarily targeting the SMB protocol on port 445.
- **Consistent TTPs:** Attackers consistently used a set of commands to first gain persistence by adding a malicious SSH key and then perform basic system reconnaissance before attempting to download further malware.
- **Malware Delivery:** The use of `wget` and `curl` to download and execute scripts from remote servers is a common and ongoing tactic observed across all log files. The `urbotnetisass` payload appears to be a multi-architecture botnet client.
- **Targeted Services:** SSH (port 22) and SMB (port 445) remain the most heavily targeted services, indicating widespread automated scanning for vulnerable systems.
