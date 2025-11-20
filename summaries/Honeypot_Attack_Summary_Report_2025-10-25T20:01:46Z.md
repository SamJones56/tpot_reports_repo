Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T20:01:29Z
**Timeframe:** 2025-10-25T19:20:01Z to 2025-10-25T20:00:01Z
**Files Used:**
- agg_log_20251025T192001Z.json
- agg_log_20251025T194001Z.json
- agg_log_20251025T200001Z.json

### Executive Summary
This report summarizes 17,669 malicious events recorded by the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. The most frequent attacker IP was 80.94.95.238, predominantly targeting SSH (port 22) and SMB (port 445). A significant number of automated attacks appear to be reconnaissance scans and attempts to install malicious SSH keys for persistent access. Several CVEs were noted, including older vulnerabilities (CVE-2002-0012, CVE-2002-0013) and more recent ones (CVE-2018-7600, CVE-2019-11500, CVE-2024-3721).

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6023
- Honeytrap: 5190
- Suricata: 3010
- Dionaea: 1060
- Ciscoasa: 1726
- Sentrypeer: 259
- Mailoney: 163
- Tanner: 75
- Adbhoney: 28
- H0neytr4p: 42
- Dicompot: 21
- Honeyaml: 21
- Heralding: 16
- ConPot: 14
- Redishoneypot: 15
- ElasticPot: 5
- Ipphoney: 1

**Top Attacking IPs:**
- 80.94.95.238: 3307
- 114.47.12.143: 1016
- 103.189.235.164: 390
- 222.98.122.37: 356
- 39.115.195.164: 356
- 150.95.27.21: 316
- 72.167.220.12: 303
- 101.36.117.148: 247
- 118.193.61.170: 207
- 165.154.14.28: 203
- 185.113.139.51: 209
- 107.170.36.5: 254
- 139.59.64.179: 218
- 152.32.172.117: 184
- 172.208.48.177: 179

**Top Targeted Ports/Protocols:**
- 22: 770
- 445: 1023
- 5060: 259
- 8333: 246
- 5903: 138
- 5901: 119
- 25: 163
- 80: 75
- 23: 65
- 5904: 80
- 5905: 81
- 443: 33
- 5909: 51
- 5907: 54
- 5908: 50
- TCP/22: 27

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-2018-7600 CVE-2018-7600: 4
- CVE-2024-3721 CVE-2024-3721: 1
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 36
- `lockr -ia .ssh`: 36
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 36
- System reconnaissance commands (`uname -a`, `whoami`, `w`, `top`, `lscpu`, `free -m`, etc.): ~35 each
- `Enter new UNIX password: `: 25

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 1565
- ET DROP Dshield Block Listed Source group 1 (2402000): 397
- ET SCAN NMAP -sS window 1024 (2009582): 188
- ET HUNTING RDP Authentication Bypass Attempt (2034857): 47
- ET INFO Reserved Internal IP Traffic (2002752): 57
- ET CINS Active Threat Intelligence Poor Reputation IP groups: Multiple triggers

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 32
- root/various passwords: 20+
- admin/various passwords: 15+

**Files Uploaded/Downloaded:**
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2

**HTTP User-Agents:**
- None observed.

**SSH Clients and Servers:**
- SSH Clients: None observed.
- SSH Servers: None observed.

**Top Attacker AS Organizations:**
- None observed.

### Key Observations and Anomalies
- A high volume of attacks originate from the IP address 80.94.95.238, indicating a persistent threat source.
- The frequent use of a specific SSH key (`...mdrfckr`) suggests a coordinated campaign to gain unauthorized access.
- Attackers are using a mix of system reconnaissance commands to profile the compromised system before potentially deploying further malware.
- The presence of SMB traffic (port 445) alongside SSH attempts indicates attackers are probing for multiple common vulnerabilities.
- One interesting command sequence involved attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from `213.209.143.62`, which should be investigated.
- A mix of very old and recent CVEs are being scanned for, suggesting broad, untargeted scanning campaigns.