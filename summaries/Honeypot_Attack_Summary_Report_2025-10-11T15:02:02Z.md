# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T15:01:25Z
**Timeframe:** 2025-10-11T14:20:01Z to 2025-10-11T15:00:01Z
**Files Used:** `agg_log_20251011T142001Z.json`, `agg_log_20251011T144001Z.json`, `agg_log_20251011T150001Z.json`

## Executive Summary

This report summarizes 19,342 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Dionaea and Suricata. The most frequent attacks originated from IP address `41.38.10.88`. The primary targets were ports 445 (SMB) and 22 (SSH). Several CVEs were detected, including exploits related to DoublePulsar. A large volume of automated commands were attempted, primarily focused on system enumeration and establishing remote access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 8834
- Dionaea: 3461
- Suricata: 2561
- Honeytrap: 2334
- Ciscoasa: 1827
- Sentrypeer: 102
- Tanner: 48
- Redishoneypot: 46
- Mailoney: 29
- H0neytr4p: 23
- Honeyaml: 22
- Heralding: 16
- ConPot: 11
- ElasticPot: 11
- Adbhoney: 10
- Dicompot: 6
- Ipphoney: 1

### Top Attacking IPs
- 41.38.10.88: 2523
- 117.141.201.194: 1331
- 138.197.43.50: 1246
- 157.245.101.239: 959
- 223.100.22.69: 777
- 212.87.220.20: 620
- 123.139.116.220: 449
- 152.32.206.160: 305
- 146.190.154.85: 302
- 36.139.226.237: 289
- 161.248.189.80: 282
- 113.83.130.100: 217
- 209.38.226.254: 217
- 4.213.138.243: 203
- 187.45.95.66: 189
- 118.193.61.63: 183
- 103.48.84.20: 177
- 46.62.199.37: 149
- 191.37.72.46: 118
- 45.150.11.214: 113

### Top Targeted Ports/Protocols
- 445: 3413
- TCP/445: 1327
- 22: 1360
- 5903: 190
- TCP/5900: 140
- 5060: 102
- 8333: 97
- 5901: 87
- 5908: 84
- 5909: 82
- 6379: 43
- TCP/22: 39

### Most Common CVEs
- CVE-2021-3449: 3
- CVE-2019-11500: 2
- CVE-2016-20016: 1

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 38
- `lockr -ia .ssh`: 38
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 38
- `cat /proc/cpuinfo | grep name | wc -l`: 37
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 37
- `ls -lh $(which ls)`: 37
- `which ls`: 37
- `crontab -l`: 37
- `w`: 37
- `uname -m`: 37
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 37
- `top`: 37
- `uname`: 37
- `uname -a`: 37
- `whoami`: 37
- `lscpu | grep Model`: 37
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 37
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 36
- `Enter new UNIX password: `: 23
- `Enter new UNIX password:`: 17

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1325
- ET DROP Dshield Block Listed Source group 1: 299
- ET SCAN NMAP -sS window 1024: 149
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 92
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 69
- ET INFO Reserved Internal IP Traffic: 60
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 36

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 34
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 18
- root/nPSpP4PBW0: 13
- root/3245gs5662d34: 12
- root/LeitboGi0ro: 12
- test/555555: 6
- ubnt/0987654321: 6
- default/admin123: 6

### Files Uploaded/Downloaded
- 11: 3
- fonts.gstatic.com: 3
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 3
- ie8.css?ver=1.0: 3
- html5.js?ver=3.7.3: 3

### HTTP User-Agents
- No user agents were recorded in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were identified in this timeframe.

### Top Attacker AS Organizations
- No AS organization data was available in this timeframe.

## Key Observations and Anomalies

- **High Volume of SMB Exploitation:** The significant number of events on port 445, combined with the "DoublePulsar Backdoor" signature, indicates a widespread, automated campaign targeting the SMB protocol.
- **Repetitive System Enumeration:** The top commands are all variations of reconnaissance commands, suggesting that attackers are using automated scripts to gather information about the compromised systems.
- **Credential Stuffing:** A wide variety of usernames and passwords were attempted, with a mix of default credentials and more complex passwords. The high frequency of `345gs5662d34` as both a username and password is an unusual anomaly.
- **SSH Key Manipulation:** Multiple commands are focused on modifying the `.ssh/authorized_keys` file to grant persistent access to the attackers.
