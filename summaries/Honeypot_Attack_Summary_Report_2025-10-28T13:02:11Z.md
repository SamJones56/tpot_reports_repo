Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T13:01:49Z
**Timeframe:** 2025-10-28T12:20:01Z to 2025-10-28T13:00:01Z
**Files Used:**
- agg_log_20251028T122001Z.json
- agg_log_20251028T124001Z.json
- agg_log_20251028T130001Z.json

### Executive Summary
This report summarizes 8602 attacks recorded by the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie and Honeytrap honeypots. The most targeted services were SIP (5060) and SSH (22). Several attackers attempted to deploy malware and add SSH keys for persistence. Two CVEs were detected: CVE-2023-26801 and CVE-2021-35394.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 2871
- Honeytrap: 2218
- Ciscoasa: 1726
- Suricata: 684
- Sentrypeer: 597
- Dionaea: 353
- Mailoney: 79
- Adbhoney: 28
- ConPot: 20
- Tanner: 15
- ElasticPot: 4
- H0neytr4p: 4
- Honeyaml: 3

**Top Attacking IPs:**
- 212.11.64.219: 1094
- 45.130.202.25: 1078
- 144.172.108.231: 505
- 164.92.236.103: 283
- 180.242.216.184: 318
- 23.91.96.123: 252
- 103.49.239.184: 188
- 161.132.58.31: 173
- 103.154.87.242: 84
- 68.183.149.135: 111

**Top Targeted Ports/Protocols:**
- 5060: 597
- 22: 434
- 445: 328
- 5038: 1078
- 8333: 162
- 5901: 130
- TCP/22: 101

**Most Common CVEs:**
- CVE-2023-26801
- CVE-2021-35394

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `echo '...' | base64 -d | perl &`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/1QAZ2wsx3EDC
- mirror/mirror
- bill/P@ssw0rd
- root/l0cktid3
- root/l0g1c2

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- w.sh
- c.sh
- skyljne.mpsl
- soap-envelope

**HTTP User-Agents:**
- No activity detected.

**SSH Clients and Servers:**
- No activity detected.

**Top Attacker AS Organizations:**
- No data available in the logs.

### Key Observations and Anomalies
- A significant number of attacks involved attempts to modify the `.ssh` directory and add a new authorized SSH key, indicating attempts at persistent access.
- One of the most interesting commands observed was a base64 encoded perl script, which appears to be an IRC bot with DDoS capabilities.
- The presence of commands to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from a remote server `202.55.132.254` suggests a malware infection attempt.
- The detection of CVE-2023-26801 and CVE-2021-35394 indicates that attackers are actively exploiting known vulnerabilities.
