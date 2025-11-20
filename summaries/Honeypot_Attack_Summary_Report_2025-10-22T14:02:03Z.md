## Honeypot Attack Summary Report

**Report Time:** 2025-10-22T14:01:44Z
**Timeframe:** 2025-10-22T13:20:02Z to 2025-10-22T14:00:01Z
**Log Files:**
- agg_log_20251022T132002Z.json
- agg_log_20251022T134002Z.json
- agg_log_20251022T140001Z.json

### Executive Summary

This report summarizes 19,632 events collected from multiple honeypots. The majority of attacks were captured by the Cowrie, Dionaea, and Honeytrap honeypots. The most targeted service was SMB on port 445. A significant number of reconnaissance and exploitation activities were observed, including attempts to install SSH keys and download malicious scripts.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 6710
*   Dionaea: 5240
*   Honeytrap: 3287
*   Suricata: 2094
*   Ciscoasa: 1677
*   Sentrypeer: 302
*   Mailoney: 97
*   Adbhoney: 66
*   Tanner: 66
*   H0neytr4p: 25
*   Redishoneypot: 18
*   Miniprint: 18
*   Dicompot: 15
*   ElasticPot: 7
*   ConPot: 7
*   Honeyaml: 2
*   Ipphoney: 1

**Top Attacking IPs:**
*   1.9.70.82: 4241
*   117.72.114.221: 1251
*   196.251.88.103: 987
*   124.226.219.166: 340
*   88.210.63.16: 293
*   107.170.36.5: 250
*   178.176.250.39: 219
*   187.110.238.50: 194
*   150.139.194.15: 185
*   118.45.205.44: 173
*   36.50.54.8: 155
*   167.99.47.118: 110
*   139.59.74.228: 110

**Top Targeted Ports/Protocols:**
*   445: 4331
*   22: 1186
*   5060: 302
*   TCP/21: 238
*   5903: 229
*   8333: 162
*   21: 127
*   5901: 111
*   25: 97
*   TCP/445: 57
*   5904: 75
*   5905: 75
*   80: 63
*   23: 48

**Most Common CVEs:**
*   CVE-2021-3449 CVE-2021-3449
*   CVE-2002-0013 CVE-2002-0012
*   CVE-1999-0183
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2001-0414

**Commands Attempted by Attackers:**
*   `uname -a`
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `ls -lh $(which ls)`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `top`
*   `whoami`

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET SCAN NMAP -sS window 1024
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET FTP FTP PWD command attempt without login
*   ET FTP FTP CWD command attempt without login
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   ET INFO Reserved Internal IP Traffic

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   pi/raspberry
*   root/3245gs5662d34
*   root/bpsi1234
*   root/Bqy98lqZp
*   root/adminHW
*   postgres/postgres123
*   root/br1p232277

**Files Uploaded/Downloaded:**
*   wget.sh;
*   leakix.net)
*   w.sh;
*   c.sh;
*   fonts.gstatic.com
*   11

**HTTP User-Agents:**
*   No user agents were logged in this period.

**SSH Clients:**
*   No specific SSH clients were logged.

**SSH Servers:**
*   No specific SSH servers were logged.

**Top Attacker AS Organizations:**
*   No AS organizations were logged in this period.

### Key Observations and Anomalies

*   **Persistent SSH Key Installation:** A recurring pattern involves attackers attempting to remove existing SSH configurations and install their own public SSH key. This indicates a clear objective to establish persistent access.
*   **Malicious Script Downloads:** Several commands were observed attempting to download and execute shell scripts (e.g., `w.sh`, `c.sh`, `wget.sh`) from external servers. These scripts are likely used for botnet recruitment, crypto mining, or other malicious activities.
*   **Scanning and Probing:** A high volume of events are related to scanning activities, particularly on ports 445 (SMB) and 22 (SSH). This is typical of automated scanners searching for vulnerable systems.
*   **Credential Stuffing:** A wide variety of username and password combinations were attempted, indicating automated brute-force or credential stuffing attacks. Common default credentials like `pi/raspberry` and `admin/admin` were frequently used.
