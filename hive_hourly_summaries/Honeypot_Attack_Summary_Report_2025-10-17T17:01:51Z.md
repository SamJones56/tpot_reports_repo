Here is a consolidated Honeypot Attack Summary Report based on the provided log files.

### Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T17:01:21Z
**Timeframe of Analysis:** 2025-10-17T16:20:01Z to 2025-10-17T17:00:01Z
**Log Files:**
- `agg_log_20251017T162001Z.json`
- `agg_log_20251017T164001Z.json`
- `agg_log_20251017T170001Z.json`

### Executive Summary

This report summarizes 11,159 malicious events captured by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Honeytrap and Ciscoasa. Attackers primarily focused on ports 22 (SSH) and 5060 (SIP). A variety of CVEs were targeted, and numerous commands were executed on the honeypots, indicating attempts to profile the systems and establish further access.

### Detailed Analysis

**Attacks by Honeypot:**
- **Cowrie:** 5203
- **Honeytrap:** 1860
- **Ciscoasa:** 1406
- **Sentrypeer:** 975
- **Suricata:** 1042
- **ElasticPot:** 443
- **Dionaea:** 50
- **H0neytr4p:** 56
- **Tanner:** 30
- **Adbhoney:** 20
- **Redishoneypot:** 20
- **Mailoney:** 19
- **Honeyaml:** 15
- **ConPot:** 13
- **Heralding:** 6
- **Ipphoney:** 1

**Top Attacking IPs:**
- 72.146.232.13
- 166.140.87.173
- 172.86.95.115
- 172.86.95.98
- 103.145.145.74
- 103.70.12.139
- 103.149.230.61
- 5.181.86.179
- 77.83.240.70
- 103.179.56.51

**Top Targeted Ports/Protocols:**
- 5060
- 22
- 9200
- 443
- 8333
- 23
- 5905
- 5904
- TCP/80
- TCP/445

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2001-0414

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep model | grep name | wc -l`
- `top`
- `uname`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `w`
- `crontab -l`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO CURL User Agent
- ET HUNTING RDP Authentication Bypass Attempt
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- GPL INFO SOCKS Proxy attempt

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/admin_123
- cs/123
- ubnt/ubnt11
- maryam/1
- marian/123
- root/123@Robert
- support/support333
- unknown/unknown2006
- blank/blank2009

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in the logs.

**Top Attacker AS Organizations:**
- No AS organizations were identified in this period.

### Key Observations and Anomalies

-   **High Volume of Automated Scans:** The high number of events from a wide range of IPs suggests large-scale, automated scanning campaigns.
-   **Focus on SSH and SIP:** The targeting of ports 22 and 5060 is consistent with attackers looking for exposed SSH servers for remote access and SIP servers for potential toll fraud or communication interception.
-   **Credential Stuffing:** The variety of usernames and passwords attempted indicates credential stuffing attacks against common services.
-   **Post-Exploitation Commands:** The commands executed after apparent successful logins show attackers attempting to gather system information, establish persistent access by adding SSH keys, and download additional malware.
-   **Malware Download Attempts:** The presence of `wget` and `curl` commands, along with filenames like `w.sh`, `c.sh`, and `wget.sh`, points to attempts to download and execute malicious scripts.

This concludes the Honeypot Attack Summary Report. Further analysis will be conducted in the next reporting period.
