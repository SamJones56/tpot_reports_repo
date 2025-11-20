
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T12:01:34Z
**Timeframe:** 2025-10-13T11:20:01Z to 2025-10-13T12:01:34Z
**Files Used:**
- agg_log_20251013T112001Z.json
- agg_log_20251013T114001Z.json
- agg_log_20251013T120001Z.json

## Executive Summary
This report summarizes 26,079 events collected from multiple honeypots. The most frequently targeted services were SMB (port 445) and SSH (port 22). The majority of attacks originated from the IP address 45.234.176.18. A significant number of attacks involved attempts to install the DoublePulsar backdoor and exploit vulnerabilities in Realtek SDK and Oracle SQL. Attackers predominantly used system reconnaissance commands and attempted to install SSH keys for persistence.

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 9,731
- Cowrie: 9,209
- Dionaea: 2,662
- Suricata: 1,743
- Ciscoasa: 1,541
- Sentrypeer: 960
- Redishoneypot: 62
- H0neytr4p: 39
- Tanner: 51
- Mailoney: 17
- Honeyaml: 18
- ConPot: 11
- Adbhoney: 9
- Miniprint: 6
- Dicompot: 7
- ElasticPot: 3

### Top Attacking IPs
- 45.234.176.18: 8,163
- 182.183.34.173: 1,437
- 188.212.135.108: 1,292
- 134.199.201.196: 992
- 129.212.176.83: 693
- 20.2.136.52: 705
- 84.54.196.98: 451
- 223.100.22.69: 618
- 83.221.204.44: 541
- 88.214.50.58: 306

### Top Targeted Ports/Protocols
- 445: 2,580
- 22: 1,464
- 5038: 1,292
- 5060: 970
- TCP/445: 567
- 6379: 62
- 80: 53
- 27017: 35
- 443: 37
- 23: 29
- UDP/5060: 44

### Most Common CVEs
- CVE-2006-0189: 19
- CVE-2022-27255: 19
- CVE-2002-0013 CVE-2002-0012: 12
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
- CVE-2005-4050: 5
- CVE-2019-11500: 3

### Commands Attempted by Attackers
- uname -m: 35
- uname -a: 35
- whoami: 35
- crontab -l: 35
- which ls: 35
- w: 35
- top: 35
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 35
- ls -lh $(which ls): 35
- lscpu | grep Model: 35
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 35
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 34
- cat /proc/cpuinfo | grep model | grep name | wc -l: 35
- cat /proc/cpuinfo | grep name | wc -l: 33
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 32
- lockr -ia .ssh: 32
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr": 32
- Enter new UNIX password: : 26
- Enter new UNIX password::: 26

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 562
- ET DROP Dshield Block Listed Source group 1: 241
- ET SCAN NMAP -sS window 1024: 191
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 184
- ET HUNTING RDP Authentication Bypass Attempt: 77
- ET INFO Reserved Internal IP Traffic: 51
- ET SCAN Potential SSH Scan: 24
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 15
- ET VOIP SIP UDP Softphone INVITE overflow: 15
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 7

### Users / Login Attempts (User/Password)
- 345gs5662d34/345gs5662d34: 31
- ftpuser/ftppassword: 17
- deploy/123123: 15
- admin1234/admin1234: 12
- mega/123: 11
- holu/holu: 12
- vpn/vpnpass: 10
- support/support444: 6
- test/123321: 4
- support/1q2w3e: 4

### Files Uploaded/Downloaded
- 11: 9
- fonts.gstatic.com: 9
- css?family=Libre+Franklin...: 9
- ie8.css?ver=1.0: 9
- html5.js?ver=3.7.3: 9
- wget.sh;: 4
- Mozi.a+varcron: 2
- ?format=json: 2
- w.sh;: 1
- c.sh;: 1

### HTTP User-Agents
- No user-agents recorded in this period.

### SSH Clients and Servers
- No SSH clients or servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

## Key Observations and Anomalies
- The IP address 45.234.176.18 was responsible for a disproportionately high volume of attack traffic, indicating a targeted or persistent attacker.
- A recurring command sequence was observed across multiple sessions, attempting to remove existing SSH configurations and install a new authorized key. This suggests an automated script is being used to gain persistent access. The included SSH key ends with the identifier "mdrfckr".
- The high number of triggers for the "DoublePulsar Backdoor" signature suggests ongoing attempts to exploit the SMB vulnerability (likely related to EternalBlue).
- The presence of commands like `wget` and `curl` to download shell scripts from `180.93.42.18` indicates attempts to deploy second-stage malware payloads.
- The variety of honeypots that logged events (from Cowrie for SSH to Honeytrap for various TCP ports) demonstrates a broad, non-specific scanning and exploitation approach by most attackers.
