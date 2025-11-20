# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T03:01:24Z
**Timeframe:** 2025-10-10T02:20:02Z to 2025-10-10T03:00:01Z
**Files Used:**
- agg_log_20251010T022002Z.json
- agg_log_20251010T024001Z.json
- agg_log_20251010T030001Z.json

## Executive Summary

This report summarizes 17,818 malicious events recorded across the honeypot network. The majority of activity was captured by the Cowrie and Suricata honeypots. A significant volume of attacks originated from IP address `125.22.21.233`, primarily targeting SMB port 445, and `35.200.201.144` and `4.144.169.44`, which were engaged in extensive SSH brute-force activity.

Attackers predominantly targeted SSH (22), SMB (445), and SIP (5060) services. A large number of Suricata alerts pointed to the `DoublePulsar Backdoor`, indicating attempts to exploit vulnerabilities related to the EternalBlue family. SSH-based attacks consistently attempted to deploy a specific RSA public key to gain persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 8225
- **Suricata:** 3562
- **Honeytrap:** 3383
- **Ciscoasa:** 1676
- **Sentrypeer:** 352
- **Dionaea:** 152
- **ElasticPot:** 90
- **H0neytr4p:** 98
- **Tanner:** 52
- **Redishoneypot:** 52
- **ConPot:** 52
- **Mailoney:** 47
- **Dicompot:** 30
- **Adbhoney:** 22
- **Honeyaml:** 12
- **Miniprint:** 8
- **Heralding:** 3
- **Ipphoney:** 2

### Top Attacking IPs
- 125.22.21.233 (1506)
- 35.200.201.144 (1250)
- 4.144.169.44 (1251)
- 167.250.224.25 (1335)
- 129.154.42.120 (309)
- 223.197.248.209 (307)
- 146.190.93.207 (307)
- 189.126.4.42 (382)
- 45.134.26.3 (338)
- 34.71.99.10 (307)
- 88.210.63.16 (280)
- 154.221.19.149 (272)
- 203.23.199.85 (219)
- 200.77.172.159 (173)

### Top Targeted Ports/Protocols
- TCP/445 (1501)
- 22 (1287)
- 5060 (352)
- 5903 (203)
- 8333 (165)
- 9200 (84)
- 443 (88)
- 1433 (72)
- 5908 (83)
- 5909 (83)
- 5901 (74)
- 80 (51)
- 6379 (39)
- 25 (42)

### Most Common CVEs
- CVE-2001-0414
- CVE-2002-0012
- CVE-2002-0013
- CVE-2002-1149
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2013-7471
- CVE-2018-10561
- CVE-2018-10562
- CVE-2019-11500
- CVE-2021-3449
- CVE-1999-0517

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh` (29)
- `lockr -ia .ssh` (29)
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && ...` (29)
- `cat /proc/cpuinfo | grep name | wc -l` (29)
- `Enter new UNIX password:` (29)
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'` (29)
- `uname -a` (29)
- `whoami` (29)
- `w` (29)
- `crontab -l` (29)

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (1499)
- ET DROP Dshield Block Listed Source group 1 (697)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (338)
- ET SCAN NMAP -sS window 1024 (151)
- ET HUNTING RDP Authentication Bypass Attempt (154)
- ET INFO Reserved Internal IP Traffic (56)
- ET SCAN Suspicious inbound to MSSQL port 1433 (22)
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source) (30)
- ET CINS Active Threat Intelligence Poor Reputation IP group (multiple) (54)
- ET DROP Spamhaus DROP Listed Traffic Inbound (multiple) (24)

### Users / Login Attempts
- `345gs5662d34/345gs5662d34` (26)
- `root/stfu_and_be_quite` (6)
- `debian/debian1234567890` (6)
- `ubnt/ubnt33` (6)
- `admin/1234` (6)
- `guest/guest10` (6)
- `sshd/cms500` (6)
- `config/config8` (6)
- `support/password@123` (6)

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

### HTTP User-Agents
- No HTTP User-Agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH client or server versions were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organization data was available in this period.

## Key Observations and Anomalies

1.  **High-Volume SMB Scans:** The most frequent event was related to the DoublePulsar backdoor, indicating widespread, automated scanning for systems vulnerable to EternalBlue exploits. IP `125.22.21.233` was the sole source of this traffic.
2.  **Persistent SSH Intrusion Attempts:** A coordinated SSH brute-force campaign is ongoing. Attackers are using a wide variety of credentials and, upon successful login, immediately attempt to disable SSH protections (`chattr -ia .ssh`) and install a persistent SSH key. The command `cd ~ && rm -rf .ssh && ...` was attempted 29 times, showing a consistent attack methodology across different sessions.
3.  **RDP Scanning:** A notable number of alerts for "RDP Authentication Bypass Attempt" and "MS Terminal Server Traffic on Non-standard Port" suggest attackers are actively searching for exposed Remote Desktop Protocol services.
4.  **Lack of Sophistication:** The majority of attacks appear to be automated and opportunistic, relying on common vulnerabilities and weak credentials rather than targeted, sophisticated methods. The commands executed post-breach are reconnaissance-focused (`uname -a`, `whoami`, `lscpu`) before attempting to establish persistence.
