
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T06:01:25Z
**Timeframe:** 2025-10-17T05:20:01Z to 2025-10-17T06:00:01Z
**Log Files:**
- agg_log_20251017T052001Z.json
- agg_log_20251017T054001Z.json
- agg_log_20251017T060001Z.json

## Executive Summary
This report summarizes 22,053 events captured by the honeypot network. The majority of attacks targeted SMB (port 445), likely exploiting vulnerabilities like EternalBlue. A significant number of SSH brute-force attacks and web CVE exploitation attempts were also observed. The most active attacker IP was 59.152.191.3.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4600
- Dionaea: 5531
- Suricata: 3811
- Honeytrap: 3877
- Ciscoasa: 1644
- Sentrypeer: 1311
- Mailoney: 890
- Tanner: 163
- ConPot: 77
- H0neytr4p: 24
- Wordpot: 27
- Honeyaml: 23
- Adbhoney: 11
- ElasticPot: 21
- ssh-rsa: 30
- Miniprint: 5
- Redishoneypot: 5
- Ipphoney: 3

### Top Attacking IPs
- 59.152.191.3: 3147
- 85.95.177.156: 1589
- 176.65.141.119: 822
- 88.214.50.58: 694
- 66.116.196.243: 630
- 125.163.249.56: 592
- 172.86.95.115: 510
- 172.86.95.98: 496
- 45.140.17.52: 310
- 1.1.253.134: 306

### Top Targeted Ports/Protocols
- 445: 4877
- 5060: 1311
- 22: 702
- 25: 891
- TCP/445: 1587
- 80: 196
- 5903: 226
- 1952: 156
- TCP/1433: 120
- 1433: 106

### Most Common CVEs
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2024-12856
- CVE-2024-12885
- CVE-2014-6271
- CVE-2023-47565
- CVE-2023-52163
- CVE-2023-31983
- CVE-2009-2765
- CVE-2024-10914
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2021-42013
- CVE-2024-3721
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2001-0414
- CVE-1999-0183
- CVE-2002-1149
- CVE-2019-16920
- CVE-2019-11500
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-41773

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
- cat /proc/cpuinfo | grep name | wc -l
- uname -a
- whoami
- Enter new UNIX password:
- ./upnpsetup
- ./Dezi8EvL

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET INFO Reserved Internal IP Traffic
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/Qaz123qaz
- root/
- root/123@@@
- debian/debian2015
- guest/666
- admin/admin2000
- root/root2014
- centos/centos2025

### Files Uploaded/Downloaded
- sh
- apply.cgi
- rondo.tkg.sh|sh&echo
- arm.urbotnetisass
- login_pic.asp
- Dezi8EvL
- upnpsetup

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients and Servers
- No specific SSH clients or servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

## Key Observations and Anomalies
- The high number of events targeting port 445 and the 'DoublePulsar' signature suggest ongoing automated campaigns exploiting the EternalBlue vulnerability.
- A single IP address, 59.152.191.3, was responsible for a large portion of the total attack volume.
- Attackers frequently attempted to add their own SSH key to the `authorized_keys` file for persistent access.
- Several commands indicate attempts to download and execute malware, such as `urbotnetisass` and `Dezi8EvL`.
- A wide variety of CVEs were targeted, indicating that attackers are using a broad set of exploits to find vulnerable systems.
