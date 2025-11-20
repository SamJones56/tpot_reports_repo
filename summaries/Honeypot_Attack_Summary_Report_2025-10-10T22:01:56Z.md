# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T22:01:28Z
**Timeframe:** 2025-10-10T21:20:01Z to 2025-10-10T22:00:01Z
**Files Used:**
- agg_log_20251010T212001Z.json
- agg_log_20251010T214001Z.json
- agg_log_20251010T220001Z.json

## Executive Summary

This report summarizes 15,387 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attacks and command execution attempts. A significant number of events were also logged by Honeytrap, Suricata, and Ciscoasa honeypots. The most targeted ports were 22 (SSH) and 25 (SMTP). Attackers were observed attempting to download and execute malicious files, particularly ELF binaries associated with the "urbotnetisass" malware family.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6256
- **Honeytrap:** 3070
- **Suricata:** 2079
- **Ciscoasa:** 1792
- **Dionaea:** 895
- **Mailoney:** 867
- **Tanner:** 149
- **Sentrypeer:** 131
- **ElasticPot:** 43
- **ssh-rsa:** 34
- **Adbhoney:** 18
- **Honeyaml:** 16
- **H0neytr4p:** 14
- **ConPot:** 13
- **Redishoneypot:** 9
- **Ipphoney:** 1

### Top Attacking IPs
- **176.65.141.117:** 820
- **167.250.224.25:** 475
- **88.210.63.16:** 469
- **119.207.254.77:** 350
- **35.199.95.142:** 307
- **223.221.38.226:** 297
- **113.88.241.217:** 263
- **119.209.12.20:** 263
- **45.129.185.4:** 245
- **197.243.14.52:** 243

### Top Targeted Ports/Protocols
- **25:** 869
- **22:** 826
- **TCP/21:** 234
- **5903:** 191
- **5060:** 131
- **80:** 147
- **1143:** 156
- **UDP/5060:** 94
- **21:** 117
- **5908:** 85

### Most Common CVEs
- CVE-2022-27255 CVE-2022-27255
- CVE-2002-0013 CVE-2002-0012
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2016-20016 CVE-2016-20016
- CVE-2006-2369
- CVE-2024-3721 CVE-2024-3721
- CVE-2019-11500 CVE-2019-11500

### Commands Attempted by Attackers
- whoami
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa..."
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- w
- uname -a
- Enter new UNIX password:

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login
- ET INFO Reserved Internal IP Traffic
- ET SCAN Sipsak SIP scan
- ET SCAN Suspicious inbound to Oracle SQL port 1521
- ET CINS Active Threat Intelligence Poor Reputation IP group 47

### Users / Login Attempts
- root/
- 345gs5662d34/345gs5662d34
- root/Ahgf3487@rtjhskl854hd47893@#a4nC
- root/nPSpP4PBW0
- root/LeitboGi0ro
- proxyuser/P@ssw0rd@2025
- admin/password@123
- root/pass
- centos/centos123
- test1/test1
- ubnt/ubnt3

### Files Uploaded/Downloaded
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- soap-envelope
- addressing
- discovery
- env:Envelope>

### HTTP User-Agents
- No HTTP User-Agents were logged in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this period.

### Top Attacker AS Organizations
- No Attacker AS Organizations were logged in this period.

## Key Observations and Anomalies
- A notable command sequence involves downloading and executing several ELF binaries with names like `arm.urbotnetisass`, `mips.urbotnetisass`, etc. This indicates a coordinated attempt to infect devices with various architectures.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` was frequently observed, suggesting attackers are attempting to install their own SSH keys for persistent access.
- There is a high volume of scanning activity for MS Terminal Server (RDP) on non-standard ports, as well as FTP and SIP services.
