Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T05:01:36Z
**Timeframe:** 2025-09-30T04:20:01Z to 2025-09-30T05:00:01Z
**Files Used:**
- agg_log_20250930T042001Z.json
- agg_log_20250930T044001Z.json
- agg_log_20250930T050001Z.json

### Executive Summary

This report summarizes 14,059 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Dionaea, and Honeytrap honeypots. The most targeted services were SSH (port 22) and SMB (port 445). A significant number of brute-force attempts and automated scans were observed, with attackers attempting to exploit known vulnerabilities and gain unauthorized access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4,442
- Dionaea: 2,874
- Honeytrap: 2,254
- Suricata: 1,739
- Ciscoasa: 1,428
- Mailoney: 845
- Heralding: 301
- Tanner: 46
- ConPot: 48
- Adbhoney: 22
- H0neytr4p: 23
- Sentrypeer: 14
- Ipphoney: 9
- Miniprint: 9
- Redishoneypot: 3
- Honeyaml: 2

**Top Attacking IPs:**
- 221.121.102.137
- 86.54.42.238
- 58.181.99.75
- 58.181.99.73
- 107.167.177.160
- 179.27.96.190
- 20.169.164.223
- 103.176.78.241
- 178.128.124.111
- 185.156.73.167
- 185.156.73.166
- 92.63.197.55
- 85.208.253.156
- 92.63.197.59
- 146.190.144.138
- 190.244.25.245
- 156.238.16.164
- 129.13.189.204
- 129.13.189.202
- 80.94.95.112

**Top Targeted Ports/Protocols:**
- 445
- 22
- 25
- 8333
- vnc/5900
- 1433
- 80
- 5901
- TCP/22
- TCP/8080
- 23
- 3388
- 443
- 8728

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2023-26801
- CVE-2006-2369
- CVE-1999-0183

**Commands Attempted by Attackers:**
- Basic reconnaissance commands (`uname`, `whoami`, `ls`, `w`, `crontab -l`)
- System resource checks (`free -m`, `cat /proc/cpuinfo`, `df -h`)
- Attempts to modify SSH authorized_keys
- File download and execution using `wget` and `curl`
- Password change attempts

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO VNC Authentication Failure
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 47

**Users / Login Attempts:**
- root
- 345gs5662d34
- admin
- foundry
- koha
- jenkins
- john
- respaldo
- superadmin
- git
- user
- xx
- pp
- magda
- sa
- d
- client1
- pc
- ftp
- highgo
- oo
- dell

**Files Uploaded/Downloaded:**
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- Mozi.m
- w.sh
- c.sh
- wget.sh

**HTTP User-Agents:**
- No significant user agents were logged in the provided data.

**SSH Clients and Servers:**
- No specific SSH client or server versions were logged in the provided data.

**Top Attacker AS Organizations:**
- No specific AS organizations were logged in the provided data.

### Key Observations and Anomalies

- A high volume of automated attacks from a distributed set of IP addresses.
- Attackers are using common malware variants like Mozi and urbotnetisass.
- The majority of commands are focused on reconnaissance and establishing persistent access.
- A significant number of scans for VNC and MSSQL services were observed.
- The attackers seem to be using a common toolkit for their operations, as evidenced by the repeated use of the same commands and download URLs.
