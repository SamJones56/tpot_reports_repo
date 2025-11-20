
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T00:01:32Z
**Timeframe:** 2025-10-22T23:20:01Z to 2025-10-23T00:00:01Z
**Files Used:**
- agg_log_20251022T232001Z.json
- agg_log_20251022T234001Z.json
- agg_log_20251023T000001Z.json

## Executive Summary

This report summarizes 15,343 events collected from the honeypot network. The most engaged honeypot was Cowrie, designed to emulate SSH and Telnet services. A significant portion of the attacks originated from the IP address 109.205.211.9. The most frequently targeted port was 5060/UDP, commonly used for Session Initiation Protocol (SIP) in VoIP systems, indicating a focus on telecommunication service vulnerabilities. A variety of CVEs were targeted, and attackers frequently attempted to gain persistent access by adding their SSH keys to the system.

## Detailed Analysis

### Attacks by Honeypot

- **Cowrie:** 4422
- **Honeytrap:** 4430
- **Suricata:** 3042
- **Ciscoasa:** 1761
- **Sentrypeer:** 1021
- **Tanner:** 253
- **H0neytr4p:** 158
- **Dionaea:** 109
- **ElasticPot:** 43
- **Mailoney:** 68
- **Redishoneypot:** 12
- **ConPot:** 11
- **Adbhoney:** 5
- **Heralding:** 3
- **Dicompot:** 3
- **Ipphoney:** 1
- **Honeyaml:** 1


### Top Attacking IPs

- 109.205.211.9
- 196.251.88.103
- 174.138.3.41
- 121.43.153.90
- 88.210.63.16
- 45.94.31.135
- 201.138.161.40
- 220.117.157.183
- 101.89.218.18
- 188.164.195.81

### Top Targeted Ports/Protocols

- 5060
- 22
- 80
- 443
- 8333
- 5903
- 5901
- 445
- TCP/22
- TCP/80

### Most Common CVEs

- CVE-2021-3449
- CVE-2019-11500
- CVE-1999-0183
- CVE-2002-1149
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-41773
- CVE-2021-42013
- CVE-2006-2369

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem`
- `ls -lh $(which ls)`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh`

### Signatures Triggered

- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET CINS Active Threat Intelligence Poor Reputation IP group 44


### Users / Login Attempts

- root/c4n4r10s
- 345gs5662d34/345gs5662d34
- root/C4rl0m4gn0800.56
- git/git
- test/test2026
- root/c4t9p1
- root/c79801192
- root/C911c3nt3r
- elasticsearch/elasticsearch
- pi/raspberry
- gpadmin/gpadmin123

### Files Uploaded/Downloaded

- sh
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- css?family=Libre+Franklin...
- fonts.gstatic.com
- 11
- wget.sh;
- svg
- xlink
- #comment-1
- w.sh;
- c.sh;
- soap-envelope
- addressing
- discovery
- env:Envelope>

### HTTP User-Agents

- No user agents were logged in this timeframe.

### SSH Clients and Servers

- No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations

- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- The high volume of scans for MS Terminal Server on non-standard ports suggests widespread automated scanning for vulnerable RDP services.
- A recurring attack pattern involves attempts to remove existing SSH configurations and inject a specific public key into the `authorized_keys` file. This indicates a clear objective to establish persistent, unauthorized access.
- The variety in targeted ports and services, from VoIP (5060) to SSH (22) and web servers (80, 443), reflects the broad and opportunistic nature of the observed attacks.
- A significant number of security signatures triggered are related to blocklists (Dshield) and poor reputation IPs (CINS), underscoring the effectiveness of threat intelligence feeds in identifying malicious actors.
- The commands executed post-exploitation focus on system reconnaissance (`uname`, `lscpu`, `free`), confirming attacker interest in understanding the environment for potential further exploitation.
