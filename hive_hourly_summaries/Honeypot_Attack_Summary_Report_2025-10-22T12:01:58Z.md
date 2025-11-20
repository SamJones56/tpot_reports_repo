# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T12:01:27Z
**Timeframe:** 2025-10-22T11:20:01Z to 2025-10-22T12:00:01Z
**Files Used:**
- agg_log_20251022T112001Z.json
- agg_log_20251022T114001Z.json
- agg_log_20251022T120001Z.json

## Executive Summary

This report summarizes 19,638 attacks recorded by our honeypot network. The most targeted honeypot was Cowrie, with 8,092 events. The most frequent attacker IP was 111.175.37.46, responsible for 5,077 attacks. The most targeted port was TCP/445, indicating continued interest in SMB vulnerabilities. Multiple CVEs were exploited, with CVE-2021-3449 and CVE-2024-3721 being the most common. A variety of commands were attempted, including efforts to lock down SSH configuration and gather system information.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 8,092
- Honeytrap: 4,123
- Suricata: 3,324
- Dionaea: 1,916
- Ciscoasa: 1,626
- Sentrypeer: 322
- Mailoney: 82
- Tanner: 59
- Redishoneypot: 27
- H0neytr4p: 25
- ElasticPot: 23
- ConPot: 8
- Heralding: 3
- Dicompot: 3
- Honeyaml: 3
- ssh-rsa: 2

### Top Attacking IPs
- 111.175.37.46: 5,077
- 81.32.167.105: 1,330
- 23.150.152.105: 1,254
- 1.9.70.82: 811
- 45.140.17.153: 499
- 45.134.26.20: 493
- 124.226.219.166: 337
- 197.162.226.253: 261

### Top Targeted Ports/Protocols
- TCP/445: 1,594
- 22: 1,514
- 445: 897
- 5060: 322
- 1433: 166
- TCP/21: 156
- 5903: 152
- 23: 116

### Most Common CVEs
- CVE-2024-3721
- CVE-2021-3449
- CVE-2019-11500
- CVE-2006-2369
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2018-10562
- CVE-2018-10561

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- uname -s -v -n -r -m
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- echo "root:ovjyDEcKa7qF"|chpasswd|bash
- echo -e "eses\\ncYkAiisvuSKw\\ncYkAiisvuSKw"|passwd|bash

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,585
- 2024766: 1,585
- ET DROP Dshield Block Listed Source group 1: 284
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 235
- 2023753: 235
- ET SCAN NMAP -sS window 1024: 162
- 2009582: 162
- ET HUNTING RDP Authentication Bypass Attempt: 141
- 2034857: 141

### Users / Login Attempts
- root/BnaPbxPass1425
- root/BNBN5353BN
- root/Bobiki13
- root/Bold2014
- root/bolji55biznis
- root/bon555
- supermaint/z4ng0rber
- 345gs5662d34/345gs5662d34
- root/BndAdmin!
- hadoop/hadoop
- hadoop/hadoop123
- mysql/mysql
- mysql/mysql123

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- gpon8080&ipv=0
- discovery
- soap-envelope
- soap-encoding
- addressing
- a:ReplyTo><a:To
- wsdl

### HTTP User-Agents
- No HTTP user agents were logged in this timeframe.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- The high number of attacks on port 445 (SMB) and the triggering of the "DoublePulsar Backdoor" signature suggest a continued campaign targeting this vulnerability.
- The variety of commands attempted indicates that attackers are actively trying to gain control of compromised systems and gather information about their environment.
- The use of commands to manipulate SSH authorized_keys files is a common technique for maintaining persistent access.
