# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T13:01:37Z
**Timeframe:** 2025-10-14T12:20:01Z to 2025-10-14T13:00:01Z
**Files Used:**
- agg_log_20251014T122001Z.json
- agg_log_20251014T124001Z.json
- agg_log_20251014T130001Z.json

## Executive Summary

This report summarizes 22,753 attacks recorded across multiple honeypots. The most targeted honeypot was Cowrie, with 7,962 events. A significant portion of attacks originated from the IP address 176.65.141.119. The most targeted port was 5060/UDP (SIP), indicating interest in VoIP infrastructure, closely followed by port 25 (SMTP) and 445 (SMB). Several commands were executed on compromised systems, primarily focused on reconnaissance and establishing persistent access by modifying SSH keys. Three distinct CVEs were detected, with low exploitation counts.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 7962
- **Honeytrap:** 3630
- **Sentrypeer:** 3032
- **Mailoney:** 2557
- **Dionaea:** 2281
- **Ciscoasa:** 1731
- **Suricata:** 1312
- **Redishoneypot:** 128
- **H0neytr4p:** 36
- **Dicompot:** 30
- **Tanner:** 24
- **Honeyaml:** 11
- **ElasticPot:** 10
- **ConPot:** 7
- **Wordpot:** 2

### Top Attacking IPs
- 176.65.141.119: 2463
- 206.191.154.180: 1374
- 185.243.5.146: 1130
- 143.44.164.239: 1134
- 185.243.5.148: 767
- 50.6.225.98: 773
- 45.236.188.4: 555
- 42.119.232.181: 551
- 129.212.191.247: 502
- 196.251.84.181: 402
- 88.210.63.16: 405
- 172.86.95.115: 384
- 172.86.95.98: 384
- 77.110.107.92: 320
- 139.59.74.228: 280

### Top Targeted Ports/Protocols
- 5060: 3032
- 25: 2559
- 445: 2255
- 22: 1153
- 23: 153
- 5903: 187
- 8333: 103
- 6379: 128
- 5901: 82
- 5909: 82
- 5908: 82
- 80: 31
- 443: 30

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2

### Commands Attempted by Attackers
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 33
- lockr -ia .ssh: 33
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 33
- uname -m: 32
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 32
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 32
- ls -lh $(which ls): 32
- which ls: 32
- crontab -l: 32
- w: 32
- cat /proc/cpuinfo | grep name | wc -l: 32
- uname: 32
- uname -a: 32
- whoami: 32
- lscpu | grep Model: 32
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 32
- top: 32
- cat /proc/cpuinfo | grep model | grep name | wc -l: 32
- Enter new UNIX password: : 17
- Enter new UNIX password:: 15

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 286
- 2402000: 286
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 219
- 2023753: 219
- ET SCAN NMAP -sS window 1024: 159
- 2009582: 159
- ET HUNTING RDP Authentication Bypass Attempt: 101
- 2034857: 101
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 23
- 2400027: 23
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 18
- 2403302: 18
- ET INFO CURL User Agent: 18
- 2002824: 18

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 31
- root/Qaz123qaz: 13
- root/123@@@: 12
- root/3245gs5662d34: 13
- config/4: 6
- admin/6666: 6
- guest/guest2007: 6
- config/9: 6
- user/user2016: 6
- root/Password@2025: 7
- nobody/qwerty12: 6
- admin/dietpi: 6
- blank/000: 6
- support/test: 4

### Files Uploaded/Downloaded
- ): 1

### HTTP User-Agents
- None observed in the logs.

### SSH Clients and Servers
- None observed in the logs.

### Top Attacker AS Organizations
- None observed in the logs.

## Key Observations and Anomalies

- **High Volume, Low Sophistication:** The vast majority of attacks are automated, high-volume scans and brute-force attempts, as evidenced by the traffic to ports 5060, 25, 445 and 22.
- **Persistent SSH Access:** A recurring pattern in the Cowrie honeypot is the execution of a series of shell commands designed to clear existing SSH configurations and install a new authorized key, likely for persistent access.
- **Focus on VoIP:** The high number of events on port 5060 suggests a continued interest from attackers in exploiting SIP services, which can be used for toll fraud or to gain a foothold in a network.
- **Low CVE Exploitation:** Despite the high volume of traffic, the number of attacks matching specific CVE signatures is very low. This indicates that most of the activity is opportunistic scanning rather than targeted exploitation of known vulnerabilities.