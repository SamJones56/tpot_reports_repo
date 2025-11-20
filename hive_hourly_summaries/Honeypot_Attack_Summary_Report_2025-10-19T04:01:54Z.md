
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T04:01:31Z
**Timeframe:** 2025-10-19T03:20:01Z to 2025-10-19T04:00:01Z
**Files Used:**
- agg_log_20251019T032001Z.json
- agg_log_20251019T034001Z.json
- agg_log_20251019T040001Z.json

## Executive Summary

This report summarizes 18,528 events collected from the honeypot network over the last hour. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. A significant number of attacks originated from the IP address 38.242.213.182. The most targeted port was 5060, commonly used for SIP/VoIP services. The most common vulnerability exploited was CVE-2005-4050. Attackers were observed attempting to gain access using default or weak credentials and running reconnaissance commands.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 6820
- Honeytrap: 5086
- Suricata: 3265
- Sentrypeer: 1923
- Ciscoasa: 1091
- Dionaea: 73
- H0neytr4p: 49
- Mailoney: 51
- Tanner: 59
- Miniprint: 42
- Adbhoney: 9
- Redishoneypot: 17
- ConPot: 12
- Honeyaml: 21
- Wordpot: 1
- Ipphoney: 1
- Dicompot: 4
- Heralding: 3
- ElasticPot: 1

### Top Attacking IPs
- 38.242.213.182: 1949
- 72.146.232.13: 1182
- 198.23.190.58: 1185
- 23.94.26.58: 1128
- 194.50.16.73: 937
- 198.12.68.114: 831
- 104.248.206.169: 343
- 88.210.63.16: 461
- 196.251.88.103: 374
- 152.32.190.168: 229
- 107.170.36.5: 156
- 103.161.207.2: 159
- 116.193.191.209: 201
- 220.80.223.144: 191
- 178.156.144.245: 172
- 92.27.101.99: 168
- 31.193.137.183: 149
- 152.42.254.23: 129
- 103.159.132.91: 123
- 170.239.86.101: 123

### Top Targeted Ports/Protocols
- 5060: 1923
- UDP/5060: 1357
- 22: 1333
- 7070: 920
- 8000: 349
- 7000: 381
- 5038: 299
- 5903: 227
- 5901: 111
- 8333: 73
- 25: 51
- 443: 36
- 81: 34
- 23: 31
- 9000: 26
- 5904: 71
- 5905: 71
- 8728: 34
- TCP/22: 52
- 9100: 42

### Most Common CVEs
- CVE-2005-4050: 1355
- CVE-2002-0013 CVE-2002-0012: 12
- CVE-2019-11500 CVE-2019-11500: 8
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2001-0414: 2
- CVE-2006-2369: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 24
- lockr -ia .ssh: 24
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 24
- cat /proc/cpuinfo | grep name | wc -l: 25
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 25
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 25
- ls -lh $(which ls): 25
- which ls: 25
- crontab -l: 25
- w: 25
- uname -m: 25
- cat /proc/cpuinfo | grep model | grep name | wc -l: 25
- top: 25
- uname: 25
- uname -a: 25
- whoami: 25
- lscpu | grep Model: 25
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 25
- Enter new UNIX password: : 16
- Enter new UNIX password:": 16

### Signatures Triggered
- ET VOIP MultiTech SIP UDP Overflow: 1355
- 2003237: 1355
- ET DROP Dshield Block Listed Source group 1: 494
- 2402000: 494
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 358
- 2023753: 358
- ET SCAN NMAP -sS window 1024: 171
- 2009582: 171
- ET HUNTING RDP Authentication Bypass Attempt: 147
- 2034857: 147
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60
- ET SCAN Potential SSH Scan: 45
- 2001219: 45

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 23
- root/3245gs5662d34: 8
- support/000: 6
- support/support2009: 6
- centos/test: 6
- user/3333: 6
- config/config2020: 6
- centos/centos2011: 6
- ftpuser/ftppassword: 5
- supervisor/supervisor2014: 4
- root/45a18cd70f2014web: 4
- root/45nuewrvjil: 4
- guest/guest777: 4
- centos/centos2012: 4
- root/45ZhxNX7t6YX: 4
- root/48015594-n: 4
- vtatis/123: 4
- user/user66: 4
- root/48Ums6XupV: 4
- admin/admin123456789: 4

### Files Uploaded/Downloaded
- ?format=json: 2
- ): 1

### HTTP User-Agents
- None recorded in this timeframe.

### SSH Clients and Servers
- None recorded in this timeframe.

### Top Attacker AS Organizations
- None recorded in this timeframe.

## Key Observations and Anomalies
- The vast majority of attacks are automated and opportunistic, focusing on common vulnerabilities and weak credentials.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates attempts to install SSH keys for persistent access. This is a common tactic for botnets to maintain control over compromised machines.
- The high number of SIP/VoIP related attacks (port 5060) suggests a focused campaign against communication servers.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organization data might indicate that the honeypots designed to capture this information did not receive relevant traffic during this period, or that the logging for these fields was not triggered.
