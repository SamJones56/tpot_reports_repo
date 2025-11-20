# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T01:01:28Z
**Timeframe:** 2025-10-17T00:20:01Z to 2025-10-17T01:00:01Z
**Files Processed:**
- agg_log_20251017T002001Z.json
- agg_log_20251017T004001Z.json
- agg_log_20251017T010001Z.json

## Executive Summary

This report summarizes honeypot activity over a period of approximately 40 minutes, based on logs from three separate intervals. A total of 15,663 attacks were recorded across various honeypots. The most targeted services were Cowrie (SSH), Honeytrap, and Ciscoasa. The majority of attacks originated from a diverse set of IP addresses, with a significant number of attempts targeting ports 5060 (SIP) and 22 (SSH). Several CVEs were exploited, and attackers attempted a range of commands, primarily focused on reconnaissance and establishing further access.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 6143
- **Honeytrap:** 3343
- **Ciscoasa:** 1746
- **Suricata:** 1538
- **Sentrypeer:** 1284
- **Mailoney:** 965
- **Dionaea:** 523
- **Tanner:** 38
- **H0neytr4p:** 24
- **ConPot:** 15
- **Honeyaml:** 15
- **Miniprint:** 9
- **ElasticPot:** 7
- **Redishoneypot:** 9
- **Ipphoney:** 4

### Top Attacking IPs
- 129.212.177.47: 999
- 176.65.141.119: 821
- 41.225.37.61: 480
- 172.86.95.115: 499
- 172.86.95.98: 483
- 64.188.93.249: 288
- 211.253.37.225: 248
- 162.240.157.215: 231
- 190.129.122.120: 266
- 181.104.58.194: 270
- 174.138.116.10: 188
- 161.132.37.62: 235
- 104.168.58.11: 227
- 152.42.203.0: 202
- 14.103.163.65: 220

### Top Targeted Ports/Protocols
- 5060: 1284
- 22: 868
- 25: 969
- 445: 495
- 8333: 191
- 5903: 189
- 23: 108
- 9093: 71
- 5901: 103
- 5905: 77
- 5904: 77
- 80: 33
- 443: 28

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2001-0414
- CVE-2019-11500 CVE-2019-11500

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:
- system
- shell

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET HUNTING RDP Authentication Bypass Attempt
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- GPL SNMP request udp
- ET SCAN Sipsak SIP scan

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- user/user2012
- root/QWE123!@#qwe
- ftpuser/ftppassword
- root/Qaz123qaz
- test/test2017
- ubnt/ubnt2006
- guest/guest12345
- admin/admin2005
- root/0987654321

### Files Uploaded/Downloaded
- SOAP-ENV:Envelope>
- .i;
- ?format=json

### HTTP User-Agents
- N/A

### SSH Clients and Servers
- **SSH Clients:** N/A
- **SSH Servers:** N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

- A high volume of attacks were logged in a relatively short period, indicating automated scanning and exploitation attempts.
- The prevalence of commands related to disabling security measures (`chattr`, `lockr`) and manipulating SSH keys suggests attackers are attempting to establish persistent access.
- The `mdrfckr` comment in the SSH key is a common signature of a specific botnet.
- The variety of targeted ports indicates a broad scanning approach by attackers, looking for any open and vulnerable service.
- The logs did not contain specific information on HTTP User-Agents, SSH clients/servers, or AS organizations, which may be a limitation of the current logging configuration.
