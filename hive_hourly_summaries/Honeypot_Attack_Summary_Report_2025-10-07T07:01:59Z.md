
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T07:01:27Z
**Timeframe:** 2025-10-07T06:20:01Z to 2025-10-07T07:00:01Z

**Files Used:**
- agg_log_20251007T062001Z.json
- agg_log_20251007T064002Z.json
- agg_log_20251007T070001Z.json

## Executive Summary

This report summarizes 16,069 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The most active honeypot was Cowrie, a medium interaction SSH and Telnet honeypot, which recorded 5,877 events. The most prominent attack vector was targeting port 445 (SMB), with a significant number of events also targeting ports 22 (SSH) and 25 (SMTP). The top attacking IP address was 41.33.199.217. A notable signature, "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication", was triggered 1526 times, indicating attempts to exploit the SMB vulnerability.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 5877
- Suricata: 3011
- Honeytrap: 2693
- Dionaea: 1771
- Mailoney: 893
- Ciscoasa: 764
- Sentrypeer: 448
- Redishoneypot: 47
- ConPot: 46
- H0neytr4p: 42
- Tanner: 42
- Honeyaml: 20
- ElasticPot: 5
- Adbhoney: 4
- Dicompot: 4
- Heralding: 3
- ssh-rsa: 2
- Medpot: 1

### Top Attacking IPs

- 41.33.199.217: 1707
- 116.68.77.169: 1533
- 147.45.193.115: 1252
- 86.54.42.238: 820
- 185.126.217.241: 602
- 194.190.153.226: 460
- 172.86.95.98: 436
- 191.242.105.131: 258
- 181.188.159.138: 278
- 103.220.207.174: 328
- 172.208.24.217: 279
- 201.249.204.129: 219
- 186.121.205.29: 197
- 152.32.190.168: 146
- 51.178.143.200: 198
- 185.213.175.140: 134
- 122.114.231.175: 97
- 147.50.227.79: 100
- 103.124.100.181: 136
- 107.170.36.5: 66

### Top Targeted Ports/Protocols

- 445: 2727
- TCP/445: 1528
- 22: 898
- 25: 893
- 5060: 448
- 5903: 96
- 23: 43
- 6379: 42
- 8333: 56
- 443: 36
- TCP/80: 34
- 80: 44
- 5908: 50
- 5907: 49
- 5909: 49
- TCP/22: 15
- UDP/161: 25
- TCP/8080: 15
- 10000: 8
- 4949: 10

### Most Common CVEs

- CVE-2002-0013 CVE-2002-0012: 12
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 10
- CVE-1999-0265: 9
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-1999-0517: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2022-0543 CVE-2022-0543: 2

### Commands Attempted by Attackers

- cd ~; chattr -ia .ssh; lockr -ia .ssh: 31
- lockr -ia .ssh: 31
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 30
- uname -a: 22
- Enter new UNIX password: : 21
- Enter new UNIX password:: 21
- cat /proc/cpuinfo | grep name | wc -l: 21
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 21
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 21
- ls -lh $(which ls): 21
- which ls: 21
- crontab -l: 21
- w: 21
- uname -m: 21
- cat /proc/cpuinfo | grep model | grep name | wc -l: 21
- top: 21
- uname: 21
- whoami: 21
- lscpu | grep Model: 21
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 21

### Signatures Triggered

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1526
- 2024766: 1526
- ET DROP Dshield Block Listed Source group 1: 469
- 2402000: 469
- ET SCAN NMAP -sS window 1024: 160
- 2009582: 160
- ET INFO Reserved Internal IP Traffic: 62
- 2002752: 62
- GPL TELNET Bad Login: 24
- 2101251: 24
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 24
- 2023753: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 22
- 2403346: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 22
- 2403349: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 26
- 2403347: 26
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 20
- 2400027: 20

### Users / Login Attempts

- 345gs5662d34/345gs5662d34: 28
- tester/3245gs5662d34: 5
- ubuntu/3245gs5662d34: 5
- root/12345: 4
- username/username!: 4
- deploy/deploy@2025: 6
- tester/tester!: 6
- postgres/postgres: 3
- oracle/P@ssw0rd@123: 3
- ts3server/1234567890: 3
- admin1/admin112345: 3
- newuser/welcome: 3
- git/Password1: 3
- test1/1234567890: 3
- ubuntu/Ubuntu: 3
- tempuser/tempuser: 3
- student/P@ssw0rd1: 3
- admin/06081980: 3
- admin/06071977: 3
- admin/06061975: 3

### Files Uploaded/Downloaded

- ?format=json: 2
- ): 1

### HTTP User-Agents
- No user agents were recorded in this timeframe.

### SSH Clients and Servers
- No SSH clients or servers were recorded in this timeframe.

### Top Attacker AS Organizations
- No AS organizations were recorded in this timeframe.

## Key Observations and Anomalies

- The high number of events related to the "DoublePulsar" backdoor indicates a targeted campaign against SMB services.
- The variety of credentials used in login attempts suggests automated brute-force attacks.
- The commands executed after successful logins (if any) are typical reconnaissance commands to understand the system's architecture.
- The attacker with IP `116.68.77.169` generated a large number of events in a short period, focusing on a single honeypot, suggesting a targeted attack.
