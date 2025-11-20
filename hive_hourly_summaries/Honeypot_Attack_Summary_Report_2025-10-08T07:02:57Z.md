
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T07:02:10Z
**Timeframe:** 2025-10-08T06:20:02Z to 2025-10-08T07:00:01Z
**Files Used:**
- `agg_log_20251008T062002Z.json`
- `agg_log_20251008T064001Z.json`
- `agg_log_20251008T070001Z.json`

## Executive Summary
This report summarizes a total of 13,935 attacks recorded across the honeypot network during the reporting period. The most targeted honeypot was **Cowrie**, with 5,459 events. The top attacking IP address was **177.126.132.44** with 1,239 events. The most targeted port was port **25 (SMTP)**, indicating a high volume of mail-based attacks. A number of CVEs were detected, with **CVE-2002-0013 and CVE-2002-0012** being the most frequently observed. Attackers made numerous attempts to execute commands, primarily aimed at reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 5459
- Honeytrap: 2542
- Ciscoasa: 1711
- Mailoney: 1706
- Suricata: 1238
- Dionaea: 903
- Sentrypeer: 161
- Tanner: 97
- H0neytr4p: 45
- Honeyaml: 23
- ConPot: 10
- Adbhoney: 9
- Miniprint: 9
- Dicompot: 7
- Redishoneypot: 7
- Heralding: 3
- Wordpot: 3
- ElasticPot: 1
- Ipphoney: 1

### Top Attacking IPs
- 177.126.132.44: 1239
- 176.65.141.117: 820
- 86.54.42.238: 820
- 1.53.36.195: 770
- 36.50.54.25: 362
- 68.183.88.186: 283
- 158.51.124.56: 253
- 82.115.43.135: 215
- 49.12.98.196: 202
- 151.243.242.200: 194
- 101.36.122.23: 193
- 178.128.152.40: 184
- 211.219.22.213: 164
- 79.61.112.234: 154
- 196.251.88.103: 151
- 159.203.2.69: 149
- 45.200.232.125: 135
- 186.248.197.77: 94
- 14.103.131.112: 90
- 189.178.87.2: 89

### Top Targeted Ports/Protocols
- 25: 1707
- 445: 845
- 22: 801
- 5060: 161
- 8333: 124
- 80: 104
- 5903: 95
- 23: 83
- 8888: 55
- 5909: 53
- 5908: 50
- 5907: 49
- TCP/80: 48
- 1911: 36
- 27018: 33
- UDP/161: 27
- 8020: 21
- TCP/443: 20
- 10000: 15
- TCP/1433: 12

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 15
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 11
- CVE-2019-11500 CVE-2019-11500: 10
- CVE-2021-3449 CVE-2021-3449: 7
- CVE-2016-20016 CVE-2016-20016: 2
- CVE-2005-4050: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 33
- lockr -ia .ssh: 33
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 33
- uname -a: 21
- cat /proc/cpuinfo | grep name | wc -l: 20
- Enter new UNIX password: : 20
- Enter new UNIX password::: 20
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 20
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 20
- ls -lh $(which ls): 20
- which ls: 20
- crontab -l: 20
- w: 20
- uname -m: 20
- cat /proc/cpuinfo | grep model | grep name | wc -l: 20
- top: 20
- uname: 20
- whoami: 20
- lscpu | grep Model: 20
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 20

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 292
- 2402000: 292
- ET SCAN NMAP -sS window 1024: 169
- 2009582: 169
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60
- ET INFO CURL User Agent: 30
- 2002824: 30
- GPL SNMP request udp: 14
- 2101417: 14
- ET CINS Active Threat Intelligence Poor Reputation IP group 40: 13
- 2403339: 13
- ET CINS Active Threat Intelligence Poor Reputation IP group 65: 13
- 2403364: 13
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 12
- 2023753: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 11
- 2403343: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 11
- 2403345: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 11
- 2403346: 11
- ET SCAN Suspicious inbound to MSSQL port 1433: 11
- 2010935: 11

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 33
- sysadmin/sysadmin@1: 10
- supervisor/444: 7
- administrator/P@ssw0rd: 6
- operator/123abc: 6
- Root/444444444: 6
- root/meiyoumima: 6
- supervisor/supervisor123456789: 6
- ubnt/Ubnt2023: 6
- guest/raspberry: 5
- ali/ali12345: 4
- centos/centos12345: 4
- rocky/1234567890: 4
- root/aaa: 4
- stack/3245gs5662d34: 4
- support/123456789123456789: 4
- vpn/vpn123321: 4
- ahmed/123ahmed: 3
- arkserver/123123: 3
- arkserver/3245gs5662d34: 3

### Files Uploaded/Downloaded
- wget.sh;: 12
- c.sh;: 3
- w.sh;: 3

### HTTP User-Agents
- No data recorded in this period.

### SSH Clients
- No data recorded in this period.

### SSH Servers
- No data recorded in this period.

### Top Attacker AS Organizations
- No data recorded in this period.

## Key Observations and Anomalies
- A significant number of attacks from **177.126.132.44** were observed, focusing on the **Mailoney** honeypot, suggesting a potential campaign targeting mail servers.
- The repeated use of the command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` indicates a common tactic to install unauthorized SSH keys for persistent access.
- The high volume of traffic to port **25 (SMTP)** is indicative of attackers' interest in exploiting email services for activities such as spamming or phishing.
- The downloading and execution of shell scripts (`wget.sh`, `w.sh`, `c.sh`) from the IP address **147.93.182.114** points to automated attempts to deploy malware on compromised systems.
---
This concludes the Honeypot Attack Summary Report.
