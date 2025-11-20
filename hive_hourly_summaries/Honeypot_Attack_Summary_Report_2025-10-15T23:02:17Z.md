
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T23:01:36Z
**Timeframe:** 2025-10-15T22:20:01Z - 2025-10-15T23:00:01Z
**Files Used:**
- `agg_log_20251015T222001Z.json`
- `agg_log_20251015T224001Z.json`
- `agg_log_20251015T230001Z.json`

## Executive Summary

This report summarizes 27,309 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Honeytrap and Sentrypeer. The most frequent attacks originated from IP address `206.191.154.180`. The primary targets were ports 5060 (SIP) and 22 (SSH). Several CVEs were detected, with `CVE-2005-4050` being the most common. A large number of commands were executed, many of which were related to establishing SSH access and reconnaissance.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 17949
- **Honeytrap:** 3537
- **Sentrypeer:** 2885
- **Suricata:** 1381
- **Ciscoasa:** 1316
- **Dionaea:** 57
- **Mailoney:** 55
- **Redishoneypot:** 45
- **Tanner:** 33
- **H0neytr4p:** 26
- **Adbhoney:** 13
- **ssh-rsa:** 4
- **Dicompot:** 3
- **Heralding:** 3
- **ConPot:** 1
- **ElasticPot:** 1

### Top Attacking IPs
- **206.191.154.180:** 1134
- **185.243.5.121:** 1004
- **92.191.96.171:** 643
- **5.39.250.130:** 633
- **45.78.192.86:** 621
- **77.110.107.92:** 587
- **157.97.107.143:** 513
- **103.195.101.44:** 462
- **213.32.245.214:** 450
- **83.168.107.40:** 440
- **62.133.61.220:** 380
- **172.86.95.115:** 379
- **23.94.26.58:** 365
- **144.31.221.45:** 365
- **77.199.85.196:** 326
- **84.60.229.162:** 325
- **109.91.230.1:** 320
- **81.170.248.221:** 301
- **46.253.45.10:** 261
- **46.171.220.254:** 252

### Top Targeted Ports/Protocols
- **5060:** 2885
- **22:** 1799
- **5903:** 186
- **TCP/5900:** 131
- **UDP/5060:** 109
- **8333:** 107
- **5901:** 92
- **23:** 66
- **25:** 57
- **5905:** 56
- **5904:** 55
- **6379:** 45
- **5909:** 41
- **5907:** 40
- **5908:** 39
- **5902:** 35
- **TCP/5432:** 33
- **7443:** 31
- **TCP/22:** 30
- **80:** 29

### Most Common CVEs
- **CVE-2005-4050:** 19
- **CVE-2002-0013 CVE-2002-0012:** 7
- **CVE-2019-11500 CVE-2019-11500:** 4
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 3
- **CVE-2021-3449 CVE-2021-3449:** 3

### Commands Attempted by Attackers
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 154
- **lockr -ia .ssh:** 154
- **cd ~ && rm -rf .ssh && mkdir .ssh && echo ...:** 154
- **cat /proc/cpuinfo | grep name | wc -l:** 152
- **cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}':** 152
- **free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}':** 152
- **ls -lh $(which ls):** 152
- **which ls:** 152
- **crontab -l:** 152
- **w:** 152
- **uname -m:** 152
- **cat /proc/cpuinfo | grep model | grep name | wc -l:** 152
- **top:** 152
- **uname:** 152
- **uname -a:** 152
- **whoami:** 152
- **lscpu | grep Model:** 151
- **df -h | head -n 2 | awk 'FNR == 2 {print $2;}':** 151
- **Enter new UNIX password: :** 127
- **Enter new UNIX password%!(EXTRA string=:)**: 127

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 324
- **2402000:** 324
- **ET SCAN NMAP -sS window 1024:** 137
- **2009582:** 137
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 41:** 68
- **2400040:** 68
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 42:** 64
- **2400041:** 64
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 62
- **2023753:** 62
- **ET INFO Reserved Internal IP Traffic:** 48
- **2002752:** 48
- **ET SCAN Suspicious inbound to PostgreSQL port 5432:** 28
- **2010939:** 28
- **ET VOIP Modified Sipvicious Asterisk PBX User-Agent:** 20
- **2012296:** 20
- **ET VOIP MultiTech SIP UDP Overflow:** 19
- **2003237:** 19
- **ET CINS Active Threat Intelligence Poor Reputation IP group 45:** 10
- **2403344:** 10

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 151
- **root/Qaz123qaz:** 33
- **root/3245gs5662d34:** 24
- **root/123@@@:** 21
- **botuser/a123456:** 19
- **dolphinscheduler/dolphinscheduler2025:** 18
- **ftpuser/ftpUser:** 17
- **user1/user1pass:** 17
- **ubuntu/1qaz@WSX:** 15
- **sftpuser/sftpuser@2025:** 14
- **qclinux/1234567890:** 13
- **bot/botpassword:** 12
- **postgres/Password1234:** 12
- **weblogic/3245gs5662d34:** 12
- **dolphinscheduler/111:** 11
- **admin1/1qaz2WSX:** 11
- **dmdba/123:** 10
- **bot/3245gs5662d34:** 9
- **newuser/newuser321:** 8
- **user1/Password123!:** 8

### Files Uploaded/Downloaded
- **arm.urbotnetisass;:** 3
- **arm.urbotnetisass:** 3
- **arm5.urbotnetisass;:** 3
- **arm5.urbotnetisass:** 3
- **arm6.urbotnetisass;:** 3
- **arm6.urbotnetisass:** 3
- **arm7.urbotnetisass;:** 3
- **arm7.urbotnetisass:** 3
- **x86_32.urbotnetisass;:** 3
- **x86_32.urbotnetisass:** 3
- **mips.urbotnetisass;:** 3
- **mips.urbotnetisass:** 3
- **mipsel.urbotnetisass;:** 3
- **mipsel.urbotnetisass:** 3
- **11:** 2
- **fonts.gstatic.com:** 2
- **css?family=Libre+Franklin...:** 2
- **ie8.css?ver=1.0:** 2
- **html5.js?ver=3.7.3:** 2
- **json:** 1

### HTTP User-Agents
- (No data)

### SSH Clients
- (No data)

### SSH Servers
- (No data)

### Top Attacker AS Organizations
- (No data)

## Key Observations and Anomalies

- A significant number of commands are focused on manipulating the `.ssh` directory, indicating a clear intent to establish persistent SSH access.
- The `urbotnetisass` malware was downloaded multiple times, targeting various architectures (ARM, x86, MIPS).
- The majority of login attempts use common or default credentials, highlighting the continued effectiveness of brute-force attacks.
- The high number of events on port 5060 suggests widespread scanning for vulnerable SIP services.
