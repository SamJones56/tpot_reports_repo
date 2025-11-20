Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T07:01:35Z
**Timeframe of Analysis:** 2025-10-12T06:20:01Z to 2025-10-12T07:00:01Z
**Log Files Used:**
- agg_log_20251012T062001Z.json
- agg_log_20251012T064001Z.json
- agg_log_20251012T070001Z.json

### Executive Summary

This report summarizes 28,803 events collected from multiple honeypots. The majority of attacks were captured by the Dionaea honeypot. A significant volume of activity originated from the IP address 122.121.74.82, primarily targeting port 445 (SMB). Analysis of command execution reveals common reconnaissance and backdoor installation techniques, including attempts to add SSH keys to `authorized_keys`. Several CVEs were detected, and a number of network security signatures were triggered, with "ET DROP Dshield Block Listed Source group 1" being the most frequent.

### Detailed Analysis

**Attacks by Honeypot**
- Dionaea: 15,851
- Cowrie: 5,143
- Honeytrap: 2,908
- Ciscoasa: 1,750
- Suricata: 1,616
- Sentrypeer: 1,195
- Adbhoney: 55
- Mailoney: 106
- H0neytr4p: 59
- Tanner: 54
- ConPot: 29
- Honeyaml: 15
- Redishoneypot: 9
- Ipphoney: 4
- Heralding: 3
- Dicompot: 3
- ElasticPot: 2
- Wordpot: 1

**Top Attacking IPs**
- 122.121.74.82: 14,903
- 109.237.71.198: 1,246
- 95.170.68.246: 1,243
- 45.128.199.212: 829
- 43.229.78.35: 337
- 27.78.74.188: 167
- 103.172.205.27: 208
- 62.141.43.183: 311
- 109.195.108.173: 174
- 35.200.255.139: 155
- 211.201.163.70: 104
- 20.91.250.177: 98
- 42.51.41.137: 96
- 210.79.190.46: 88
- 185.213.165.211: 133
- 167.250.224.25: 73
- 161.132.68.222: 103
- 68.183.193.0: 97
- 107.170.36.5: 93
- 159.89.121.144: 64

**Top Targeted Ports/Protocols**
- 445: 14,947
- 5060: 1,195
- 22: 877
- TCP/21: 227
- 5903: 183
- 21: 116
- 25: 106
- 3306: 88
- 8333: 84
- 443: 59
- 5908: 80
- 5909: 80
- 5901: 69
- 23: 47
- 80: 55
- TCP/443: 17
- 5907: 47
- 27018: 34
- 10008: 21
- 10009: 21

**Most Common CVEs**
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2002-0013 CVE-2002-0012
- CVE-2016-20016 CVE-2016-20016
- CVE-1999-0183
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255

**Commands Attempted by Attackers**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 15
- `lockr -ia .ssh`: 15
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 15
- `cat /proc/cpuinfo | grep name | wc -l`: 12
- `which ls`: 12
- `ls -lh $(which ls)`: 12
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 12
- `crontab -l`: 12
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 12
- `w`: 12
- `uname -m`: 11
- `uname -a`: 11
- `whoami`: 11
- `top`: 11
- `uname`: 11
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 11
- `lscpu | grep Model`: 11
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 11
- `Enter new UNIX password: `: 7
- `Enter new UNIX password:`: 7

**Signatures Triggered**
- ET DROP Dshield Block Listed Source group 1: 443
- ET SCAN NMAP -sS window 1024: 146
- ET FTP FTP PWD command attempt without login: 113
- ET FTP FTP CWD command attempt without login: 112
- ET INFO Reserved Internal IP Traffic: 57
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 43
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 27
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 15
- ET SCAN Potential SSH Scan: 14

**Users / Login Attempts**
- cron/: 71
- 345gs5662d34/345gs5662d34: 14
- root/3245gs5662d34: 5
- admin/gzHKde9TDRW4g: 6
- root/Password123: 6
- nobody/password123: 6
- default/12345: 6
- debian/000000: 6
- ubnt/123654: 4
- centos/p@ssw0rd: 4
- admin/supervisor: 4
- root/tech: 4
- root/Samar: 4
- root/cust1admin: 4
- root/123456a: 4

**Files Uploaded/Downloaded**
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass

**HTTP User-Agents**
- No user agents recorded in this period.

**SSH Clients**
- No SSH clients recorded in this period.

**SSH Servers**
- No SSH servers recorded in this period.

**Top Attacker AS Organizations**
- No AS organizations recorded in this period.

### Key Observations and Anomalies
- The overwhelming concentration of attacks from a single IP (122.121.74.82) targeting a single port (445) suggests a coordinated, botnet-driven campaign likely exploiting SMB vulnerabilities.
- Attackers on the Cowrie honeypot are consistently attempting to modify the `.ssh/authorized_keys` file, indicating a clear goal of establishing persistent access.
- A file download attempt (`arm.urbotnetisass`, etc.) was observed, associated with the Urbotnet botnet, indicating attempts to install malware on compromised systems.
- The variety of credentials used in brute-force attempts spans default, weak, and previously breached passwords, highlighting standard attacker methodologies.