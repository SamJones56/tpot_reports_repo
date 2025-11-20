# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T20:01:31Z
**Timeframe:** 2025-10-11T19:20:02Z to 2025-10-11T20:00:01Z
**Files Used:**
- agg_log_20251011T192002Z.json
- agg_log_20251011T194001Z.json
- agg_log_20251011T200001Z.json

## Executive Summary
This report summarizes 16,603 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Honeytrap, Suricata, and Ciscoasa. The most prominent attack vector observed was related to SSH, with a high volume of login attempts and command executions. A significant amount of activity was also observed on TCP/445, likely targeting SMB vulnerabilities. The most active attacking IP was 185.144.27.63, which was responsible for a large portion of the SSH-based attacks.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 8189
- Honeytrap: 3131
- Suricata: 2954
- Ciscoasa: 1826
- Sentrypeer: 152
- Redishoneypot: 68
- Dionaea: 79
- Adbhoney: 43
- Tanner: 47
- H0neytr4p: 21
- Ipphoney: 18
- Miniprint: 17
- Mailoney: 22
- ConPot: 11
- Honeyaml: 13
- Dicompot: 7
- ElasticPot: 3
- ssh-rsa: 2

### Top Attacking IPs
- 185.144.27.63: 3960
- 71.187.237.137: 1320
- 152.32.172.117: 356
- 103.23.199.49: 301
- 13.233.157.85: 261
- 107.175.70.59: 218
- 223.197.248.209: 203
- 182.18.139.237: 203
- 91.98.20.225: 149
- 208.115.196.124: 139
- 152.32.203.205: 128
- 34.128.77.56: 124
- 167.172.111.7: 119
- 103.154.87.242: 114
- 195.190.104.66: 109
- 41.59.229.33: 109
- 68.183.193.0: 100
- 107.170.36.5: 96
- 213.32.245.214: 99
- 159.89.121.144: 93

### Top Targeted Ports/Protocols
- 22: 1309
- TCP/445: 1348
- 1235: 234
- 5903: 189
- 5060: 152
- TCP/5900: 275
- 6379: 68
- 8333: 86
- 5908: 83
- 5909: 83
- 5901: 74
- 23: 48
- TCP/22: 56
- 9001: 38
- 80: 36
- 27018: 34
- 5907: 48
- 443: 15
- UDP/161: 39
- TCP/5432: 20

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 25
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 17
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2005-4050: 1
- CVE-2022-27255 CVE-2022-27255: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 28
- lockr -ia .ssh: 28
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 28
- cat /proc/cpuinfo | grep name | wc -l: 27
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 27
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 27
- ls -lh $(which ls): 27
- which ls: 27
- crontab -l: 27
- w: 27
- uname -m: 27
- cat /proc/cpuinfo | grep model | grep name | wc -l: 27
- top: 27
- uname: 27
- uname -a: 27
- whoami: 27
- lscpu | grep Model: 27
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 27
- Enter new UNIX password: : 22
- Enter new UNIX password: 22

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1313
- 2024766: 1313
- ET DROP Dshield Block Listed Source group 1: 399
- 2402000: 399
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 180
- 2400041: 180
- ET SCAN NMAP -sS window 1024: 157
- 2009582: 157
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 98
- 2400040: 98
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 67
- 2023753: 67
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 26
- 2403344: 26
- ET SCAN Potential SSH Scan: 22
- 2001219: 22
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 19
- 2010939: 19

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 26
- root/3245gs5662d34: 4
- admin/A1b2c3d4: 6
- admin/1qazXSW@: 6
- admin/8888888888: 5
- ftpuser/test: 6
- va/va: 4
- root/!QAZ1qaz1qaz: 4
- tester/1: 4
- tester/3245gs5662d34: 4
- Admin/Passw0rd: 4
- root/root123..: 4
- test/test1234: 4
- admin/t1l2cm3r: 4
- admin/1q2w3e4r!: 4
- unknown/unknown1: 4
- test/test3: 4
- luka/luka123: 3
- root/Qazwsx123456: 3
- root/modernac0m9000: 3

### Files Uploaded/Downloaded
- ns#: 2
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1
- rdf-schema#: 1
- types#: 1
- core#: 1
- XMLSchema#: 1
- www.drupal.org): 1

### HTTP User-Agents
- No HTTP User-Agents were logged in this period.

### SSH Clients and Servers
- No specific SSH clients or servers were logged in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were logged in this period.

## Key Observations and Anomalies
- The high volume of traffic on port 22 and the commands executed suggest a coordinated botnet campaign focused on compromising devices via SSH.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys ...` indicates that attackers are attempting to install their own SSH keys for persistent access.
- The presence of the "DoublePulsar" signature indicates attacks leveraging exploits associated with the Equation Group.
- The file downloads of `*.urbotnetisass` suggest an attempt to install the Urbotnet malware.
- The variety of credentials used in login attempts suggests that attackers are using common default and weak passwords.
- The lack of HTTP user agents, specific SSH clients, and AS organization data might indicate that the logging level for these fields is not sufficient or that the attackers are using non-standard tools.
