## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10 07:00:01 UTC
**Timeframe:** 2025-10-10 06:20:01 UTC to 2025-10-10 07:00:01 UTC
**Files Used:**
- agg_log_20251010T062001Z.json
- agg_log_20251010T064001Z.json
- agg_log_20251010T070001Z.json

### Executive Summary

This report summarizes honeypot activity over the last hour, based on three log files. A total of 21,492 attacks were recorded. The most active honeypot was Cowrie, and the top attacking IP was 77.79.150.127. The most targeted port was 445/TCP (SMB). Several CVEs were observed, with the most common being related to older vulnerabilities. A significant number of shell commands were attempted, primarily focused on reconnaissance and establishing persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 8767
- Suricata: 3893
- Dionaea: 2993
- Honeytrap: 3480
- Ciscoasa: 1739
- Sentrypeer: 380
- Tanner: 64
- Mailoney: 46
- Miniprint: 45
- Redishoneypot: 22
- ConPot: 19
- H0neytr4p: 21
- ElasticPot: 4
- Adbhoney: 8
- Honeyaml: 9
- Wordpot: 2

**Top Attacking IPs:**
- 77.79.150.127: 2101
- 103.153.140.41: 1518
- 167.250.224.25: 1135
- 85.111.97.34: 1129
- 193.24.123.88: 615
- 88.214.50.58: 312
- 45.134.26.3: 301
- 103.131.192.3: 312
- 177.12.16.118: 291
- 88.210.63.16: 269

**Top Targeted Ports/Protocols:**
- 445: 2560
- TCP/445: 1513
- 22: 1422
- 1433: 380
- 5060: 380
- TCP/1433: 281
- 5903: 202
- 8333: 72
- 5908: 82
- 5909: 82

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 13
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 11
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
- CVE-2016-6563: 2
- CVE-2021-35394 CVE-2021-35394: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-1999-0517: 1
- CVE-2024-3721 CVE-2024-3721: 1

**Commands Attempted by Attackers:**
- Enter new UNIX password: : 31
- Enter new UNIX password:: 31
- cat /proc/cpuinfo | grep name | wc -l: 31
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 30
- lockr -ia .ssh: 30
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 30
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 30
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 30
- which ls: 30
- ls -lh $(which ls): 30

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1511
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 458
- ET DROP Dshield Block Listed Source group 1: 474
- ET SCAN Suspicious inbound to MSSQL port 1433: 277
- ET HUNTING RDP Authentication Bypass Attempt: 208
- ET SCAN NMAP -sS window 1024: 153

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 27
- sa/!QAZ2wsx: 10
- support/Support1234567: 6
- guest/p@ssword: 10
- operator/qwerty123456: 6
- support/951951: 6
- test/marketing: 6
- frappe/frappe!: 6
- vpn/P@ssw0rd123: 5

**Files Uploaded/Downloaded:**
- sh: 98
- Mozi.m: 4
- `cd: 4
- XMLSchema-instance: 4
- XMLSchema: 4
- ns#: 2
- ?format=json: 2
- hide.mpsl;: 1
- rdf-schema#: 1
- types#: 1
- core#: 1
- XMLSchema#: 1
- www.drupal.org): 1

**HTTP User-Agents:**
- No user agents were logged in this timeframe.

**SSH Clients and Servers:**
- No specific SSH clients or servers were logged in this timeframe.

**Top Attacker AS Organizations:**
- No attacker AS organizations were logged in this timeframe.

### Key Observations and Anomalies

- A large number of commands are focused on disabling SSH security and adding a new authorized key, indicating a clear intent to establish persistent access.
- The high number of "Enter new UNIX password: " commands suggests automated scripts attempting to change user passwords.
- The DoublePulsar backdoor signature was triggered a high number of times, suggesting an ongoing campaign leveraging this implant.
- The majority of CVEs exploited are relatively old, indicating that attackers are still finding success with legacy vulnerabilities.
- The lack of HTTP user agents, SSH clients/servers, and AS organization data might indicate a limitation in the current logging configuration or that the attacks are not leveraging services that would provide this information.
