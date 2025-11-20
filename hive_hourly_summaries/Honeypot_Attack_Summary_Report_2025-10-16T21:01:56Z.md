Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T21:01:30Z
**Timeframe:** 2025-10-16T20:20:01Z to 2025-10-16T21:00:01Z
**Files Analyzed:**
- agg_log_20251016T202001Z.json
- agg_log_20251016T204001Z.json
- agg_log_20251016T210001Z.json

**Executive Summary:**

This report summarizes the activity recorded by the T-Pot honeypot network over a 40-minute period. A total of 21,748 events were observed across various honeypots. The most targeted services were SMB (port 445), SIP (port 5060), and SSH (port 22). The majority of attacks originated from the IP address 171.102.83.142. Several CVEs were targeted, with CVE-2022-27255 being the most prominent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis:**

***Attacks by Honeypot:***
- Cowrie: 6982
- Dionaea: 4198
- Honeytrap: 3148
- Mailoney: 1606
- Sentrypeer: 2071
- Suricata: 1740
- Ciscoasa: 1609
- Tanner: 234
- H0neytr4p: 114
- ConPot: 17
- Redishoneypot: 15
- Adbhoney: 3
- Dicompot: 3
- Honeyaml: 6
- Heralding: 1
- ElasticPot: 1

***Top Attacking IPs:***
- 171.102.83.142: 4126
- 134.199.201.143: 1001
- 134.199.202.158: 902
- 176.65.141.119: 821
- 86.54.42.238: 764
- 35.199.82.7: 677
- 198.23.190.58: 652
- 172.86.95.115: 516
- 172.86.95.98: 496
- 185.243.5.158: 450
- 156.236.31.46: 339
- 144.124.225.5: 300
- 164.177.31.66: 272
- 107.170.36.5: 253
- 101.36.110.41: 241
- 103.146.52.252: 217
- 103.217.144.113: 178
- 103.171.85.219: 176
- 147.50.227.79: 226
- 103.31.39.143: 211
- 107.174.81.30: 178

***Top Targeted Ports/Protocols:***
- 445: 4139
- 5060: 2071
- 22: 1088
- 25: 1612
- 80: 238
- UDP/5060: 271
- 5903: 227
- 8333: 209
- 443: 104
- 5901: 115
- 23: 33
- 5905: 78
- 5904: 78
- 5909: 49
- 5908: 50
- 5907: 50
- TCP/22: 51
- 5902: 42

***Most Common CVEs:***
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-11500
- CVE-2006-2369
- CVE-1999-0517
- CVE-2021-3449
- CVE-2016-20016
- CVE-2001-0414

***Commands Attempted by Attackers:***
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
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- /ip cloud print
- uname -s -v -n -r -m

***Signatures Triggered:***
- ET DROP Dshield Block Listed Source group 1
- ET SCAN Sipsak SIP scan
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET INFO Reserved Internal IP Traffic
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- ET SCAN Potential SSH Scan
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 48
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET Cins Active Threat Intelligence Poor Reputation IP group 47

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- supervisor/supervisor777
- config/8888888
- root/123@@@
- test/test2011
- support/support2004
- test/test00
- root/!97176124Me
- debian/1234
- root/Qaz123qaz
- guest/guest2001
- debian/dietpi
- root/!cl0ud
- root/!cl0ud2013
- root/!Elastix13
- root/adminHW
- user/Zmcc!@#sdjf.com
- user/Yaoju20210322
- user/Yanchang@2022@Ysyhl9T

***Files Uploaded/Downloaded:***
- Mozi.m%20dlink.mips%27$
- ns#
- rdf-schema#
- types#
- core#
- XMLSchema#
- www.drupal.org)

***HTTP User-Agents:***
- None observed

***SSH Clients:***
- None observed

***SSH Servers:***
- None observed

***Top Attacker AS Organizations:***
- None observed

**Key Observations and Anomalies:**

- The IP address 171.102.83.142 was responsible for a significant portion of the observed attacks, indicating a targeted campaign from this source.
- The high number of attempts to exploit CVE-2022-27255, a vulnerability in Realtek eCos RSDK, suggests that devices using this SDK are being actively targeted.
- The commands executed by attackers are consistent with attempts to gather system information, establish persistence via SSH authorized_keys, and remove traces of their activity.
- The presence of the "Mozi" malware indicates activity from a known botnet.
- A wide variety of credentials were used in brute-force attempts, highlighting the importance of strong, unique passwords.

This report provides a snapshot of the threat landscape as observed by the honeypot network. Continuous monitoring is recommended to identify emerging threats and attack patterns.
