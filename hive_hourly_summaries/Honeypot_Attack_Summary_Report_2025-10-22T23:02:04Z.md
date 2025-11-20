**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-22T23:01:41Z
**Timeframe:** 2025-10-22T22:20:01Z to 2025-10-22T23:00:01Z
**Files Used:**
- agg_log_20251022T222001Z.json
- agg_log_20251022T224001Z.json
- agg_log_20251022T230001Z.json

**Executive Summary**

This report summarizes 14,904 attacks recorded across three log files. The most targeted honeypot was Cowrie, with a total of 4,594 events. The top attacking IP address was 143.198.201.181 with 1,253 attacks. The most targeted port was 5060, and the most common CVE observed was CVE-2021-3449. A variety of commands were attempted by attackers, with the most frequent being related to reconnaissance and establishing unauthorized SSH access.

**Detailed Analysis**

***Attacks by Honeypot***
* Cowrie: 4,594
* Honeytrap: 4,419
* Suricata: 1,777
* Ciscoasa: 1,798
* Sentrypeer: 1,044
* Dionaea: 815
* Tanner: 164
* H0neytr4p: 87
* Mailoney: 100
* Redishoneypot: 37
* ElasticPot: 13
* Honeyaml: 19
* ConPot: 12
* Dicompot: 10
* Adbhoney: 10
* Ipphoney: 4
* Miniprint: 1

***Top Attacking IPs***
* 143.198.201.181: 1,253
* 174.138.3.41: 549
* 125.235.231.74: 675
* 88.210.63.16: 293
* 185.243.5.146: 276
* 193.32.162.157: 263
* 107.170.36.5: 251
* 161.132.4.21: 179
* 174.114.170.17: 209
* 103.144.87.192: 169
* 122.160.46.61: 169
* 147.45.50.147: 139
* 103.179.27.93: 129
* 77.83.207.203: 137
* 185.243.5.137: 142
* 172.214.209.153: 145
* 185.243.5.152: 130
* 218.14.122.26: 93
* 79.110.49.8: 86
* 185.243.5.140: 99

***Top Targeted Ports/Protocols***
* 5060: 1,044
* 22: 802
* 445: 678
* 8333: 212
* 80: 159
* 1433: 89
* 5903: 137
* 5901: 122
* 443: 82
* 25: 100
* 5904: 79
* 5905: 77
* 2323: 52
* TCP/22: 62
* 5908: 52
* 5909: 34
* 5907: 32
* 8888: 31
* 6379: 37
* TCP/5432: 28

***Most Common CVEs***
* CVE-2021-3449 CVE-2021-3449: 6
* CVE-2019-11500 CVE-2019-11500: 5
* CVE-2002-0013 CVE-2002-0012: 2
* CVE-2024-3721 CVE-2024-3721: 2
* CVE-2002-1149: 2

***Commands Attempted by Attackers***
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 8
* cd ~; chattr -ia .ssh; lockr -ia .ssh: 8
* lockr -ia .ssh: 8
* uname -s -v -n -r -m: 4
* cat /proc/cpuinfo | grep name | wc -l: 8
* Enter new UNIX password: : 8
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 7
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 7
* ls -lh $(which ls): 7
* which ls: 7
* crontab -l: 7
* w: 7
* uname -m: 7
* cat /proc/cpuinfo | grep model | grep name | wc -l: 7
* top: 7
* uname: 7
* uname -a: 7
* whoami: 7
* lscpu | grep Model: 7
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 3
* rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...: 2

***Signatures Triggered***
* ET DROP Dshield Block Listed Source group 1: 366
* 2402000: 366
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 346
* 2023753: 346
* ET SCAN NMAP -sS window 1024: 179
* 2009582: 179
* ET HUNTING RDP Authentication Bypass Attempt: 146
* 2034857: 146
* ET INFO Reserved Internal IP Traffic: 62
* 2002752: 62
* ET SCAN Potential SSH Scan: 40
* 2001219: 40

***Users / Login Attempts***
* 345gs5662d34/345gs5662d34: 7
* root/c4m3tr4123: 4
* root/C4n3t4Pr3t4: 4
* user/user: 3
* postgres/adminadmin: 3
* test/test123: 3
* root/c3p15d4: 3
* root/1qaz2WSX: 3
* root/c4bl3c4bl3: 3
* admin/admin123: 2
* ram/ram: 2
* weblogic/weblogic: 2
* test/1234qwer: 2
* root/Qq123123: 2
* root/110120: 2
* root/p@$$W0rd: 2
* centos/1q2w3e4r5t: 2
* sonar/sonar123: 2
* steam/steam: 2
* mysql/mysql123: 2
* gpadmin/gpadmin: 2
* user/123: 2
* root/qwerty123: 2
* root/: 2
* root/123456789: 2
* root/rootroot: 2
* es/es123: 2
* sugi/sugi: 2
* root/abc: 2
* root/8: 2
* root/Admin123$: 2
* denny/denny: 2
* root/0: 2
* root/admin654321: 2

***Files Uploaded/Downloaded***
* css?family=Libre+Franklin...: 21
* ie8.css?ver=1.0: 21
* html5.js?ver=3.7.3: 21
* 11: 18
* fonts.gstatic.com: 18
* wget.sh;: 8
* w.sh;: 2
* c.sh;: 2
* soap-envelope: 1
* addressing: 1
* discovery: 1
* devprof: 1
* soap:Envelope>: 1

***HTTP User-Agents***
* No HTTP User-Agents were logged in this timeframe.

***SSH Clients and Servers***
* No SSH clients or servers were logged in this timeframe.

***Top Attacker AS Organizations***
* No attacker AS organizations were logged in this timeframe.

**Key Observations and Anomalies**

- A significant number of commands were executed to gather system information (uname, lscpu, free).
- Several attempts were made to download and execute shell scripts (w.sh, c.sh, wget.sh) from the IP address 213.209.143.62.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, indicating a common tactic to install a persistent SSH key for unauthorized access.
- Multiple CVEs were targeted, with a focus on older vulnerabilities.
- There is a high volume of traffic on port 5060, which is commonly used for SIP and VoIP services. This could indicate reconnaissance or attempts to exploit vulnerabilities in these services.
