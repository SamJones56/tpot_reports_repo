Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T08:01:32Z
**Timeframe:** 2025-10-07T07:20:01Z to 2025-10-07T08:00:01Z
**Files Used:**
- agg_log_20251007T072001Z.json
- agg_log_20251007T074001Z.json
- agg_log_20251007T080001Z.json

### Executive Summary
This report summarizes 19,038 attacks recorded by honeypots between 07:20 and 08:00 UTC on October 7th, 2025. The majority of attacks were captured by the Cowrie honeypot. The most frequent attacks originated from IP address 41.33.199.217. The most targeted port was port 25 (SMTP).

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7629
- Honeytrap: 3634
- Suricata: 2319
- Mailoney: 1711
- Dionaea: 1103
- Ciscoasa: 1583
- Sentrypeer: 440
- H0neytr4p: 428
- ConPot: 26
- Tanner: 43
- Redishoneypot: 34
- Honeyaml: 21
- Adbhoney: 13
- ElasticPot: 12
- ssh-rsa: 10
- Miniprint: 11
- Ipphoney: 4
- Dicompot: 4
- Medpot: 2
- Heralding: 3

**Top Attacking IPs:**
- 41.33.199.217: 903
- 86.54.42.238: 821
- 176.65.141.117: 820
- 185.126.217.241: 633
- 46.101.124.247: 606
- 172.86.95.98: 419
- 91.237.163.112: 346
- 171.231.186.190: 321
- 171.231.187.136: 278
- 103.220.207.174: 276
- 185.227.152.155: 273
- 103.118.114.22: 233
- 160.25.226.106: 193
- 103.115.50.217: 193
- 184.168.29.142: 209
- 175.207.13.86: 177
- 124.225.158.200: 172
- 14.103.253.20: 160
- 51.178.143.200: 144
- 185.213.175.140: 144

**Top Targeted Ports/Protocols:**
- 25: 1711
- 22: 1161
- 445: 1005
- 5060: 440
- 443: 446
- TCP/8080: 334
- TCP/8443: 258
- TCP/443: 166
- 5903: 95
- TCP/22: 33
- 6379: 31
- 23: 38
- 8333: 48
- 80: 35
- TCP/80: 23
- TCP/1080: 47
- 5907: 32
- 5908: 32
- 5909: 33
- 2222: 46

**Most Common CVEs:**
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-1999-0265: 2
- CVE-2002-0953: 1
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2006-2369: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 36
- lockr -ia .ssh: 36
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 36
- Enter new UNIX password: : 35
- Enter new UNIX password:: 35
- cat /proc/cpuinfo | grep name | wc -l: 35
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 35
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 35
- ls -lh $(which ls): 35
- which ls: 35
- crontab -l: 35
- w: 35
- uname -m: 35
- cat /proc/cpuinfo | grep model | grep name | wc -l: 35
- top: 35
- uname: 35
- uname -a: 35
- whoami: 40
- lscpu | grep Model: 35
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 35

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 487
- 2402000: 487
- ET SCAN NMAP -sS window 1024: 150
- 2009582: 150
- ET INFO Incoming Basic Auth Base64 HTTP Password detected unencrypted: 132
- 2006402: 132
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 57
- 2023753: 57
- GPL INFO SOCKS Proxy attempt: 39
- 2100615: 39
- ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 93: 46
- 2522092: 46
- ET TOR Known Tor Exit Node Traffic group 93: 39
- 2520092: 39
- ET TOR Known Tor Exit Node Traffic group 92: 39
- 2520091: 39
- ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 92: 33
- 2522091: 33

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 32
- root/: 8
- gitlab-runner/gitlab@123: 4
- vpn/vpn12345: 4
- github/github123321: 4
- admin/System@1234: 3
- admin/12345608: 3
- admin/!Q2w3e4r!: 3
- admin/1234pepe: 3
- admin/abcd123456!@#$%^: 3
- ahmed/ahmed1: 3
- postgres/123: 3
- reza/Password123!: 3
- gitlab-runner/3245gs5662d34: 3
- ubuntu/3245gs5662d34: 5

**Files Uploaded/Downloaded:**
- config.all.php?x: 14
- config.all.php?: 13
- config.php?: 5
- cmd.txt: 5
- wget.sh;: 4

**HTTP User-Agents:**
- None Observed

**SSH Clients:**
- None Observed

**SSH Servers:**
- None Observed

**Top Attacker AS Organizations:**
- None Observed

### Key Observations and Anomalies
- A high volume of SMTP traffic was observed, primarily from two IP addresses: 86.54.42.238 and 176.65.141.117. This could indicate a large-scale spam or phishing campaign.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` was frequently used. This is a common technique to gain persistent access to a compromised machine by adding an SSH key to the authorized_keys file.
- The CVEs detected are relatively old, suggesting that attackers are still attempting to exploit legacy vulnerabilities.
- A number of PHP files were uploaded, suggesting attempts to install web shells or other backdoors on a web server.
