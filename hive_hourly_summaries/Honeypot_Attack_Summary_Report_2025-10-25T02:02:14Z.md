Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T02:01:23Z
**Timeframe:** 2025-10-25T01:20:01Z to 2025-10-25T02:00:01Z
**Log Files:**
- agg_log_20251025T012001Z.json
- agg_log_20251025T014002Z.json
- agg_log_20251025T020001Z.json

### Executive Summary
This report summarizes 18,341 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Dionaea honeypots. The most prominent attack vector remains SMB scanning on port 445, primarily from the IP address 210.212.43.129. A significant number of SSH brute-force attempts and reconnaissance commands were also observed.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4847
- Honeytrap: 4307
- Dionaea: 3553
- Suricata: 3286
- Ciscoasa: 1815
- Sentrypeer: 199
- Mailoney: 191
- Miniprint: 46
- Tanner: 16
- Adbhoney: 17
- Dicompot: 18
- ElasticPot: 13
- Redishoneypot: 11
- ConPot: 11
- H0neytr4p: 9
- Medpot: 1
- Ipphoney: 1

**Top Attacking IPs:**
- 210.212.43.129: 3381
- 80.94.95.238: 1526
- 109.205.211.9: 799
- 188.166.126.51: 666
- 103.250.11.79: 308
- 156.246.91.141: 330
- 222.124.17.227: 288
- 165.154.14.28: 287
- 107.170.36.5: 254
- 196.251.71.24: 251
- 203.83.231.93: 269
- 156.232.11.142: 178
- 122.166.248.162: 178
- 103.211.217.182: 194
- 182.93.50.90: 104
- 182.93.7.194: 134
- 77.83.207.203: 111
- 107.150.104.184: 111
- 45.136.68.49: 87
- 68.183.149.135: 113
- 167.250.224.25: 133
- 117.3.142.50: 44
- 27.254.192.185: 140
- 175.12.108.55: 162
- 185.213.165.180: 188
- 8.154.2.217: 136
- 152.32.218.149: 97
- 196.251.116.93: 35
- 121.132.81.3: 35
- 2.57.121.112: 36

**Top Targeted Ports/Protocols:**
- 445: 3454
- 22: 728
- 5060: 199
- 25: 191
- 5903: 136
- 5901: 123
- 8333: 85
- TCP/22: 83
- 5905: 80
- 5904: 80
- 9100: 46
- 27017: 35
- TCP/1080: 37
- 5907: 52
- 5908: 51
- 5909: 50
- 5902: 43
- 3388: 19
- 2323: 22
- 23: 16

**Most Common CVEs:**
- CVE-2021-44228
- CVE-2019-11500
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2023-26801
- CVE-2009-2765
- CVE-2019-16920
- CVE-2023-31983
- CVE-2020-10987
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2023-47565
- CVE-2014-6271
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

**Commands Attempted by Attackers:**
- uname -a: 23
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 20
- lockr -ia .ssh: 20
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 20
- cat /proc/cpuinfo | grep name | wc -l: 20
- ls -lh $(which ls): 20
- which ls: 20
- crontab -l: 20
- w: 20
- uname -m: 20
- cat /proc/cpuinfo | grep model | grep name | wc -l: 20
- top: 20
- uname: 22
- whoami: 22
- lscpu | grep Model: 22
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 22
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 19
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 19
- Enter new UNIX password: : 17
- Enter new UNIX password:: 17

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1244
- 2023753: 1244
- ET DROP Dshield Block Listed Source group 1: 704
- 2402000: 704
- ET HUNTING RDP Authentication Bypass Attempt: 273
- 2034857: 273
- ET SCAN NMAP -sS window 1024: 182
- 2009582: 182
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Potential SSH Scan: 43
- 2001219: 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 26
- 2403347: 26
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 26
- 2403350: 26
- GPL INFO SOCKS Proxy attempt: 25
- 2100615: 25

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 19
- root/eladmin: 4
- root/elas240615: 4
- root/Elast1x: 4
- root/elastik79!: 4
- root/elastix: 4
- root/Elastix: 4
- admin/20051975: 3
- admin/20021979: 3
- admin/20011977: 3
- admin/1qwert: 3
- admin/1qay2wsx: 3
- user/hanna: 3
- user/gsxr750: 3
- user/goldwing: 3
- user/frisky: 3
- user/famous: 3
- user/aa123456~~: 3
- user/a985772159@: 3
- user/a13915417585: 3
- user/Zjzy_2023: 3
- user/Zjzy_2022: 3

**Files Uploaded/Downloaded:**
- wget.sh;: 4
- `busybox: 2
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 2
- rondo.qre.sh||busybox: 2
- rondo.qre.sh||curl: 2
- rondo.qre.sh)|sh: 2
- discovery: 2
- arm.uhavenobotsxd;: 1
- arm.uhavenobotsxd: 1
- arm5.uhavenobotsxd;: 1
- arm5.uhavenobotsxd: 1
- arm6.uhavenobotsxd;: 1
- arm6.uhavenobotsxd: 1
- arm7.uhavenobotsxd;: 1
- arm7.uhavenobotsxd: 1
- x86_32.uhavenobotsxd;: 1
- x86_32.uhavenobotsxd: 1
- mips.uhavenobotsxd;: 1
- mips.uhavenobotsxd: 1

**HTTP User-Agents:**
- None Observed

**SSH Clients:**
- None Observed

**SSH Servers:**
- None Observed

**Top Attacker AS Organizations:**
- None Observed

### Key Observations and Anomalies
- The IP address `210.212.43.129` was extremely active, focusing exclusively on SMB scanning (port 445), indicating a widespread automated campaign likely searching for vulnerabilities like EternalBlue.
- Attackers consistently attempt to add a specific SSH public key to the `authorized_keys` file. This suggests a coordinated effort to maintain persistent access to compromised machines.
- A variety of download attempts for ARM and x86 architecture malware were observed via `wget` and `curl`, indicating botnet propagation attempts targeting a wide range of IoT and server devices.
- The high volume of RDP-related alerts, specifically "ET HUNTING RDP Authentication Bypass Attempt" and "ET SCAN MS Terminal Server Traffic on Non-standard Port", points to significant interest in compromising Remote Desktop services.

This concludes the Honeypot Attack Summary Report. Further analysis will be conducted as more data becomes available.
