
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T04:01:34Z
**Timeframe:** 2025-10-18T03:20:01Z to 2025-10-18T04:00:02Z
**Files Used:**
- agg_log_20251018T032001Z.json
- agg_log_20251018T034001Z.json
- agg_log_20251018T040002Z.json

## Executive Summary
This report summarizes 15,292 suspicious events captured by the honeypot network. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH-based threats. A significant portion of the attacks originated from the IP address 72.146.232.13, and port 22 (SSH) was the most targeted port. Attackers were observed attempting to add their SSH keys to the authorized_keys file, a common technique for maintaining persistent access. A number of CVEs were also scanned for, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 8907
- Honeytrap: 2757
- Suricata: 1667
- Ciscoasa: 1341
- Sentrypeer: 247
- Mailoney: 108
- Dionaea: 48
- H0neytr4p: 41
- ConPot: 43
- Tanner: 34
- Miniprint: 45
- Dicompot: 18
- Redishoneypot: 17
- ElasticPot: 4
- Adbhoney: 4
- Ipphoney: 4
- Heralding: 3
- Honeyaml: 3
- Wordpot: 1

### Top Attacking IPs
- 72.146.232.13: 885
- 210.236.249.126: 1249
- 157.92.145.135: 556
- 45.135.232.248: 321
- 172.190.89.127: 329
- 35.222.117.243: 291
- 162.214.92.14: 365
- 178.185.136.57: 261
- 103.189.235.93: 298
- 41.216.177.55: 267
- 182.75.216.74: 292
- 66.181.171.136: 285
- 81.30.162.18: 247
- 194.107.115.65: 229
- 105.27.148.94: 258
- 217.154.35.203: 218
- 103.164.76.22: 255
- 223.93.164.218: 194
- 223.247.33.150: 212
- 107.170.36.5: 165

### Top Targeted Ports/Protocols
- 22: 1438
- 1971: 235
- 5060: 247
- 5903: 223
- TCP/5900: 293
- 25: 108
- 5901: 114
- 5905: 73
- 5904: 71
- 8333: 66
- TCP/8080: 40
- TCP/22: 48
- 9100: 45
- 443: 22
- 6699: 21
- 1025: 22
- 5908: 49
- 5907: 49
- 5909: 34
- 3702: 18

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 11
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 10
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
- CVE-2024-3721 CVE-2024-3721: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2009-2765: 2
- CVE-2019-16920 CVE-2019-16920: 2
- CVE-2023-31983 CVE-2023-31983: 2
- CVE-2023-47565 CVE-2023-47565: 2
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051: 2
- CVE-2014-6271: 2
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2020-10987 CVE-2020-10987: 1
- CVE-2001-0414: 1
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 1
- CVE-2023-52163 CVE-2023-52163: 1
- CVE-2024-10914 CVE-2024-10914: 1
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
- CVE-2021-42013 CVE-2021-42013: 1
- CVE-2006-2369: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 42
- lockr -ia .ssh: 42
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 42
- cat /proc/cpuinfo | grep name | wc -l: 42
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 41
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 41
- ls -lh $(which ls): 41
- which ls: 41
- crontab -l: 41
- w: 41
- uname -m: 41
- cat /proc/cpuinfo | grep model | grep name | wc -l: 41
- top: 41
- uname: 41
- uname -a: 41
- whoami: 40
- lscpu | grep Model: 40
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 39
- Enter new UNIX password: : 27
- Enter new UNIX password:: 27

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 326
- 2402000: 326
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 216
- 2023753: 216
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 165
- 2400041: 165
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 130
- 2400040: 130
- ET SCAN NMAP -sS window 1024: 119
- 2009582: 119
- ET HUNTING RDP Authentication Bypass Attempt: 64
- 2034857: 64
- ET INFO Reserved Internal IP Traffic: 51
- 2002752: 51
- ET SCAN Potential SSH Scan: 40
- 2001219: 40
- ET INFO CURL User Agent: 26
- 2002824: 26
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 10
- 2403346: 10

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 37
- ftpuser/ftppassword: 16
- root/123@Robert: 15
- root/3245gs5662d34: 9
- ftpuser/3245gs5662d34: 8
- centos/3: 4
- debian/333333: 4
- blank/webmaster: 4
- nobody/qwerty1234: 4
- centos/centos2003: 4
- test/0000000: 4
- supervisor/supervisor2001: 4
- blank/777: 4
- nobody/88: 4
- unknown/123654: 4
- config/toor: 4
- root/1Sth1S4R3al: 3
- root/1T0On3: 3
- root/1qazxsw23edc: 5
- root/!QAZ2wsx: 3

### Files Uploaded/Downloaded
- 11: 17
- fonts.gstatic.com: 17
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 16
- ie8.css?ver=1.0: 16
- html5.js?ver=3.7.3: 16
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 4
- rondo.qre.sh||busybox: 4
- rondo.qre.sh||curl: 4
- rondo.qre.sh)|sh: 4
- 129.212.146.61: 4
- `busybox: 3
- rondo.dgx.sh||busybox: 3
- rondo.dgx.sh||curl: 3
- rondo.dgx.sh)|sh&: 3
- rondo.sbx.sh|sh&echo${IFS}: 2
- login_pic.asp: 2
- apply.cgi: 2
- rondo.tkg.sh|sh&echo: 2
- cfg_system_time.htm: 2
- ?format=json: 4

### HTTP User-Agents
- No user agents were logged in the provided data.

### SSH Clients
- No SSH clients were logged in the provided data.

### SSH Servers
- No SSH servers were logged in the provided data.

### Top Attacker AS Organizations
- No AS organizations were logged in the provided data.

## Key Observations and Anomalies
- The high number of attacks on the Cowrie honeypot, which emulates an SSH server, suggests a large amount of automated scanning for vulnerable SSH servers.
- The most common commands executed by attackers are related to reconnaissance (e.g., `uname -a`, `whoami`) and attempting to add a new SSH key to the `authorized_keys` file. This is a strong indicator of automated scripts attempting to create persistent backdoors.
- The wide range of CVEs being scanned for, even those with low counts, indicates that attackers are casting a wide net to find any potential vulnerability.
- There is a noticeable lack of data for HTTP User-Agents, SSH clients and servers, and attacker AS organizations. This might be a limitation of the current honeypot configuration or the nature of the attacks themselves.

