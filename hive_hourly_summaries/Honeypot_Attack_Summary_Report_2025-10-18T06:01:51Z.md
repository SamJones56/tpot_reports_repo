# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T06:01:24Z
**Timeframe:** 2025-10-18T05:20:01Z to 2025-10-18T06:00:01Z
**Files:** agg_log_20251018T052001Z.json, agg_log_20251018T054001Z.json, agg_log_20251018T060001Z.json

## Executive Summary

This report summarizes 11,159 attacks recorded by honeypots. The majority of attacks were captured by the Cowrie honeypot. The most targeted port was 22/TCP (SSH). The top attacking IP address was 221.121.100.32. A number of CVEs were detected, with the most frequent being CVE-2002-0013, CVE-2002-0012, and CVE-2024-3721. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
* Cowrie: 4147
* Honeytrap: 2703
* Suricata: 1592
* Dionaea: 877
* Ciscoasa: 1376
* Sentrypeer: 184
* ConPot: 78
* Tanner: 43
* Mailoney: 58
* H0neytr4p: 26
* Miniprint: 28
* Adbhoney: 19
* ElasticPot: 7
* Redishoneypot: 10
* Ipphoney: 2
* Honeyaml: 6
* Dicompot: 3

### Top 10 Attacking IPs
* 221.121.100.32: 817
* 72.146.232.13: 912
* 103.115.56.3: 602
* 88.210.63.16: 349
* 34.96.180.174: 227
* 202.165.15.132: 229
* 107.170.36.5: 246
* 155.4.244.107: 198
* 24.189.75.180: 167
* 150.95.84.172: 153

### Top 10 Targeted Ports/Protocols
* 445: 832
* 22: 781
* 5903: 221
* 5060: 184
* 5901: 111
* TCP/5900: 192
* 8333: 77
* 80: 41
* 1025: 58
* 25: 58

### Most Common CVEs
* CVE-2002-0013 CVE-2002-0012
* CVE-2001-0414
* CVE-2024-3721 CVE-2024-3721
* CVE-2023-26801 CVE-2023-26801
* CVE-2009-2765
* CVE-2019-16920 CVE-2019-16920
* CVE-2023-31983 CVE-2023-31983
* CVE-2020-10987 CVE-2020-10987
* CVE-2023-47565 CVE-2023-47565
* CVE-2014-6271
* CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051
* CVE-2021-35394 CVE-2021-35394
* CVE-2005-4050
* CVE-2019-11500 CVE-2019-11500

### Top 10 Commands Attempted by Attackers
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
* cat /proc/cpuinfo | grep name | wc -l
* Enter new UNIX password: 
* Enter new UNIX password:
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
* ls -lh $(which ls)
* which ls

### Top 10 Signatures Triggered
* ET DROP Dshield Block Listed Source group 1
* 2402000
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* 2023753
* ET SCAN NMAP -sS window 1024
* 2009582
* ET HUNTING RDP Authentication Bypass Attempt
* 2034857
* ET INFO Reserved Internal IP Traffic
* 2002752
* ET DROP Spamhaus DROP Listed Traffic Inbound group 42
* 2400041
* ET DROP Spamhaus DROP Listed Traffic Inbound group 41
* 2400040

### Top 10 Users / Login Attempts
* 345gs5662d34/345gs5662d34
* nobody/4
* admin/admin2018
* nobody/0
* root/2014.unicob.2014
* root/2014elcdM!!
* admin/22
* unknown/666666
* guest/guest2016
* root/Qaz123qaz

### Files Uploaded/Downloaded
* 11
* fonts.gstatic.com
* css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
* ie8.css?ver=1.0
* html5.js?ver=3.7.3
* server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=
* rondo.qre.sh||busybox
* rondo.qre.sh||curl
* rondo.qre.sh)|sh
* `busybox
* wget.sh;
* ohshit.sh;
* w.sh;
* c.sh;

### HTTP User-Agents
* No HTTP User-Agents were logged in this timeframe.

### SSH Clients
* No SSH clients were logged in this timeframe.

### SSH Servers
* No SSH servers were logged in this timeframe.

### Top Attacker AS Organizations
* No attacker AS organizations were logged in this timeframe.

## Key Observations and Anomalies

* A significant number of commands are related to establishing persistent SSH access by adding a public key to the `authorized_keys` file.
* There is a mix of automated scanning activity (NMAP, MS Terminal Server scans) and more targeted attacks.
* The presence of commands like `cat /proc/cpuinfo` and `uname -a` suggests attackers are performing reconnaissance to understand the system they have compromised.
* Multiple download attempts for shell scripts (`wget.sh`, `ohshit.sh`, `w.sh`, `c.sh`) from the same IP address (213.209.143.167) were observed.
* The high number of attacks on port 445 suggests continued attempts to exploit SMB vulnerabilities.

This concludes the Honeypot Attack Summary Report.
