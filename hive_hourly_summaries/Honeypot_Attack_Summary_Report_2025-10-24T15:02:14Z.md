
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T15:01:42Z
**Timeframe:** 2025-10-24T14:20:01Z to 2025-10-24T15:00:01Z
**Files Used:**
- agg_log_20251024T142001Z.json
- agg_log_20251024T144002Z.json
- agg_log_20251024T150001Z.json

## Executive Summary
This report summarizes honeypot activity over the last three periods, totaling 29,452 events. The majority of attacks targeted the Dionaea honeypot. The most prominent attacking IP was 114.47.12.143, and the most targeted port was 445/TCP (SMB). A number of CVEs were detected, with attackers attempting various commands, primarily related to establishing SSH access and system reconnaissance.

## Detailed Analysis

### Attacks by Honeypot
- Dionaea: 12990
- Cowrie: 7932
- Suricata: 3427
- Honeytrap: 3188
- Ciscoasa: 1465
- Sentrypeer: 249
- Heralding: 65
- Tanner: 45
- Mailoney: 29
- Adbhoney: 19
- ConPot: 17
- H0neytr4p: 11
- Redishoneypot: 9
- Honeyaml: 3
- ssh-rsa: 2
- ElasticPot: 1

### Top Attacking IPs
- 114.47.12.143: 12590
- 45.78.193.108: 1244
- 109.205.211.9: 1832
- 80.94.95.238: 1241
- 143.198.201.181: 834
- 88.214.50.58: 305
- 1.52.49.141: 350
- 192.3.216.182: 311
- 42.200.78.78: 300
- 23.95.37.90: 258
- 23.94.26.58: 190
- 119.28.113.215: 181
- 181.188.159.138: 245
- 183.36.126.68: 161
- 20.255.62.58: 305
- 103.179.218.243: 316
- 123.58.212.64: 212
- 118.194.235.169: 247
- 167.172.130.181: 174
- 107.172.155.3: 199

### Top Targeted Ports/Protocols
- 445: 12943
- 22: 1110
- 5060: 249
- 5903: 103
- 5901: 88
- 8333: 66
- TCP/80: 66
- 5905: 60
- 5904: 60
- UDP/5060: 97
- vnc/5900: 65
- 80: 34
- 23: 21
- 4443: 21
- 25: 17
- 9042: 51
- 2068: 39
- TCP/22: 29
- 3306: 21

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-16920 CVE-2019-16920
- CVE-2021-35395 CVE-2021-35395
- CVE-2016-20017 CVE-2016-20017
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163 CVE-2023-52163
- CVE-2023-47565 CVE-2023-47565
- CVE-2023-31983 CVE-2023-31983
- CVE-2024-10914 CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051
- CVE-2024-3721 CVE-2024-3721
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2021-42013 CVE-2021-42013
- CVE-2016-6563

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 42
- lockr -ia .ssh: 42
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 42
- cat /proc/cpuinfo | grep name | wc -l: 40
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 40
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 40
- ls -lh $(which ls): 40
- which ls: 40
- crontab -l: 40
- w: 40
- uname -m: 40
- cat /proc/cpuinfo | grep model | grep name | wc -l: 40
- top: 40
- uname: 40
- uname -a: 41
- whoami: 39
- lscpu | grep Model: 38
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 38
- Enter new UNIX password: : 24
- Enter new UNIX password:: 24

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 1817
- 2023753: 1817
- ET HUNTING RDP Authentication Bypass Attempt: 624
- 2034857: 624
- ET DROP Dshield Block Listed Source group 1: 201
- 2402000: 201
- ET SCAN NMAP -sS window 1024: 142
- 2009582: 142
- ET SCAN Sipsak SIP scan: 94
- 2008598: 94
- ET INFO VNC Authentication Failure: 63
- 2002920: 63
- ET INFO Reserved Internal IP Traffic: 45
- 2002752: 45
- ET SCAN Potential SSH Scan: 25
- 2001219: 25
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 18
- 2400027: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 12
- 2403302: 12

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 39
- root/3245gs5662d34: 16
- root/dolT7355: 4
- root/Dnensrc1982: 4
- lixuan/lixuan123: 4
- root/DockElastix: 4
- root/asd123456789: 3
- root/123456sa: 3
- desktop/desktop123: 5
- nginx/123456789: 3
- prueba/123123: 3
- root/Password@2: 3
- root/1234qazwsx: 3
- logify/logify: 3
- root/DoF.2o12: 3
- support/$upp0rt: 3
- root/domehe67: 3

### Files Uploaded/Downloaded
- 104.199.212.115: 5
- 129.212.146.61: 5
- server.cgi?func=server02_main_submit&counter=...: 5
- rondo.dgx.sh||busybox: 6
- rondo.dgx.sh||curl: 6
- rondo.dgx.sh)|sh&: 6
- cfg_system_time.htm: 5
- system.html: 3
- rondo.tkg.sh|sh&echo: 4
- rondo.qre.sh||busybox: 4
- rondo.qre.sh||curl: 4
- rondo.qre.sh)|sh: 4
- `busybox: 2
- apply.cgi: 4
- rondo.sbx.sh|sh&echo${IFS}: 2
- login_pic.asp: 2
- Mozi.m: 2
- arm.urbotnetisass: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass: 1

### HTTP User-Agents
- No user agents recorded in this timeframe.

### SSH Clients and Servers
- No SSH clients or servers recorded in this timeframe.

### Top Attacker AS Organizations
- No attacker AS organizations recorded in this timeframe.

## Key Observations and Anomalies
- The vast majority of attacks are automated and opportunistic, focusing on common vulnerabilities and weak credentials.
- The IP address 114.47.12.143 was responsible for a significant portion of the total attack volume, indicating a potentially compromised machine or a dedicated attacker.
- The prevalence of commands related to SSH key manipulation suggests a common objective of gaining persistent access to compromised systems.
- A wide range of CVEs were targeted, but with low frequency, suggesting broad scanning activity rather than a targeted campaign.
- Several files related to the 'urbotnetisass' malware family were downloaded, indicating an attempt to install this specific malware on the honeypot.
