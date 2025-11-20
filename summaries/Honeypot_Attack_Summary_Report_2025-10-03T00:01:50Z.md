
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T00:01:24Z
**Timeframe:** 2025-10-02T23:20:01Z to 2025-10-03T00:00:01Z
**Files Used:**
- agg_log_20251002T232001Z.json
- agg_log_20251002T234001Z.json
- agg_log_20251003T000001Z.json

## Executive Summary

This report summarizes 10,335 events collected from three honeypot log files over a 40-minute period. The majority of attacks were captured by the Cowrie, Ciscoasa, and Sentrypeer honeypots. The most targeted services were SIP (5060) and SSH (22). A significant number of attacks originated from IP address 23.175.48.211. Several CVEs were observed, with CVE-2022-27255 being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing unauthorized SSH access.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 3233
- Ciscoasa: 2694
- Sentrypeer: 1731
- Suricata: 1342
- Mailoney: 841
- Honeytrap: 229
- Heralding: 96
- Adbhoney: 34
- Dionaea: 69
- H0neytr4p: 25
- Tanner: 17
- Honeyaml: 8
- ConPot: 4
- Ipphoney: 5
- Redishoneypot: 6
- ElasticPot: 1

### Top Attacking IPs

- 23.175.48.211: 1243
- 176.65.141.117: 820
- 212.87.220.20: 520
- 185.156.73.166: 362
- 92.63.197.55: 351
- 92.63.197.59: 319
- 190.129.114.196: 307
- 51.178.43.161: 283
- 27.79.43.89: 230
- 27.79.7.177: 226
- 198.12.68.114: 262
- 34.140.24.231: 153
- 150.95.155.240: 159
- 103.4.92.103: 134
- 103.49.238.99: 129
- 46.105.87.113: 181
- 79.117.123.72: 108
- 146.190.99.104: 104
- 23.95.44.35: 102
- 101.36.119.50: 99

### Top Targeted Ports/Protocols

- 5060: 1731
- 25: 837
- 22: 505
- 4369: 100
- vnc/5900: 96
- UDP/5060: 149
- 23: 49
- TCP/22: 45
- TCP/1433: 22
- 443: 23
- 8000: 13
- 80: 21
- TCP/80: 15
- 1433: 14
- 81: 16
- 445: 15
- TCP/8080: 22

### Most Common CVEs

- CVE-2022-27255
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2023-26801
- CVE-2009-2765
- CVE-2019-16920
- CVE-2023-31983
- CVE-2020-10987
- CVE-2023-47565
- CVE-2015-2051
- CVE-2024-33112
- CVE-2022-37056
- CVE-2019-10891
- CVE-2014-6271

### Commands Attempted by Attackers

- pm path com.ufo.miner
- pm install /data/local/tmp/ufo.apk
- rm -f /data/local/tmp/ufo.apk
- am start -n com.ufo.miner/com.example.test.MainActivity
- ps | grep trinity
- rm -rf /data/local/tmp/*
- chmod 0755 /data/local/tmp/nohup
- chmod 0755 /data/local/tmp/trinity
- /data/local/tmp/nohup su -c /data/local/tmp/trinity
- /data/local/tmp/nohup /data/local/tmp/trinity
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- which ls
- ls -lh $(which ls)
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- crontab -l
- w
- echo -e "password\\n16hEIqI5ftNu\\n16hEIqI5ftNu"|passwd|bash
- echo "password\\n16hEIqI5ftNu\\n16hEIqI5ftNu\\n"|passwd

### Signatures Triggered

- ET DROP Dshield Block Listed Source group 1: 258
- ET SCAN NMAP -sS window 1024: 166
- ET INFO VNC Authentication Failure: 94
- ET SCAN Sipsak SIP scan: 100
- ET INFO Reserved Internal IP Traffic: 56
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 21
- ET SCAN Potential SSH Scan: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 29
- ET CINS Active Threat Intelligence Poor Reputation IP group 41: 30
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 20

### Users / Login Attempts

- root/admin3
- mysql/mysql
- test/zhbjETuyMffoL8F
- tomcat/tomcat
- developer/developer
- demo/demo
- root/111111
- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- ansible/test123
- seekcy/Joysuch@Locate2020
- admin/qwerfdsazxcv
- root/Aa112211.
- root/135790135790
- seekcy/Joysuch@Locate2023
- root/Admin123

### Files Uploaded/Downloaded

- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- server.cgi...
- `busybox`
- rondo.qre.sh||busybox
- rondo.qre.sh||curl
- rondo.qre.sh)|sh
- rondo.sbx.sh|sh&echo${IFS}
- login_pic.asp

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients and Servers
- No SSH clients or servers were logged in this timeframe.

### Top Attacker AS Organizations
- No AS organizations were logged in this timeframe.

## Key Observations and Anomalies

- The high volume of attacks from a single IP (23.175.48.211) suggests a targeted or automated campaign.
- The prevalence of commands related to modifying SSH authorized_keys indicates a focus on establishing persistent access.
- The variety of CVEs exploited, ranging from old to more recent vulnerabilities, highlights the opportunistic nature of the attackers.
- The commands related to "ufo.miner" suggest attempts to install cryptocurrency mining software on compromised devices.
- The "rondo.qre.sh" and "rondo.sbx.sh" download attempts appear to be part of a coordinated campaign to execute malicious scripts.
