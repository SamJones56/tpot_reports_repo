Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T05:01:30Z
**Timeframe:** 2025-10-08T04:20:01Z to 2025-10-08T05:00:01Z
**Files Used:**
- agg_log_20251008T042001Z.json
- agg_log_20251008T044001Z.json
- agg_log_20251008T050001Z.json

**Executive Summary**
This report summarizes 17,358 attacks recorded by honeypots over a 40-minute period. The most targeted honeypot was Cowrie, with 5,277 events. The most frequent attacker IP was 103.6.4.2, responsible for 3,793 events. The most targeted port was 445/TCP (SMB). Several CVEs were detected, and a number of commands were attempted by attackers, primarily related to modifying SSH authorized_keys.

**Detailed Analysis**

***Attacks by Honeypot:***
- Cowrie: 5277
- Dionaea: 4406
- Honeytrap: 2895
- Suricata: 2750
- Ciscoasa: 1666
- Heralding: 63
- Sentrypeer: 65
- Mailoney: 70
- Adbhoney: 43
- Redishoneypot: 30
- H0neytr4p: 29
- Tanner: 22
- ConPot: 15
- Honeyaml: 9
- ElasticPot: 6
- Miniprint: 10
- ssh-rsa: 2

***Top Attacking IPs:***
- 103.6.4.2: 3793
- 171.224.178.152: 1389
- 124.71.148.26: 538
- 5.141.26.114: 536
- 51.159.59.17: 490
- 81.192.46.45: 480
- 202.74.239.125: 376
- 103.174.115.5: 355
- 14.63.217.28: 238
- 165.227.174.138: 232
- 103.211.71.25: 229
- 221.225.83.45: 175
- 49.75.185.71: 183
- 103.254.172.165: 153
- 120.48.133.231: 152
- 179.27.96.190: 118
- 103.241.45.120: 109
- 171.244.142.175: 104
- 85.208.253.229: 115
- 31.58.87.45: 120
- 196.251.80.79: 72
- 68.183.207.213: 95
- 107.170.36.5: 97
- 3.149.59.26: 56
- 130.83.245.115: 55
- 103.159.199.42: 70

***Top Targeted Ports/Protocols:***
- 445: 4338
- TCP/445: 1385
- 22: 715
- 2053: 245
- 8333: 149
- vnc/5900: 63
- 5903: 95
- TCP/22: 64
- 23: 38
- 5060: 65
- 25: 70
- 443: 22
- 81: 20
- 8888: 9
- 6379: 15
- 10000: 21
- 9090: 20
- 5907: 49
- 5908: 50
- 5909: 48

***Most Common CVEs:***
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2024-3721

***Commands Attempted by Attackers:***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 32
- lockr -ia .ssh: 32
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 32
- cat /proc/cpuinfo | grep name | wc -l: 32
- Enter new UNIX password: : 31
- Enter new UNIX password::: 31
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 32
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 32
- ls -lh $(which ls): 32
- which ls: 32
- crontab -l: 32
- w: 32
- uname -m: 32
- cat /proc/cpuinfo | grep model | grep name | wc -l: 32
- top: 32
- uname: 32
- uname -a: 32
- whoami: 33
- lscpu | grep Model: 32
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 32
- chmod 0755 /data/local/tmp/nohup: 2
- chmod 0755 /data/local/tmp/trinity: 2
- chmod +x setup.sh; sh setup.sh; ...: 1

***Signatures Triggered:***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1382
- 2024766: 1382
- ET DROP Dshield Block Listed Source group 1: 379
- 2402000: 379
- ET SCAN NMAP -sS window 1024: 164
- 2009582: 164
- ET INFO VNC Authentication Failure: 62
- 2002920: 62
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET SCAN Potential SSH Scan: 38
- 2001219: 38
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 23
- 2403342: 23
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 19
- 2403347: 19
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 18
- 2403346: 18

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34: 31
- ubuntu/3245gs5662d34: 17
- supervisor/159753: 6
- admin/ubnt: 6
- Support/1q2w3e4r5t: 6
- centos/centos1234: 6
- root/admin01: 6
- sysadmin/sysadmin@1: 9
- ubuntu/admin123!@#: 3
- ubuntu/1qaz@WSX: 3
- ubuntu/ubuntu.2026: 3
- ubuntu/test2025: 3
- sysadmin/3245gs5662d34: 3
- ubuntu/Qwe123: 3
- ubuntu/ubuntu123123: 3
- root/root5: 6
- centos/centos4: 6
- ubuntu/Aa123123: 4
- default/marketing: 4
- user/123123123a: 4

***Files Uploaded/Downloaded:***
- discovery
- )
- soap-envelope
- soap-encoding
- addressing
- a:ReplyTo><a:To
- wsdl

***HTTP User-Agents:***
- None observed.

***SSH Clients:***
- None observed.

***SSH Servers:***
- None observed.

***Top Attacker AS Organizations:***
- None observed.

**Key Observations and Anomalies**
- A high volume of attacks on port 445 (SMB), with a significant number of events triggering the DoublePulsar backdoor signature.
- A large number of SSH login attempts with common and default credentials.
- Attackers consistently attempted to modify the `.ssh/authorized_keys` file to gain persistent access.
- A small number of files were uploaded/downloaded via the Dionaea honeypot, related to SOAP/WSDL protocols.

This concludes the Honeypot Attack Summary Report.