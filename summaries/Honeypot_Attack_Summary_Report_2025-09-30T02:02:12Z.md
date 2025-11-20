Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T02:01:48Z
**Timeframe:** 2025-09-30T01:20:02Z to 2025-09-30T02:00:01Z
**Files Used:**
- agg_log_20250930T012002Z.json
- agg_log_20250930T014001Z.json
- agg_log_20250930T020001Z.json

**Executive Summary**
This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 20,529 events were recorded, with Cowrie being the most frequently targeted honeypot. The most prominent attacker IP was 160.25.118.10, responsible for a significant portion of the attacks. A variety of CVEs were exploited, and numerous commands were attempted, primarily focusing on reconnaissance and establishing control.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 13,531
- Suricata: 3,031
- Honeytrap: 2,307
- Ciscoasa: 1,438
- Dionaea: 38
- Redishoneypot: 30
- ConPot: 27
- Tanner: 27
- Sentrypeer: 22
- Adbhoney: 21
- H0neytr4p: 18
- Mailoney: 17
- ElasticPot: 8
- Honeyaml: 8
- Dicompot: 3
- Heralding: 3

***Top Attacking IPs***
- 160.25.118.10: 8,000
- 129.212.189.55: 2,120
- 189.32.116.45: 1,380
- 45.169.200.254: 457
- 185.156.73.166: 373
- 185.156.73.167: 367
- 92.63.197.55: 358
- 197.211.55.20: 340
- 92.63.197.59: 338
- 179.40.112.10: 303
- 197.5.145.102: 284
- 185.255.91.39: 249
- 103.113.105.228: 176
- 34.132.83.158: 133
- 20.193.141.133: 103
- 172.245.163.134: 98
- 103.27.79.187: 93
- 167.172.189.176: 79
- 80.94.95.112: 68
- 211.253.31.30: 63
- 94.254.0.234: 63
- 14.241.254.5: 58
- 179.32.33.160: 58
- 3.131.215.38: 54
- 167.99.250.163: 54
- 185.216.117.150: 53
- 34.128.77.56: 53

***Top Targeted Ports/Protocols***
- 22: 2,440
- TCP/445: 1,375
- 8333: 105
- 23: 76
- TCP/22: 68
- 6443: 50
- 8888: 32
- UDP/161: 31
- UDP/5060: 30
- 6379: 24
- 80: 24
- 5060: 16

***Most Common CVEs***
- CVE-2002-0013 CVE-2002-0012: 17
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 12
- CVE-1999-0183: 6
- CVE-1999-0517: 3
- CVE-2005-4050: 2
- CVE-2001-0414: 1
- CVE-2006-2369: 1
- CVE-2024-12856 CVE-2024-12856 CVE-2024-12885: 1

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 28
- lockr -ia .ssh: 28
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 28
- cat /proc/cpuinfo | grep name | wc -l: 17
- uname -a: 17
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 16
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 16
- which ls: 16
- ls -lh $(which ls): 16
- crontab -l: 16
- w: 16
- uname -m: 16
- cat /proc/cpuinfo | grep model | grep name | wc -l: 16
- top: 16
- uname: 16
- whoami: 16
- lscpu | grep Model: 16
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 16
- Enter new UNIX password: : 6
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 7
- cd /data/local/tmp/; rm *; busybox wget ...: 3
- Enter new UNIX password:: 4

***Signatures Triggered***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,373
- 2024766: 1,373
- ET DROP Dshield Block Listed Source group 1: 468
- 2402000: 468
- ET SCAN NMAP -sS window 1024: 229
- 2009582: 229
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Potential SSH Scan: 53
- 2001219: 53
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 40
- 2403344: 40
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 20
- 2400031: 20
- GPL TELNET Bad Login: 20
- 2101251: 20

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 28
- root/nPSpP4PBW0: 9
- root/3245gs5662d34: 9
- superadmin/admin123: 7
- test/zhbjETuyMffoL8F: 5
- root/LeitboGi0ro: 5
- foundry/foundry: 4
- root/2glehe5t24th1issZs: 4
- hello/hello: 3
- lx/lx: 3
- root/server123: 3

***Files Uploaded/Downloaded***
- arm.urbotnetisass: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass: 3
- x86_32.urbotnetisass: 3
- 104.199.212.115:8088: 2
- apply.cgi: 2

**Key Observations and Anomalies**
- A high volume of activity was observed from the IP address 160.25.118.10, indicating a targeted or persistent attacker.
- The significant number of events on the Cowrie honeypot suggests a focus on SSH-based attacks.
- The commands executed by attackers are primarily for system reconnaissance, credential manipulation, and disabling security measures.
- The presence of the DoublePulsar backdoor signature indicates attempts to install sophisticated malware.
- The downloading of various `urbotnetisass` files suggests a campaign to infect devices with a botnet.
- A variety of CVEs are being exploited, with a focus on older, well-known vulnerabilities.
- There is a noticeable amount of scanning activity, particularly from Nmap, indicating reconnaissance phases of attacks.
- Login attempts use common and default credentials, highlighting the importance of strong password policies.
