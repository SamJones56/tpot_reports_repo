Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T07:01:35Z
**Timeframe:** 2025-10-18T06:20:02Z to 2025-10-18T07:00:01Z
**Files Used:**
- agg_log_20251018T062002Z.json
- agg_log_20251018T064001Z.json
- agg_log_20251018T070001Z.json

**Executive Summary**

This report summarizes 14,023 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and telnet-based brute-force and command-injection attacks. The most active attacking IP address was 72.146.232.13. Port 22 (SSH) was the most targeted port. Attackers were observed attempting to run system reconnaissance commands and download malicious payloads. A number of CVEs were detected, with the most frequent being related to older vulnerabilities.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 7250
- Honeytrap: 2713
- Suricata: 2067
- Ciscoasa: 1327
- Mailoney: 230
- Sentrypeer: 177
- Dionaea: 86
- H0neytr4p: 44
- ConPot: 23
- Tanner: 44
- ElasticPot: 23
- Redishoneypot: 18
- Adbhoney: 6
- Dicompot: 3
- Heralding: 3
- Honeyaml: 9

***Top Attacking IPs***
- 72.146.232.13: 918
- 88.214.50.58: 738
- 152.32.239.90: 435
- 9.223.176.221: 435
- 223.197.248.209: 435
- 150.5.169.138: 433
- 37.27.209.186: 366
- 185.149.112.248: 356
- 154.92.19.175: 351
- 85.209.134.43: 367
- 51.195.149.120: 264
- 88.210.63.16: 239
- 171.244.40.23: 350
- 103.115.56.3: 294
- 150.95.84.172: 209
- 107.170.36.5: 247
- 142.93.161.59: 179
- 118.26.36.195: 154
- 203.3.112.219: 150
- 176.65.141.119: 154

***Top Targeted Ports/Protocols***
- 22: 1124
- 5903: 224
- 25: 230
- 5060: 177
- 5901: 111
- 8333: 73
- TCP/5900: 98
- 1971: 78
- 5904: 76
- 5905: 76
- 443: 40
- 80: 34
- TCP/5432: 35
- 445: 26
- 3306: 20

***Most Common CVEs***
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2002-0013 CVE-2002-0012: 2
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2006-2369: 2
- CVE-2024-3721 CVE-2024-3721: 2
- CVE-2001-0414: 2
- CVE-2005-4050: 1
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2009-2765: 1
- CVE-2019-16920 CVE-2019-16920: 1
- CVE-2023-31983 CVE-2023-31983: 1
- CVE-2020-10987 CVE-2020-10987: 1
- CVE-2023-47565 CVE-2023-47565: 1
- CVE-2014-6271: 1
- CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2025-11488 CVE-2024-33112 CVE-2022-37056 CVE-2019-10891 CVE-2015-2051: 1

***Commands Attempted by Attackers***
- lscpu | grep Model: 41
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 41
- cat /proc/cpuinfo | grep name | wc -l: 40
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 40
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 40
- ls -lh $(which ls): 40
- which ls: 40
- crontab -l: 40
- w: 40
- uname -m: 40
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 39
- lockr -ia .ssh: 39
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 39
- Enter new UNIX password: : 29
- Enter new UNIX password:: 29

***Signatures Triggered***
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 601
- 2023753: 601
- ET DROP Dshield Block Listed Source group 1: 322
- 2402000: 322
- ET HUNTING RDP Authentication Bypass Attempt: 264
- 2034857: 264
- ET SCAN NMAP -sS window 1024: 125
- 2009582: 125
- ET INFO Reserved Internal IP Traffic: 49
- 2002752: 49
- ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 56
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41: 45

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 37
- root/123@Robert: 10
- root/3245gs5662d34: 10
- root/Qaz123qaz: 6
- ftpuser/ftppassword: 7
- support/support2025: 4
- centos/centos2000: 4
- test/test2019: 4
- mir/123: 3
- tiptop/tiptop123: 3

***Files Uploaded/Downloaded***
- 11: 14
- fonts.gstatic.com: 14
- css?family=Libre+Franklin...: 14
- ie8.css?ver=1.0: 14
- html5.js?ver=3.7.3: 14
- binary.sh: 10
- arm.urbotnetisass: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass: 3

***HTTP User-Agents***
- No HTTP User-Agents were recorded in this period.

***SSH Clients and Servers***
- No specific SSH client or server versions were recorded in this period.

***Top Attacker AS Organizations***
- No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**

- A significant amount of reconnaissance and automated exploitation attempts were observed, particularly targeting SSH services. The commands executed suggest attackers are profiling systems for potential inclusion in botnets or for cryptomining activities.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys` was widespread, indicating a common tactic to maintain persistent access to compromised systems.
- Multiple attempts to download and execute `urbotnetisass` malware targeting various architectures (ARM, x86, MIPS) were observed, originating from the IP `94.154.35.154`. This suggests a coordinated campaign to deploy a specific botnet.
- The presence of multiple CVEs indicates that attackers are still attempting to exploit a wide range of vulnerabilities, including very old ones.
- The Suricata signatures triggered are consistent with the observed attack traffic, with a high number of alerts for traffic from blocklisted IPs and scanning activity.
