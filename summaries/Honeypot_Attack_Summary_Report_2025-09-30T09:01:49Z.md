Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T09:01:25Z
**Timeframe:** 2025-09-30T08:20:01Z to 2025-09-30T09:00:01Z
**Files Analyzed:**
- agg_log_20250930T082001Z.json
- agg_log_20250930T084001Z.json
- agg_log_20250930T090001Z.json

**Executive Summary**

This report summarizes 12,468 malicious events targeting our honeypot infrastructure over a 40-minute period. The most prominent attack vector was repeated attempts to exploit SMB vulnerabilities, with a significant amount of traffic from a single IP address (105.112.198.126). Additionally, a large number of SIP scans were observed from IP address 194.50.16.131. A variety of malware download attempts and credential stuffing attacks were also recorded.

**Detailed Analysis**

***Attacks by Honeypot***

- Sentrypeer: 1846
- Suricata: 3085
- Cowrie: 1925
- Honeytrap: 2703
- Mailoney: 864
- Ciscoasa: 1436
- Dionaea: 446
- Tanner: 35
- Redishoneypot: 30
- Adbhoney: 12
- H0neytr4p: 29
- ConPot: 21
- Honeyaml: 18
- ElasticPot: 9
- Dicompot: 6
- Miniprint: 2
- Ipphoney: 1

***Top Attacking IPs***

- 194.50.16.131: 1759
- 105.112.198.126: 1463
- 145.239.139.38: 962
- 86.54.42.238: 821
- 185.156.73.167: 363
- 185.156.73.166: 366
- 92.63.197.55: 352
- 92.63.197.59: 332
- 179.43.97.86: 263
- 171.102.83.142: 189
- 119.92.236.1: 103
- 5.141.80.212: 95
- 94.102.4.12: 79
- 130.83.245.115: 78
- 80.94.95.112: 63
- 3.131.215.38: 66
- 3.134.148.59: 63
- 129.13.189.204: 63
- 185.170.144.3: 56
- 222.140.130.115: 50

***Top Targeted Ports/Protocols***

- 5060: 1809
- 445: 297
- TCP/445: 1460
- 25: 864
- 22: 325
- 8333: 185
- 27017: 108
- 23: 45
- TCP/22: 44
- 1433: 23
- 6379: 30
- UDP/161: 31
- 80: 36
- 443: 25
- 5901: 25
- 8000: 29
- 8081: 15
- 8090: 8
- 1194: 8
- 4040: 12

***Most Common CVEs***

- CVE-2002-0013 CVE-2002-0012: 17
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 12
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2005-4050: 1
- CVE-1999-0183: 1
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 1
- CVE-2024-3721 CVE-2024-3721: 1

***Commands Attempted by Attackers***

- A variety of system enumeration commands such as `uname`, `lscpu`, `df`, `free`, `w`, `crontab -l`, and `top`.
- Attempts to download and execute malware from `94.154.35.154`, specifically the `urbotnetisass` malware.
- Attempts to modify SSH authorized_keys to add a malicious key.
- Attempts to change user passwords with `passwd`.

***Signatures Triggered***

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766)
- ET DROP Dshield Block Listed Source group 1 (2402000)
- ET SCAN NMAP -sS window 1024 (2009582)
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- ET INFO Reserved Internal IP Traffic (2002752)
- ET CINS Active Threat Intelligence Poor Reputation IP groups

***Users / Login Attempts***

A large number of brute-force login attempts were observed, with common usernames such as 'root', 'admin', 'user', 'dev', 'ubuntu', 'pi', 'osmc', and 'seekcy'.

***Files Uploaded/Downloaded***

- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

***HTTP User-Agents***

- No HTTP user agents were recorded in the logs.

***SSH Clients and Servers***

- No specific SSH client or server versions were recorded in the logs.

***Top Attacker AS Organizations***

- No attacker AS organizations were recorded in the logs.

**Key Observations and Anomalies**

- The overwhelming majority of attacks were automated scans and exploitation attempts, typical of botnet activity.
- The `urbotnetisass` malware download attempts indicate a coordinated campaign to compromise IoT devices and servers.
- The high number of SMB exploits and SIP scans suggests that these are currently the most targeted services.
- The variety of credentials used in brute-force attacks indicates that attackers are using common and default credential lists.
- There is a noticeable overlap in attacking IPs across the different honeypots, suggesting that attackers are not targeting specific services but are scanning entire IP ranges.
