Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T07:01:20Z
**Timeframe:** 2025-10-02T06:20:01Z to 2025-10-02T07:00:01Z
**Files Used:**
- agg_log_20251002T062001Z.json
- agg_log_20251002T064002Z.json
- agg_log_20251002T070001Z.json

**Executive Summary**

This report summarizes 22,161 malicious attacks recorded by honeypots within the specified timeframe. The most targeted services were Honeytrap, Cowrie, and Suricata. A significant portion of attacks originated from IP address 45.234.176.18. The most common attack vectors involved targeting port 25 and leveraging exploits related to DoublePulsar.

**Detailed Analysis**

***Attacks by Honeypot***

*   Honeytrap: 8246
*   Cowrie: 7045
*   Suricata: 2786
*   Mailoney: 2490
*   Ciscoasa: 951
*   Dionaea: 468
*   ElasticPot: 25
*   Sentrypeer: 29
*   Tanner: 29
*   Adbhoney: 23
*   H0neytr4p: 29
*   ConPot: 16
*   Honeyaml: 15
*   Wordpot: 3
*   Redishoneypot: 3
*   Dicompot: 3

***Top Attacking IPs***

*   45.234.176.18: 4566
*   103.220.207.174: 2030
*   176.65.141.117: 1640
*   182.8.97.216: 1548
*   106.75.131.128: 1226
*   86.54.42.238: 821
*   144.130.11.9: 372
*   167.99.49.89: 420
*   102.210.254.71: 325
*   92.63.197.55: 319

***Top Targeted Ports/Protocols***

*   25: 2490
*   TCP/445: 1544
*   22: 966
*   445: 391
*   8333: 81
*   9092: 57
*   9093: 57
*   5901: 56
*   TCP/1433: 38
*   80: 38

***Most Common CVEs***

*   CVE-2002-0013 CVE-2002-0012: 12
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
*   CVE-2021-3449 CVE-2021-3449: 7
*   CVE-2019-11500 CVE-2019-11500: 4
*   CVE-1999-0183: 3
*   CVE-2006-2369: 1

***Commands Attempted by Attackers***

*   uname -a: 44
*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 40
*   lockr -ia .ssh: 40
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 40
*   cat /proc/cpuinfo | grep name | wc -l: 40
*   top: 39
*   uname: 39
*   whoami: 39
*   lscpu | grep Model: 39
*   df -h | head -n 2 | awk '...': 39
*   free -m | grep Mem | awk '...': 39
*   ls -lh $(which ls): 39
*   which ls: 39
*   crontab -l: 39
*   w: 39
*   uname -m: 39
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 39
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '...': 39
*   Enter new UNIX password: : 23
*   Enter new UNIX password:: 17

***Signatures Triggered***

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1541
*   2024766: 1541
*   ET DROP Dshield Block Listed Source group 1: 318
*   2402000: 318
*   ET SCAN NMAP -sS window 1024: 159
*   2009582: 159
*   ET INFO Reserved Internal IP Traffic: 50
*   2002752: 50
*   ET SCAN Suspicious inbound to MSSQL port 1433: 35
*   2010935: 35
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43: 33
*   2403342: 33

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 38
*   root/3245gs5662d34: 14
*   root/LeitboGi0ro: 11
*   test/zhbjETuyMffoL8F: 10
*   root/nPSpP4PBW0: 11
*   root/2glehe5t24th1issZs: 10
*   foundry/foundry: 11
*   openstack/openstack123: 5
*   ubuntu/1qaz2WSX: 4

***Files Uploaded/Downloaded***

*   arm.urbotnetisass: 4
*   arm5.urbotnetisass: 4
*   arm6.urbotnetisass: 4
*   arm7.urbotnetisass: 4
*   x86_32.urbotnetisass: 4
*   mips.urbotnetisass: 4
*   mipsel.urbotnetisass: 4
*   wget.sh;: 4

***HTTP User-Agents***

*   No HTTP User-Agents were logged in this timeframe.

***SSH Clients***

*   No SSH clients were logged in this timeframe.

***SSH Servers***

*   No SSH servers were logged in this timeframe.

***Top Attacker AS Organizations***

*   No attacker AS organizations were logged in this timeframe.

**Key Observations and Anomalies**

*   A large number of attacks from 45.234.176.18, primarily targeting the Honeytrap honeypot.
*   The "DoublePulsar Backdoor" signature was triggered a significant number of times, indicating attempts to install this backdoor.
*   Attackers consistently attempted to modify the SSH authorized_keys file to gain persistent access.
*   Multiple download attempts of various `*.urbotnetisass` files suggest a coordinated campaign to install a botnet client on compromised devices.
*   Reconnaissance commands like `uname -a`, `lscpu`, and `whoami` are very common, indicating attackers are profiling the systems they compromise.
