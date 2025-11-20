Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T13:01:30Z
**Timeframe:** 2025-10-17T12:20:01Z to 2025-10-17T13:00:01Z
**Log Files:** agg_log_20251017T122001Z.json, agg_log_20251017T124001Z.json, agg_log_20251017T130001Z.json

**Executive Summary**

This report summarizes 29,845 recorded events from three honeypot log files. The majority of attacks were captured by the Sentrypeer, Cowrie, and Honeytrap honeypots. The most frequent attacks were directed at port 5060 (SIP). The IP address 2.57.121.61 was the most active attacker. Several CVEs were targeted, and a number of commands were attempted by attackers, indicating attempts to gather system information and establish persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

*   Sentrypeer: 10137
*   Cowrie: 7618
*   Honeytrap: 6055
*   Suricata: 3338
*   Dionaea: 1217
*   Ciscoasa: 898
*   H0neytr4p: 51
*   Adbhoney: 44
*   Mailoney: 66
*   Tanner: 30
*   Redishoneypot: 40
*   Miniprint: 18
*   Honeyaml: 14
*   ElasticPot: 9
*   Dicompot: 8
*   Ipphoney: 2

***Top Attacking IPs***

*   2.57.121.61: 9697
*   77.83.240.70: 4427
*   183.203.206.150: 1317
*   41.113.1.181: 1112
*   51.89.1.87: 1090
*   72.146.232.13: 732
*   129.212.188.93: 669
*   61.79.116.66: 601
*   203.135.22.130: 600

***Top Targeted Ports/Protocols***

*   5060: 10437
*   TCP/445: 2419
*   22: 1345
*   445: 654
*   TCP/21: 146
*   443: 51

***Most Common CVEs***

*   CVE-2002-0013 CVE-2002-0012: 7
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1

***Commands Attempted by Attackers***

*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 27
*   lockr -ia .ssh: 27
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 26
*   cat /proc/cpuinfo | grep name | wc -l: 26
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 26
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 26
*   ls -lh $(which ls): 26
*   which ls: 26
*   crontab -l: 26
*   w: 26
*   uname -m: 25
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 25
*   top: 25
*   uname: 25
*   uname -a: 25
*   whoami: 25
*   lscpu | grep Model: 25
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 25
*   Enter new UNIX password: : 15
*   Enter new UNIX password:: 15

***Signatures Triggered***

*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 2415
*   2024766: 2415
*   ET DROP Dshield Block Listed Source group 1: 207
*   2402000: 207
*   ET SCAN NMAP -sS window 1024: 92
*   2009582: 92

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 24
*   root/123@Robert: 10
*   test/test: 6
*   guest/guest2007: 6
*   centos/22: 6
*   operator/1234567: 6
*   supervisor/supervisor2021: 6
*   ftpuser/ftppassword: 11
*   root/!Q2w3e4r: 4

***Files Uploaded/Downloaded***

*   Mozi.m: 4
*   json: 3

***HTTP User-Agents***

*   No user agents recorded in this period.

***SSH Clients and Servers***

*   No SSH clients or servers recorded in this period.

***Top Attacker AS Organizations***

*   No attacker AS organizations recorded in this period.

**Key Observations and Anomalies**

*   The high number of attacks on port 5060 suggests a focus on VoIP infrastructure.
*   The commands executed indicate a pattern of attackers attempting to enumerate system hardware and user activity.
*   The `DoublePulsar` signature indicates exploitation attempts related to the EternalBlue vulnerability.
*   The repeated attempts to modify the `.ssh/authorized_keys` file show a clear intent to establish persistent SSH access.
*   The "Mozi.m" file is associated with the Mozi botnet, which targets IoT devices.
