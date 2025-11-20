**Honeypot Attack Summary Report**

*   **Report Generation Time**: 2025-10-07T20:01:40Z
*   **Timeframe**: 2025-10-07T19:20:01Z to 2025-10-07T20:00:02Z
*   **Files**: `agg_log_20251007T192001Z.json`, `agg_log_20251007T194001Z.json`, `agg_log_20251007T200002Z.json`

**Executive Summary**

This report summarizes 21,059 attacks recorded over a period of approximately 40 minutes. The most prominent attack vector was SIP scanning, targeting port 5060, primarily originating from the IP address `2.57.121.61`. The `Sentrypeer` honeypot recorded the highest number of events. A significant number of login attempts were observed by the `Cowrie` honeypot, with a variety of usernames and passwords. The most frequently observed CVE was `CVE-2021-44228` (Log4Shell).

**Detailed Analysis**

*   **Attacks by Honeypot**:
    *   Sentrypeer: 8303
    *   Cowrie: 4081
    *   Honeytrap: 2324
    *   Dionaea: 1999
    *   Mailoney: 1685
    *   Ciscoasa: 1280
    *   Suricata: 1186
    *   Redishoneypot: 48
    *   Tanner: 24
    *   ConPot: 28
    *   ElasticPot: 26
    *   H0neytr4p: 31
    *   Miniprint: 18
    *   Adbhoney: 11
    *   Honeyaml: 12
    *   Dicompot: 2
    *   Ipphoney: 1

*   **Top Attacking IPs**:
    *   2.57.121.61: 7501
    *   83.219.7.170: 1951
    *   170.64.161.21: 1404
    *   118.194.230.211: 1015
    *   86.54.42.238: 821
    *   176.65.141.117: 820
    *   138.197.43.50: 790
    *   185.255.126.223: 496
    *   23.94.26.58: 237
    *   85.31.230.43: 132
    *   187.33.59.116: 107
    *   38.47.94.38: 89
    *   198.23.190.58: 71
    *   107.170.36.5: 85
    *   68.183.207.213: 81

*   **Top Targeted Ports/Protocols**:
    *   5060: 8303
    *   445: 1955
    *   25: 1685
    *   22: 778
    *   3388: 131
    *   5910: 132
    *   8333: 89
    *   6379: 48
    *   5903: 82
    *   TCP/22: 44
    *   9200: 26

*   **Most Common CVEs**:
    *   CVE-2021-44228: 25
    *   CVE-2002-0013 CVE-2002-0012: 4
    *   CVE-2019-11500 CVE-2019-11500: 2
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2

*   **Commands Attempted by Attackers**:
    *   uname -s -v -n -r -m: 4
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh: 2
    *   lockr -ia .ssh: 2
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 2
    *   cat /proc/cpuinfo | grep name | wc -l: 2
    *   echo ... | passwd | bash: 2
    *   Enter new UNIX password: : 2
    *   Enter new UNIX password:: 2
    *   echo ... | passwd: 2
    *   cat /proc/cpuinfo | grep name | head -n 1 | awk ...: 2
    *   crontab -l: 2
    *   w: 2
    *   uname -m: 2
    *   cat /proc/cpuinfo | grep model | grep name | wc -l: 2
    *   top: 2
    *   uname: 2
    *   uname -a: 2
    *   free -m | grep Mem | awk ...: 1
    *   ls -lh $(which ls): 1
    *   which ls: 1
    *   whoami: 1
    *   lscpu | grep Model: 1
    *   df -h | head -n 2 | awk ...: 1

*   **Signatures Triggered**:
    *   ET DROP Dshield Block Listed Source group 1: 348
    *   2402000: 348
    *   ET SCAN NMAP -sS window 1024: 140
    *   2009582: 140
    *   ET INFO Reserved Internal IP Traffic: 48
    *   2002752: 48
    *   ET SCAN Potential SSH Scan: 35
    *   2001219: 35
    *   ET SCAN Sipsak SIP scan: 35
    *   2008598: 35
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 34
    *   2023753: 34
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 47: 22
    *   2403346: 22
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 42: 14
    *   2403341: 14
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 45: 14
    *   2403344: 14
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 46: 17
    *   2403345: 17
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 14
    *   2400031: 14

*   **Users / Login Attempts**:
    *   admin/Admin123: 6
    *   admin/adminadmin: 6
    *   osmanatmc/Acamtanamso1: 6
    *   ubnt/1234: 6
    *   user/user: 5
    *   admin/abcd1234: 4
    *   vpn/vpn12: 4
    *   telecomadmin/admintelecom: 4
    *   root/abcd1234: 4
    *   root/112233: 4
    *   ubnt/ubnt1: 4
    *   config/config: 4
    *   admin/admin1: 4
    *   esuser/esuser: 3
    *   sysadmin/sysadmin@1: 3
    *   user/1: 3
    *   ftpuser/abc123: 3
    *   admin/admin123: 3
    *   root/Passw0rd: 3
    *   vagrant/vagrant: 3
    *   deploy/deploy123: 3
    *   root/toor: 3
    *   root/root@123: 3

*   **Files Uploaded/Downloaded**:
    *   Mozi.m: 4

*   **HTTP User-Agents**:
    *   *None observed*

*   **SSH Clients**:
    *   *None observed*

*   **SSH Servers**:
    *   *None observed*

*   **Top Attacker AS Organizations**:
    *   *None observed*

**Key Observations and Anomalies**

*   The overwhelming majority of traffic was directed at port 5060 (SIP), with a single IP (`2.57.121.61`) responsible for over a third of all recorded events. This indicates a large-scale, automated scanning campaign targeting VoIP services.
*   The `Cowrie` honeypot captured numerous attempts to run reconnaissance commands (`uname`, `cat /proc/cpuinfo`, `w`, etc.) and modify SSH authorized_keys, suggesting attackers are attempting to establish persistent access.
*   The download of "Mozi.m" was observed multiple times. Mozi is a known P2P botnet that targets IoT devices, indicating attempts to recruit the honeypot into the botnet.
*   Despite a high volume of attacks, there is a lack of diversity in CVEs, with `CVE-2021-44228` being the primary vulnerability scanned for.

This concludes the Honeypot Attack Summary Report.