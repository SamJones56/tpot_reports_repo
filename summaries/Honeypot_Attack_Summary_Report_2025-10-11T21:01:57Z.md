Honeypot Attack Summary Report

**Report Time:** 2025-10-11T21:01:39Z
**Timeframe:** 2025-10-11T20:20:02Z to 2025-10-11T21:00:01Z
**Files:** agg_log_20251011T202002Z.json, agg_log_20251011T204001Z.json, agg_log_20251011T210001Z.json

**Executive Summary**

This report summarizes 23,831 events recorded across three honeypot log files. The majority of attacks were captured by the Cowrie honeypot, with significant activity also detected on Dionaea and Honeytrap. The most prominent attacking IP address was 185.144.27.63, responsible for a large volume of the observed traffic. The most targeted ports were 445 (SMB) and 22 (SSH). A number of CVEs were detected, with older vulnerabilities being the most frequently targeted. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 13,067
*   Dionaea: 3,919
*   Honeytrap: 3,127
*   Ciscoasa: 1,713
*   Suricata: 1,570
*   Sentrypeer: 113
*   Mailoney: 110
*   Tanner: 76
*   Redishoneypot: 51
*   Adbhoney: 36
*   H0neytr4p: 25
*   ConPot: 16
*   ElasticPot: 4
*   Honeyaml: 4

***Top Attacking IPs***

*   185.144.27.63: 7,277
*   203.121.29.98: 3,094
*   223.100.22.69: 780
*   103.181.142.244: 401
*   34.128.77.56: 297
*   177.75.6.242: 286
*   101.126.132.190: 280
*   14.225.205.231: 279
*   14.103.234.168: 271
*   200.46.125.168: 183

***Top Targeted Ports/Protocols***

*   445: 3,872
*   22: 2,254
*   5903: 188
*   25: 118
*   5060: 113
*   8333: 86
*   80: 78
*   TCP/80: 66
*   TCP/22: 66
*   6379: 51

***Most Common CVEs***

*   CVE-2002-0013, CVE-2002-0012: 21
*   CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 13
*   CVE-2019-11500: 5
*   CVE-2021-3449: 3
*   CVE-1999-0183: 2
*   CVE-2024-4577, CVE-2002-0953: 2
*   CVE-2024-4577: 2
*   CVE-2021-41773: 1
*   CVE-2021-42013: 1
*   CVE-2018-11776: 1
*   CVE-2021-35394: 1

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 55
*   `lockr -ia .ssh`: 55
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo ...`: 54
*   `cat /proc/cpuinfo | grep name | wc -l`: 28
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 29
*   `ls -lh $(which ls)`: 29
*   `which ls`: 29
*   `crontab -l`: 29
*   `w`: 29
*   `uname -m`: 28
*   `Enter new UNIX password: `: 24
*   `Enter new UNIX password:`: 24

***Signatures Triggered***

*   ET DROP Dshield Block Listed Source group 1: 399
*   2402000: 399
*   ET SCAN NMAP -sS window 1024: 162
*   2009582: 162
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 114
*   2023753: 114
*   ET INFO Reserved Internal IP Traffic: 60
*   2002752: 60
*   ET SCAN Potential SSH Scan: 52
*   2001219: 52

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 50
*   centos/centos: 6
*   admin/qwe123: 6
*   root/root01: 6
*   admin/admin2: 6
*   admin/Huawei@123: 6
*   root/666666: 6
*   root/2020: 6
*   root/656565: 6
*   USERID/PASSW0RD: 6

***Files Uploaded/Downloaded***

*   sh: 98
*   wget.sh;: 8
*   11: 7
*   fonts.gstatic.com: 7
*   css?family=Libre+Franklin...: 7
*   ie8.css?ver=1.0: 7
*   html5.js?ver=3.7.3: 6
*   boatnet.x86;: 3
*   boatnet.x86;cat: 3
*   boatnet.mips;: 3

***HTTP User-Agents***

*   No HTTP user agents were logged in the provided data.

***SSH Clients and Servers***

*   No SSH clients or servers were logged in the provided data.

***Top Attacker AS Organizations***

*   No attacker AS organizations were logged in the provided data.

**Key Observations and Anomalies**

*   The high volume of attacks from 185.144.27.63 suggests a targeted or automated campaign from this source.
*   The prevalence of attacks targeting SMB (port 445) and SSH (port 22) is consistent with common attack vectors for compromising servers.
*   The targeting of older CVEs indicates that attackers are still finding success with legacy vulnerabilities that may not be patched in all environments.
*   The commands attempted by attackers show a clear pattern of reconnaissance, privilege escalation, and establishing persistence.
*   The `Dshield Block Listed Source` signature was the most frequently triggered, indicating that many of the attacking IPs are known malicious actors.
*   The Cowrie honeypot was the most engaged, suggesting a high volume of SSH and Telnet-based attacks.
