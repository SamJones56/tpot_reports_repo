Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T21:01:37Z
**Timeframe of a report:** 2025-10-05T20:20:01Z to 2025-10-05T21:00:01Z
**Files Used:**
- agg_log_20251005T202001Z.json
- agg_log_20251005T204002Z.json
- agg_log_20251005T210001Z.json

**Executive Summary**
This report summarizes 11,975 attacks recorded across multiple honeypots. The majority of attacks were against the Cowrie (SSH/Telnet) and Mailoney (SMTP) honeypots. A significant number of brute-force attempts and automated scans were observed from a wide range of IP addresses. Attackers attempted to deploy shell scripts, likely for botnet propagation. Several CVEs were targeted, with a focus on older vulnerabilities.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 4,361
    *   Mailoney: 3,329
    *   Suricata: 1,409
    *   Ciscoasa: 1,379
    *   Honeytrap: 768
    *   Sentrypeer: 401
    *   Dionaea: 58
    *   ElasticPot: 43
    *   Tanner: 53
    *   Adbhoney: 41
    *   H0neytr4p: 43
    *   Honeyaml: 34
    *   ConPot: 28
    *   Redishoneypot: 25
    *   Miniprint: 3

*   **Top Attacking IPs:**
    *   86.54.42.238: 1641
    *   176.65.141.117: 1640
    *   102.211.210.151: 807
    *   172.86.95.98: 383
    *   27.79.44.136: 312
    *   89.23.123.161: 232
    *   42.7.246.81: 270
    *   103.77.173.191: 212
    *   139.59.66.39: 198
    *   196.251.80.29: 132

*   **Top Targeted Ports/Protocols:**
    *   25: 3329
    *   22: 675
    *   5060: 401
    *   23: 167
    *   80: 61
    *   TCP/80: 64
    *   TCP/1433: 35
    *   9200: 37
    *   TCP/22: 50
    *   443: 43

*   **Most Common CVEs:**
    *   CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
    *   CVE-2021-3449
    *   CVE-2019-11500
    *   CVE-2024-4577
    *   CVE-2002-0953
    *   CVE-2021-41773
    *   CVE-2021-42013
    *   CVE-2005-4050
    *   CVE-2024-3721

*   **Commands Attempted by Attackers:**
    *   cd ~; chattr -ia .ssh; lockr -ia .ssh
    *   lockr -ia .ssh
    *   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
    *   cat /proc/cpuinfo | grep name | wc -l
    *   Enter new UNIX password:
    *   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
    *   ls -lh $(which ls)
    *   uname -a
    *   whoami
    *   /ip cloud print

*   **Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   ET SCAN Potential SSH Scan
    *   ET INFO Reserved Internal IP Traffic
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 41
    *   ET SCAN Suspicious inbound to MSSQL port 1433
    *   GPL INFO SOCKS Proxy attempt
    *   ET CINS Active Threat Intelligence Poor Reputation IP (groups 43-51)

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   root/root1234
    *   platform/12345
    *   tomcat/tomcat!@#
    *   kim/123
    *   lamination/lamination123
    *   ftpbackup/ftpbackup1
    *   and many others.

*   **Files Uploaded/Downloaded:**
    *   sh: 90
    *   wget.sh;: 16
    *   w.sh;: 4
    *   c.sh;: 4

*   **HTTP User-Agents:**
    *   Not observed in this period.

*   **SSH Clients:**
    *   Not observed in this period.

*   **SSH Servers:**
    *   Not observed in this period.

*   **Top Attacker AS Organizations:**
    *   Not observed in this period.

**Key Observations and Anomalies**
- The high volume of SMTP traffic from two specific IPs (86.54.42.238 and 176.65.141.117) suggests a coordinated campaign.
- The commands executed after successful SSH logins are consistent with establishing a persistent presence and gathering system information.
- A notable increase in scans for TCP port 1433 (MSSQL) and attempts to exploit older vulnerabilities.
- Attackers are using `wget` and `curl` to download and execute shell scripts, a common tactic for malware and botnet deployment.
- The presence of commands like `/ip cloud print` suggests some attacks are targeting MikroTik RouterOS devices.
