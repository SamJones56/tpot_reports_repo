Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T15:01:37Z
**Timeframe:** 2025-10-07T14:20:01Z to 2025-10-07T15:00:01Z
**Files Used:** agg_log_20251007T142001Z.json, agg_log_20251007T144001Z.json, agg_log_20251007T150001Z.json

### Executive Summary

This report summarizes 12,210 events collected from the honeypot network. The majority of attacks targeted the Cowrie (SSH/Telnet) honeypot. A significant number of events were also observed on the Honeytrap and Mailoney honeypots. The most prominent attack vector involved attempts to exploit common vulnerabilities and weak credentials. The most frequently observed CVE was CVE-2021-44228 (Log4j). Attackers commonly attempted to modify the SSH `authorized_keys` file to gain persistent access.

### Detailed Analysis

**Attacks by Honeypot**

*   Cowrie: 6074
*   Honeytrap: 2074
*   Mailoney: 1689
*   Suricata: 1508
*   Sentrypeer: 608
*   H0neytr4p: 64
*   Tanner: 55
*   ElasticPot: 29
*   ConPot: 25
*   Adbhoney: 19
*   Redishoneypot: 15
*   Honeyaml: 13
*   Dicompot: 9
*   Ipphoney: 6
*   Heralding: 6
*   Ciscoasa: 7
*   Dionaea: 7

**Top Attacking IPs**

*   86.54.42.238: 1641
*   129.212.184.179: 1008
*   45.140.17.52: 651
*   185.255.126.223: 557
*   172.237.112.229: 819
*   93.115.79.198: 322
*   49.12.203.154: 347
*   138.124.20.112: 362
*   196.251.69.141: 366
*   38.248.12.102: 358
*   27.254.137.144: 363
*   87.201.127.149: 209
*   103.149.27.228: 191
*   27.112.78.170: 134
*   152.32.213.170: 94
*   216.189.157.132: 94
*   179.43.176.236: 89
*   74.225.1.50: 89
*   3.130.96.91: 127

**Top Targeted Ports/Protocols**

*   25: 1689
*   22: 899
*   5060: 608
*   8333: 189
*   5903: 96
*   443: 64
*   80: 48
*   1434: 34
*   9200: 26
*   23: 35

**Most Common CVEs**

*   CVE-2021-44228 CVE-2021-44228: 34
*   CVE-1999-0265: 12
*   CVE-2002-0013 CVE-2002-0012: 5
*   CVE-2002-1149: 1
*   CVE-2023-26801 CVE-2023-26801: 1

**Commands Attempted by Attackers**

*   cd ~; chattr -ia .ssh; lockr -ia .ssh: 24
*   lockr -ia .ssh: 24
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 24
*   cat /proc/cpuinfo | grep name | wc -l: 24
*   Enter new UNIX password: : 24
*   Enter new UNIX password::: 24
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 24
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 24
*   ls -lh $(which ls): 24
*   which ls: 24
*   crontab -l: 24
*   w: 24
*   uname -m: 24
*   cat /proc/cpuinfo | grep model | grep name | wc -l: 24
*   top: 24
*   uname: 24
*   uname -a: 24
*   whoami: 24
*   lscpu | grep Model: 24
*   uname -s -v -n -r -m: 7

**Signatures Triggered**

*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 459
*   2023753: 459
*   ET DROP Dshield Block Listed Source group 1: 333
*   2402000: 333
*   ET SCAN NMAP -sS window 1024: 141
*   2009582: 141
*   ET INFO Reserved Internal IP Traffic: 57
*   2002752: 57
*   ET EXPLOIT Apache Obfuscated log4j RCE Attempt (tcp ldap) (CVE-2021-44228): 16
*   2034755: 16

**Users / Login Attempts**

*   345gs5662d34/345gs5662d34: 24
*   sysadmin/sysadmin@1: 10
*   sysadmin/sysadmin!: 4

**Files Uploaded/Downloaded**

*   wget.sh;: 24
*   w.sh;: 6
*   c.sh;: 6

**HTTP User-Agents**

*   No user agents were logged in this timeframe.

**SSH Clients and Servers**

*   No SSH clients or servers were logged in this timeframe.

**Top Attacker AS Organizations**

*   No attacker AS organizations were logged in this timeframe.

### Key Observations and Anomalies

*   The high number of Cowrie events suggests a focus on brute-forcing SSH and Telnet credentials.
*   The repeated commands to remove and replace SSH `authorized_keys` files indicate a common tactic to maintain persistent access to compromised systems.
*   The continued scanning for the Log4j vulnerability (CVE-2021-44228) highlights that attackers are still actively seeking to exploit this vulnerability.
*   A significant amount of traffic is being dropped due to blocklists (Dshield, Spamhaus), indicating that these services are effective at mitigating a portion of the attacks.
*   The command `uname -s -v -n -r -m` was observed, which is a less common variant of `uname -a` for system enumeration.
