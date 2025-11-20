**Honeypot Attack Summary Report**

*   **Report Generation Time:** 2025-10-16T08:01:30Z
*   **Timeframe:** 2025-10-16T07:20:01Z to 2025-10-16T08:00:02Z
*   **Files Used:**
    *   `agg_log_20251016T072001Z.json`
    *   `agg_log_20251016T074002Z.json`
    *   `agg_log_20251016T080002Z.json`

**Executive Summary**

This report summarizes 20,366 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were reconnaissance and automated exploit attempts, with a significant number of brute-force login attempts against SSH (Cowrie) and SIP (Sentrypeer) services. A large volume of traffic was also observed on ports related to SMB and VNC. Several known CVEs were targeted, and attackers attempted to execute various commands, including reconnaissance and attempts to install SSH keys for persistence.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Cowrie: 6672
    *   Suricata: 3748
    *   Honeytrap: 3465
    *   Sentrypeer: 3105
    *   Dionaea: 1451
    *   Ciscoasa: 1677
    *   Mailoney: 93
    *   H0neytr4p: 74
    *   Tanner: 32
    *   Adbhoney: 14
    *   Honeyaml: 11
    *   Ipphoney: 12
    *   ElasticPot: 8
    *   ConPot: 4

*   **Top Attacking IPs:**
    *   45.248.163.142: 1539
    *   45.118.147.13: 1242
    *   125.163.32.197: 1058
    *   196.251.88.103: 998
    *   23.94.26.58: 885
    *   88.214.50.58: 354
    *   205.185.115.224: 400
    *   172.86.95.115: 403
    *   172.86.95.98: 487
    *   107.172.155.3: 335
    *   185.243.5.158: 436
    *   103.165.236.27: 311
    *   62.141.43.183: 321
    *   107.170.36.5: 250
    *   103.49.238.251: 252
    *   198.12.68.114: 178

*   **Top Targeted Ports/Protocols:**
    *   5060: 3105
    *   TCP/445: 1538
    *   445: 1287
    *   22: 1020
    *   TCP/5900: 381
    *   5903: 226
    *   8333: 155
    *   3306: 110
    *   5901: 126
    *   443: 63
    *   25: 93

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
    *   CVE-2021-3449 CVE-2021-3449
    *   CVE-2019-11500 CVE-2019-11500
    *   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255
    *   CVE-2006-2369

*   **Commands Attempted by Attackers:**
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `uname -a`
    *   `whoami`
    *   `w`
    *   `crontab -l`
    *   `top`
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
    *   `lscpu | grep Model`
    *   `Enter new UNIX password:`

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET SCAN NMAP -sS window 1024
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 42
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   ET INFO Reserved Internal IP Traffic
    *   ET SCAN Potential SSH Scan
    *   GPL INFO SOCKS Proxy attempt
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 47

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   root/
    *   gitlab/
    *   sign/
    *   edition/
    *   community/
    *   user/user2007
    *   admin/techsupport
    *   support/support2021
    *   ubnt/7777
    *   default/default111
    *   debian/debian2014

*   **Files Uploaded/Downloaded:**
    *   json: 2

*   **HTTP User-Agents:**
    *   (None observed)

*   **SSH Clients:**
    *   (None observed)

*   **SSH Servers:**
    *   (None observed)

*   **Top Attacker AS Organizations:**
    *   (None observed)

**Key Observations and Anomalies**

*   A significant amount of traffic is associated with the DoublePulsar backdoor, indicating attempts to exploit SMB vulnerabilities.
*   The most common command executed by attackers is an attempt to add an SSH key to the `authorized_keys` file for persistent access.
*   There is a high volume of scanning and brute-force activity across multiple ports, particularly SIP (5060), SMB (445), and SSH (22).
*   The attacking IPs originate from a diverse range of countries, suggesting the use of botnets or compromised servers for attacks.
*   No successful data exfiltration or significant file uploads were observed, indicating that the attacks were primarily focused on initial access and reconnaissance.
