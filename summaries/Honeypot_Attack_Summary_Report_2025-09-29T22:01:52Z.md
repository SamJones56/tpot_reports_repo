Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T22:01:21Z
**Timeframe:** 2025-09-29T21:20:02Z to 2025-09-29T22:00:01Z
**Files Used:** `agg_log_20250929T212002Z.json`, `agg_log_20250929T214001Z.json`, `agg_log_20250929T220001Z.json`

### Executive Summary

This report summarizes 19,882 events collected from T-Pot honeypots over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot. The most prominent attacker IP was `160.25.118.10`, and the most targeted port was TCP/22 (SSH). Several CVEs were detected, with `CVE-2021-3449` and `CVE-2019-11500` being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control of the compromised system.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 13944
*   Honeytrap: 2476
*   Suricata: 1624
*   Ciscoasa: 1495
*   Dionaea: 89
*   Tanner: 66
*   Redishoneypot: 40
*   ConPot: 38
*   Adbhoney: 23
*   Sentrypeer: 23
*   Mailoney: 26
*   H0neytr4p: 18
*   ElasticPot: 8
*   Honeyaml: 6
*   Heralding: 3
*   Wordpot: 1

**Top Attacking IPs:**
*   160.25.118.10: 6661
*   134.199.197.102: 1987
*   91.210.179.185: 384
*   89.111.131.103: 384
*   203.190.53.154: 291
*   121.229.191.90: 376
*   45.119.81.249: 233
*   103.86.198.162: 293
*   152.42.165.179: 376
*   185.156.73.167: 368
*   92.63.197.55: 362
*   185.156.73.166: 368
*   92.63.197.59: 334
*   125.21.53.232: 323
*   167.172.189.176: 324
*   27.111.32.174: 318
*   192.227.223.50: 212
*   218.78.46.81: 205
*   103.146.159.179: 213

**Top Targeted Ports/Protocols:**
*   22: 2361
*   8333: 197
*   TCP/22: 80
*   80: 63
*   23: 39
*   445: 23
*   TCP/1433: 21
*   1701: 22
*   TCP/1521: 23
*   25: 21
*   8888: 21
*   6379: 34

**Most Common CVEs:**
*   CVE-2021-3449
*   CVE-2019-11500
*   CVE-1999-0265
*   CVE-2002-0013
*   CVE-2002-0012
*   CVE-1999-0517
*   CVE-2016-20016
*   CVE-2006-2369

**Commands Attempted by Attackers:**
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
*   `lockr -ia .ssh`
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
*   `uname -a`
*   `cat /proc/cpuinfo | grep name | wc -l`
*   `whoami`
*   `lscpu | grep Model`
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
*   `crontab -l`
*   `w`
*   `uname -m`
*   `top`
*   `Enter new UNIX password:`

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   ET SCAN NMAP -sS window 1024
*   ET SCAN MS Terminal Server Traffic on Non-standard Port
*   ET INFO Login Credentials Possibly Passed in POST Data
*   ET SCAN Potential SSH Scan
*   ET INFO Reserved Internal IP Traffic
*   ET CINS Active Threat Intelligence Poor Reputation IP
*   ET DROP Spamhaus DROP Listed Traffic Inbound
*   ET HUNTING RDP Authentication Bypass Attempt

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   root/3245gs5662d34
*   root/nPSpP4PBW0
*   test/zhbjETuyMffoL8F
*   old/sor123in
*   geoserver/geoserver
*   work/workwork
*   agent/agent
*   postgres/postgres
*   reboot/reboot
*   unreal/unreal123

**Files Uploaded/Downloaded:**
*   arm.urbotnetisass
*   arm5.urbotnetisass
*   arm6.urbotnetisass
*   arm7.urbotnetisass
*   x86_32.urbotnetisass
*   mips.urbotnetisass
*   mipsel.urbotnetisass
*   k.php?a=x86_64,325BCC1917D2UX9XH
*   upnpsetup

**HTTP User-Agents:**
*   *No user agents recorded in this period.*

**SSH Clients:**
*   *No specific SSH clients recorded in this period.*

**SSH Servers:**
*   *No specific SSH servers recorded in this period.*

**Top Attacker AS Organizations:**
*   *No AS organization data recorded in this period.*

### Key Observations and Anomalies

*   The attacker at `160.25.118.10` was responsible for a significant portion of the total attack volume, indicating a targeted or persistent campaign.
*   The commands executed by attackers suggest a common pattern of attempting to disable security measures (`chattr`), install their own SSH keys for persistence, and then perform basic system reconnaissance.
*   The downloaded files (`*.urbotnetisass`) are indicative of botnet activity, where the attackers are attempting to enlist the compromised machine into a larger network of infected devices.
*   The presence of multiple CVEs suggests that attackers are scanning for a wide range of vulnerabilities, likely using automated tools.

This concludes the Honeypot Attack Summary Report.