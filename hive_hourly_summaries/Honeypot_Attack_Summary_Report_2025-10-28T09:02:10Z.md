**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-28T09:01:28Z
**Timeframe:** 2025-10-28T08:20:02Z to 2025-10-28T09:00:01Z
**Files Used:** `agg_log_20251028T082002Z.json`, `agg_log_20251028T084001Z.json`, `agg_log_20251028T090001Z.json`

**Executive Summary**

This report summarizes 24,820 attacks recorded across the honeypot network. The majority of attacks were captured by the Honeytrap, Cowrie, and Suricata honeypots. The most prominent attacker IP was `77.83.240.70`. The most targeted ports were 445 (SMB) and 5060 (SIP). Several CVEs were detected, with `CVE-2002-0013` and `CVE-2002-0012` being the most frequent. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Honeytrap: 12077
    *   Cowrie: 4688
    *   Suricata: 3188
    *   Ciscoasa: 1707
    *   Sentrypeer: 1694
    *   Dionaea: 1184
    *   Mailoney: 90
    *   ConPot: 28
    *   Tanner: 38
    *   Redishoneypot: 30
    *   Dicompot: 23
    *   Adbhoney: 22
    *   Miniprint: 20
    *   Honeyaml: 15
    *   ElasticPot: 4
    *   H0neytr4p: 6
    *   Heralding: 3
    *   Ipphoney: 3

*   **Top Attacking IPs:**
    *   77.83.240.70: 8827
    *   123.21.253.80: 1399
    *   178.128.232.91: 1244
    *   144.172.108.231: 934
    *   182.176.117.154: 692
    *   212.30.37.8: 753
    *   159.89.20.223: 800
    *   185.243.5.121: 418
    *   223.241.247.214: 284
    *   43.225.158.169: 283
    *   41.216.178.119: 278
    *   163.172.99.31: 327
    *   202.143.111.139: 437
    *   88.210.63.16: 309
    *   69.63.77.146: 271
    *   185.213.164.17: 352
    *   91.224.92.34: 161
    *   103.160.49.173: 145
    *   193.24.211.28: 116
    *   167.250.224.25: 80

*   **Top Targeted Ports/Protocols:**
    *   TCP/445: 1397
    *   445: 980
    *   5060: 1694
    *   5038: 753
    *   22: 745
    *   5901: 256
    *   1433: 157
    *   8333: 128
    *   5903: 106
    *   25: 90
    *   23: 44
    *   TCP/22: 57
    *   UDP/5060: 39
    *   6379: 30
    *   9090: 36

*   **Most Common CVEs:**
    *   CVE-2002-0013 CVE-2002-0012: 17
    *   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 9
    *   CVE-2005-4050: 1
    *   CVE-2022-27255 CVE-2022-27255: 1
    *   CVE-2006-2369: 1

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `Enter new UNIX password:`
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
    *   `ls -lh $(which ls)`
    *   `which ls`
    *   `crontab -l`
    *   `w`
    *   `uname -m`
    *   `top`
    *   `uname -a`
    *   `whoami`
    *   `lscpu | grep Model`
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

*   **Signatures Triggered:**
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   ET INFO Reserved Internal IP Traffic
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 46
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 41
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 12
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 44
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 48
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
    *   ET SCAN Suspicious inbound to PostgreSQL port 5432
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 34
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 3
    *   ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   root/kian
    *   root/kigashoyting
    *   root/1008
    *   sophia1/sophia1
    *   postgres/postgres
    *   root/klmn45
    *   ubuntu/ubuntu
    *   elsearch/elsearch
    *   rancher/rancher123

*   **Files Uploaded/Downloaded:**
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

*   **HTTP User-Agents:**
    *   python-requests/2.6.0 CPython/2.7.5 Linux/3.10.0-1160.119.1.el7.x86_64

*   **SSH Clients and Servers:**
    *   *No SSH clients or servers were recorded in this timeframe.*

*   **Top Attacker AS Organizations:**
    *   *No attacker AS organizations were recorded in this timeframe.*

**Key Observations and Anomalies**

The attacker with IP `77.83.240.70` was particularly aggressive, responsible for a significant portion of the total attacks. The commands attempted indicate a clear pattern of trying to gain system information and establish a foothold via SSH keys. The downloaded files, such as `arm.urbotnetisass`, suggest attempts to install malware on compromised systems. The high number of SMB (port 445) related attacks, particularly the "DoublePulsar Backdoor" signature, indicates a focus on exploiting Windows vulnerabilities.