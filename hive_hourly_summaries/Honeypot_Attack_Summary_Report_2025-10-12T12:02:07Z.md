Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T12:01:40Z
**Timeframe:** 2025-10-12T11:20:01Z to 2025-10-12T12:00:01Z
**Files Used:**
- agg_log_20251012T112001Z.json
- agg_log_20251012T114001Z.json
- agg_log_20251012T120001Z.json

**Executive Summary**

This report summarizes 22,566 attacks recorded across three honeypot log files. The most targeted honeypots were Honeytrap and Cowrie, indicating a high volume of automated attacks. A single IP address, 173.239.216.40, was responsible for a significant number of these attacks, primarily targeting port 5038. Attackers attempted to exploit several vulnerabilities, including CVE-2019-11500, and executed commands aimed at reconnaissance and establishing persistent access. Notably, there were instances of file downloads, such as `wget.sh`, suggesting that some attackers successfully compromised the honeypots to fetch additional malicious scripts.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Honeytrap: 8872
    *   Cowrie: 7916
    *   Ciscoasa: 1802
    *   Dionaea: 1150
    *   Suricata: 1146
    *   Sentrypeer: 1270
    *   H0neytr4p: 73
    *   Tanner: 67
    *   Mailoney: 98
    *   Redishoneypot: 95
    *   Miniprint: 13
    *   Adbhoney: 15
    *   ssh-rsa: 30
    *   Honeyaml: 10
    *   ConPot: 7
    *   ElasticPot: 2

*   **Top Attacking IPs:**
    *   173.239.216.40: 6694
    *   45.128.199.212: 872
    *   202.88.244.34: 474
    *   34.123.134.194: 349
    *   178.185.136.57: 323
    *   103.165.218.190: 444
    *   103.189.235.222: 247
    *   8.219.217.47: 285
    *   103.174.212.243: 317
    *   27.71.237.24: 303
    *   62.141.43.183: 325
    *   104.168.4.151: 249
    *   46.253.45.10: 313
    *   43.229.78.35: 225
    *   118.193.38.232: 253

*   **Top Targeted Ports/Protocols:**
    *   5038: 6694
    *   5060: 1270
    *   22: 993
    *   445: 493
    *   TCP/21: 150
    *   5903: 191
    *   6379: 89
    *   21: 75
    *   25: 100
    *   8333: 77
    *   3306: 65
    *   5908: 84
    *   5909: 83
    *   5901: 79
    *   443: 65
    *   80: 62

*   **Most Common CVEs:**
    *   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
    *   CVE-2019-11500 CVE-2019-11500: 2
    *   CVE-1999-0183: 1
    *   CVE-2016-20016 CVE-2016-20016: 1
    *   CVE-2002-0013 CVE-2002-0012: 1
    *   CVE-2002-1149: 1

*   **Commands Attempted by Attackers:**
    *   `uname -a`: 53
    *   `whoami`: 53
    *   `lscpu | grep Model`: 53
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 53
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 53
    *   `lockr -ia .ssh`: 53
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 53
    *   `cat /proc/cpuinfo | grep name | wc -l`: 53
    *   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 52
    *   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 51
    *   `ls -lh $(which ls)`: 51
    *   `which ls`: 51
    *   `crontab -l`: 51
    *   `w`: 51
    *   `uname -m`: 52
    *   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 51
    *   `top`: 51
    *   `uname`: 51
    *   `Enter new UNIX password: `: 36
    *   `Enter new UNIX password:`: 36

*   **Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1: 309
    *   ET SCAN NMAP -sS window 1024: 153
    *   ET FTP FTP PWD command attempt without login: 75
    *   ET FTP FTP CWD command attempt without login: 75
    *   ET INFO Reserved Internal IP Traffic: 60
    *   ET INFO CURL User Agent: 19
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 29: 14
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 2: 13
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 12: 11
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port: 10

*   **Users / Login Attempts:**
    *   `cron/`: 59
    *   `345gs5662d34/345gs5662d34`: 51
    *   `root/`: 30
    *   `root/3245gs5662d34`: 14
    *   `admin/123654`: 6
    *   `test/test2020`: 6
    *   `root/rootpass`: 6
    *   `root/0000`: 6
    *   `user/ubuntu`: 6
    *   `antonio/antonio`: 6

*   **Files Uploaded/Downloaded:**
    *   wget.sh;: 4
    *   w.sh;: 1
    *   c.sh;: 1

*   **HTTP User-Agents:**
    *   None observed.

*   **SSH Clients and Servers:**
    *   SSH Clients: None observed.
    *   SSH Servers: None observed.

*   **Top Attacker AS Organizations:**
    *   None observed.

**Key Observations and Anomalies**

*   The high concentration of attacks from the IP address 173.239.216.40 suggests a targeted or persistent attacker. This IP should be monitored closely.
*   The prevalence of attacks on port 5038 indicates a potential focus on a specific service or vulnerability.
*   The repeated execution of a command to add an SSH key to `authorized_keys` is indicative of automated scripts attempting to create backdoors.
*   The successful download of files like `wget.sh` in the latest log file is a critical event, as it demonstrates the potential for attackers to escalate their presence and introduce further malware.
