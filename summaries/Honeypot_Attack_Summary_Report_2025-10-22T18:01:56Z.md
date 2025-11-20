Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-22T18:01:32Z
**Timeframe:** 2025-10-22T17:20:01Z to 2025-10-22T18:00:01Z
**Files:** agg_log_20251022T172001Z.json, agg_log_20251022T174001Z.json, agg_log_20251022T180001Z.json

**Executive Summary**

This report summarizes 15,751 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Dionaea, and Honeytrap honeypots. The most targeted service was SMB on port 445, followed by SSH on port 22 and SIP on port 5060. A significant number of brute-force attempts and automated attacks were observed, including attempts to install SSH keys and download malicious scripts.

**Detailed Analysis**

***Attacks by Honeypot***

*   Cowrie: 4694
*   Dionaea: 4521
*   Honeytrap: 3348
*   Ciscoasa: 1697
*   Suricata: 695
*   Sentrypeer: 582
*   Tanner: 59
*   Mailoney: 69
*   Redishoneypot: 30
*   ConPot: 24
*   H0neytr4p: 12
*   Adbhoney: 7
*   Honeyaml: 6
*   ElasticPot: 2
*   Medpot: 2
*   Miniprint: 2
*   Ipphoney: 1

***Top Attacking IPs***

*   182.8.161.75: 4357
*   91.124.88.15: 2130
*   198.23.190.58: 399
*   107.170.232.33: 288
*   185.113.139.51: 267
*   107.150.20.228: 283
*   85.208.253.229: 273
*   103.48.84.147: 262
*   178.185.136.57: 238
*   103.179.218.243: 247
*   213.6.203.226: 203
*   198.98.57.141: 209
*   162.214.211.246: 199
*   181.23.101.20: 167
*   152.32.189.21: 189
*   196.191.212.102: 174
*   185.243.5.146: 202
*   107.170.36.5: 154
*   103.164.63.144: 204
*   117.72.186.129: 166

***Top Targeted Ports/Protocols***

*   445: 4413
*   5038: 2130
*   5060: 582
*   22: 610
*   UDP/5060: 180
*   8333: 137
*   1433: 92
*   80: 53
*   23: 83
*   25: 69
*   5905: 79
*   5904: 76
*   6379: 26
*   5901: 43
*   5902: 38
*   5903: 38

***Most Common CVEs***

*   CVE-2022-27255
*   CVE-2021-3449
*   CVE-2002-1149

***Commands Attempted by Attackers***

*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
*   cat /proc/cpuinfo | grep name | wc -l
*   cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   ls -lh $(which ls)
*   which ls
*   crontab -l
*   w
*   uname -m
*   cat /proc/cpuinfo | grep model | grep name | wc -l
*   top
*   uname
*   uname -a
*   whoami
*   lscpu | grep Model
*   df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
*   Enter new UNIX password:

***Signatures Triggered***

*   ET SCAN Sipsak SIP scan (2008598)
*   ET DROP Dshield Block Listed Source group 1 (2402000)
*   ET SCAN NMAP -sS window 1024 (2009582)
*   ET INFO Reserved Internal IP Traffic (2002752)
*   ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255) (2038669)
*   GPL INFO SOCKS Proxy attempt (2100615)
*   ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
*   ET CINS Active Threat Intelligence Poor Reputation IP
*   ET DROP Spamhaus DROP Listed Traffic Inbound

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34
*   root/3245gs5662d34
*   respaldo/respaldo123
*   temp/123qwe
*   temp/3245gs5662d34
*   and various other common and random usernames.

***Files Uploaded/Downloaded***

*   sigma.sh
*   &currentsetting.htm=1

***HTTP User-Agents***

*   No user agents recorded in this period.

***SSH Clients and Servers***

*   No specific SSH clients or servers recorded in this period.

***Top Attacker AS Organizations***

*   No AS organizations recorded in this period.

**Key Observations and Anomalies**

*   **High Volume of SMB Traffic:** The continued high volume of traffic to port 445 suggests widespread scanning for vulnerable SMB services.
*   **Targeted SIP Scanning:** The significant number of events on port 5060, particularly from the IP 91.124.88.15, indicates targeted scanning for vulnerabilities in VoIP systems.
*   **Automated SSH Attacks:** The repeated use of commands to download and install SSH keys indicates automated attacks aimed at gaining persistent access to compromised systems.
*   **CVE Exploitation:** Attempts to exploit CVE-2022-27255 (Realtek) and other vulnerabilities were observed.
*   **Malware Download:** An attempt to download a malicious shell script (`sigma.sh`) was recorded.
