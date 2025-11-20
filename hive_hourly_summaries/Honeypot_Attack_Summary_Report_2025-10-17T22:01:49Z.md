Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T22:01:29Z
**Timeframe:** 2025-10-17T21:20:01Z - 2025-10-17T22:00:01Z
**Log Files:** agg_log_20251017T212001Z.json, agg_log_20251017T214001Z.json, agg_log_20251017T220001Z.json

**Executive Summary**
This report summarizes 23,213 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attacks. A significant number of events were also flagged by Suricata, detecting various network intrusion signatures. The top attacking IP addresses originate from a diverse range of countries, with attackers primarily targeting common service ports like SSH (22), SIP (5060), and SMB (445). Several CVEs were detected, with CVE-2022-27255 being the most frequent. Attackers were observed attempting to add their SSH keys to the authorized_keys file for persistent access.

**Detailed Analysis**

***Attacks by Honeypot***
*   Cowrie: 12617
*   Suricata: 3235
*   Honeytrap: 3201
*   Sentrypeer: 1469
*   Ciscoasa: 1412
*   ElasticPot: 938
*   Tanner: 72
*   Mailoney: 66
*   Dionaea: 47
*   H0neytr4p: 51
*   Adbhoney: 37
*   Redishoneypot: 40
*   ConPot: 13
*   Dicompot: 6
*   Heralding: 4
*   Wordpot: 1

***Top Attacking IPs***
*   182.66.121.30: 1412
*   47.242.172.212: 1243
*   72.146.232.13: 1212
*   5.167.79.4: 1226
*   172.86.95.115: 517
*   172.86.95.98: 502
*   104.223.122.114: 336
*   190.153.249.99: 286
*   103.67.78.117: 282
*   52.187.9.8: 332
*   14.103.123.8: 195
*   128.199.183.223: 194
*   88.210.63.16: 223
*   140.249.81.156: 208
*   103.149.86.99: 233

***Top Targeted Ports/Protocols***
*   22: 1986
*   TCP/445: 1431
*   5060: 1469
*   9200: 938
*   5903: 225
*   8333: 115
*   5901: 115
*   80: 73
*   25: 68
*   5905: 77
*   5904: 77
*   TCP/22: 73
*   443: 43
*   UDP/5060: 118
*   6379: 37

***Most Common CVEs***
*   CVE-2022-27255: 28
*   CVE-2002-0013, CVE-2002-0012: 11
*   CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 8
*   CVE-1999-0183: 2
*   CVE-2002-1149: 1

***Commands Attempted by Attackers***
*   `cd ~ && rm -rf .ssh && ...`: 62
*   `lockr -ia .ssh`: 62
*   `cat /proc/cpuinfo | ...`: 62
*   `uname -a`: 62
*   `whoami`: 62
*   `w`: 62
*   `crontab -l`: 62
*   `Enter new UNIX password: `: 44
*   `cd /data/local/tmp/; busybox wget ...`: 1
*   `rm -rf /data/local/tmp; mkdir -p ...`: 2

***Signatures Triggered***
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1410
*   ET DROP Dshield Block Listed Source group 1: 340
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 294
*   ET SCAN NMAP -sS window 1024: 182
*   ET HUNTING RDP Authentication Bypass Attempt: 110
*   ET SCAN Sipsak SIP scan: 89
*   ET INFO Reserved Internal IP Traffic: 58
*   ET SCAN Potential SSH Scan: 57
*   ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 28
*   ET INFO CURL User Agent: 31

***Users / Login Attempts***
*   345gs5662d34/345gs5662d34: 55
*   root/3245gs5662d34: 16
*   ftpuser/ftppassword: 16
*   root/123@Robert: 14
*   user/888888: 6
*   centos/77: 6
*   ubnt/asdfgh: 6
*   ubnt/qwer1234: 6
*   support/999: 6
*   ubnt/passwd: 6

***Files Uploaded/Downloaded***
*   wget.sh;: 12
*   w.sh;: 3
*   c.sh;: 3

***HTTP User-Agents***
*   No HTTP user-agents were recorded in this period.

***SSH Clients***
*   No SSH clients were recorded in this period.

***SSH Servers***
*   No SSH servers were recorded in this period.

***Top Attacker AS Organizations***
*   No attacker AS organizations were recorded in this period.

**Key Observations and Anomalies**
*   **Persistent Access Attempts:** The repeated attempts to add an SSH key to `authorized_keys` is a clear indicator of attackers trying to establish persistent access to the compromised system.
*   **Reconnaissance Commands:** The frequent use of commands like `uname -a`, `lscpu`, and `free -m` suggests that attackers are performing reconnaissance to understand the system's architecture and resources.
*   **Automated Attacks:** The high volume of login attempts with common and default credentials points to large-scale, automated brute-force campaigns.
*   **Targeting of Multiple Services:** The wide range of targeted ports indicates that attackers are scanning for any open service they can exploit, not just SSH.
*   **DoublePulsar Detection:** The high number of `DoublePulsar Backdoor` signatures indicates that exploits related to the EternalBlue vulnerability (MS17-010) are still prevalent.
