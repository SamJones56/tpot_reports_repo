Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T02:01:37Z
**Timeframe:** 2025-10-19T01:20:01Z to 2025-10-19T02:00:01Z
**Log Files:**
- agg_log_20251019T012001Z.json
- agg_log_20251019T014001Z.json
- agg_log_20251019T020001Z.json

**Executive Summary**

This report summarizes 29,994 events collected from the honeypot network between 2025-10-19T01:20:01Z and 2025-10-19T02:00:01Z. The majority of attacks targeted the Cowrie honeypot, with significant activity also observed on Suricata and Honeytrap. Attackers predominantly targeted SSH (port 22) and SIP (port 5060). The most frequently observed CVE was CVE-2005-4050. A variety of brute-force login attempts and command executions were recorded, with many commands focused on reconnaissance and establishing control of the compromised system.

**Detailed Analysis**

***Attacks by Honeypot***

*   **Cowrie:** 22,338
*   **Honeytrap:** 2,522
*   **Suricata:** 2,514
*   **Sentrypeer:** 1,550
*   **Ciscoasa:** 855
*   **Dionaea:** 51
*   **Mailoney:** 45
*   **Tanner:** 22
*   **H0neytr4p:** 19
*   **Adbhoney:** 15
*   **ConPot:** 14
*   **Dicompot:** 12
*   **Honeyaml:** 7
*   **Heralding:** 6
*   **ElasticPot:** 6
*   **Redishoneypot:** 9
*   **Miniprint:** 9

***Top Attacking IPs***

*   34.47.232.78: 960
*   72.146.232.13: 924
*   198.23.190.58: 914
*   23.94.26.58: 873
*   194.50.16.73: 750
*   103.90.225.35: 567
*   42.96.43.148: 419
*   198.12.68.114: 467
*   36.64.68.99: 556
*   79.106.73.114: 415

***Top Targeted Ports/Protocols***

*   22: 2,643
*   5060: 1,550
*   UDP/5060: 1,048
*   5903: 172
*   1979: 117
*   TCP/22: 83
*   8333: 71
*   5901: 85
*   5905: 59
*   5904: 59

***Most Common CVEs***

*   CVE-2005-4050: 1,038
*   CVE-2002-0013 CVE-2002-0012: 30
*   CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 16
*   CVE-2021-35394 CVE-2021-35394: 4
*   CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 2
*   CVE-2001-0414: 1
*   CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1

***Commands Attempted by Attackers***

*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 201
*   `lockr -ia .ssh`: 200
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 200
*   `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 178
*   `ls -lh $(which ls)`: 177
*   `which ls`: 177
*   `crontab -l`: 177
*   `w`: 175
*   `uname -m`: 174
*   `cat /proc/cpuinfo | grep model | grep name | wc -l`: 174
*   `top`: 174
*   `uname`: 174
*   `cat /proc/cpuinfo | grep name | wc -l`: 172
*   `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 175
*   `uname -a`: 172
*   `whoami`: 172
*   `lscpu | grep Model`: 169
*   `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 169
*   `Enter new UNIX password: `: 107
*   `Enter new UNIX password:`: 82
*   `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 27

***Signatures Triggered***

*   ET VOIP MultiTech SIP UDP Overflow (2003237): 1038
*   ET DROP Dshield Block Listed Source group 1 (2402000): 370
*   ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 230
*   ET SCAN NMAP -sS window 1024 (2009582): 132
*   ET HUNTING RDP Authentication Bypass Attempt (2034857): 85
*   ET SCAN Potential SSH Scan (2001219): 76
*   ET INFO Reserved Internal IP Traffic (2002752): 47
*   ET CINS Active Threat Intelligence Poor Reputation IP group 47 (2403346): 22
*   GPL SNMP request udp (2101417): 19
*   ET DROP Spamhaus DROP Listed Traffic Inbound group 28 (2400027): 17

***Users / Login Attempts***

*   345gs5662d34/345gs5662d34: 190
*   root/3245gs5662d34: 53
*   root/123@Robert: 35
*   ftpuser/ftppassword: 27
*   mcuser/mcuser123: 23
*   sonarqube/sonarqube123: 18
*   edge/edge: 22
*   off/123: 26
*   gta/gta: 25
*   sentry/123: 20

***Files Uploaded/Downloaded***

*   wget.sh;: 8
*   loader.sh&&chmod: 4
*   w.sh;: 2
*   c.sh;: 2
*   11: 1
*   fonts.gstatic.com: 1
*   css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&subset=latin%2Clatin-ext: 1
*   ie8.css?ver=1.0: 1
*   html5.js?ver=3.7.3: 1

***HTTP User-Agents***

*   No user agents recorded in this period.

***SSH Clients and Servers***

*   No specific SSH clients or servers recorded in this period.

***Top Attacker AS Organizations***

*   No attacker AS organizations recorded in this period.

**Key Observations and Anomalies**

*   **High Volume of Cowrie Attacks:** The Cowrie honeypot, emulating an SSH server, continues to be the most targeted, indicating a high volume of automated SSH brute-force attacks and botnet activity.
*   **SIP and VOIP Targeting:** The frequent triggering of the "ET VOIP MultiTech SIP UDP Overflow" signature, corresponding to CVE-2005-4050, suggests a focus on exploiting vulnerabilities in VOIP systems.
*   **Reconnaissance and Control Commands:** A significant portion of the commands executed on the honeypots are related to system reconnaissance (e.g., `uname`, `lscpu`, `df`) and attempts to establish persistent access by modifying SSH authorized_keys.
*   **Repetitive Malicious Commands:** The repeated attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from the same IP address (72.61.131.157) in two of the three log files indicate a persistent attacker attempting to deploy malware.
*   **Lack of Sophistication:** The majority of observed attacks appear to be automated and opportunistic, relying on common vulnerabilities and weak credentials. There is little evidence of sophisticated, targeted attacks in this dataset.