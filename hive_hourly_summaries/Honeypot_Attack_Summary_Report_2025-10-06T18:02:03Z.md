Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-06T18:01:29Z
**Timeframe:** 2025-10-06T17:20:02Z to 2025-10-06T18:00:01Z
**Files Used:**
- agg_log_20251006T172002Z.json
- agg_log_20251006T174001Z.json
- agg_log_20251006T180001Z.json

### Executive Summary
This report summarizes the analysis of 14,395 events captured by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based attacks. A significant number of events were also captured by the Honeytrap and Suricata honeypots. The most targeted ports were 22 (SSH), 25 (SMTP), and 5060 (SIP). A number of CVEs were detected, with CVE-2021-44228 (Log4Shell) being the most prevalent.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6264
- Honeytrap: 3123
- Suricata: 1833
- Ciscoasa: 1168
- Mailoney: 854
- Dionaea: 512
- Sentrypeer: 385
- Redishoneypot: 73
- H0neytr4p: 59
- Tanner: 50
- Miniprint: 21
- Dicompot: 10
- Adbhoney: 10
- Heralding: 12
- ConPot: 9
- Honeyaml: 9
- ElasticPot: 3

**Top Attacking IPs:**
- 50.6.225.98
- 80.94.95.238
- 176.65.141.117
- 172.86.95.98
- 104.248.81.123
- 190.129.114.222
- 198.46.207.98
- 69.62.104.9
- 193.122.200.89
- 103.26.136.173

**Top Targeted Ports/Protocols:**
- 22
- 25
- 5060
- 445
- 3306
- 8333

**Most Common CVEs:**
- CVE-2021-44228
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2019-16920
- CVE-2024-12856
- CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163
- CVE-2023-47565
- CVE-2023-31983
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051
- CVE-2024-33112
- CVE-2022-37056
- CVE-2019-10891
- CVE-2024-3721
- CVE-2021-42013
- CVE-2016-6563

**Commands Attempted by Attackers:**
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- ET DROP Dshield Block Listed Source group 1 (2402000)
- ET SCAN NMAP -sS window 1024 (2009582)
- ET INFO Reserved Internal IP Traffic (2002752)
- ET HUNTING RDP Authentication Bypass Attempt (2034857)

**Users / Login Attempts:**
- appuser/
- 345gs5662d34/345gs5662d34
- ubuntu/3245gs5662d34
- sftpuser/3245gs5662d34

**Files Uploaded/Downloaded:**
- wget.sh;
- rondo.dgx.sh||busybox
- Mozi.m
- w.sh;
- c.sh;

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organizations were identified in the logs.

### Key Observations and Anomalies
- The high number of Cowrie events suggests a sustained campaign of brute-force attacks against SSH and Telnet services.
- The significant number of events targeting SMTP (port 25) indicates potential spam or phishing campaigns.
- The repeated attempts to execute commands related to modifying SSH authorized_keys files suggest attackers are attempting to establish persistent access.
- The presence of the Log4Shell vulnerability (CVE-2021-44228) continues to be a common attack vector.
- A number of commands were observed that attempt to download and execute shell scripts from remote servers, a common tactic for malware deployment.
- The IP address `50.6.225.98` was particularly active, responsible for over 1200 events. Further investigation of this IP is recommended.