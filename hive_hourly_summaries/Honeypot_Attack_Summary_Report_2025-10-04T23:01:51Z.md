Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T23:01:33Z
**Timeframe:** 2025-10-04T22:20:02Z to 2025-10-04T23:00:01Z
**Files Used:**
*   agg_log_20251004T222002Z.json
*   agg_log_20251004T224001Z.json
*   agg_log_20251004T230001Z.json

### Executive Summary

This report summarizes 6966 attacks recorded by the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks were SSH brute-force attempts captured by the Cowrie honeypot. A significant number of attacks were also observed targeting Cisco ASA devices and mail servers. The most frequent attacker IP was 176.65.141.117, primarily targeting mail services. A variety of CVEs were exploited, with CVE-2005-4050 being the most common. Attackers attempted to gain control of systems by adding their SSH keys to the authorized_keys file and downloading malicious scripts.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 2570
*   Ciscoasa: 1546
*   Suricata: 978
*   Mailoney: 864
*   Sentrypeer: 589
*   Honeytrap: 165
*   Tanner: 74
*   H0neytr4p: 47
*   Heralding: 47
*   ConPot: 35
*   Dionaea: 20
*   Redishoneypot: 9
*   Adbhoney: 9
*   Honeyaml: 6
*   ElasticPot: 5
*   ssh-rsa: 2

**Top Attacking IPs:**
*   176.65.141.117
*   172.86.95.98
*   202.157.177.161
*   103.176.20.115
*   155.4.244.107
*   137.184.202.107
*   103.176.78.151
*   107.175.70.80
*   202.79.29.108
*   222.107.251.147

**Top Targeted Ports/Protocols:**
*   25
*   5060
*   22
*   80
*   443
*   TCP/80
*   UDP/5060
*   TCP/22
*   vnc/5900
*   1025

**Most Common CVEs:**
*   CVE-2005-4050
*   CVE-2022-27255
*   CVE-2021-3449
*   CVE-2019-11500
*   CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
*   CVE-2002-0013, CVE-2002-0012
*   CVE-2024-3721
*   CVE-2006-3602, CVE-2006-4458, CVE-2006-4542

**Commands Attempted by Attackers:**
*   cd ~; chattr -ia .ssh; lockr -ia .ssh
*   lockr -ia .ssh
*   cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
*   cat /proc/cpuinfo | grep name | wc -l
*   Enter new UNIX password:
*   free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
*   ls -lh $(which ls)
*   which ls
*   crontab -l
*   w
*   uname -m
*   top
*   uname
*   uname -a
*   whoami

**Signatures Triggered:**
*   ET DROP Dshield Block Listed Source group 1
*   2402000
*   ET SCAN NMAP -sS window 1024
*   2009582
*   ET INFO Python aiohttp User-Agent Observed Inbound
*   2064326
*   ET CINS Active Threat Intelligence Poor Reputation IP group 43
*   2403342
*   ET VOIP MultiTech SIP UDP Overflow
*   2003237
*   ET INFO Reserved Internal IP Traffic
*   2002752
*   ET SCAN Potential SSH Scan
*   2001219
*   ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
*   2038669

**Users / Login Attempts:**
*   345gs5662d34/345gs5662d34
*   root/nPSpP4PBW0
*   root/09N1RCa1Hs31
*   novinhost/novinhost.org
*   admin/26071978
*   admin/26061994
*   admin/26051994
*   admin/26031976
*   admin/26021981
*   root/Raja@123
*   root/optimus1
*   test/zhbjETuyMffoL8F
*   joel/joel123
*   fer/fer
*   root/2glehe5t24th1issZs
*   root/3245gs5662d34

**Files Uploaded/Downloaded:**
*   wget.sh;
*   &currentsetting.htm=1
*   w.sh;
*   c.sh;

**HTTP User-Agents:**
*   None Observed

**SSH Clients:**
*   None Observed

**SSH Servers:**
*   None Observed

**Top Attacker AS Organizations:**
*   None Observed

### Key Observations and Anomalies

*   **High Volume of Mail Attacks:** A significant number of attacks were directed at port 25, indicating a focus on exploiting mail servers. The IP `176.65.141.117` was responsible for the vast majority of these attacks.
*   **Repetitive SSH Commands:** A common pattern observed in Cowrie logs was a series of commands to add an SSH key to the `authorized_keys` file, indicating a coordinated campaign to gain persistent access.
*   **File Download Attempts:** The Adbhoney honeypot captured attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`), suggesting an attempt to install malware or establish a backdoor.
*   **Targeting of VoIP Services:** The Sentrypeer honeypot and Suricata signatures show a consistent interest in SIP services on port 5060.
*   **Exploitation of Older Vulnerabilities:** The presence of CVEs from as early as 1999 suggests that attackers are still scanning for and attempting to exploit old, unpatched vulnerabilities.

This concludes the Honeypot Attack Summary Report.