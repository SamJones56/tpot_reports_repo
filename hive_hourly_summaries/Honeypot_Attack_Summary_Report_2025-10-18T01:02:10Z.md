Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T01:01:29Z
**Timeframe Covered:** 2025-10-18T00:20:01Z to 2025-10-18T01:00:01Z
**Log Files Used:**
- agg_log_20251018T002001Z.json
- agg_log_20251018T004001Z.json
- agg_log_20251018T010001Z.json

### Executive Summary
This report summarizes 9,022 events collected from the honeypot network over a 40-minute period. The most targeted services were SSH (Cowrie) and various TCP/UDP ports (Honeytrap). The majority of attacks originated from the IP address `72.146.232.13`. Attackers primarily scanned for open ports, attempted brute-force logins, and executed commands to gain persistent access by adding SSH keys to `authorized_keys`. Multiple CVEs were targeted, with a focus on older vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot**
- **Cowrie:** 3,004
- **Honeytrap:** 2,324
- **Ciscoasa:** 1,439
- **Suricata:** 1,207
- **Dionaea:** 360
- **Sentrypeer:** 284
- **Tanner:** 191
- **Mailoney:** 81
- **H0neytr4p:** 55
- **Redishoneypot:** 35
- **Adbhoney:** 24
- **ElasticPot:** 6
- **Honeyaml:** 5
- **ConPot:** 4
- **Dicompot:** 3

**Top Attacking IPs**
- **72.146.232.13:** 861
- **77.46.147.77:** 317
- **177.229.197.38:** 291
- **95.39.201.205:** 273
- **43.162.111.169:** 247
- **31.193.128.244:** 262
- **88.210.63.16:** 320
- **195.178.110.201:** 177
- **107.170.36.5:** 234
- **103.23.198.49:** 197
- **103.171.85.118:** 199
- **107.150.102.23:** 145
- **68.183.149.135:** 111
- **150.187.25.120:** 79
- **167.250.224.25:** 95
- **185.243.5.137:** 70
- **159.89.121.144:** 63
- **68.183.207.213:** 63
- **185.243.5.152:** 42
- **3.134.148.59:** 52

**Top Targeted Ports/Protocols**
- **22:** 569
- **445:** 322
- **5060:** 284
- **80:** 188
- **5903:** 192
- **5901:** 102
- **25:** 83
- **8333:** 75
- **5904:** 77
- **5905:** 76
- **6379:** 35
- **UDP/5060:** 29
- **TCP/80:** 36
- **23:** 32
- **9001:** 41
- **5907:** 41
- **5909:** 33
- **5908:** 32
- **5902:** 38

**Most Common CVEs**
- **CVE-2005-4050:** 26
- **CVE-2002-1149:** 8
- **CVE-2021-35394 CVE-2021-35394:** 2
- **CVE-2002-0013 CVE-2002-0012:** 2
- **CVE-2006-2369:** 2
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 1
- **CVE-2019-11500 CVE-2019-11500:** 1

**Commands Attempted by Attackers**
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 11
- **lockr -ia .ssh:** 11
- **cd ~ && rm -rf .ssh && ... authorized_keys ...:** 11
- **cat /proc/cpuinfo | grep name | wc -l:** 11
- **cat /proc/cpuinfo | grep name | head -n 1 | ...:** 11
- **free -m | grep Mem | ...:** 11
- **ls -lh $(which ls):** 11
- **which ls:** 11
- **crontab -l:** 11
- **w:** 11
- **uname -m:** 11
- **uname -a:** 11
- **whoami:** 10
- **top:** 11
- **Enter new UNIX password: :** 8
- **Enter new UNIX password_:** 8
- **rm -rf /data/local/tmp; ... wget ...:** 2

**Signatures Triggered**
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 246
- **2023753:** 246
- **ET DROP Dshield Block Listed Source group 1:** 236
- **2402000:** 236
- **ET SCAN NMAP -sS window 1024:** 123
- **2009582:** 123
- **ET HUNTING RDP Authentication Bypass Attempt:** 103
- **2034857:** 103
- **ET INFO Reserved Internal IP Traffic:** 48
- **2002752:** 48
- **ET VOIP MultiTech SIP UDP Overflow:** 26
- **2003237:** 26
- **ET INFO CURL User Agent:** 20
- **2002824:** 20
- **ET CINS Active Threat Intelligence Poor Reputation IP group 50:** 16

**Users / Login Attempts**
- **345gs5662d34/345gs5662d34:** 10
- **admin/admin2018:** 5
- **ftpuser/ftppassword:** 4
- **centos/centos2002:** 4
- **supervisor/supervisor2021:** 4
- **blank/99999:** 4
- **blank/22:** 4
- **user/user2006:** 4
- **ubnt/ubnt2012:** 4
- **debian/112233:** 4
- **operator/operator2024:** 4
- **operator/operator2000:** 4
- **config/config999:** 4
- **root/1nd0n3t2014:** 3
- **root/1nf04lln3t:** 3
- **root/1NFORSERVEISW32:** 3
- **root/1Nt3gr4t10n:** 3
- **root/1nte5eR:** 3
- **root/1OsmarYesit:** 3

**Files Uploaded/Downloaded**
- **wget.sh;**: 8
- **ohsitsvegawellrip.sh||wget:** 2
- **ohsitsvegawellrip.sh||curl:** 2
- **ohsitsvegawellrip.sh)&&chmod:** 2
- **w.sh;**: 2
- **c.sh;**: 2
- **):** 1

**HTTP User-Agents**
- N/A

**SSH Clients**
- N/A

**SSH Servers**
- N/A

**Top Attacker AS Organizations**
- N/A

### Key Observations and Anomalies
- **Persistent Access Attempts:** A significant number of commands were aimed at establishing persistent access. The repeated use of commands to remove existing `.ssh` directories and add a specific public SSH key to `authorized_keys` indicates a coordinated campaign.
- **System Reconnaissance:** Attackers consistently ran commands like `uname -a`, `lscpu`, and `free -m` to gather information about the compromised system's architecture and resources.
- **Malware Download Attempts:** Multiple attempts to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`, `ohsitsvegawellrip.sh`) were observed, primarily from the IP `213.209.143.167`. This suggests attempts to install malware or cryptominers.
- **High Volume Scans:** The high count of "MS Terminal Server Traffic on Non-standard Port" and "NMAP -sS" signatures indicates widespread, automated scanning for vulnerable RDP and other services. The Dshield blocklist signature also triggered frequently, confirming that many attacking IPs are known bad actors.

This summary highlights a dynamic threat landscape with attackers employing automated tools for scanning, brute-forcing, and deploying malware. Continuous monitoring remains essential.