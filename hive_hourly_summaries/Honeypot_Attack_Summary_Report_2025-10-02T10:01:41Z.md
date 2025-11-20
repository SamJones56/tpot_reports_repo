Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T10:01:22Z
**Timeframe:** 2025-10-02T09:20:01Z to 2025-10-02T10:00:01Z
**Files Used:** agg_log_20251002T092001Z.json, agg_log_20251002T094001Z.json, agg_log_20251002T100001Z.json

### Executive Summary
This report summarizes 14,294 attacks recorded across three log files. The most targeted honeypot was Cowrie, with a total of 5,978 events. The most active attacking IP was 41.38.25.159. The most targeted port was 445/TCP (SMB). Several CVEs were detected, with CVE-2002-0013 and CVE-2002-0012 being the most frequent.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 5978
* Dionaea: 2689
* Mailoney: 1641
* Suricata: 1490
* Honeytrap: 1154
* Ciscoasa: 1042
* Redishoneypot: 79
* ElasticPot: 45
* H0neytr4p: 40
* Sentrypeer: 34
* Dicompot: 22
* Tanner: 24
* Adbhoney: 16
* ConPot: 13
* Ipphoney: 3
* Honeyaml: 4

**Top Attacking IPs:**
* 41.38.25.159
* 176.65.141.117
* 88.214.50.58
* 57.128.190.44
* 38.57.234.191
* 34.131.131.43
* 124.156.238.210
* 92.63.197.55
* 185.156.73.166
* 92.63.197.59
* 8.243.64.201
* 188.166.61.89

**Top Targeted Ports/Protocols:**
* 445
* 25
* 22
* 2525
* 6379
* 8333
* 23
* 9200
* 443
* 5060
* 1433
* TCP/8080
* 5901
* TCP/1080

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
* CVE-2021-3449 CVE-2021-3449
* CVE-2019-11500 CVE-2019-11500
* CVE-2001-0414
* CVE-2006-2369
* CVE-2023-26801 CVE-2023-26801
* CVE-2021-35394 CVE-2021-35394

**Commands Attempted by Attackers:**
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
* cat /proc/cpuinfo | grep name | wc -l
* uname -a
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
* ls -lh $(which ls)
* crontab -l
* whoami
* Enter new UNIX password:

**Signatures Triggered:**
* ET SCAN MS Terminal Server Traffic on Non-standard Port
* ET DROP Dshield Block Listed Source group 1
* ET HUNTING RDP Authentication Bypass Attempt
* ET SCAN NMAP -sS window 1024
* ET INFO Reserved Internal IP Traffic
* GPL SNMP request udp
* ET INFO CURL User Agent

**Users / Login Attempts:**
* 345gs5662d34/345gs5662d34
* root/3245gs5662d34
* old/sor123in
* old/3245gs5662d34
* root/2glehe5t24th1issZs
* root/nPSpP4PBW0
* agent/agent
* test/zhbjETuyMffoL8F

**Files Uploaded/Downloaded:**
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass
* fonts.gstatic.com
* ie8.css?ver=1.0
* html5.js?ver=3.7.3

**HTTP User-Agents:**
* None recorded

**SSH Clients:**
* None recorded

**SSH Servers:**
* None recorded

**Top Attacker AS Organizations:**
* None recorded

### Key Observations and Anomalies
* A significant number of commands are related to reconnaissance and establishing persistence, such as gathering system information (`uname -a`, `cat /proc/cpuinfo`) and manipulating SSH keys.
* The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, indicating attempts to install a persistent backdoor.
* A large number of attacks are downloading files with `.urbotnetisass` extension, suggesting a coordinated botnet campaign.
* The most frequent attacking IP, 41.38.25.159, was responsible for a large volume of attacks across different honeypots.
* The prevalence of SMB port 445 scans continues to be a dominant feature of these attacks.
