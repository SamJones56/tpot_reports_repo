# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T03:01:24Z
**Timeframe:** 2025-10-19T02:20:01Z to 2025-10-19T03:00:01Z
**Files Used:**
- agg_log_20251019T022001Z.json
- agg_log_20251019T024001Z.json
- agg_log_20251019T030001Z.json

## Executive Summary
This report summarizes honeypot activity over a six-minute interval, revealing a total of 17,950 events. The majority of these attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant number of events were also logged by Suricata and Honeytrap, highlighting active network scanning and exploitation attempts. The most frequently observed attack vector was SIP VoIP abuse, associated with CVE-2005-4050. A wide range of other CVEs were also detected, pointing to a diverse set of vulnerabilities being targeted. Most commands executed by attackers were focused on reconnaissance and establishing persistence.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 8292
- Suricata: 3294
- Honeytrap: 3118
- Sentrypeer: 1958
- Ciscoasa: 1064
- Tanner: 68
- Mailoney: 40
- Dionaea: 33
- ConPot: 18
- H0neytr4p: 15
- Redishoneypot: 12
- Miniprint: 11
- Honeyaml: 8
- Dicompot: 7
- Adbhoney: 6
- ElasticPot: 6

### Top Attacking IPs
- 94.126.59.114
- 72.146.232.13
- 198.23.190.58
- 23.94.26.58
- 194.50.16.73
- 81.19.135.103
- 198.12.68.114
- 123.60.212.114
- 88.210.63.16
- 196.251.88.103
- 107.170.36.5
- 210.79.142.221

### Top Targeted Ports/Protocols
- 5060
- 22
- UDP/5060
- 5903
- TCP/22
- 5901
- 8333
- 80
- TCP/80
- 3388
- 25

### Most Common CVEs
- CVE-2005-4050
- CVE-2024-4577
- CVE-2021-41773
- CVE-2021-42013
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2023-49103
- CVE-2002-0953
- CVE-2002-0013
- CVE-2002-0012
- CVE-2021-3449
- CVE-2025-10442
- CVE-2001-0414
- CVE-2019-11500

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:
- uname -s -v -n -r -m
- User-Agent: Mozilla/5.0 (compatible; CyberOKInspect/1.0; +https://www.cyberok.ru/policy.html)

### Signatures Triggered
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN Potential SSH Scan
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- GPL INFO SOCKS Proxy attempt
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET INFO CURL User Agent
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET CINS Active Threat Intelligence Poor Reputation IP group 47
- ET CINS Active Threat Intelligence Poor Reputation IP group 50
- ET CINS Active Threat Intelligence Poor Reputation IP group 3

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- admin/admin2012
- ftpuser/ftppassword
- root/123@Robert
- root/3245gs5662d34
- guest/guest2009
- admin/admin2006
- centos/centos2022
- root/453094323

### Files Uploaded/Downloaded
- sh
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- welcome.jpg)
- writing.jpg)
- tags.jpg)
- policy.html
- policy.html)

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients
- No SSH clients were logged in this timeframe.

### SSH Servers
- No SSH servers were logged in this timeframe.

### Top Attacker AS Organizations
- No AS organizations were logged in this timeframe.

## Key Observations and Anomalies
- The high number of Cowrie events suggests a focus on brute-force SSH attacks, a common tactic for gaining initial access.
- The prevalence of the "ET VOIP MultiTech SIP UDP Overflow" signature indicates that attackers are actively targeting VoIP systems.
- The variety of CVEs being exploited highlights the need for broad-spectrum vulnerability management.
- The commands executed post-compromise are typical of attackers looking to gather system information and secure their foothold.
- A notable command attempts to add an SSH key to the authorized_keys file, a clear indicator of an attempt to establish persistent access.
