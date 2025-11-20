Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-26T03:01:22Z
**Timeframe:** 2025-10-26T02:20:01Z to 2025-10-26T03:00:01Z
**Files Used:**
- agg_log_20251026T022001Z.json
- agg_log_20251026T024001Z.json
- agg_log_20251026T030001Z.json

**Executive Summary**
This report summarizes 16,413 events collected from the honeypot network. The most active honeypots were Suricata, Honeytrap, and Cowrie. A significant portion of attacks originated from the IP address 109.205.211.9. The most targeted ports were 22 (SSH) and 5060 (SIP). Several CVEs were detected, with the most common being related to remote code execution and denial of service. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***
- Suricata: 5115
- Honeytrap: 4862
- Cowrie: 3914
- Ciscoasa: 1856
- Sentrypeer: 215
- Tanner: 81
- Mailoney: 137
- Redishoneypot: 49
- Adbhoney: 27
- Dionaea: 45
- H0neytr4p: 44
- ConPot: 16
- ssh-rsa: 30
- Dicompot: 9
- Miniprint: 6
- Honeyaml: 7

***Top Attacking IPs***
- 109.205.211.9: 3550
- 80.94.95.238: 1542
- 178.62.254.40: 561
- 195.199.212.141: 348
- 103.179.218.243: 356
- 46.188.119.26: 336
- 107.170.36.5: 251
- 54.38.52.18: 268
- 103.250.11.207: 261
- 193.24.211.28: 236
- 107.172.76.10: 203
- 222.98.122.37: 184
- 134.122.70.79: 90
- 167.71.221.242: 125
- 167.250.224.25: 131
- 196.251.80.153: 99
- 185.243.5.121: 111
- 68.183.149.135: 109

***Top Targeted Ports/Protocols***
- 22: 589
- 5060: 215
- 8333: 184
- 25: 137
- 5903: 129
- 5901: 120
- 80: 78
- 6379: 37
- 23: 61
- TCP/22: 63
- 5905: 81
- 5904: 77
- 443: 27

***Most Common CVEs***
- CVE-2002-1149
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2018-7600 CVE-2018-7600
- CVE-2006-2369
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:

***Signatures Triggered***
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET DROP Spamhaus DROP Listed Traffic Inbound
- ET CINS Active Threat Intelligence Poor Reputation IP

***Users / Login Attempts***
- root/freepbx2222
- root/freepbx770
- 345gs5662d34/345gs5662d34
- root/daspasswort
- thomas/1234
- root/adminHW
- root/
- user/simon1
- hiroshi/hiroshi
- blue/blue
- jose/123
- colin/colin
- hassan/hassan
- firefart/firefart

***Files Uploaded/Downloaded***
- wget.sh
- w.sh
- c.sh
- welcome.jpg
- writing.jpg
- tags.jpg
- ip

***HTTP User-Agents***
- Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0.0.0 Safari/537.36

***SSH Clients and Servers***
- No specific SSH client or server versions were logged in the provided data.

***Top Attacker AS Organizations***
- No specific AS organizations were logged in the provided data.

**Key Observations and Anomalies**
- A large number of commands are focused on disabling SSH security features and adding a new authorized key, indicating a clear intent to establish persistent access.
- The presence of commands to gather system information (CPU, memory, etc.) is likely for reconnaissance purposes, possibly to tailor future attacks or assess the honeypot's resources.
- The variety of usernames and passwords attempted in login attempts suggests the use of common credential lists.

This concludes the Honeypot Attack Summary Report.