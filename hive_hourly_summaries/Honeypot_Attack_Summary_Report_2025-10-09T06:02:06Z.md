Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T06:01:36Z
**Timeframe:** 2025-10-09T05:20:01Z - 2025-10-09T06:00:01Z
**Files Used:**
- agg_log_20251009T052001Z.json
- agg_log_20251009T054001Z.json
- agg_log_20251009T060001Z.json

**Executive Summary**

This report summarizes 18,920 malicious events recorded across the honeypot network. The most engaged honeypot was Cowrie, a testament to the high volume of SSH and Telnet-based attacks. A significant portion of the attacks originated from the IP address 190.35.66.46, which was involved in 1,849 events. The most targeted port was 445/TCP, a common target for SMB exploits. A number of CVEs were detected, including CVE-2002-0013, CVE-2002-0012, CVE-1999-0517, CVE-2001-0414 and CVE-2019-11500. A variety of commands were attempted by attackers, with `uname -a` and `whoami` being the most frequent, indicating that attackers are actively trying to gather information about the systems they compromise.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 5,857
- Dionaea: 3,113
- Suricata: 3,622
- Honeytrap: 3,600
- Ciscoasa: 1,693
- Mailoney: 872
- Sentrypeer: 56
- H0neytr4p: 30
- Tanner: 25
- Adbhoney: 13
- Redishoneypot: 12
- ConPot: 7
- Honeyaml: 6
- Miniprint: 4

***Top Attacking IPs***

- 190.35.66.46: 1,849
- 46.162.209.20: 1,452
- 86.54.42.238: 821
- 80.94.95.238: 814
- 203.82.41.210: 462
- 45.78.193.100: 339
- 110.41.68.168: 325
- 77.110.107.92: 327
- 49.247.35.31: 416
- 220.80.223.144: 290
- 152.32.145.111: 292
- 143.198.195.7: 322
- 212.33.235.243: 149
- 77.105.133.167: 153
- 89.111.172.19: 129
- 114.219.56.203: 315
- 202.83.162.167: 169
- 201.249.87.203: 159
- 36.95.221.140: 159
- 14.103.127.242: 122

***Top Targeted Ports/Protocols***

- 445: 2,314
- TCP/445: 1,447
- 22: 794
- 25: 872
- 1027: 351
- TCP/21: 214
- 5903: 203
- 8333: 138
- 21: 102
- 23: 100
- 5901: 73
- 5060: 56
- 5909: 50
- 5908: 49
- 5907: 48
- 27017: 37
- 27018: 35
- TCP/1027: 18
- 5672: 18
- 22022: 19

***Most Common CVEs***

- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2001-0414
- CVE-2019-11500

***Commands Attempted by Attackers***

- uname -a: 33
- whoami: 33
- lscpu | grep Model: 33
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 32
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 32
- lockr -ia .ssh: 32
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 32
- cat /proc/cpuinfo | grep name | wc -l: 32
- Enter new UNIX password: : 31
- Enter new UNIX password: 31
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 32
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 32
- crontab -l: 32
- w: 32
- uname -m: 32
- cat /proc/cpuinfo | grep model | grep name | wc -l: 32
- top: 31
- uname: 32
- ls -lh $(which ls): 31
- which ls: 31

***Signatures Triggered***

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1,445
- 2024766: 1,445
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 600
- 2023753: 600
- ET DROP Dshield Block Listed Source group 1: 490
- 2402000: 490
- ET SCAN NMAP -sS window 1024: 160
- 2009582: 160
- ET FTP FTP PWD command attempt without login: 107
- 2010735: 107
- ET FTP FTP CWD command attempt without login: 104
- 2010731: 104
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 25
- 2403346: 25
- ET CINS Active Threat Intelligence Poor Reputation IP group 41: 20
- 2403340: 20
- ET HUNTING RDP Authentication Bypass Attempt: 23
- 2034857: 23

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34: 32
- root/root333: 6
- operator/operator88: 6
- support/1212: 6
- supervisor/asdfgh: 6
- support/support123: 6
- unknown/unknown66: 6
- steam/steam@2025: 6
- user/1994: 4
- nobody/nobody44: 4
- default/p@ssword: 4
- a/123123: 4
- supervisor/supervisor12345678: 4
- guest/webmaster: 4
- david/123123: 4
- support/support0: 4
- user1/P@ssw0rd123: 3
- david/1234567890: 3
- nexus/P@ssw0rd@2025: 3
- it/it21: 3

***Files Uploaded/Downloaded***

- 11: 6
- fonts.gstatic.com: 6
- css?family=Libre+Franklin...: 6
- ie8.css?ver=1.0: 6
- html5.js?ver=3.7.3: 6
- policy.html: 2
- policy.html): 1
- bot.html): 1

***HTTP User-Agents***

No data available.

***SSH Clients and Servers***

No data available.

***Top Attacker AS Organizations***

No data available.

**Key Observations and Anomalies**

- The high number of attacks on port 445/TCP and the triggering of the DoublePulsar Backdoor signature suggest that there is a significant amount of scanning and exploitation activity related to the EternalBlue vulnerability.
- The most common commands attempted by attackers are focused on system information gathering, which is a typical first step after gaining initial access to a system.
- The attacker at 190.35.66.46 was particularly aggressive, responsible for nearly 10% of all recorded events. This IP should be monitored closely.
- The variety of credentials used in login attempts suggests that attackers are using a wide range of default and common passwords.
- No HTTP User-Agents, SSH clients, or server versions were recorded, which may indicate that the attacks are primarily automated and not being conducted from standard interactive shells.

This concludes the Honeypot Attack Summary Report.
