Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T09:01:26Z
**Timeframe:** 2025-10-02T08:20:01Z to 2025-10-02T09:00:01Z
**Files Used:**
- agg_log_20251002T082001Z.json
- agg_log_20251002T084001Z.json
- agg_log_20251002T090001Z.json

**Executive Summary**

This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three log files. A total of 13,427 attacks were recorded, with a significant number targeting the Honeytrap and Cowrie honeypots. The most prominent attack vector was via IP address 103.220.207.174. Port 25 (SMTP) was the most targeted port. Several CVEs were exploited, with CVE-2021-3449 being the most frequent. Attackers attempted a variety of commands, primarily focused on establishing remote access and control.

**Detailed Analysis**

***Attacks by honeypot:***
- Honeytrap: 4658
- Cowrie: 3486
- Mailoney: 1696
- Suricata: 1300
- Ciscoasa: 1033
- Dionaea: 1008
- Redishoneypot: 80
- Tanner: 49
- H0neytr4p: 35
- Adbhoney: 25
- Sentrypeer: 22
- Honeyaml: 15
- ConPot: 11
- Dicompot: 4
- Miniprint: 2
- Ipphoney: 1
- ElasticPot: 1
- Medpot: 1

***Top attacking IPs:***
- 103.220.207.174: 3645
- 176.65.141.117: 1640
- 41.38.25.159: 675
- 185.156.73.166: 362
- 92.63.197.55: 356
- 92.63.197.59: 319
- 81.4.100.134: 257
- 31.58.171.28: 229
- 211.227.185.88: 229
- 103.59.94.223: 232
- 91.237.163.114: 221
- 51.222.85.63: 206

***Top targeted ports/protocols:***
- 25: 1696
- 445: 866
- 22: 594
- 6379: 73
- 8333: 93
- 1433: 62
- TCP/1433: 68
- 80: 52
- 23: 53
- 443: 35
- 27017: 34
- 5060: 22

***Most common CVEs:***
- CVE-2021-3449: 7
- CVE-2019-11500: 5
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2003-0825: 4
- CVE-2025-57819 CVE-2025-57819: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2023-26801 CVE-2023-26801: 1
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1

***Commands attempted by attackers:***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 19
- `lockr -ia .ssh`: 19
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 19
- `uname -a`: 9
- `top`: 8
- `uname`: 8
- `whoami`: 8
- `lscpu | grep Model`: 8
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 8
- `cat /proc/cpuinfo | grep name | wc -l`: 7
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 7
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 7
- `ls -lh $(which ls)`: 7
- `which ls`: 7
- `crontab -l`: 7
- `w`: 7
- `uname -m`: 7
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 7

***Signatures triggered:***
- ET DROP Dshield Block Listed Source group 1: 339
- 2402000: 339
- ET SCAN NMAP -sS window 1024: 166
- 2009582: 166
- ET SCAN Suspicious inbound to MSSQL port 1433: 67
- 2010935: 67
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 30
- 2403349: 30
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 31
- 2403341: 31
- ET CINS Active Threat Intelligence Poor Reputation IP group 43: 20
- 2403342: 20
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 18
- 2403346: 18

***Users / login attempts:***
- 345gs5662d34/345gs5662d34: 18
- root/nPSpP4PBW0: 9
- superadmin/admin123: 7
- foundry/foundry: 6
- geoserver/geoserver: 5
- root/LeitboGi0ro: 6
- root/3245gs5662d34: 5
- test/zhbjETuyMffoL8F: 5
- sa/: 3
- root/admin@123: 2
- root/adminHW: 2

***Files uploaded/downloaded:***
- wget.sh;: 8
- 11: 9
- fonts.gstatic.com: 9
- css?family=Libre+Franklin...: 9
- ie8.css?ver=1.0: 9
- html5.js?ver=3.7.3: 9
- arm.urbotnetisass;: 3
- arm.urbotnetisass: 3
- arm5.urbotnetisass;: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass;: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass;: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass;: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass;: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass;: 3
- mipsel.urbotnetisass: 3

***HTTP User-Agents:***
- Not available in logs.

***SSH clients and servers:***
- Not available in logs.

***Top attacker AS organizations:***
- Not available in logs.

**Key Observations and Anomalies**

- The high volume of attacks from a single IP (103.220.207.174) suggests a targeted or persistent campaign.
- The prevalence of commands related to SSH key manipulation indicates attempts to establish persistent backdoor access.
- A significant number of attacks on port 25 (SMTP) were observed, likely related to spam or phishing campaigns.
- The `urbotnetisass` malware was repeatedly downloaded, indicating a botnet propagation attempt.
- The commands to gather system information (`uname`, `lscpu`, etc.) are typical reconnaissance activities performed by attackers to tailor their exploits.

This concludes the Honeypot Attack Summary Report. Continued monitoring is recommended.
