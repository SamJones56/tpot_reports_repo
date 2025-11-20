Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21T04:01:32Z
**Timeframe:** 2025-10-21T03:20:01Z to 2025-10-21T04:00:01Z
**Files Used:**
- agg_log_20251021T032001Z.json
- agg_log_20251021T034001Z.json
- agg_log_20251021T040001Z.json

**Executive Summary**

This report summarizes 7814 attacks recorded by the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. A significant number of attacks were also observed on web application and IoT device honeypots. The most frequent attacks originated from IP address 72.146.232.13. Several CVEs were targeted, with CVE-2024-3721 being the most common. Attackers attempted a variety of commands, primarily focused on reconnaissance and establishing control over the compromised system.

**Detailed Analysis**

***Attacks by honeypot***
- Cowrie: 5304
- Honeytrap: 1422
- Suricata: 631
- Sentrypeer: 229
- Dionaea: 34
- Ciscoasa: 44
- H0neytr4p: 54
- Tanner: 12
- Mailoney: 14
- Redishoneypot: 20
- ConPot: 8
- Honeyaml: 10
- Adbhoney: 29
- ElasticPot: 3

***Top attacking IPs***
- 72.146.232.13: 573
- 152.42.203.0: 400
- 151.236.62.110: 362
- 103.52.37.10: 357
- 146.190.93.207: 312
- 62.193.106.227: 257
- 212.64.199.58: 322
- 184.168.29.142: 298
- 107.175.70.59: 263
- 87.106.35.227: 238
- 185.243.5.158: 216
- 36.88.28.122: 228
- 102.88.137.145: 174
- 222.107.251.147: 179
- 85.18.236.229: 169
- 103.49.238.251: 134
- 190.162.113.74: 154
- 43.160.204.100: 114
- 103.134.154.55: 104
- 107.170.36.5: 144

***Top targeted ports/protocols***
- 22: 722
- 5060: 229
- 8333: 121
- 2002: 78
- 5904: 73
- 5905: 71
- 443: 52
- 5901: 40
- 5902: 36
- 5903: 35
- 6379: 18
- 15000: 16
- 15001: 16
- 25: 9
- 8000: 10
- 49152: 14
- 9001: 10
- 8087: 8
- 10333: 8
- 7002: 7

***Most common CVEs***
- CVE-2024-3721: 6
- CVE-2019-11500: 1
- CVE-2002-0013: 2
- CVE-2002-0012: 2
- CVE-1999-0517: 1
- CVE-2021-3449: 1
- CVE-2025-34036: 1

***Commands attempted by attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 35
- lockr -ia .ssh: 35
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 35
- cat /proc/cpuinfo | grep name | wc -l: 35
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 35
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 34
- ls -lh $(which ls): 35
- which ls: 35
- crontab -l: 35
- w: 35
- uname -m: 35
- cat /proc/cpuinfo | grep model | grep name | wc -l: 35
- top: 35
- uname: 35
- uname -a: 35
- whoami: 35
- lscpu | grep Model: 35
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 35
- Enter new UNIX password: : 31
- Enter new UNIX password::: 31
- chmod 0755 /data/local/tmp/nohup: 1
- chmod 0755 /data/local/tmp/trinity: 1

***Signatures triggered***
- ET DROP Dshield Block Listed Source group 1: 191
- 2402000: 191
- ET SCAN NMAP -sS window 1024: 85
- 2009582: 85
- ET INFO Reserved Internal IP Traffic: 43
- 2002752: 43
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 36
- 2023753: 36
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 16
- 2010939: 16
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 12
- 2403350: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 7
- 2403344: 7
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 5
- 2403341: 5
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 4
- 2403343: 4
- ET WEB_SPECIFIC_APPS TBK DVR-4104/4216 Command Injection Attempt (CVE-2024-3721): 4
- 2061111: 4

***Users / login attempts***
- 345gs5662d34/345gs5662d34: 34
- user01/Password01: 14
- deploy/1234: 3
- jenkins/jenkins2025: 3
- user/qwer1234: 3
- deploy/123123: 7
- artem/123: 4
- helloworld/helloworld: 4
- frappe/2024: 3
- root/Abcabc123: 3
- root/Abcd2024: 3
- ali/alipass: 3
- root/Ceshi123: 3
- sky/123: 3
- ftpuser/Aa@123456: 3
- deploy/3245gs5662d34: 6
- test/pass: 3
- root/Lk@123456: 3
- etienne/etienne123: 3

***Files uploaded/downloaded***
- string.js: 1

***HTTP User-Agents***
- No user agents recorded.

***SSH clients and servers***
- No SSH clients or servers recorded.

***Top attacker AS organizations***
- No AS organizations recorded.

**Key Observations and Anomalies**

- A large number of commands executed are related to system reconnaissance, such as checking CPU information, memory, and user activity. This is a common tactic for attackers to understand the environment they have compromised.
- The command to add an SSH key to `authorized_keys` is a clear indicator of an attempt to establish persistent access to the honeypot.
- The presence of CVE-2024-3721, related to a command injection vulnerability, suggests that attackers are actively exploiting recent vulnerabilities.
- The file `string.js` was uploaded, which could be a component of a larger attack, such as a web-based skimmer or a part of a malicious toolkit. Further analysis of this file is recommended.
- The lack of HTTP user agents, SSH clients, and AS organization data might indicate misconfiguration in logging or that the attacks are not leveraging these protocols in a way that is being logged.
