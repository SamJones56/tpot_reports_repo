Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-29T16:01:45Z
**Timeframe:** 2025-09-29T15:21:06Z to 2025-09-29T16:00:01Z
**Files Used:**
- agg_log_20250929T152106Z.json
- agg_log_20250929T154048Z.json
- agg_log_20250929T160001Z.json

**Executive Summary**

This report summarizes 12,721 recorded events from the T-Pot honeypot network, aggregated from three recent log files. The majority of attacks were detected by the Cowrie and Suricata honeypots. A significant portion of the attacks originated from IP address 121.52.153.77. The most targeted port was TCP/445, commonly associated with SMB. Several CVEs were detected, with CVE-2021-44228 (Log4Shell) being the most frequent. Attackers attempted a variety of commands, many of which were aimed at reconnaissance and establishing persistence.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 5092
- Suricata: 2931
- Honeytrap: 2039
- Mailoney: 835
- Ciscoasa: 1430
- Dionaea: 157
- Tanner: 38
- Redishoneypot: 46
- Adbhoney: 32
- H0neytr4p: 26
- ElasticPot: 19
- Heralding: 22
- Sentrypeer: 23
- Ipphoney: 16
- ConPot: 8
- Dicompot: 3
- ssh-rsa: 2
- Honeyaml: 2

***Top Attacking IPs***
- 121.52.153.77: 1492
- 86.54.42.238: 821
- 103.140.249.62: 332
- 51.178.24.221: 330
- 102.88.137.80: 308
- 185.255.91.28: 324
- 35.185.154.63: 337
- 185.156.73.167: 374
- 91.237.163.113: 375
- 185.156.73.166: 368
- 92.63.197.55: 361
- 45.249.245.22: 292
- 92.63.197.59: 331
- 197.5.145.150: 265
- 209.141.43.77: 267
- 94.41.18.235: 235
- 36.91.166.34: 209
- 45.61.187.220: 204
- 113.249.101.146: 197
- 182.44.78.224: 130

***Top Targeted Ports/Protocols***
- TCP/445: 1537
- 25: 829
- 22: 671
- 1433: 88
- 8333: 80
- 23: 88
- TCP/1433: 67
- 10443: 58
- 80: 36
- TCP/80: 49
- 6379: 42
- 4444: 34
- TCP/22: 28
- 8000: 23
- 24000: 22
- 8181: 23
- 9090: 11
- 5001: 12
- 9200: 11
- 8081: 10

***Most Common CVEs***
- CVE-2021-44228: 37
- CVE-2002-0013, CVE-2002-0012: 6
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 5
- CVE-2021-3449: 5
- CVE-2019-11500: 4
- CVE-2024-3721: 3
- CVE-1999-0183: 1

***Commands Attempted by Attackers***
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 28
- lockr -ia .ssh: 28
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 28
- cat /proc/cpuinfo | grep name | wc -l: 29
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 29
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 29
- ls -lh $(which ls): 29
- which ls: 29
- crontab -l: 29
- w: 29
- uname -m: 29
- cat /proc/cpuinfo | grep model | grep name | wc -l: 29
- top: 29
- uname: 29
- uname -a: 32
- whoami: 29
- lscpu | grep Model: 29
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 29
- Enter new UNIX password: : 22
- Enter new UNIX password:: 22

***Signatures Triggered***
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1534
- 2024766: 1534
- ET DROP Dshield Block Listed Source group 1: 299
- 2402000: 299
- ET SCAN NMAP -sS window 1024: 200
- 2009582: 200
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 118
- 2023753: 118
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Suspicious inbound to MSSQL port 1433: 56
- 2010935: 56
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 39
- 2400031: 39
- ET ATTACK_RESPONSE Possible MS CMD Shell opened on local system: 31
- 2008953: 31
- ET INFO CURL User Agent: 31
- 2002824: 31
- GPL INFO SOCKS Proxy attempt: 14
- 2100615: 14

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 25
- root/nPSpP4PBW0: 13
- seekcy/Joysuch@Locate2022: 5
- foundry/foundry: 4
- seekcy/Joysuch@Locate2023: 4
- superadmin/admin123: 5
- root/3245gs5662d34: 5
- seekcy/3245gs5662d34: 5
- root/Aa112211.: 5
- seekcy/Joysuch@Locate2020: 5
- allinone/allinone: 3
- mysql/aini130.: 3
- ubuntu/asd123456: 3
- root/LeitboGi0ro: 3
- test/zhbjETuyMffoL8F: 5
- seekcy/Joysuch@Locate2024: 4
- oguz/oguz: 3
- seekcy/Joysuch@Locate2025: 3
- work/workwork: 3
- root/zhbjETuyMffoL8F: 3

***Files Uploaded/Downloaded***
- wget.sh;: 8
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
- w.sh;: 2
- c.sh;: 2
- Mozi.m%20dlink.mips%27$: 1

***HTTP User-Agents***
- No HTTP User-Agents were detected in this period.

***SSH Clients and Servers***
- No specific SSH clients or servers were identified in the logs for this period.

***Top Attacker AS Organizations***
- No attacker AS organizations were identified in the logs for this period.

**Key Observations and Anomalies**

- A large number of attacks are attributed to a single IP address, 121.52.153.77, which primarily targeted SMB on port 445. The associated Suricata signature points to the DoublePulsar backdoor.
- The commands executed by attackers are consistent with initial reconnaissance and attempts to establish persistence by adding an SSH key to `authorized_keys`.
- There is evidence of attackers attempting to download and execute malicious scripts (`.sh` files) and binaries (`.urbotnetisass`).
- The prevalence of CVE-2021-44228 (Log4Shell) indicates that this vulnerability is still being actively exploited.
- A significant amount of scanning activity was observed, particularly from Nmap.
