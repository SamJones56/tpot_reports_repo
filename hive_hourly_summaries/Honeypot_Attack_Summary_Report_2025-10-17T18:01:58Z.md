Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T18:01:36Z
**Timeframe:** 2025-10-17T17:20:01Z - 2025-10-17T18:00:01Z
**Files Used:**
- agg_log_20251017T172001Z.json
- agg_log_20251017T174001Z.json
- agg_log_20251017T180001Z.json

**Executive Summary**
This report summarizes 10,877 events recorded across multiple honeypots. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. The most prominent attacking IP address was 72.146.232.13. A significant number of commands executed by attackers involved reconnaissance and attempts to deploy malware.

**Detailed Analysis**

**Attacks by Honeypot**
- Cowrie: 5236
- Honeytrap: 1701
- Ciscoasa: 1391
- Sentrypeer: 973
- Suricata: 889
- ElasticPot: 435
- Dionaea: 63
- Redishoneypot: 48
- Adbhoney: 38
- Tanner: 34
- Miniprint: 27
- H0neytr4p: 21

**Top Attacking IPs**
- 72.146.232.13: 918
- 172.86.95.115: 379
- 172.86.95.98: 362
- 110.53.126.241: 351
- 103.172.205.139: 358
- 142.134.228.223: 306
- 70.30.91.23: 308
- 27.254.149.199: 242
- 190.119.198.81: 242
- 190.162.113.74: 242
- 103.172.28.62: 288
- 203.210.135.87: 227
- 180.76.116.176: 144
- 72.167.52.254: 194
- 107.170.36.5: 151
- 68.183.149.135: 112
- 179.127.26.32: 105
- 103.114.146.178: 146
- 221.179.57.254: 143

**Top Targeted Ports/Protocols**
- 5060: 973
- 22: 879
- 9200: 435
- 8333: 117
- 5904: 75
- 5905: 76
- TCP/22: 38
- 6379: 48
- 80: 34
- TCP/80: 29
- 23: 23
- 3306: 23
- 5901: 43
- 5902: 39
- 5903: 41

**Most Common CVEs**
- CVE-2002-0013 CVE-2002-0012
- CVE-2005-4050

**Commands Attempted by Attackers**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 26
- lockr -ia .ssh: 26
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys: 26
- cat /proc/cpuinfo | grep name | wc -l: 26
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 26
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 26
- ls -lh $(which ls): 26
- which ls: 26
- crontab -l: 26
- w: 26
- uname -m: 26
- uname -a: 26
- whoami: 26
- Enter new UNIX password: : 18

**Signatures Triggered**
- ET DROP Dshield Block Listed Source group 1: 211
- 2402000: 211
- ET SCAN NMAP -sS window 1024: 122
- 2009582: 122
- ET INFO Reserved Internal IP Traffic: 48
- 2002752: 48
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 48
- 2023753: 48
- ET INFO CURL User Agent: 26
- 2002824: 26
- ET SCAN Potential SSH Scan: 22
- 2001219: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 52: 18
- 2403351: 18

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 25
- root/123@Robert: 12
- ftpuser/ftppassword: 6
- root/3245gs5662d34: 7
- guest/guest2022: 4
- ubnt/alpine: 4
- nobody/5555: 4
- nobody/1qaz2wsx: 4
- support/support2023: 4
- default/default2022: 4

**Files Uploaded/Downloaded**
- wget.sh;: 16
- binary.sh;: 10
- binary.sh: 10
- w.sh;: 4
- c.sh;: 4

**HTTP User-Agents**
- No HTTP User-Agents were recorded in this timeframe.

**SSH Clients**
- No specific SSH clients were recorded in this timeframe.

**SSH Servers**
- No specific SSH servers were recorded in this timeframe.

**Top Attacker AS Organizations**
- No attacker AS organizations were recorded in this timeframe.

**Key Observations and Anomalies**
- A recurring attack pattern involved attempts to modify the `.ssh/authorized_keys` file with the same SSH key, indicating a coordinated campaign.
- Attackers frequently used reconnaissance commands such as `uname -a`, `whoami`, and `lscpu` to gather system information before attempting further exploitation.
- Several attackers attempted to download and execute shell scripts (e.g., `wget.sh`, `w.sh`, `c.sh`, `binary.sh`), suggesting a malware infection campaign.
- The IP address 72.146.232.13 was consistently the most active attacker across all three time windows.
- There is a strong focus on SSH (port 22), SIP (port 5060), and Elasticsearch (port 9200) services.
- The Suricata logs show a high number of events from blocklisted IPs (Dshield), which effectively reduces the attack surface.
