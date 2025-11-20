Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-08T13:01:41Z
**Timeframe:** 2025-10-08T12:20:01Z to 2025-10-08T13:00:01Z
**Files Used:**
- agg_log_20251008T122001Z.json
- agg_log_20251008T124001Z.json
- agg_log_20251008T130001Z.json

### Executive Summary

This report summarizes 12,894 events collected from the honeypot network. The majority of activity was captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based attacks. A significant number of attacks originated from IP address 20.164.21.26. The most frequently targeted ports were 445 (SMB) and 22 (SSH). Attackers were observed attempting to execute reconnaissance commands and modify SSH authorized_keys to gain persistent access. Several CVEs were detected, with the most frequent being related to remote code execution vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 6234
- Honeytrap: 1738
- Ciscoasa: 1671
- Mailoney: 886
- Dionaea: 953
- Suricata: 1034
- Sentrypeer: 192
- Redishoneypot: 23
- H0neytr4p: 28
- Tanner: 25
- Miniprint: 55
- ConPot: 9
- ElasticPot: 8
- Ipphoney: 6
- Heralding: 16
- Wordpot: 1
- Honeyaml: 10
- Adbhoney: 3
- ssh-rsa: 2

**Top Attacking IPs:**
- 20.164.21.26: 1253
- 182.176.149.227: 911
- 86.54.42.238: 821
- 128.199.52.185: 581
- 139.167.46.226: 470
- 107.173.140.58: 203
- 79.117.123.72: 263
- 167.172.153.88: 260
- 187.33.251.218: 173
- 154.88.2.70: 170
- 41.226.27.251: 125
- 107.172.252.231: 119
- 83.168.108.5: 119
- 161.49.89.39: 114
- 186.56.11.17: 109
- 41.128.181.199: 109
- 107.174.55.72: 181
- 202.83.162.167: 146
- 79.116.10.214: 219
- 196.251.84.140: 118

**Top Targeted Ports/Protocols:**
- 445: 915
- 22: 900
- 25: 888
- 5060: 192
- 5903: 100
- TCP/5900: 97
- 9100: 55
- 23: 76
- 5901: 88
- 8333: 56
- 5908: 49
- 5907: 49
- 5909: 49
- TCP/22: 27
- 6379: 18
- 3333: 35
- 8069: 23
- 443: 23
- 17001: 16
- UDP/161: 16

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2005-4050

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 24
- lockr -ia .ssh: 24
- cd ~ && rm -rf .ssh && ...: 24
- Enter new UNIX password: : 20
- Enter new UNIX password:: 20
- cat /proc/cpuinfo | grep name | wc -l: 20
- uname -a: 20
- whoami: 20
- uname -m: 20
- w: 20
- crontab -l: 20
- top: 20
- cat /proc/cpuinfo | ...: 20
- free -m | grep Mem | ...: 20
- which ls: 20
- ls -lh $(which ls): 20
- lscpu | grep Model: 20
- df -h | head -n 2 | ...: 20
- cat /proc/cpuinfo | grep model | ...: 20
- uname: 20

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1 / 2402000: 277
- ET SCAN NMAP -sS window 1024 / 2009582: 148
- ET DROP Spamhaus DROP Listed Traffic Inbound group 41 / 2400040: 100
- ET INFO Reserved Internal IP Traffic / 2002752: 60
- ET SCAN Potential SSH Scan / 2001219: 23
- ET INFO CURL User Agent / 2002824: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 2 / 2403301: 16
- ET DROP Spamhaus DROP Listed Traffic Inbound group 11 / 2400010: 11
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28 / 2400027: 12
- GPL SNMP request udp / 2101417: 8

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 22
- sysadmin/sysadmin@1: 15
- supervisor/supervisor1234: 6
- root/pfsense: 4
- support/support123456: 4
- guest/guest5: 6
- root/freenas: 6
- blank/attadmin: 6
- ubnt/ubnt4: 4
- support/supp0r7: 4
- root/44444444: 6
- 12345/12345: 6
- sysadmin/3245gs5662d34: 4
- ubuntu/3245gs5662d34: 4
- supervisor/supervisor1234567: 4
- guest/1q2w3e4r: 3
- amir/amir123: 2
- root/: 6
- admin/1q2w3e4r: 2
- minecraft/minecraft1234: 2

**Files Uploaded/Downloaded:**
- wget.sh;: 4
- w.sh;: 1
- c.sh;: 1
- ): 1
- rondo.naz.sh|sh&...: 1

**HTTP User-Agents:**
- No HTTP User-Agents were observed in this period.

**SSH Clients and Servers:**
- No specific SSH client or server versions were logged.

**Top Attacker AS Organizations:**
- No attacker AS organization data was available in the logs.

### Key Observations and Anomalies

- **High Volume of SSH Activity:** The Cowrie honeypot logged the highest number of events, indicating that SSH brute-force attacks and command execution attempts are the most prevalent threats in this timeframe.
- **Reconnaissance and Persistence:** The most common commands executed by attackers are related to system reconnaissance (e.g., `uname -a`, `whoami`, `cat /proc/cpuinfo`) and establishing persistence by modifying the `.ssh/authorized_keys` file.
- **Targeted Services:** Besides SSH (22) and SMB (445), there is significant traffic towards SMTP (25) and SIP (5060), suggesting that attackers are also scanning for vulnerable mail and VoIP services.
- **Malware Download Attempts:** A few commands indicate attempts to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`), which is a common tactic for deploying malware or botnet clients.
- **Credential Stuffing:** The variety of usernames and passwords attempted suggests automated credential stuffing attacks against common services. The pair `345gs5662d34/345gs5662d34` was the most frequently used.
