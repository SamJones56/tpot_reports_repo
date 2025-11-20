Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T08:01:36Z
**Timeframe of Logs:** 2025-10-19T07:20:01Z to 2025-10-19T08:00:01Z
**Log Files Used:**
- agg_log_20251019T072001Z.json
- agg_log_20251019T074002Z.json
- agg_log_20251019T080001Z.json

**Executive Summary:**
This report summarizes 25,230 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie honeypot. The most prominent attack vector was VNC on port 5900, originating from the IP address 185.243.96.105. A significant number of brute-force attempts and reconnaissance commands were observed. Several CVEs were exploited, with CVE-2005-4050 being the most frequent.

**Detailed Analysis:**

***Attacks by Honeypot:***
- Cowrie: 8,703
- Heralding: 5,379
- Honeytrap: 4,034
- Suricata: 3,439
- Sentrypeer: 2,170
- Ciscoasa: 1,019
- Tanner: 121
- H0neytr4p: 120
- Adbhoney: 78
- Dionaea: 76
- Mailoney: 34
- Dicompot: 18
- Honeyaml: 16
- Redishoneypot: 12
- ConPot: 10
- Ipphoney: 1

***Top Attacking IPs:***
- 185.243.96.105: 5,109
- 194.50.16.73: 2,068
- 72.146.232.13: 1,218
- 198.23.190.58: 1,218
- 23.94.26.58: 1,181
- 198.12.68.114: 845
- 152.42.130.45: 608
- 178.62.252.242: 541
- 159.223.6.241: 490
- 104.198.246.170: 452

***Top Targeted Ports/Protocols:***
- vnc/5900: 5,109
- 5060: 2,170
- 22: 2,013
- UDP/5060: 1,393
- 5038: 440
- 80: 108
- 23: 177
- 5903: 226
- 8333: 165
- TCP/22: 111

***Most Common CVEs:***
- CVE-2005-4050: 1,390
- CVE-2002-0013 CVE-2002-0012: 5
- CVE-2019-11500 CVE-2019-11500: 5
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2010-0569: 2
- CVE-2002-1149: 1
- CVE-2016-20016 CVE-2016-20016: 1
- CVE-2006-2369: 1
- CVE-2001-0414: 1

***Commands Attempted by Attackers:***
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 28
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 28
- lockr -ia .ssh: 28
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...: 6
- cat /proc/cpuinfo | grep name | wc -l: 5
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 5
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 5
- ls -lh $(which ls): 5
- which ls: 5
- crontab -l: 5
- w: 5
- uname -m: 5
- cat /proc/cpuinfo | grep model | grep name | wc -l: 5
- top: 5
- uname: 5
- uname -a: 5
- whoami: 4
- lscpu | grep Model: 4
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 4
- Enter new UNIX password: : 4

***Signatures Triggered:***
- ET VOIP MultiTech SIP UDP Overflow: 1,390
- 2003237: 1,390
- ET DROP Dshield Block Listed Source group 1: 448
- 2402000: 448
- GPL INFO SOCKS Proxy attempt: 311
- 2100615: 311
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 182
- 2023753: 182
- ET SCAN NMAP -sS window 1024: 174
- 2009582: 174
- ET SCAN Potential SSH Scan: 97
- 2001219: 97
- ET HUNTING RDP Authentication Bypass Attempt: 64
- 2034857: 64
- ET INFO Reserved Internal IP Traffic: 55
- 2002752: 55

***Users / Login Attempts:***
- 345gs5662d34/345gs5662d34: 28
- /1q2w3e4r: 25
- /Passw0rd: 24
- /passw0rd: 16
- /qwertyui: 9
- root/3245gs5662d34: 7
- user01/Password01: 7
- blank/blank12345: 6
- ubnt/ubnt2016: 6
- support/support2016: 6
- support/7777777: 5
- root/Welcome2021: 5
- /1qaz2wsx: 5

***Files Uploaded/Downloaded:***
- wget.sh;: 28
- w.sh;: 7
- c.sh;: 7
- rondo.qpu.sh||wget: 1
- rondo.qpu.sh)|sh&echo: 1

***HTTP User-Agents:***
- No HTTP user-agents were logged in this period.

***SSH Clients:***
- No specific SSH clients were logged.

***SSH Servers:***
- No specific SSH servers were logged.

***Top Attacker AS Organizations:***
- No attacker AS organizations were logged.

**Key Observations and Anomalies:**
- The overwhelming majority of attacks are automated and programmatic, focusing on VNC, SIP, and SSH services.
- Attackers are consistently attempting to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`) from the IP address 213.209.143.62.
- A common TTP observed is the attempt to delete and replace the `.ssh/authorized_keys` file to maintain persistence.
- A large number of Suricata alerts are related to the Dshield blocklist, indicating that many of the attacking IPs are known bad actors.
- Despite thousands of login attempts, there is a wide variety of usernames and passwords being used, suggesting large-scale brute-force attacks from pre-compiled lists.
