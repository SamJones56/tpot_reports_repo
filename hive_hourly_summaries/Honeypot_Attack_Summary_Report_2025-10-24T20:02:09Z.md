Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T20:01:38Z
**Timeframe:** 2025-10-24T19:20:01Z to 2025-10-24T20:00:01Z
**Files Used:**
- agg_log_20251024T192001Z.json
- agg_log_20251024T194001Z.json
- agg_log_20251024T200001Z.json

**Executive Summary**

This report summarizes 17,847 attacks recorded across three honeypot log files. The majority of attacks were captured by the Cowrie, Honeytrap, and Suricata honeypots. A significant portion of the attacks originated from the IP address 109.205.211.9. Port 22 (SSH) was the most targeted port. Attackers attempted to execute various commands, including efforts to manipulate SSH authorized keys and download malicious scripts. Multiple CVEs were detected, with CVE-2001-0414 and CVE-2005-4050 appearing in multiple log files.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 6271
- Honeytrap: 4717
- Suricata: 4354
- Ciscoasa: 1813
- Sentrypeer: 335
- Mailoney: 142
- Dionaea: 83
- Adbhoney: 42
- Tanner: 28
- H0neytr4p: 7
- Dicompot: 10
- Ipphoney: 4
- Heralding: 3
- Redishoneypot: 3
- Honeyaml: 2
- ConPot: 2
- ElasticPot: 1

**Top Attacking IPs:**
- 109.205.211.9: 2718
- 80.94.95.238: 1731
- 199.127.63.138: 1220
- 103.140.127.215: 1250
- 20.2.136.52: 624
- 107.170.36.5: 252
- 14.103.123.6: 237
- 104.168.76.140: 283
- 170.239.86.101: 268
- 180.76.134.56: 220
- 14.225.3.79: 204
- 103.72.147.99: 204
- 2.57.121.61: 178
- 218.51.148.194: 154
- 181.23.101.20: 124
- 167.250.224.25: 95
- 170.64.161.168: 91
- 103.172.28.62: 83
- 77.83.207.203: 75
- 68.183.149.135: 73

**Top Targeted Ports/Protocols:**
- 22: 1117
- 5060: 335
- 8333: 209
- 25: 142
- 5903: 136
- 5901: 117
- 5904: 78
- 5905: 78
- TCP/80: 54
- 5908: 52
- 5907: 50
- 5909: 50
- TCP/445: 42
- 2022: 42
- 1521: 26
- 445: 14
- 23: 12
- 3128: 11
- TCP/22: 11
- 2049: 10

**Most Common CVEs:**
- CVE-1999-0183
- CVE-2001-0414
- CVE-2002-0012
- CVE-2002-0013
- CVE-2005-4050
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2009-2765
- CVE-2014-6271
- CVE-2015-2051
- CVE-2016-20017
- CVE-2018-10561
- CVE-2018-10562
- CVE-2019-10891
- CVE-2019-16920
- CVE-2021-35395
- CVE-2021-42013
- CVE-2021-44228
- CVE-2022-37056
- CVE-2023-31983
- CVE-2023-47565
- CVE-2023-52163
- CVE-2024-10914
- CVE-2024-12856
- CVE-2024-12885
- CVE-2024-33112
- CVE-2024-3721
- CVE-2025-11488

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 12
- lockr -ia .ssh: 12
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 12
- cat /proc/cpuinfo | grep name | wc -l: 12
- Enter new UNIX password: : 11
- Enter new UNIX password::: 11
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 12
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 12
- ls -lh $(which ls): 12
- which ls: 12
- crontab -l: 12
- w: 12
- uname -m: 12
- cat /proc/cpuinfo | grep model | grep name | wc -l: 12
- top: 12
- uname: 12
- uname -a: 12
- whoami: 12
- lscpu | grep Model: 12
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 11

**Signatures Triggered:**
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 2278
- ET HUNTING RDP Authentication Bypass Attempt: 743
- ET DROP Dshield Block Listed Source group 1: 383
- ET SCAN NMAP -sS window 1024: 186
- ET INFO Reserved Internal IP Traffic: 59
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 44: 14
- ET CINS Active Threat Intelligence Poor Reputation IP group 51: 21
- ET CINS Active Threat Intelligence Poor Reputation IP group 50: 11
- ET CINS Active Threat Intelligence Poor Reputation IP group 49: 18
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 11
- ET DROP Spamhaus DROP Listed Traffic Inbound group 49: 8
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 8

**Users / Login Attempts:**
- root/: 30
- 345gs5662d34/345gs5662d34: 8
- root/1234: 5
- root/P@ssw0rd: 5
- root/passw0rd: 5
- root/45674567: 4
- root/dx83695087: 4
- root/b0lc0rp: 4
- root/102030Th@: 4
- root/palosanto: 4
- root/admin123: 4
- root/Admin123: 4
- root/dyc101: 4
- root/admin@2001: 4
- root/admin@1234: 4
- root/Admin1234: 4
- root/P@ssw0rd123: 4
- root/Password@1: 4
- user/jxlt1234!@#$: 3
- user/juMkxWWKW=SMVB4HPr-5N: 3

**Files Uploaded/Downloaded:**
- 1.sh;: 6
- 34.165.197.224: 5
- gpon80&ipv=0: 4
- wget.sh;: 4
- server.cgi?func=server02_main_submit&counter=6.7496022225883&TEST_BTN4=: 3
- rondo.dgx.sh||busybox: 3
- rondo.dgx.sh||curl: 3
- rondo.dgx.sh)|sh&: 3
- system.html: 2
- rondo.tkg.sh|sh&echo: 2
- rondo.qre.sh||busybox: 2
- rondo.qre.sh||curl: 2
- rondo.qre.sh)|sh: 2
- cfg_system_time.htm: 2
- w.sh;: 1
- c.sh;: 1
- login_pic.asp: 1
- apply.cgi: 1
- rondo.sbx.sh|sh&echo${IFS}: 1
- `busybox: 1

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were identified in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organizations were identified in the logs.

**Key Observations and Anomalies**

- **SSH Key Manipulation:** A frequently observed command sequence involves modifying the `.ssh/authorized_keys` file. This indicates a common tactic to establish persistent access to compromised systems. The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~` was seen in all three log files.
- **Script-based Attacks:** Attackers were observed downloading and executing shell scripts, such as `1.sh`, `w.sh`, and `wget.sh`, from external servers. This suggests automated attacks using predefined scripts to perform malicious actions.
- **Scanning Activity:** The high number of "ET SCAN" signatures, particularly for MS Terminal Server and NMAP, indicates widespread scanning for vulnerable services.
- **RDP Attacks:** A significant number of "ET HUNTING RDP Authentication Bypass Attempt" signatures were triggered, highlighting the focus on exploiting Remote Desktop Protocol vulnerabilities.
- **Multiple CVEs:** A wide range of CVEs were detected, indicating that attackers are attempting to exploit a diverse set of vulnerabilities, from older ones like CVE-2001-0414 to more recent ones.
- **Credential Stuffing:** The logs show a large variety of username and password combinations being attempted, with a strong focus on the `root` user and common default passwords.
