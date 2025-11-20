Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T03:01:29Z
**Timeframe:** 2025-10-11T02:20:01Z to 2025-10-11T03:00:01Z
**Files Used:**
- agg_log_20251011T022001Z.json
- agg_log_20251011T024001Z.json
- agg_log_20251011T030001Z.json

### Executive Summary
This report summarizes 13,665 malicious events detected by the honeypot network. The primary attack vectors observed were SSH brute-force attempts and scans for common vulnerabilities. A significant portion of the attacks originated from a small number of IP addresses, indicating targeted activity. The most active honeypots were Cowrie, Honeytrap, and Suricata, which collectively accounted for over 70% of the recorded events.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4218
- Honeytrap: 3361
- Suricata: 2211
- Ciscoasa: 1802
- Dionaea: 846
- Mailoney: 863
- Redishoneypot: 74
- ConPot: 69
- Tanner: 80
- Miniprint: 40
- Sentrypeer: 37
- H0neytr4p: 20
- Dicompot: 12
- Honeyaml: 12
- Adbhoney: 13
- ElasticPot: 4
- Heralding: 3

**Top Attacking IPs:**
- 176.65.141.117: 820
- 223.100.22.69: 721
- 161.132.48.14: 523
- 167.250.224.25: 478
- 88.210.63.16: 433
- 4.213.160.153: 360
- 165.227.174.138: 251
- 164.68.117.126: 258
- 103.13.206.142: 243
- 185.39.19.40: 243
- 202.39.251.216: 218
- 104.164.110.31: 205
- 103.23.199.87: 109
- 36.67.70.198: 109
- 182.76.204.237: 115
- 103.55.36.22: 148
- 190.221.50.123: 95
- 68.183.193.0: 102
- 107.170.36.5: 98

**Top Targeted Ports/Protocols:**
- 25: 866
- 22: 695
- 445: 804
- 5903: 189
- 8333: 92
- 6379: 74
- 5908: 85
- 5909: 83
- 5901: 71
- 1025: 63
- 80: 74
- 9100: 40
- TCP/22: 29
- 1433: 17
- 5060: 15
- 7547: 13

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 9
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-1999-0517: 1
- CVE-2006-2369: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 15
- `lockr -ia .ssh`: 15
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 15
- `cat /proc/cpuinfo | grep name | wc -l`: 12
- `Enter new UNIX password: `: 12
- `Enter new UNIX password:`: 12
- `uname -a`: 13
- `whoami`: 12
- `w`: 12
- `uname -m`: 12
- `crontab -l`: 12
- `top`: 12
- `uname`: 12
- `which ls`: 12
- `ls -lh $(which ls)`: 12

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 710
- 2402000: 710
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 398
- 2023753: 398
- ET HUNTING RDP Authentication Bypass Attempt: 193
- 2034857: 193
- ET SCAN NMAP -sS window 1024: 160
- 2009582: 160
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET SCAN Suspicious inbound to MSSQL port 1433: 18
- 2010935: 18
- ET SCAN Potential SSH Scan: 13
- 2001219: 13

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 14
- root/nPSpP4PBW0: 6
- admin/nimda: 7
- ubnt/ubnt10: 5
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 5
- root/p@ssword: 5
- admin/Boxx123: 6
- config/passw0rd: 6
- root/1q2w3e4r: 6
- root/LeitboGi0ro: 5

**Files Uploaded/Downloaded:**
- sh: 6
- 11: 5
- fonts.gstatic.com: 5
- css?family=Libre+Franklin...: 5
- ie8.css?ver=1.0: 5
- html5.js?ver=3.7.3: 5
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1

**HTTP User-Agents:**
- No user agents were logged in this period.

**SSH Clients and Servers:**
- No specific SSH clients or servers were logged in this period.

**Top Attacker AS Organizations:**
- No AS organizations were logged in this period.

### Key Observations and Anomalies
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently observed, indicating a common tactic to install a persistent SSH key for backdoor access.
- A notable spike in activity was observed from the IP address `176.65.141.117`, which was responsible for over 800 events in a short period, primarily targeting the Cowrie honeypot.
- The majority of commands executed are reconnaissance commands, suggesting attackers are attempting to identify the system's architecture and running services before deploying payloads.
- The presence of the `arm.urbotnetisass` and related files in download attempts suggests activity related to IoT botnets.
