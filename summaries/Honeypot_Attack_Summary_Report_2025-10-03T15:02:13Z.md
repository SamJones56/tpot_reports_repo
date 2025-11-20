Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-03T15:01:26Z
**Timeframe:** 2025-10-03T14:20:02Z to 2025-10-03T15:00:01Z
**Files Used:**
- agg_log_20251003T142002Z.json
- agg_log_20251003T144001Z.json
- agg_log_20251003T150001Z.json

### Executive Summary
This report summarizes 10,721 suspicious events captured by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attacks and command execution attempts. A significant number of attacks were also logged by the Ciscoasa and Suricata honeypots. The most frequent attacks originated from IP addresses 176.65.141.117 and 217.154.99.56. The primary targets were ports 22 (SSH) and 25 (SMTP).

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 5772
- Ciscoasa: 2132
- Suricata: 1404
- Mailoney: 713
- Sentrypeer: 292
- Honeytrap: 121
- Adbhoney: 81
- Dionaea: 49
- ConPot: 36
- H0neytr4p: 29
- Tanner: 28
- Honeyaml: 24
- Ipphoney: 13
- Redishoneypot: 10
- Medpot: 4
- ElasticPot: 3

**Top Attacking IPs:**
- 176.65.141.117: 680
- 179.7.102.161: 385
- 217.154.99.56: 324
- 14.225.220.78: 350
- 152.32.189.21: 327
- 43.166.245.172: 258
- 43.160.193.141: 258
- 94.182.95.185: 332
- 92.80.63.123: 276
- 140.249.81.156: 238
- 103.189.89.76: 243
- 216.108.227.59: 247
- 154.221.27.234: 212
- 158.174.211.17: 184
- 185.156.73.166: 260
- 102.88.137.213: 169
- 92.63.197.59: 240
- 40.115.18.231: 189
- 103.189.234.28: 144
- 103.72.147.99: 150

**Top Targeted Ports/Protocols:**
- 22: 781
- 25: 713
- 5060: 292
- TCP/445: 383
- TCP/80: 112
- 23: 43
- 80: 48
- 443: 29
- UDP/5060: 13
- TCP/5432: 33

**Most Common CVEs:**
- CVE-2002-0012
- CVE-2002-0013
- CVE-1999-0517
- CVE-2006-2369
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2009-2765
- CVE-2014-6271
- CVE-2015-2051
- CVE-2019-10891
- CVE-2019-11500
- CVE-2019-16920
- CVE-2021-3449
- CVE-2021-42013
- CVE-2022-37056
- CVE-2023-31983
- CVE-2023-47565
- CVE-2023-52163
- CVE-2024-10914
- CVE-2024-12856
- CVE-2024-12885
- CVE-2024-33112
- CVE-2024-3721

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 32
- lockr -ia .ssh: 32
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 32
- cat /proc/cpuinfo | grep name | wc -l: 32
- Enter new UNIX password: : 28
- Enter new UNIX password::: 28
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 32
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 32
- ls -lh $(which ls): 32
- which ls: 32
- crontab -l: 32
- w: 32
- uname -m: 32
- cat /proc/cpuinfo | grep model | grep name | wc -l: 31
- top: 31
- uname: 31
- uname -a: 32
- whoami: 31
- lscpu | grep Model: 31
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 31

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 378
- 2024766: 378
- ET DROP Dshield Block Listed Source group 1: 237
- 2402000: 237
- ET SCAN NMAP -sS window 1024: 186
- 2009582: 186
- ET INFO Reserved Internal IP Traffic: 58
- 2002752: 58
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 26
- 2010939: 26
- ET INFO curl User-Agent Outbound: 24
- 2013028: 24
- ET HUNTING curl User-Agent to Dotted Quad: 30
- 2034567: 30
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 26
- 2400031: 26
- ET CINS Active Threat Intelligence Poor Reputation IP group 13: 12
- 2403312: 12

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 31
- superadmin/admin123: 12
- root/LeitboGi0ro: 12
- foundry/foundry: 12
- root/nPSpP4PBW0: 15
- root/2glehe5t24th1issZs: 12
- superadmin/3245gs5662d34: 6
- root/3245gs5662d34: 3
- test/zhbjETuyMffoL8F: 6
- ntuser/ntuser: 5

**Files Uploaded/Downloaded:**
- wget.sh;: 36
- w.sh;: 9
- c.sh;: 9
- rondo.dgx.sh||busybox: 3
- rondo.dgx.sh||curl: 3
- rondo.dgx.sh)|sh&: 3
- apply.cgi: 2
- rondo.tkg.sh|sh&echo: 2
- rondo.qre.sh||busybox: 2
- rondo.qre.sh||curl: 2
- rondo.qre.sh)|sh: 2

**HTTP User-Agents:**
- No user agents were logged.

**SSH Clients:**
- No SSH clients were logged.

**SSH Servers:**
- No SSH servers were logged.

**Top Attacker AS Organizations:**
- No attacker AS organizations were logged.

### Key Observations and Anomalies
- The overwhelming number of commands attempted are reconnaissance commands, suggesting automated scripts are trying to identify the system architecture and available resources.
- The command to add an SSH key to `authorized_keys` is a common persistence mechanism.
- The DoublePulsar backdoor signature indicates attempts to exploit SMB vulnerabilities, likely related to the EternalBlue exploit. This is a high-severity threat.
- The variety of credentials used suggests that attackers are using common default credential lists for a wide range of devices and applications.
- Attackers are attempting to download and execute shell scripts (`wget.sh`, `w.sh`, `c.sh`), a common tactic for installing malware or botnet clients.
