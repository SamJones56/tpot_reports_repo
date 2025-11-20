Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-28T11:01:32Z
**Timeframe of Report:** 2025-10-28 10:20:01 UTC to 2025-10-28 11:00:01 UTC
**Files Used to Generate Report:**
- agg_log_20251028T102001Z.json
- agg_log_20251028T104001Z.json
- agg_log_20251028T110001Z.json

**Executive Summary:**
This report summarizes 22,763 attacks recorded by the honeypot network. The majority of attacks were registered by the Cowrie and Suricata honeypots. A significant portion of the attacks originated from IP addresses 1.227.83.42, 105.96.52.140, and 93.88.136.82. The most targeted port was TCP/445, commonly associated with SMB services, indicating a focus on exploiting Windows vulnerabilities. Several CVEs were detected, with a focus on older vulnerabilities. A large number of automated commands were attempted, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Cowrie: 8303
- Suricata: 5952
- Honeytrap: 3734
- Ciscoasa: 1786
- Sentrypeer: 1790
- Dionaea: 655
- Tanner: 168
- Mailoney: 188
- Adbhoney: 129
- H0neytr4p: 21
- Redishoneypot: 15
- ElasticPot: 12
- Honeyaml: 7
- ConPot: 2
- Ipphoney: 1

**Top Attacking IPs:**
- 1.227.83.42: 1303
- 105.96.52.140: 1302
- 203.171.29.193: 1247
- 93.88.136.82: 1400
- 144.172.108.231: 1150
- 45.134.26.62: 501
- 45.140.17.144: 500
- 5.202.249.9: 417
- 185.243.5.121: 459

**Top Targeted Ports/Protocols:**
- TCP/445: 4048
- 5060: 1790
- 22: 1147
- 445: 571
- 5901: 380
- 8333: 159
- 80: 167
- 25: 188
- 5903: 132
- TCP/22: 125
- TCP/80: 135

**Most Common CVEs:**
- CVE-2002-1149: 6
- CVE-2021-3449 CVE-2021-3449: 6
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
- CVE-2006-2369: 1

**Commands Attempted by Attacker:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 47
- lockr -ia .ssh: 47
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 47
- Basic system reconnaissance commands (uname, whoami, top, etc.): 46 each
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...: 19
- Enter new UNIX password: : 22

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 4038
- 2024766: 4038
- ET DROP Dshield Block Listed Source group 1: 412
- 2402000: 412
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 288
- 2023753: 288
- ET SCAN NMAP -sS window 1024: 196
- 2009582: 196
- ET HUNTING RDP Authentication Bypass Attempt: 115
- 2034857: 115

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 44
- root/: 33
- root/3245gs5662d34: 24
- freeswitch/Password123: 6
- otsmanager/P@ssw0rd@1: 5
- root/kp1617: 4
- root/Kraken77: 4
- survey/survey: 4
- root/Ks: 4
- root/Kulerman11: 4

**Files Uploaded/Downloaded:**
- wget.sh;: 52
- w.sh;: 13
- c.sh;: 13
- sh: 6
- Mozi.m: 4
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1

**HTTP User-Agents:**
- No user agents were recorded in this period.

**SSH Clients:**
- No SSH clients were recorded in this period.

**SSH Servers:**
- No SSH servers were recorded in this period.

**Top Attacker AS Organizations:**
- No AS organizations were recorded in this period.

**Key Observations and Anomalies:**
- The high number of attacks on TCP/445 and the triggering of the DoublePulsar signature suggest a continued interest in exploiting the EternalBlue vulnerability.
- The majority of attempted commands are automated scripts for reconnaissance and setting up SSH backdoors.
- Attackers are attempting to download and execute shell scripts (e.g., w.sh, c.sh, wget.sh) from external servers, indicating attempts to install malware or establish botnet clients.
- The variety of credentials used in brute-force attacks suggests the use of common password lists.
- There is a noticeable lack of sophisticated attacks, with most activity appearing to be automated and opportunistic scanning and exploitation attempts.
