Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T23:01:40Z
**Timeframe:** 2025-10-18T22:20:01Z to 2025-10-18T23:00:01Z
**Files Used:**
- agg_log_20251018T222001Z.json
- agg_log_20251018T224001Z.json
- agg_log_20251018T230001Z.json

**Executive Summary**

This report summarizes 18,243 events collected from the T-Pot honeypot network over a period of approximately 40 minutes. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH-based threats. A significant number of attacks were also observed on the Honeytrap, Suricata, Sentrypeer, and Ciscoasa honeypots. The most prominent attack vector appears to be related to VOIP services, as evidenced by the high number of "ET VOIP MultiTech SIP UDP Overflow" signatures. Attackers were observed attempting to gain access via common credentials and execute commands to gather system information and establish persistent access.

**Detailed Analysis**

**Attacks by Honeypot**
- Cowrie: 8612
- Honeytrap: 3279
- Suricata: 2902
- Sentrypeer: 2061
- Ciscoasa: 1148
- Dionaea: 84
- H0neytr4p: 36
- Mailoney: 27
- Tanner: 22
- Redishoneypot: 21
- Dicompot: 15
- ConPot: 14
- Adbhoney: 9
- ElasticPot: 5
- Heralding: 3
- Ipphoney: 3
- Honeyaml: 2

**Top Attacking IPs**
- 5.167.79.4: 1255
- 72.146.232.13: 1218
- 198.23.190.58: 1199
- 23.94.26.58: 1158
- 194.50.16.73: 984
- 198.12.68.114: 854
- 179.51.153.37: 338
- 116.193.190.103: 341
- 207.166.168.62: 335
- 172.200.228.35: 328

**Top Targeted Ports/Protocols**
- 5060: 2061
- 22: 1629
- UDP/5060: 1392
- 5903: 225
- 8333: 134
- 5901: 116

**Most Common CVEs**
- CVE-2005-4050: 1375
- CVE-2002-0013 CVE-2002-0012: 13
- CVE-2025-30208 CVE-2025-30208: 7
- CVE-2024-3721 CVE-2024-3721: 6
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 5
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2001-0414: 2
- CVE-2023-27997 CVE-2023-27997: 1
- CVE-2021-35394 CVE-2021-35394: 1

**Commands Attempted by Attackers**
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 32
- cat /proc/cpuinfo | grep name | wc -l: 32
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 32
- uname -a: 32
- Enter new UNIX password: : 18
- Enter new UNIX password::: 18

**Signatures Triggered**
- ET VOIP MultiTech SIP UDP Overflow: 1375
- 2003237: 1375
- ET DROP Dshield Block Listed Source group 1: 381
- 2402000: 381
- ET SCAN NMAP -sS window 1024: 166
- 2009582: 166
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 137
- 2023753: 137

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 32
- root/123@Robert: 9
- support/Passw@rd: 6
- guest/777: 6
- nobody/nobody2018: 6
- unknown/2222222: 6

**Files Uploaded/Downloaded**
- 11: 5
- fonts.gstatic.com: 5
- wget.sh;: 4
- yukari.sh;: 4
- css?family=Libre+Franklin...: 4
- ie8.css?ver=1.0: 4
- html5.js?ver=3.7.3: 4
- w.sh;: 1
- c.sh;: 1
- Mozi.m%20dlink.mips%27$: 1

**HTTP User-Agents**
- No HTTP User-Agents were logged in this period.

**SSH Clients and Servers**
- No specific SSH clients or servers were logged in this period.

**Top Attacker AS Organizations**
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- **High Volume of Cowrie Attacks:** The high number of attacks on the Cowrie honeypot (8612) suggests a significant amount of automated SSH scanning and brute-force activity.
- **VOIP-Targeted Attacks:** The most frequently triggered signature, "ET VOIP MultiTech SIP UDP Overflow," indicates a focus on exploiting vulnerabilities in VOIP systems. This is corroborated by the high number of events on port 5060.
- **Repetitive Commands:** Attackers frequently used a series of commands to enumerate system information (e.g., `uname -a`, `cat /proc/cpuinfo`), check for running processes, and attempt to add their SSH key to the `authorized_keys` file for persistent access.
- **Common Credentials:** The login attempts show the use of common and default credentials, such as "guest/guest" and "support/password" variations.
- **Lack of Diversity in Exploits:** The CVEs triggered are limited in variety, with CVE-2005-4050 being the most common, which is related to the VOIP attacks. This could indicate a specific campaign or a widely used exploit kit.