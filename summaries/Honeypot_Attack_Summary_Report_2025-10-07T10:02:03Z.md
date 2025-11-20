Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T10:01:39Z
**Timeframe:** 2025-10-07T09:20:01Z to 2025-10-07T10:00:02Z
**Files Used:**
- agg_log_20251007T092001Z.json
- agg_log_20251007T094001Z.json
- agg_log_20251007T100002Z.json

**Executive Summary**

This report summarizes 14,746 attacks recorded across multiple honeypots. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant number of attacks originated from IP address 86.54.42.238. The most frequently targeted port was port 25 (SMTP), followed closely by port 22 (SSH). Attackers attempted to exploit several vulnerabilities, with CVE-2002-0013 and CVE-2002-0012 being the most common. A recurring command pattern involving the manipulation of SSH authorized_keys files was observed, suggesting attempts to establish persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 7585
- Honeytrap: 2915
- Mailoney: 1659
- Suricata: 1827
- Sentrypeer: 426
- Redishoneypot: 79
- Dionaea: 47
- Tanner: 54
- H0neytr4p: 60
- Ciscoasa: 26
- ConPot: 23
- Honeyaml: 25
- Adbhoney: 8
- ElasticPot: 5
- Heralding: 3
- Wordpot: 2
- Ipphoney: 2

***Top Attacking IPs***

- 86.54.42.238: 821
- 170.64.145.101: 910
- 176.65.141.117: 783
- 27.71.28.90: 434
- 37.46.18.91: 393
- 128.199.183.223: 336
- 88.214.50.58: 324
- 14.225.205.58: 284
- 190.12.108.68: 317
- 43.163.95.10: 153
- 172.86.95.98: 405
- 103.183.74.130: 129
- 103.220.207.174: 312
- 38.242.235.163: 267
- 152.32.189.21: 307

***Top Targeted Ports/Protocols***

- 25: 1659
- 22: 912
- 5060: 426
- 6379: 79
- 8333: 95
- 5903: 94
- 23: 56
- TCP/22: 56
- 80: 57
- 443: 52
- 27017: 43
- 5908: 52
- 5907: 50
- 5909: 50
- TCP/1433: 25

***Most Common CVEs***

- CVE-2002-0013 CVE-2002-0012: 12
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-1999-0265: 7
- CVE-2019-11500 CVE-2019-11500: 4
- CVE-2023-26801 CVE-2023-26801: 2
- CVE-1999-0183: 1
- CVE-2005-4050: 1

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh: 52
- lockr -ia .ssh: 52
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ...: 53
- cat /proc/cpuinfo | grep name | wc -l: 50
- Enter new UNIX password: : 50
- Enter new UNIX password::: 50
- crontab -l: 50
- w: 50
- uname -m: 50
- top: 50
- whoami: 50
- uname: 50
- uname -a: 50

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1: 536
- 2402000: 536
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 228
- 2023753: 228
- ET SCAN NMAP -sS window 1024: 156
- 2009582: 156
- ET HUNTING RDP Authentication Bypass Attempt: 112
- 2034857: 112
- ET INFO Reserved Internal IP Traffic: 59
- 2002752: 59
- ET SCAN Potential SSH Scan: 42
- 2001219: 42

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34: 49
- ubuntu/3245gs5662d34: 8
- deploy/deploy!: 9
- vpn/vpn!123: 5
- username/username@123: 5
- guest/3245gs5662d34: 5
- admin/05071982: 3
- admin/05071978: 3
- admin/05051995: 3
- admin/05041993: 3
- admin/05031985: 3

***Files Uploaded/Downloaded***

- w.sh: 1
- c.sh: 1
- wget.sh: 1
- soap-envelope: 1
- addressing: 1
- discovery: 1
- env:Envelope>: 1

***HTTP User-Agents***

- No HTTP user agents were logged in this period.

***SSH Clients and Servers***

- No specific SSH clients or servers were logged in this period.

***Top Attacker AS Organizations***

- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- A high number of commands related to SSH key manipulation (`.ssh/authorized_keys`) were observed across all log files, indicating a coordinated campaign to gain persistent access to compromised systems.
- The prevalence of attacks on port 25 (SMTP) suggests a focus on exploiting email servers for spam or phishing campaigns.
- The commands executed by attackers appear to be scripted, focusing on system enumeration and establishing persistence. The uniformity of these commands across different attacking IPs suggests the use of automated attack tools.
- Several signatures related to well-known scanning tools and blocklisted IPs were triggered, confirming that the traffic is from malicious sources.
- There is a noticeable absence of HTTP-based attacks and related data such as User-Agents in this dataset, with the focus being primarily on SSH, SMTP, and other service-level attacks.
