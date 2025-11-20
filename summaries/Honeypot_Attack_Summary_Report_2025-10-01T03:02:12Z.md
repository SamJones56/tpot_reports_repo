Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-01T03:01:31Z
**Timeframe:** 2025-10-01T02:20:01Z to 2025-10-01T03:00:01Z
**Log Files:**
- agg_log_20251001T022001Z.json
- agg_log_20251001T024001Z.json
- agg_log_20251001T030001Z.json

### Executive Summary

This report summarizes 11,838 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Honeytrap and Suricata. Attackers predominantly targeted port 25 (SMTP) and port 22 (SSH). A variety of CVEs were observed, with reconnaissance and exploit attempts against multiple vulnerabilities. A large number of automated commands were executed, primarily focused on reconnaissance and establishing unauthorized SSH access.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4972
- Honeytrap: 2614
- Suricata: 1618
- Ciscoasa: 1355
- Mailoney: 845
- Tanner: 138
- Adbhoney: 58
- H0neytr4p: 53
- Miniprint: 46
- Dionaea: 40
- Honeyaml: 33
- Dicompot: 15
- Sentrypeer: 12
- Redishoneypot: 11
- ConPot: 11
- ElasticPot: 8
- Ipphoney: 6
- Heralding: 3

**Top Attacking IPs:**
- 92.242.166.161: 824
- 47.236.169.168: 625
- 45.95.52.162: 529
- 173.249.52.138: 524
- 78.159.98.113: 520
- 41.216.228.199: 517
- 103.72.147.99: 400
- 107.150.110.167: 382
- 104.199.255.247: 368
- 185.156.73.166: 350
- 92.63.197.55: 345
- 185.156.73.167: 346
- 92.63.197.59: 314
- 107.173.85.161: 247
- 107.174.55.72: 208
- 14.29.129.250: 202
- 88.214.50.58: 211
- 195.87.80.171: 71
- 204.76.203.28: 70
- 129.13.189.202: 46

**Top Targeted Ports/Protocols:**
- 25: 845
- 22: 560
- 80: 151
- 8333: 116
- 443: 47
- 9100: 46
- 23: 61
- TCP/80: 56
- 2323: 24
- 8888: 42

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-11500
- CVE-2019-12263
- CVE-2019-12261
- CVE-2019-12260
- CVE-2019-12255
- CVE-2020-11910
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-35394
- CVE-2021-41773
- CVE-2021-42013
- CVE-2006-2369
- CVE-2005-4050

**Commands Attempted by Attackers:**
- uname -a
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- Enter new UNIX password:
- Enter new UNIX password:

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET INFO CURL User Agent
- 2002824
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- 2403343
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- 2403341

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- root/2glehe5t24th1issZs
- minecraft/3245gs5662d34
- test/zhbjETuyMffoL8F
- chenl/chenl
- root/LeitboGi0ro
- root/nPSpP4PBW0
- postgres/asdf1234
- superadmin/admin123
- superadmin/3245gs5662d34
- foundry/foundry

**Files Uploaded/Downloaded:**
- sh
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- wget.sh;
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;

**HTTP User-Agents:**
- None Observed

**SSH Clients:**
- None Observed

**SSH Servers:**
- None Observed

**Top Attacker AS Organizations:**
- None Observed

### Key Observations and Anomalies

- **Automated Reconnaissance and Exploitation:** The high volume of identical commands across multiple attacking IPs suggests widespread automated attacks. These scripts primarily perform system reconnaissance (e.g., `uname -a`, `cat /proc/cpuinfo`) and attempt to install malicious SSH keys.
- **Botnet Activity:** The downloading and execution of files such as `arm.urbotnetisass`, `mips.urbotnetisass`, etc., are indicative of botnet propagation attempts targeting various architectures. The `urbotnetisass` filename is particularly noteworthy and suggests a specific malware family.
- **Credential Stuffing:** A wide range of usernames and passwords were attempted, indicating credential stuffing attacks against SSH and other services. The credentials range from common defaults (e.g., `root/123456`) to more complex passwords.
- **Targeting of Multiple Vulnerabilities:** The variety of CVEs detected, including older vulnerabilities, indicates that attackers are using a broad set of exploits to maximize their chances of compromising a system.

This report highlights the continuous and automated nature of threats targeting internet-facing systems. The observed activity suggests a combination of opportunistic attacks and targeted campaigns to expand botnet infrastructure.
