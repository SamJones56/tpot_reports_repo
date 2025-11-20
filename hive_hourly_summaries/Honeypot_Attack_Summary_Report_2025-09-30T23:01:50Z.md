Honeypot Attack Summary Report

**Report Generation Time:** 2025-09-30T23:01:26Z
**Timeframe:** 2025-09-30T22:20:01Z to 2025-09-30T23:00:01Z
**Files Used:**
- agg_log_20250930T222001Z.json
- agg_log_20250930T224001Z.json
- agg_log_20250930T230001Z.json

**Executive Summary**

This report summarizes 12,363 attacks recorded by honeypots over a 40-minute period. The majority of attacks were SSH brute-force attempts captured by the Cowrie honeypot. A significant number of attacks were also observed on web and network service honeypots. Attackers attempted to download and execute malware, primarily targeting IoT devices. Several CVEs were targeted, with a focus on remote code execution vulnerabilities.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 6725
- Honeytrap: 2314
- Suricata: 1410
- Ciscoasa: 1409
- Tanner: 123
- H0neytr4p: 96
- Sentrypeer: 60
- Adbhoney: 51
- Redishoneypot: 51
- Dionaea: 40
- Honeyaml: 27
- Miniprint: 27
- Mailoney: 13
- Dicompot: 9
- ConPot: 8

***Top Attacking IPs***

- 103.75.180.31
- 197.199.224.52
- 185.156.73.167
- 185.156.73.166
- 185.213.165.150
- 194.56.148.235
- 117.33.238.13
- 203.215.177.203
- 14.63.217.28
- 193.163.72.91

***Top Targeted Ports/Protocols***

- 22
- 80
- 443
- 23
- 8333
- 5060
- 6379
- 1521
- TCP/22

***Most Common CVEs***

- CVE-2019-11500
- CVE-2021-3449
- CVE-2002-0013
- CVE-2002-0012
- CVE-2006-2369
- CVE-1999-0517
- CVE-2023-26801
- CVE-2021-35394

***Commands Attempted by Attackers***

- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- uname -a
- whoami
- Enter new UNIX password:

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 43
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET CINS Active Threat Intelligence Poor Reputation IP group 41
- ET CINS Active Threat Intelligence Poor Reputation IP group 40

***Users / Login Attempts***

- 345gs5662d34/345gs5662d34
- root/nPSpP4PBW0
- root/LeitboGi0ro
- root/2glehe5t24th1issZs
- slave/slave123
- superadmin/admin123
- foundry/foundry
- test/zhbjETuyMffoL8F
- bb/bb123
- wan/wan123

***Files Uploaded/Downloaded***

- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- Mozi.m
- ns#
- rdf-schema#

***HTTP User-Agents***

- No user agents recorded in this period.

***SSH Clients and Servers***

- No specific SSH clients or servers were identified in the logs.

***Top Attacker AS Organizations***

- No AS organization data was available in the logs.

**Key Observations and Anomalies**

- A high volume of coordinated attacks from the 185.156.73.0/24 subnet was observed, suggesting a single actor or botnet.
- The repeated attempts to download and execute `urbotnetisass` malware from the same IP address (94.154.35.154) across multiple honeypots indicate a targeted campaign.
- The attackers' commands show a clear pattern of attempting to gain persistence by adding their SSH key to the `authorized_keys` file and gathering system information.
- The targeting of multiple CVEs, including older vulnerabilities, highlights the need for patching legacy systems.
