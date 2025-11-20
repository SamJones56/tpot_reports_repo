Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T02:01:41Z
**Timeframe:** 2025-10-14T01:20:02Z to 2025-10-14T02:00:01Z
**Files Used:**
- agg_log_20251014T012002Z.json
- agg_log_20251014T014002Z.json
- agg_log_20251014T020001Z.json

**Executive Summary**

This report summarizes 29,028 events collected from the T-Pot honeypot network over a 40-minute interval. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant number of attacks originated from IP addresses 103.165.231.174 and 8.222.207.98. The most frequently targeted port was 445 (SMB), followed by 5060 (SIP) and 22 (SSH). Attackers attempted to exploit several vulnerabilities, with CVE-2005-4050 being the most common. A variety of shell commands were executed, primarily focused on reconnaissance and establishing persistent access.

**Detailed Analysis**

***Attacks by Honeypot***

- Cowrie: 13,202
- Dionaea: 5,769
- Sentrypeer: 3,140
- Honeytrap: 2,930
- Redishoneypot: 1,582
- Suricata: 1,696
- Mailoney: 388
- Tanner: 112
- ssh-rsa: 108
- H0neytr4p: 29
- ConPot: 24
- Ciscoasa: 23
- Adbhoney: 15
- Honeyaml: 7
- Heralding: 3

***Top Attacking IPs***

- 103.165.231.174
- 8.222.207.98
- 42.119.232.181
- 20.2.136.52
- 185.243.5.146
- 129.212.185.225
- 129.212.176.119
- 200.87.27.60
- 45.130.202.16
- 45.236.188.4

***Top Targeted Ports/Protocols***

- 445
- 5060
- 22
- 6379
- 5038
- 5903
- 25
- 80

***Most Common CVEs***

- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2024-4577 CVE-2002-0953
- CVE-2024-4577 CVE-2024-4577
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-2018-11776
- CVE-2019-11500 CVE-2019-11500
- CVE-2024-3721 CVE-2024-3721
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2002-1149
- CVE-2001-0414

***Commands Attempted by Attackers***

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`
- `top`
- `uname -a`
- `whoami`

***Signatures Triggered***

- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET VOIP MultiTech SIP UDP Overflow
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET DROP Spamhaus DROP Listed Traffic Inbound group 28
- ET CINS Active Threat Intelligence Poor Reputation IP group 46

***Users / Login Attempts***

- root/
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/Password@2025
- ubuntu/passw0rd
- support/123
- root/Qaz123qaz
- centos/centos2012
- default/default999
- ubnt/administrator

***Files Uploaded/Downloaded***

- sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass
- html5.js?ver=3.7.3
- fonts.gstatic.com
- ie8.css?ver=1.0

***HTTP User-Agents***
- No user agents recorded in this timeframe.

***SSH Clients***
- No SSH clients recorded in this timeframe.

***SSH Servers***
- No SSH servers recorded in this timeframe.

***Top Attacker AS Organizations***
- No AS organizations recorded in this timeframe.

**Key Observations and Anomalies**

- A significant number of commands are related to modifying the `.ssh/authorized_keys` file, indicating a widespread campaign to establish persistent SSH access.
- The `urbotnetisass` malware was downloaded for multiple architectures (ARM, x86, MIPS), suggesting a cross-platform attack campaign.
- The high number of scans on port 445 (SMB) and 5060 (SIP) suggests that attackers are actively searching for vulnerable systems running these services.
- The commands executed indicate a focus on system reconnaissance, with attackers attempting to identify the CPU model, memory, and available disk space.
