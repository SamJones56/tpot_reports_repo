
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-14T16:01:35Z
**Timeframe:** 2025-10-14T15:20:01Z to 2025-10-14T16:00:01Z
**Files Used:**
- agg_log_20251014T152001Z.json
- agg_log_20251014T154001Z.json
- agg_log_20251014T160001Z.json

## Executive Summary
This report summarizes 19,238 security events captured by the T-Pot honeypot network. The majority of attacks were registered on the Dionaea, Cowrie, and Sentrypeer honeypots. A significant portion of the traffic originated from the IP address 200.84.214.248. The most targeted ports were 445 (SMB) and 5060 (SIP). A number of CVEs were detected, and attackers attempted various commands, primarily focused on reconnaissance and establishing persistent access.

## Detailed Analysis

### Attacks by Honeypot
- Dionaea: 3374
- Sentrypeer: 3599
- Cowrie: 3840
- Honeytrap: 3720
- Ciscoasa: 1741
- Suricata: 1508
- Mailoney: 904
- Tanner: 177
- Adbhoney: 125
- H0neytr4p: 98
- ConPot: 34
- Redishoneypot: 39
- ElasticPot: 10
- Dicompot: 7
- Honeyaml: 29
- Miniprint: 30
- Ipphoney: 3

### Top Attacking IPs
- 200.84.214.248: 3135
- 185.243.5.146: 1246
- 206.191.154.180: 1343
- 185.243.5.148: 762
- 172.86.95.98: 415
- 172.86.95.115: 408
- 88.210.63.16: 405
- 89.117.54.101: 399
- 209.15.115.240: 265
- 62.141.43.183: 322

### Top Targeted Ports/Protocols
- 445: 3226
- 5060: 3599
- 22: 543
- 80: 185
- 25: 910
- 1433: 99
- 443: 87
- 5903: 197
- 5901: 136
- TCP/1433: 97

### Most Common CVEs
- CVE-2002-1149
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2023-26801 CVE-2023-26801
- CVE-2018-10562 CVE-2018-10561
- CVE-2013-7471 CVE-2013-7471
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542
- CVE-2006-2369

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem
- uname -a
- whoami
- Enter new UNIX password: 
- chmod 0755 /data/local/tmp/nohup
- chmod 0755 /data/local/tmp/trinity
- /data/local/tmp/nohup su -c /data/local/tmp/trinity

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET INFO CURL User Agent

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/Qaz123qaz
- root/Password@2025
- guest/guest2024
- guest/2222222
- config/88
- user/5
- root/Ced34116200
- default/default222
- support/abc123

### Files Uploaded/Downloaded
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png
- ns#
- sign_in
- no_avatar-849f9c04a3a0d0cea2424ae97b27447dc64a7dbfae83c036c45b403392f0e8ba.png
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- No HTTP User-Agents were recorded in this period.

### SSH Clients and Servers
- No SSH clients or servers were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

## Key Observations and Anomalies
- The volume of attacks remained consistently high across the reporting period.
- A significant number of commands were related to establishing SSH access and gathering system information, suggesting attempts to create persistent backdoors.
- The `urbotnetisass` malware was downloaded for various architectures (arm, x86, mips), indicating a widespread campaign targeting IoT devices and embedded systems.
- The IP address 200.84.214.248 was the most active attacker, responsible for a large number of events targeting SMB services.
- There is a noticeable amount of scanning activity for MS Terminal Server, MSSQL, and RDP, indicating that attackers are actively searching for vulnerable Windows systems.
