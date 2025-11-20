Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T10:01:29Z
**Timeframe:** 2025-10-04T09:20:01Z to 2025-10-04T10:00:01Z
**Files Analyzed:**
- agg_log_20251004T092001Z.json
- agg_log_20251004T094001Z.json
- agg_log_20251004T100001Z.json

**Executive Summary:**
This report summarizes 21,778 attacks recorded by the honeypots over the last hour. The majority of attacks were detected by the Suricata, Cowrie, and Dionaea honeypots. A significant portion of the traffic targeted SMB (port 445), likely related to exploits like the DoublePulsar backdoor, which was the most frequently triggered signature. Attackers predominantly used a small set of IPs, with `62.176.70.101` being the most active. A number of CVEs were detected, and attackers attempted a variety of commands, including efforts to add SSH keys for persistent access.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Suricata
- Cowrie
- Dionaea
- Mailoney
- Ciscoasa
- Honeytrap
- Sentrypeer
- Redishoneypot
- Adbhoney
- Tanner
- ConPot
- H0neytr4p

**Top Attacking IPs:**
- 62.176.70.101
- 203.92.35.94
- 210.2.131.130
- 39.171.62.133
- 118.172.155.37
- 93.115.79.198
- 176.65.141.117
- 115.124.85.161
- 196.251.80.29
- 157.10.52.50

**Top Targeted Ports/Protocols:**
- TCP/445
- 445
- 25
- 22
- 5060
- 3306
- TCP/80
- 6379
- 23
- TCP/5432

**Most Common CVEs:**
- CVE-2021-3449
- CVE-2019-11500
- CVE-2002-0013
- CVE-2002-0012
- CVE-2024-3721
- CVE-2016-20016
- CVE-2021-35394

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `which ls`
- `ls -lh $(which ls)`
- `crontab -l`
- `w`
- `uname -m`
- `uname -a`
- `whoami`
- `top`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`
- `Enter new UNIX password:`

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET CINS Active Threat Intelligence Poor Reputation IP group 51
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET CINS Active Threat Intelligence Poor Reputation IP group 68
- ET CINS Active Threat Intelligence Poor Reputation IP group 45

**Users / Login Attempts:**
- a2billinguser/
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- superadmin/admin123
- root/nPSpP4PBW0
- azureuser/azureuser@123
- root/Root123!@#
- test/zhbjETuyMffoL8F
- cstrike/123
- adm/abc123

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- boatnet.mpsl;

**HTTP User-Agents:**
- None observed.

**SSH Clients and Servers:**
- No specific SSH client or server versions were recorded in the logs.

**Top Attacker AS Organizations:**
- No specific AS organizations were recorded in the logs.

**Key Observations and Anomalies:**
- A recurring command sequence was observed where attackers attempt to add their SSH public key to the `authorized_keys` file. This is a common technique for establishing persistent access to a compromised machine. The repeated use of the same SSH key across different attacking IPs suggests a coordinated campaign.
- Several commands were executed to gather system information, such as CPU, memory, and disk space. This is typical post-exploitation behavior to assess the resources of the compromised system.
- The `rm -rf /tmp/secure.sh; ...` command suggests an attempt to remove competing malware or security scripts.
- Attackers were observed downloading and executing shell scripts (`wget.sh`, `w.sh`, `c.sh`), indicating attempts to install malware or other tools.
