
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T13:01:33Z
**Timeframe of Analysis:** 2025-10-10T12:20:01Z to 2025-10-10T13:00:01Z
**Files Used:**
- agg_log_20251010T122001Z.json
- agg_log_20251010T124001Z.json
- agg_log_20251010T130001Z.json

## Executive Summary

This report summarizes 17,815 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks targeted the Cowrie honeypot, indicating a high volume of SSH brute-force attempts. A significant number of scans were also observed on services like SMB (port 445) and SIP (port 5060). The most frequent attacker IP was 51.89.1.86. Several CVEs were detected, with the most common being related to older vulnerabilities. A recurring command pattern was observed where attackers attempted to add their SSH key to the `authorized_keys` file for persistent access.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 10,953
- **Honeytrap:** 2,344
- **Ciscoasa:** 1,762
- **Suricata:** 1,435
- **Dionaea:** 821
- **Sentrypeer:** 367
- **Mailoney:** 42
- **Tanner:** 22
- **H0neytr4p:** 16
- **Redishoneypot:** 12
- **ConPot:** 8
- **ElasticPot:** 8
- **Adbhoney:** 8
- **Dicompot:** 6
- **Honeyaml:** 5
- **Medpot:** 2
- **Heralding:** 3
- **Ipphoney:** 1

### Top Attacking IPs
- **51.89.1.86:** 1246
- **134.199.195.1:** 999
- **167.250.224.25:** 880
- **36.85.250.177:** 644
- **154.92.109.196:** 605
- **52.187.61.159:** 526
- **109.230.196.142:** 427
- **103.107.183.97:** 376
- **77.110.107.92:** 327
- **200.46.125.168:** 302
- **223.197.186.7:** 292
- **101.100.194.23:** 292
- **192.227.152.87:** 248
- **80.98.255.233:** 278
- **160.251.166.49:** 253
- **186.219.133.136:** 243
- **104.168.4.151:** 282
- **4.197.171.110:** 169
- **77.221.152.109:** 168
- **150.109.244.181:** 159

### Top Targeted Ports/Protocols
- **22:** 1579
- **445:** 656
- **5060:** 367
- **5903:** 196
- **5901:** 143
- **8333:** 141
- **1433:** 102
- **TCP/1433:** 106
- **5909:** 83
- **5908:** 82
- **25:** 48
- **23:** 32
- **TCP/445:** 49
- **5907:** 48
- **6036:** 24
- **5910:** 34
- **8001:** 13
- **TCP/8080:** 12
- **TCP/8001:** 11
- **UDP/161:** 14

### Most Common CVEs
- **CVE-2002-0013 CVE-2002-0012:** 10
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 6
- **CVE-2019-11500 CVE-2019-11500:** 3
- **CVE-2021-3449 CVE-2021-3449:** 3
- **CVE-1999-0183:** 1
- **CVE-2021-35394 CVE-2021-35394:** 1

### Commands Attempted by Attackers
- **cd ~; chattr -ia .ssh; lockr -ia .ssh:** 51
- **lockr -ia .ssh:** 51
- **cd ~ && rm -rf .ssh && ...:** 51
- **cat /proc/cpuinfo | grep name | wc -l:** 51
- **Enter new UNIX password:** 51
- **Enter new UNIX password:** 51
- **cat /proc/cpuinfo | grep name | head -n 1 | awk ...:** 51
- **free -m | grep Mem | awk ...:** 51
- **ls -lh $(which ls):** 51
- **which ls:** 51
- **crontab -l:** 51
- **w:** 51
- **uname -m:** 51
- **cat /proc/cpuinfo | grep model | grep name | wc -l:** 51
- **top:** 51
- **uname:** 51
- **uname -a:** 51
- **whoami:** 51
- **lscpu | grep Model:** 51
- **df -h | head -n 2 | awk ...:** 51
- **echo "cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps" | sh:** 2
- **cat /proc/1/mounts && ls /proc/1/; curl2; ps aux; ps\n:** 2
- **curl2:** 2

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 301
- **2402000:** 301
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 205
- **2023753:** 205
- **ET SCAN NMAP -sS window 1024:** 146
- **2009582:** 146
- **ET HUNTING RDP Authentication Bypass Attempt:** 96
- **2034857:** 96
- **ET SCAN Suspicious inbound to MSSQL port 1433:** 100
- **2010935:** 100
- **ET INFO Reserved Internal IP Traffic:** 57
- **2002752:** 57
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 48
- **2024766:** 48
- **ET CINS Active Threat Intelligence Poor Reputation IP group 2:** 20
- **2403301:** 20
- **ET DROP Spamhaus DROP Listed Traffic Inbound group 28:** 16
- **2400027:** 16
- **ET INFO CURL User Agent:** 10
- **2002824:** 10

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 51
- **github/githubgithub:** 9
- **admin/marketing:** 6
- **support/P@ssw0rd:** 6
- **zabbix/zabbix:** 6
- **guest/admin123:** 5
- **minecraft/123minecraft:** 5
- **bitwarden/bitwarden123:** 5
- **tempuser/P@ssw0rd:** 5
- **root/QWE12345:** 4
- **root/QWE12345@:** 4
- **centos/centos10:** 4
- **root/QWE12345!:** 4
- **root/QWE12345.:** 4
- **root/QWE@12345:** 4
- **root/QWE!12345:** 4
- **root/QWE.12345:** 4
- **support/99999:** 4
- **teamspeak3/password1:** 4
- **root/@QWE12345:** 4

### Files Uploaded/Downloaded
- **boatnet.mpsl;**: 1

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients
- No SSH clients recorded in this period.

### SSH Servers
- No SSH servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

## Key Observations and Anomalies

1.  **High Volume of Automated Attacks:** The repetitive nature of commands, login attempts, and scans across multiple IPs suggests widespread automated attacks, likely from botnets.
2.  **Focus on SSH:** The high number of events on the Cowrie honeypot and the targeting of port 22 indicates that SSH remains a primary vector for attackers. The common command to install an SSH key confirms the goal of establishing persistent access.
3.  **Use of Older CVEs:** The detected CVEs are relatively old, suggesting that attackers are scanning for unpatched legacy systems.
4.  **Suspicious File Download:** A file named `boatnet.mpsl` was downloaded. This is likely a payload for a botnet. Further analysis of this file is recommended.
5.  **Reconnaissance Activity:** The use of commands like `lscpu`, `uname -a`, and `free -m` indicates that attackers are performing reconnaissance to understand the system they have compromised.
