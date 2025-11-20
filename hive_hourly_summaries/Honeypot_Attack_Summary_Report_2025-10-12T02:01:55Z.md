
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T02:01:36Z
**Timeframe:** 2025-10-12T01:20:02Z to 2025-10-12T02:00:01Z
**Files Used:**
- agg_log_20251012T012002Z.json
- agg_log_20251012T014001Z.json
- agg_log_20251012T020001Z.json

## Executive Summary

This report summarizes 16,403 attacks detected by the honeypot network. The most targeted honeypot was Cowrie, a medium interaction SSH and Telnet honeypot. A significant number of attacks were detected by Suricata, a network intrusion detection system. Attackers were observed attempting to exploit known vulnerabilities, gain unauthorized access using common credentials, and execute malicious commands.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7772
- Suricata: 3173
- Honeytrap: 3109
- Ciscoasa: 1862
- Sentrypeer: 146
- Mailoney: 130
- Dionaea: 70
- Tanner: 31
- H0neytr4p: 30
- ConPot: 23
- Redishoneypot: 21
- Adbhoney: 17
- Honeyaml: 12
- ElasticPot: 4
- ssh-rsa: 2
- Miniprint: 1

### Top Attacking IPs
- 213.130.93.177: 1472
- 157.245.101.239: 1249
- 71.168.162.91: 615
- 118.194.250.47: 317
- 79.100.236.115: 355
- 117.23.59.88: 411
- 103.176.79.139: 309
- 147.45.112.157: 178
- 42.248.124.215: 194
- 51.75.194.44: 203

### Top Targeted Ports/Protocols
- 22: 1201
- TCP/445: 1469
- 5903: 187
- 5060: 146
- 25: 130
- 5908: 84
- 5909: 84
- 5901: 75
- 10000: 38
- TCP/22: 48

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 6
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 1
- CVE-2019-11500 CVE-2019-11500: 1

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 39
- lockr -ia .ssh: 39
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 39
- cat /proc/cpuinfo | grep name | wc -l: 30
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 30
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 30
- ls -lh $(which ls): 30
- which ls: 30
- crontab -l: 30
- w: 30
- uname -m: 30
- cat /proc/cpuinfo | grep model | grep name | wc -l: 30
- top: 30
- uname: 30
- uname -a: 30
- whoami: 31
- lscpu | grep Model: 30
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 30
- Enter new UNIX password: : 17

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1466
- ET DROP Dshield Block Listed Source group 1: 516
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 165
- ET SCAN NMAP -sS window 1024: 159
- ET HUNTING RDP Authentication Bypass Attempt: 59
- ET INFO Reserved Internal IP Traffic: 62
- ET SCAN Potential SSH Scan: 37
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 28
- ET INFO CURL User Agent: 10

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 38
- root/3245gs5662d34: 14
- Default/passwd: 6
- admin/123321: 4
- operator/operator13: 4
- user/user11: 4
- sa/: 4
- root/Passwd123: 4
- root/VienAnHiepViet123: 4
- admin/123.com: 4
- root/asd: 4
- jira/jira: 4
- root/!Q2w3e4r: 4
- pi/raspberry: 4
- root/oussama: 4
- root/A1b2c3d4: 4
- root/ipnet769: 4
- root/asd123456.: 4
- default/Default2020: 4
- misp/Password1234: 4

### Files Uploaded/Downloaded
- wget.sh;: 4
- arm.urbotnetisass;: 1
- arm.urbotnetisass: 1
- arm5.urbotnetisass;: 1
- arm5.urbotnetisass: 1
- arm6.urbotnetisass;: 1
- arm6.urbotnetisass: 1
- arm7.urbotnetisass;: 1
- arm7.urbotnetisass: 1
- x86_32.urbotnetisass;: 1
- x86_32.urbotnetisass: 1
- mips.urbotnetisass;: 1
- mips.urbotnetisass: 1
- mipsel.urbotnetisass;: 1
- mipsel.urbotnetisass: 1
- icanhazip.com: 2
- w.sh;: 1
- c.sh;: 1

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies
- The vast majority of attacks are automated, focusing on common vulnerabilities and weak credentials.
- The high number of Suricata alerts for "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication" indicates a significant amount of scanning for hosts vulnerable to this exploit.
- The commands attempted by attackers suggest an effort to gather system information, escalate privileges, and establish persistence. The repeated attempts to modify `.ssh/authorized_keys` is a common technique to maintain access to a compromised system.
- The variety of files downloaded, such as `arm.urbotnetisass`, `mips.urbotnetisass`, etc., suggests that attackers are attempting to deploy malware on a wide range of architectures.
