
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T05:01:48Z
**Timeframe:** 2025-10-25T04:20:01Z to 2025-10-25T05:00:01Z
**Log Files:**
- agg_log_20251025T042001Z.json
- agg_log_20251025T044001Z.json
- agg_log_20251025T050001Z.json

## Executive Summary

This report summarizes 21,019 malicious events recorded by the honeypot network over the specified period. The majority of activity was captured by the Cowrie (SSH/Telnet), Suricata (IDS/IPS), and Honeytrap honeypots. A significant portion of the attacks originated from IP address `109.205.211.9`. The most targeted services were SSH (Port 22) and SMB (Port 445). Attackers were observed attempting to gain initial access via brute-force attacks and then execute commands to gather system information and install malware, including variants of the `urbotnet` botnet. Several CVEs were triggered, indicating attempts to exploit known vulnerabilities.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7727
- Suricata: 5787
- Honeytrap: 4488
- Ciscoasa: 1862
- Dionaea: 524
- Sentrypeer: 185
- Mailoney: 145
- H0neytr4p: 76
- Tanner: 113
- Redishoneypot: 35
- Honeyaml: 24
- Adbhoney: 19
- ConPot: 17
- Miniprint: 9
- ElasticPot: 6
- Ipphoney: 2

### Top Attacking IPs
- 109.205.211.9: 2663
- 190.6.14.144: 1491
- 164.92.85.77: 1247
- 80.94.95.238: 1480
- 50.6.225.98: 1251
- 85.208.253.156: 488
- 152.32.252.65: 470
- 222.124.17.227: 469
- 197.44.15.210: 387
- 125.23.248.170: 388
- 103.186.1.197: 379
- 107.170.36.5: 253
- 156.246.91.141: 255
- 14.103.177.217: 202
- 167.99.78.165: 174
- 46.245.82.12: 184
- 18.224.184.103: 133
- 103.76.120.90: 134
- 119.92.70.82: 129
- 14.34.157.138: 123

### Top Targeted Ports/Protocols
- 445 (SMB): 2302 (includes TCP/445)
- 22 (SSH): 1121 (includes TCP/22)
- 8333: 193
- 80 (HTTP): 114 (includes TCP/80)
- 5060 (SIP): 185
- 5903: 134
- 25 (SMTP): 145
- 5901: 118
- 3306 (MySQL): 79
- 5905: 77
- 5904: 77
- 443 (HTTPS): 62
- 6667 (IRC): 63
- 8888: 18
- 5909: 52
- 5908: 50
- 5907: 49
- 5902: 39
- 6379 (Redis): 18
- 1234: 34

### Most Common CVEs
- CVE-2024-4577: 8
- CVE-2002-0013, CVE-2002-0012: 5
- CVE-2019-11500: 4
- CVE-2021-3449: 3
- CVE-2021-41773: 2
- CVE-2021-42013: 2
- CVE-2024-12856, CVE-2024-12885: 1
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 1
- CVE-2006-2369: 1

### Commands Attempted by Attackers
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys ...`: 37
- `lockr -ia .ssh`: 37
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 37
- `cat /proc/cpuinfo | grep name | wc -l`: 38
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 38
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 38
- `ls -lh $(which ls)`: 38
- `which ls`: 38
- `crontab -l`: 38
- `w`: 38
- `uname -m`: 38
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 38
- `top`: 38
- `uname`: 38
- `uname -a`: 38
- `whoami`: 38
- `lscpu | grep Model`: 37
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 37
- `Enter new UNIX password: `: 24
- `Enter new UNIX password:`: 22

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 2055
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766): 1485
- ET HUNTING RDP Authentication Bypass Attempt (2034857): 693
- ET DROP Dshield Block Listed Source group 1 (2402000): 504
- ET SCAN NMAP -sS window 1024 (2009582): 184
- ET INFO Reserved Internal IP Traffic (2002752): 57
- ET SCAN Potential SSH Scan (2001219): 24
- ET CINS Active Threat Intelligence Poor Reputation IP group 50 (2403349): 29
- ET CINS Active Threat Intelligence Poor Reputation IP group 46 (2403345): 23
- ET INFO CURL User Agent (2002824): 10

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 37
- root/3245gs5662d34: 14
- root/elastix456xxxxxx: 4
- root/elastix321nia: 4
- root/elastix352: 4
- jenkins/!@#$%^: 4
- root/oscar123: 4
- root/Admin.123: 4
- myftp/myftp: 4
- root/t5r4e3: 4
- root/sa2023: 4
- marie/marie: 4
- cyril/cyril: 4
- root/elastix66: 4
- admin/admin123: 4
- pc01/pc01: 3
- root/ted: 3
- root/Asdf123456: 3
- support/support2025: 3
- support/3245gs5662d34: 3

### Files Uploaded/Downloaded
- sh: 188
- arm.urbotnetisass: 2
- arm5.urbotnetisass: 2
- arm6.urbotnetisass: 2
- arm7.urbotnetisass: 2
- x86_32.urbotnetisass: 2
- mips.urbotnetisass: 2
- mipsel.urbotnetisass: 2
- 129.212.146.61:8088: 2
- apply.cgi: 2
- json: 1
- soap-envelope: 1
- addressing: 1
- discovery: 1
- env:Envelope>: 1
- welcome.jpg): 1
- writing.jpg): 1
- tags.jpg): 1

### HTTP User-Agents
- No HTTP User-Agents were recorded in this timeframe.

### SSH Clients and Servers
- No specific SSH client or server versions were recorded.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this timeframe.

## Key Observations and Anomalies

- **High Volume of Cowrie Events:** The large number of events from the Cowrie honeypot indicates a high level of automated SSH and Telnet brute-force and command execution attempts.
- **Botnet Activity:** The downloading of files named `arm.urbotnetisass` and its variants from IP `94.154.35.154` (observed in logs) is a strong indicator of an automated campaign to expand a botnet.
- **Reconnaissance and Persistence:** Attackers consistently ran a series of commands to fingerprint the system (`uname`, `lscpu`, `whoami`) immediately followed by attempts to establish persistence by adding their SSH key to `authorized_keys`. The use of `chattr` and `lockr` suggests an attempt to prevent other attackers or administrators from removing their access.
- **DoublePulsar Activity:** The triggering of the "DoublePulsar Backdoor" signature indicates that attackers are still actively scanning for and attempting to exploit systems vulnerable to the SMB exploits leaked by the Shadow Brokers.
