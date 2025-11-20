# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-23T01:01:34Z
**Timeframe:** 2025-10-23T00:20:01Z to 2025-10-23T01:00:01Z
**Files Used:**
- agg_log_20251023T002001Z.json
- agg_log_20251023T004001Z.json
- agg_log_20251023T010001Z.json

---

## Executive Summary

This report summarizes 24,703 malicious activities detected by our honeypot network. The primary attack vectors were exploits targeting SMB (port 445) and SSH (port 22). A significant portion of the attacks originated from a small number of IP addresses, suggesting targeted campaigns or botnet activity. The most active honeypots were Suricata, Dionaea, and Honeytrap, indicating a high volume of network intrusions and malware propagation attempts.

---

## Detailed Analysis

### Attacks by Honeypot
- Suricata: 6875
- Dionaea: 5927
- Honeytrap: 4488
- Cowrie: 4353
- Ciscoasa: 1773
- Sentrypeer: 934
- Tanner: 167
- H0neytr4p: 116
- Mailoney: 29
- Redishoneypot: 26
- ConPot: 6
- Dicompot: 3
- Adbhoney: 2
- Wordpot: 2
- Heralding: 1
- Honeyaml: 1

### Top Attacking IPs
- 177.46.198.90
- 109.205.211.9
- 46.29.8.110
- 117.2.158.169
- 42.112.247.103
- 138.197.43.50
- 121.43.153.90
- 41.38.5.6
- 203.82.41.210
- 88.210.63.16
- 68.183.4.42
- 185.243.5.146
- 107.170.36.5
- 156.236.31.46
- 172.214.209.153
- 167.250.224.25
- 160.187.147.124
- 68.183.149.135
- 185.243.5.152
- 185.243.5.137

### Top Targeted Ports/Protocols
- 445
- TCP/445
- 5060
- 22
- 80
- 5903
- 5901
- 443
- TCP/22
- 1433
- 8333
- 5904
- 5905
- TCP/80
- 23
- 25

### Most Common CVEs
- CVE-2019-11500
- CVE-2002-1149
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

### Commands Attempted by Attackers
- uname -s -v -n -r -m
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- Accept-Encoding: gzip
- chmod +x clean.sh; sh clean.sh; ...
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; ...

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET WEB_SERVER Possible HTTP 404 XSS Attempt (Local Source)
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 42
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET CINS Active Threat Intelligence Poor Reputation IP group 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 46
- ET WEB_SERVER WEB-PHP phpinfo access

### Users / Login Attempts
- root/Ca691v5N03r15
- root/ca6wUras6x88EC0
- root/Cagayan88
- root/cairoegyptADMIN
- root/callnovo2014
- 345gs5662d34/345gs5662d34
- git/123
- vagrant/vagrant
- esuser/123
- ftpuser/ftpuser
- esuser/esuser123
- root/12345
- root/toor
- root/111111
- root/1q2w3e4r
- root/cal3dxsxtX
- root/Cambio01

### Files Uploaded/Downloaded
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- ?format=json

### HTTP User-Agents
- No user agents were logged in this period.

### SSH Clients and Servers
- **SSH Clients**: No SSH clients were logged in this period.
- **SSH Servers**: No SSH servers were logged in this period.

### Top Attacker AS Organizations
- No AS organizations were logged in this period.

---

## Key Observations and Anomalies

- **High Volume of SMB Scans**: The high number of events on port 445, coupled with DoublePulsar-related signatures, indicates widespread scanning for and exploitation of the EternalBlue vulnerability (MS17-010).
- **SSH Brute-Force and Command Execution**: The Cowrie honeypot captured numerous SSH login attempts with common and default credentials. Successful logins were followed by reconnaissance commands (`uname`, `lscpu`, etc.) and attempts to install SSH keys for persistent access.
- **Repetitive Attack Patterns**: Many of the top attacking IPs exhibited identical, scripted behavior, particularly in the commands executed post-exploitation. This is characteristic of automated botnet activity.
- **Targeting of RDP**: A significant number of "ET HUNTING RDP Authentication Bypass Attempt" signatures were triggered, indicating that attackers are actively searching for exposed Remote Desktop Protocol services.
