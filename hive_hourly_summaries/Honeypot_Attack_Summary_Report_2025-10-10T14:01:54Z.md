
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T14:01:28Z
**Timeframe:** 2025-10-10T13:20:02Z to 2025-10-10T14:00:01Z
**Files Used:**
- agg_log_20251010T132002Z.json
- agg_log_20251010T134001Z.json
- agg_log_20251010T140001Z.json

## Executive Summary
This report summarizes 12,218 malicious events captured by the honeypot network. The majority of attacks were SSH brute-force attempts and SMBv1 exploit attempts. A significant number of attacks originated from IP address `39.34.90.61`, which was observed attempting to install the DoublePulsar backdoor.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 4099
- Suricata: 2599
- Honeytrap: 2571
- Ciscoasa: 1737
- Mailoney: 850
- H0neytr4p: 78
- Dionaea: 71
- Miniprint: 69
- Tanner: 35
- Sentrypeer: 35
- Dicompot: 15
- Honeyaml: 20
- ConPot: 9
- ssh-rsa: 8
- Redishoneypot: 12
- Adbhoney: 6
- Ipphoney: 2
- ElasticPot: 1
- Medpot: 1

### Top Attacking IPs
- 39.34.90.61: 1090
- 167.250.224.25: 851
- 176.65.141.117: 820
- 14.225.203.222: 317
- 181.49.50.6: 253
- 42.200.66.164: 240
- 167.71.196.171: 189
- 152.53.195.199: 188
- 88.210.63.16: 137
- 159.89.121.144: 107

### Top Targeted Ports/Protocols
- TCP/445: 1086
- 25: 842
- 22: 620
- 5903: 201
- 8333: 151
- 5901: 151
- 443: 78
- 5908: 83
- 5909: 82
- 9100: 69
- 1433: 82
- 23: 26
- 80: 23
- 5060: 35
- 17000: 27
- 1521: 29

### Most Common CVEs
- CVE-1999-0183
- CVE-2016-20016
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

### Commands Attempted by Attackers
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
- uname -a
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- crontab -l
- w
- uname -m
- top
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- /ip cloud print
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- tftp; wget; /bin/busybox DYVDP

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET INFO CURL User Agent
- GPL INFO SOCKS Proxy attempt
- ET SCAN Suspicious inbound to Oracle SQL port 1521

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/
- admin/P@ssword123
- Ubnt/555555555
- user/1234567890
- admin/abcd123456
- root/ASD123
- student/1
- tomcat/tomcat
- test/abc123
- lab/lab!
- deployer/deployer@
- github/Password123

### Files Uploaded/Downloaded
- discovery
- soap-envelope
- soap-encoding
- addressing
- a:ReplyTo><a:To
- wsdl

### HTTP User-Agents
- None observed

### SSH Clients and Servers
- None observed

### Top Attacker AS Organizations
- None observed

## Key Observations and Anomalies
- A high volume of SMB traffic from `39.34.90.61` suggests a targeted campaign to exploit the vulnerability associated with the DoublePulsar backdoor.
- The IP `176.65.141.117` was responsible for a large number of SMTP requests, possibly indicating a spam campaign or reconnaissance.
- A recurring command involves attempts to add a specific SSH public key to the authorized_keys file, indicating a consistent attempt to maintain persistent access.
- A variety of brute-force credentials were attempted, with a mix of default passwords and common patterns.
