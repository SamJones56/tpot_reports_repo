Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-04T16:01:31Z
**Timeframe:** 2025-10-04T15:20:01Z to 2025-10-04T16:00:01Z
**Files Used:**
- agg_log_20251004T152001Z.json
- agg_log_20251004T154001Z.json
- agg_log_20251004T160001Z.json

### Executive Summary

This report summarizes 9,901 events collected from the honeypot network. The majority of malicious activities were captured by the Cowrie and Dionaea honeypots. The most frequent attacks targeted SMB (port 445), SSH (port 22), and SMTP (port 25). A significant portion of attacks originated from IP addresses 15.235.131.242, 138.197.43.50, and 106.75.131.128. Several CVEs were exploited, and a variety of shell commands were attempted, indicating efforts to profile the system and download malicious payloads.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 4406
- Dionaea: 1718
- Mailoney: 830
- Ciscoasa: 1493
- Suricata: 828
- Sentrypeer: 209
- Honeytrap: 101
- Tanner: 89
- Adbhoney: 45
- ConPot: 52
- H0neytr4p: 47
- Redishoneypot: 26
- Dicompot: 22
- Honeyaml: 20
- Ipphoney: 9
- Heralding: 3
- Miniprint: 3

**Top Attacking IPs:**
- 15.235.131.242
- 138.197.43.50
- 106.75.131.128
- 83.168.107.46
- 176.65.141.117
- 64.188.71.75
- 116.202.103.166
- 51.195.149.120
- 46.105.87.113
- 45.186.251.70

**Top Targeted Ports/Protocols:**
- 445
- 22
- 25
- 5060
- 80
- 443
- 23
- TCP/5432
- 6379
- TCP/1433
- UDP/161

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-3449 CVE-2021-3449
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-44228 CVE-2021-44228

**Commands Attempted by Attackers:**
- uname -s -v -n -r -m
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp;... (and variants)
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- crontab -l
- w
- whoami
- mount -o remount,rw /...
- export PATH=...

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET INFO curl User-Agent Outbound
- ET HUNTING curl User-Agent to Dotted Quad
- ET SCAN Suspicious inbound to PostgreSQL port 5432
- GPL SNMP request udp
- ET SCAN Suspicious inbound to MSSQL port 1433
- ET CINS Active Threat Intelligence Poor Reputation IP (various groups)
- ET DROP Spamhaus DROP Listed Traffic Inbound (various groups)

**Users / Login Attempts:**
- root/Aazad@123
- teste/teste
- ubuntu/ubuntu
- root/Alexa@123
- 345gs5662d34/345gs5662d34
- test2/test2
- steam/steam123
- es/es
- root/1qaz@WSX
- deploy/deploy

**Files Uploaded/Downloaded:**
- wget.sh;
- w.sh;
- c.sh;
- ip.php
- soap-envelope
- addressing
- discovery
- devprof
- soap:Envelope>

**HTTP User-Agents:**
- (No data in logs)

**SSH Clients and Servers:**
- (No data in logs)

**Top Attacker AS Organizations:**
- (No data in logs)

### Key Observations and Anomalies

- **High Volume from Single IPs:** A small number of IP addresses are responsible for a large percentage of the total attack volume, suggesting targeted or botnet-driven activity.
- **Payload Download Attempts:** The repeated use of `wget` and `curl` in attempted commands points to attackers trying to download and execute malicious scripts from external servers. The command `rm -rf /data/local/tmp;...` is a clear indicator of this pattern.
- **System Reconnaissance:** Commands like `uname`, `lscpu`, `cat /proc/cpuinfo`, and `free -m` are used by attackers to gather information about the compromised system's architecture and resources.
- **Lack of HTTP/SSH Data:** The absence of specific data for HTTP User-Agents and SSH clients/servers might indicate that attacks over these vectors were not successful enough to log detailed metadata, or that the primary attacks focused on other protocols like SMB and SMTP.
- **Targeting of Database Ports:** A notable number of scans were directed at PostgreSQL (5432) and MSSQL (1433) ports, indicating interest in compromising database servers.
