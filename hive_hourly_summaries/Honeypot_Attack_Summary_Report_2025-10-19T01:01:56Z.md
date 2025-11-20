
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T01:01:27Z
**Timeframe:** 2025-10-19T00:20:01Z to 2025-10-19T01:00:01Z
**Files Used:** `agg_log_20251019T002001Z.json`, `agg_log_20251019T004001Z.json`, `agg_log_20251019T010001Z.json`

## Executive Summary

This report summarizes 16,833 events collected from the honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts and automated script executions. A significant number of events were also flagged by Suricata, primarily related to VoIP vulnerabilities (CVE-2005-4050). The most prominent attacking IP addresses originate from various global locations, with a notable concentration of activity from `45.10.175.77` and `39.99.144.218`. Attackers primarily targeted SIP (5060) and SSH (22) ports.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7032
- Honeytrap: 3147
- Suricata: 3108
- Sentrypeer: 1990
- Ciscoasa: 1150
- H0neytr4p: 192
- Tanner: 58
- Dionaea: 57
- ConPot: 37
- Mailoney: 23
- Dicompot: 21
- Honeyaml: 6
- Redishoneypot: 6
- Ipphoney: 5
- ElasticPot: 1

### Top Attacking IPs
- 45.10.175.77
- 72.146.232.13
- 198.23.190.58
- 23.94.26.58
- 39.99.144.218
- 194.50.16.73
- 198.12.68.114
- 88.210.63.16
- 202.140.142.229
- 116.193.190.134

### Top Targeted Ports/Protocols
- 5060
- 22
- UDP/5060
- 5903
- 8333
- 443
- 5901
- 80
- TCP/443
- TCP/80

### Most Common CVEs
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2021-35394 CVE-2021-35394
- CVE-2024-4577 CVE-2024-4577
- CVE-2024-4577 CVE-2002-0953
- CVE-2001-0414
- CVE-2006-2369
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773
- CVE-2021-42013 CVE-2021-42013
- CVE-1999-0183
- CVE-2019-11500 CVE-2019-11500

### Commands Attempted by Attackers
- `uname -a`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa..."`
- `cat /proc/cpuinfo | grep name | wc -l`
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `w`
- `uname -m`

### Signatures Triggered
- ET VOIP MultiTech SIP UDP Overflow
- ET DROP Dshield Block Listed Source group 1
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET SCAN NMAP -sS window 1024
- ET HUNTING RDP Authentication Bypass Attempt
- ET INFO Reserved Internal IP Traffic
- ET SCAN Potential SSH Scan
- ET CINS Active Threat Intelligence Poor Reputation IP group 49
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- GPL SNMP request udp

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- debian/debian2023
- default/default2000
- support/support2008
- test/test2004
- nobody/77
- ubnt/112233
- root/Unknown@123
- root/3mm4nu3l19
- root/3mpAsterisk

### Files Uploaded/Downloaded
- sh
- loader.sh
- loader.sh&&chmod
- loader.sh|sh;#
- gpon8080&ipv=0
- soap-envelope
- addressing
- discovery
- devprof
- soap:Envelope>

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

- **VoIP Attacks:** The high number of `ET VOIP MultiTech SIP UDP Overflow` signatures, corresponding to CVE-2005-4050, indicates a widespread, automated campaign targeting VoIP servers.
- **SSH-based Persistence:** A recurring command sequence (`cd ~ && rm -rf .ssh && ... authorized_keys`) shows a clear and repeated attempt by attackers to establish persistent access to compromised machines by adding their SSH key.
- **System Reconnaissance:** Attackers frequently run commands like `uname`, `lscpu`, `free -m`, and `cat /proc/cpuinfo`, which are typical reconnaissance activities to understand the compromised environment before deploying further payloads.
- **Lack of Diversity in Payloads:** The files downloaded are predominantly simple shell scripts (`sh`, `loader.sh`), suggesting the initial stage of an attack, likely leading to the download of more sophisticated malware.
