# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-24T21:01:29Z
**Timeframe of Logs:** 2025-10-24T20:20:01Z to 2025-10-24T21:00:01Z
**Files Used:**
- agg_log_20251024T202001Z.json
- agg_log_20251024T204001Z.json
- agg_log_20251024T210001Z.json

## Executive Summary

This report summarizes 23,219 events captured by the honeypot network. The majority of malicious traffic was captured by the Honeytrap, Cowrie, and Suricata honeypots. Attackers primarily focused on exploiting SSH and SMB vulnerabilities, with a significant number of brute-force login attempts using the 'root' user. A recurring attack pattern involved attempts to modify SSH authorized keys for persistent access and download malicious scripts. The most prominent attacking IP was 159.223.179.74.

## Detailed Analysis

### Attacks by Honeypot
- Honeytrap: 8143
- Cowrie: 7040
- Suricata: 5434
- Ciscoasa: 1743
- Sentrypeer: 228
- Dionaea: 164
- Tanner: 64
- Miniprint: 67
- Mailoney: 128
- ConPot: 58
- Adbhoney: 33
- Redishoneypot: 22
- H0neytr4p: 19
- ElasticPot: 61
- Honeyaml: 5
- Ipphoney: 5
- Dicompot: 3
- ssh-ed25519: 2

### Top Attacking IPs
- 159.223.179.74: 3675
- 109.205.211.9: 2545
- 199.127.63.138: 1732
- 114.34.113.140: 1324
- 80.94.95.238: 1387
- 47.239.59.121: 1042
- 117.2.142.24: 313
- 103.172.28.62: 336
- 36.103.243.179: 308
- 177.10.201.7: 329

### Top Targeted Ports/Protocols
- 22
- 445
- 8333
- 5060
- 5901
- 5903
- 25
- 80
- 9100
- 9200

### Most Common CVEs
- CVE-2021-3449
- CVE-2019-11500
- CVE-2006-2369
- CVE-2024-4577
- CVE-2002-0953
- CVE-2021-41773
- CVE-2021-42013
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-1999-0183

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- uname -a
- whoami
- lscpu | grep Model
- top
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- Enter new UNIX password:
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET HUNTING RDP Authentication Bypass Attempt
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP
- ET SCAN Sipsak SIP scan

### Users / Login Attempts
- root/
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/12345
- root/123
- root/1qazxsw2
- root/trips123
- root/AvazZ@2019.avaco
- root/nimda
- root/sistema500
- root/sm.2013
- root/a
- root/aa
- root/aaa
- root/aaaa

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- sh
- arm.urbotnetisass
- arm5.urbotnetisass
- arm6.urbotnetisass
- arm7.urbotnetisass
- x86_32.urbotnetisass
- mips.urbotnetisass
- mipsel.urbotnetisass

### HTTP User-Agents
- N/A

### SSH Clients
- N/A

### SSH Servers
- N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies

1.  **Persistent Access Attempts:** A significant number of command executions were aimed at modifying the `.ssh/authorized_keys` file. This is a clear indicator of attackers attempting to establish persistent, passwordless access to the compromised system.

2.  **Malware Delivery:** The logs show multiple attempts to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) and ELF binaries (`.urbotnetisass` files for different architectures). This suggests a coordinated campaign to deploy malware, likely for botnet recruitment.

3.  **System Reconnaissance:** Attackers frequently ran commands to gather information about the system's hardware (`lscpu`, `/proc/cpuinfo`) and operating system (`uname -a`), which is a typical precursor to more targeted attacks.

4.  **High Volume Scanning:** The high counts for signatures like "ET SCAN MS Terminal Server Traffic on Non-standard Port" and the variety of targeted ports indicate widespread, automated scanning activity across the internet, looking for any open and vulnerable services.
