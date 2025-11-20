# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T16:01:28Z
**Timeframe:** 2025-10-19T15:20:01Z to 2025-10-19T16:00:01Z
**Files:** agg_log_20251019T152001Z.json, agg_log_20251019T154001Z.json, agg_log_20251019T160001Z.json

## Executive Summary

This report summarizes 22,094 events collected from the T-Pot honeypot network over the last hour. The primary attack vectors observed were SSH brute-force attempts and scans for vulnerabilities in VOIP and Windows services. The most active honeypot was Cowrie, indicating a high volume of SSH-based attacks. A significant number of commands were attempted post-compromise, primarily focused on reconnaissance and establishing further persistence by adding SSH keys.

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 7472
- Honeytrap: 6090
- Sentrypeer: 2842
- Suricata: 2630
- Dionaea: 2162
- Ciscoasa: 732
- H0neytr4p: 53
- Tanner: 49
- Mailoney: 25
- Redishoneypot: 17
- ElasticPot: 8
- Adbhoney: 6
- Ipphoney: 4
- Honeyaml: 4

### Top Attacking IPs
- 198.23.238.154: 2797
- 84.162.68.10: 1617
- 194.50.16.73: 1491
- 198.23.190.58: 1204
- 72.146.232.13: 1212
- 23.94.26.58: 1182
- 198.12.68.114: 848
- 103.79.155.140: 690
- 45.128.199.34: 511
- 157.230.85.50: 306
- 185.243.5.103: 380
- 103.181.142.244: 228
- 103.145.145.75: 212
- 185.158.22.150: 232
- 203.83.234.180: 218
- 61.190.114.203: 200
- 119.255.245.44: 195
- 91.235.160.35: 188
- 107.170.36.5: 165
- 60.199.224.2: 159

### Top Targeted Ports/Protocols
- 5038: 2880
- 5060: 2842
- 445: 1853
- 22: 1611
- UDP/5060: 1394
- 5903: 226
- TCP/22: 140
- 1433: 86
- 8333: 86
- 5901: 123
- 5904: 75
- 5905: 75
- 42: 90
- 23: 43
- 80: 49
- 11211: 38
- 443: 34
- 5907: 49
- 5908: 50
- 5909: 49

### Most Common CVEs
- CVE-2005-4050: 1385
- CVE-2003-0825: 12
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2021-3449 CVE-2021-3449: 4
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2001-0414: 2
- CVE-2002-1149: 1

### Commands Attempted by Attackers
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 20
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 20
- lockr -ia .ssh: 20
- cat /proc/cpuinfo | grep name | wc -l: 20
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 20
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 20
- ls -lh $(which ls): 20
- which ls: 20
- crontab -l: 20
- w: 20
- uname -m: 20
- cat /proc/cpuinfo | grep model | grep name | wc -l: 20
- top: 20
- uname: 20
- uname -a: 20
- whoami: 20
- lscpu | grep Model: 20
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 20
- Enter new UNIX password: : 16
- Enter new UNIX password:": 16

### Signatures Triggered
- ET VOIP MultiTech SIP UDP Overflow: 1385
- ET DROP Dshield Block Listed Source group 1: 270
- ET SCAN NMAP -sS window 1024: 167
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 138
- ET SCAN Potential SSH Scan: 129
- ET INFO Reserved Internal IP Traffic: 56
- ET HUNTING RDP Authentication Bypass Attempt: 44
- ET CINS Active Threat Intelligence Poor Reputation IP group 97: 9
- ET INFO CURL User Agent: 17
- GPL EXPLOIT WINS name query overflow attempt TCP: 12

### Users / Login Attempts
- 345gs5662d34/345gs5662d34: 19
- user01/Password01: 11
- debian/debian2003: 6
- config/config12345678: 6
- blank/blank2013: 6
- guest/2222: 6
- support/33333: 6
- admin/7: 6
- user/22222: 6
- root/9: 6
- root/692569: 4
- user/p@ssw0rd: 4
- nobody/password321: 4
- root/699133: 4
- deploy/123123: 4
- root/6998226: 4
- test/asdfgh: 4
- root/69983758: 4
- root/6dZ47Qvae1BxTQE6: 4
- root/6pgxrp3tjy2q: 4

### Files Uploaded/Downloaded
- nse.html): 1
- &currentsetting.htm=1: 1

### HTTP User-Agents
- No user agents recorded.

### SSH Clients
- No SSH clients recorded.

### SSH Servers
- No SSH servers recorded.

### Top Attacker AS Organizations
- No AS organizations recorded.

## Key Observations and Anomalies

- **Consistent SSH Key Injection**: A recurring command sequence attempts to remove existing SSH configurations and inject a specific public key ("...mdrfckr"). This indicates a coordinated campaign to maintain persistent access to compromised systems.
- **VOIP Vulnerability Scanning**: The high number of "ET VOIP MultiTech SIP UDP Overflow" signatures, coupled with traffic on ports 5060 and 5038, suggests widespread automated scanning for vulnerabilities in SIP-based VOIP systems.
- **Lack of Diversity in Post-Exploitation**: The commands executed by attackers are almost identical across multiple sessions, suggesting the use of automated scripts rather than interactive sessions. The focus is on system reconnaissance and establishing SSH persistence.
- **Low-level CVEs**: The triggered CVEs are relatively old, indicating that attackers are targeting legacy or unpatched systems.
