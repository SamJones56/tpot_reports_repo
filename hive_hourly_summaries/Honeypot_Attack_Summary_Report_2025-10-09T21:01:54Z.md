# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-09T21:01:30Z
**Timeframe:** 2025-10-09T20:20:01Z to 2025-10-09T21:00:01Z
**Log Files:**
- agg_log_20251009T202001Z.json
- agg_log_20251009T204001Z.json
- agg_log_20251009T210001Z.json

## Executive Summary

This report summarizes 21,674 events recorded across the honeypot network. The majority of attacks targeted SSH services, as observed by the Cowrie honeypot, which accounted for over half of all interactions. Attackers predominantly originated from IP address `167.250.224.25`. The primary activities involved automated scanning for open ports, brute-force login attempts, and the execution of post-breach commands aimed at establishing persistent access via SSH keys. Suricata network alerts frequently triggered for traffic from known malicious sources and scans for services on non-standard ports.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 12,921
- **Honeytrap:** 3,761
- **Suricata:** 2,197
- **Ciscoasa:** 1,723
- **Sentrypeer:** 727
- **Dionaea:** 64
- **Miniprint:** 47
- **Mailoney:** 52
- **Tanner:** 51
- **Honeyaml:** 33
- **Adbhoney:** 17
- **H0neytr4p:** 27
- **Redishoneypot:** 25
- **ConPot:** 18
- **Dicompot:** 3
- **ssh-rsa:** 2
- **ElasticPot:** 5
- **Ipphoney:** 1

### Top Attacking IPs
- 167.250.224.25: 1,745
- 182.92.98.125: 1,144
- 129.212.180.86: 998
- 80.94.95.238: 757
- 151.95.223.48: 470
- 172.245.208.136: 347
- 64.227.102.57: 347
- 107.175.189.123: 333
- 81.30.162.18: 277
- 189.8.108.156: 368
- 192.3.105.24: 283
- 88.210.63.16: 243
- 113.196.185.120: 327
- 105.27.148.94: 322

### Top Targeted Ports/Protocols
- 22
- 5060
- 5903
- 5908
- 5909
- 5901
- 8333
- 80
- 25
- 2222
- 9000

### Most Common CVEs
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-3449
- CVE-2021-35394
- CVE-2019-11500
- CVE-2006-2369
- CVE-1999-0183

### Commands Attempted by Attackers
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `uname -a`
- `whoami`
- `w`
- `crontab -l`
- `top`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753)
- ET DROP Dshield Block Listed Source group 1 (2402000)
- ET SCAN NMAP -sS window 1024 (2009582)
- ET HUNTING RDP Authentication Bypass Attempt (2034857)
- ET INFO Reserved Internal IP Traffic (2002752)
- ET CINS Active Threat Intelligence Poor Reputation IP (various groups)
- ET SCAN Potential SSH Scan (2001219)
- GPL SNMP request udp (2101417)

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- root/[iss@b31@2025, ABcd1234, Admin123!, asdfghjkl, ...]
- operator/administrator
- devops/devops12
- support/support@1
- server/Password123!
- administrator/password@123
- test/[test123, test333, P@ssw0rd1]
- mcserver/[P@ssw0rd@123, 3245gs5662d34]
- user/1984

### Files Uploaded/Downloaded
- `mips.nn`
- `botx.mpsl`
- `w.sh`
- `c.sh`
- `wget.sh`
- `fonts.gstatic.com`
- `css?family=Libre+Franklin...`
- `ie8.css?ver=1.0`
- `html5.js?ver=3.7.3`

### HTTP User-Agents
- None recorded.

### SSH Clients
- None recorded.

### SSH Servers
- None recorded.

### Top Attacker AS Organizations
- None recorded.

## Key Observations and Anomalies

1.  **High-Volume Automated Attacks:** The observed activity is characteristic of widespread, automated scanning and exploitation campaigns. The repetition in commands, IPs, and targeted ports across a short timeframe supports this conclusion.
2.  **Focus on SSH Credential Hijacking:** A predominant attack vector is the attempt to add a new SSH public key to the `authorized_keys` file. This indicates a clear objective to establish persistent, passwordless access to compromised systems.
3.  **Reconnaissance Post-Exploitation:** Attackers consistently attempt to gather system information (CPU, memory, kernel version) immediately after simulated breaches. This is a standard step to understand the compromised environment for further exploitation.
4.  **Legacy Vulnerability Scanning:** The CVEs being targeted are notably old, suggesting a strategy to find and compromise unpatched or legacy systems that are still prevalent on the internet.
5.  **Malware Delivery Attempts:** The downloading of shell scripts (`w.sh`, `c.sh`) and files with names like `botx.mpsl` points to attempts to deploy malware, likely for inclusion in a botnet.
