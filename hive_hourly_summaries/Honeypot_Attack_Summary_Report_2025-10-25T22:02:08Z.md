
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-25T22:01:40Z
**Timeframe:** 2025-10-25T21:20:01Z to 2025-10-25T22:00:02Z
**Log Files:**
- agg_log_20251025T212001Z.json
- agg_log_20251025T214002Z.json
- agg_log_20251025T220002Z.json

---

## Executive Summary

This report summarizes 23,382 events collected from multiple honeypots over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie (SSH/Telnet) honeypot, followed by Honeytrap and Suricata. The most prominent activity involved widespread scanning and brute-force attempts targeting SSH (port 22) and SMB (port 445). A significant number of attacks originated from the IP address 80.94.95.238. Attackers were observed attempting to disable security measures, install SSH keys for persistence, and perform system reconnaissance. Multiple CVEs were triggered, with CVE-2022-27255 (related to Realtek SDK) being the most common.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 8,536
- **Honeytrap:** 5,432
- **Suricata:** 4,096
- **Dionaea:** 2,434
- **Ciscoasa:** 1,812
- **Sentrypeer:** 805
- **Mailoney:** 98
- **Redishoneypot:** 45
- **ElasticPot:** 24
- **H0neytr4p:** 28
- **Tanner:** 21
- **ConPot:** 20
- **Honeyaml:** 14
- **Ipphoney:** 10
- **Adbhoney:** 2
- **Wordpot:** 1

### Top Attacking IPs
- 80.94.95.238: 3,224
- 41.139.169.77: 2,356
- 109.205.211.9: 964
- 143.198.201.181: 917
- 103.123.53.88: 811
- 23.94.26.58: 1,015
- 167.172.36.54: 378
- 159.65.199.13: 334
- 211.201.163.70: 356
- 103.187.147.214: 356
- 122.155.223.9: 287
- 83.97.24.41: 261
- 70.162.118.238: 241
- 107.170.36.5: 169
- 107.175.37.3: 173

### Top Targeted Ports/Protocols
- 445: 2,362
- 22: 1,250
- 5060: 805
- UDP/5060: 466
- 8333: 243
- 5903: 127
- 5901: 111
- 25: 98
- 5904: 79
- 5905: 76
- TCP/22: 71
- 6379: 42
- 23: 25
- 8728: 52

### Most Common CVEs
- CVE-2022-27255
- CVE-2021-35394
- CVE-2019-11500
- CVE-2021-44228
- CVE-2025-22457
- CVE-2001-0414
- CVE-2018-14847
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`
- `cat /proc/cpuinfo | grep name | wc -l`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `which ls`
- `crontab -l`
- `uname -a`
- `whoami`
- `lscpu | grep Model`
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`
- `top`
- `Enter new UNIX password:`

### Signatures Triggered
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN Sipsak SIP scan
- ET HUNTING RDP Authentication Bypass Attempt
- ET SCAN NMAP -sS window 1024
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)
- ET INFO Reserved Internal IP Traffic
- ET CINS Active Threat Intelligence Poor Reputation IP

### Users / Login Attempts
- 345gs5662d34 / 345gs5662d34
- root / (blank)
- root / 3245gs5662d34
- root / root123
- root / fgmljdm070412030910
- admin / immortal
- test / test123
- oracle / !QAZ@wsx
- joel / joel1234
- root / raspberry
- admin / 140388

### Files Uploaded/Downloaded
- mips
- boatnet.mpsl;

### HTTP User-Agents
- No user-agents were recorded in this period.

### SSH Clients and Servers
- No specific SSH client or server versions were recorded in this period.

### Top Attacker AS Organizations
- No attacker AS organizations were recorded in this period.

---

## Key Observations and Anomalies

1.  **High-Volume Scanning:** The sheer volume of events (over 23,000 in ~40 minutes) indicates widespread, automated scanning campaigns are ongoing. The focus on ports 22 (SSH), 445 (SMB), and 5060 (SIP) is consistent with typical opportunistic attacks.
2.  **Credential Stuffing:** The variety of usernames and passwords suggests credential stuffing attacks, where attackers use lists of compromised credentials. The username `345gs5662d34` with a matching password was attempted 38 times across the period.
3.  **SSH Key Persistence:** A recurring pattern in the `Cowrie` logs is a multi-step command to remove existing `.ssh` directories, create a new one, and inject a specific public SSH key. This is a clear attempt to establish persistent access.
4.  **Targeted Exploitation:** The frequent triggering of Suricata signature for CVE-2022-27255 indicates that attackers are actively trying to exploit this vulnerability in Realtek SDKs, which is common in IoT devices.
5.  **Anomalous SMB Traffic:** The significant spike in traffic to port 445 within the last 20 minutes, primarily from IP `41.139.169.77`, suggests a targeted campaign against SMB services, possibly related to vulnerabilities like WannaCry or others.
