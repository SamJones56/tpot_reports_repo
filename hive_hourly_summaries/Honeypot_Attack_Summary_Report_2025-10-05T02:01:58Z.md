
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-05T02:01:37Z
**Timeframe:** 2025-10-05T01:20:01Z - 2025-10-05T02:00:01Z
**Files Used:**
- agg_log_20251005T012001Z.json
- agg_log_20251005T014001Z.json
- agg_log_20251005T020001Z.json

---

## Executive Summary

This report summarizes 8881 security events captured by the honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most prominent attack vectors involved attempts to brute-force credentials over SSH (port 22) and SMTP (port 25). A significant number of events were also logged for SIP (port 5060). The most common attacker IP was 8.210.214.44.

---

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 3441
- Ciscoasa: 1542
- Mailoney: 848
- Suricata: 1198
- Honeytrap: 799
- Sentrypeer: 564
- H0neytr4p: 164
- Tanner: 155
- Dionaea: 113
- Adbhoney: 20
- Redishoneypot: 21
- ConPot: 10
- ElasticPot: 4
- Honeyaml: 2

### Top Attacking IPs
- 8.210.214.44: 1245
- 176.65.141.117: 820
- 83.168.107.46: 325
- 172.86.95.98: 288
- 197.220.93.103: 283
- 121.229.25.10: 178
- 37.84.126.4: 249
- 198.12.68.114: 167
- 159.65.133.160: 135
- 111.68.104.76: 115
- 45.186.251.70: 115
- 109.94.172.237: 94
- 154.201.90.141: 94
- 119.45.160.142: 93
- 180.76.98.88: 87
- 175.6.37.135: 82
- 171.104.143.176: 82
- 183.207.45.102: 80
- 23.94.26.58: 77
- 88.214.25.24: 72

### Top Targeted Ports/Protocols
- 25: 846
- 5060: 564
- 22: 588
- 443: 164
- 80: 155
- 1433: 63
- TCP/1433: 68
- UDP/5060: 59
- TCP/80: 45
- 23: 24
- 6379: 18
- 81: 27
- 2222: 9

### Most Common CVEs
- CVE-2005-4050
- CVE-2019-11500

### Commands Attempted by Attackers
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
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- chmod +x setup.sh; sh setup.sh; ...
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 380
- 2402000: 380
- ET SCAN NMAP -sS window 1024: 102
- 2009582: 102
- ET SCAN Suspicious inbound to MSSQL port 1433: 67
- 2010935: 67
- ET INFO Reserved Internal IP Traffic: 52
- 2002752: 52
- ET VOIP MultiTech SIP UDP Overflow: 56
- 2003237: 56
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 51
- 2023753: 51

### Users / Login Attempts
- 345gs5662d34/345gs5662d34
- ake/ake123
- root/ubuntu20svm
- novinhost/novinhost.org
- root/09N1RCa1Hs31
- root/Sunil@123
- root/Aa111222
- anonymous/
- root/wordpress@123
- root/Aakash@123
- root/nPSpP4PBW0
- root/Amar@123
- farmacia/farmacia123
- user/123qweASD
- sa/123456789

### Files Uploaded/Downloaded
- wget.sh;
- w.sh;
- c.sh;
- sh

### HTTP User-Agents
- No user agents were logged in this timeframe.

### SSH Clients
- No SSH clients were logged in this timeframe.

### SSH Servers
- No SSH servers were logged in this timeframe.

### Top Attacker AS Organizations
- No AS organizations were logged in this timeframe.

---

## Key Observations and Anomalies

- A high number of attempts to modify SSH authorized_keys files were observed, indicating a campaign to establish persistent access.
- Attackers are using shell scripts (wget.sh, w.sh, c.sh) to download and execute malicious payloads.
- The majority of attacks are automated and follow predictable patterns of scanning and brute-forcing.
- The presence of commands to gather system information (cpuinfo, free, uname) suggests that attackers are attempting to profile the compromised systems for further exploitation.
