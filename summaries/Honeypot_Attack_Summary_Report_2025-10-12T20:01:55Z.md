
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T20:01:32Z
**Timeframe:** 2025-10-12T19:20:01Z to 2025-10-12T20:00:01Z
**Files Used:**
- agg_log_20251012T192001Z.json
- agg_log_20251012T194001Z.json
- agg_log_20251012T200001Z.json

---

## Executive Summary

This report summarizes 19,201 malicious events recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet brute-force activity. The most frequent attacker IP was 45.78.192.214, and the most targeted port was 5060 (SIP). A significant number of reconnaissance and system information gathering commands were observed.

---

## Detailed Analysis

### Attacks by Honeypot
- Cowrie: 9147
- Honeytrap: 3251
- Sentrypeer: 1966
- Ciscoasa: 1760
- Dionaea: 842
- Suricata: 1507
- Tanner: 484
- Mailoney: 96
- H0neytr4p: 46
- ConPot: 48
- Redishoneypot: 24
- ElasticPot: 6
- Adbhoney: 6
- Dicompot: 6
- Honeyaml: 9
- Heralding: 3

### Top Attacking IPs
- 45.78.192.214: 1201
- 45.128.199.212: 1066
- 115.138.86.57: 644
- 43.164.64.51: 488
- 182.76.204.237: 286
- 134.199.228.210: 288
- 200.225.246.102: 386
- 172.86.95.98: 367
- 147.50.231.135: 268
- 62.141.43.183: 324
- 183.63.103.84: 290
- 118.219.239.122: 228
- 51.75.194.10: 248
- 175.148.158.216: 238
- 27.254.235.13: 242
- 197.5.145.150: 219
- 152.32.185.214: 228
- 34.122.106.61: 223
- 151.35.102.57: 164
- 79.52.234.38: 207

### Top Targeted Ports/Protocols
- 5060: 1966
- 22: 1296
- 445: 742
- 80: 483
- 5903: 191
- 23: 156
- 3306: 63
- 8333: 81
- 5909: 85
- 5908: 84
- 25: 98
- 5901: 80
- 10001: 36
- 5907: 49
- 6379: 15

### Most Common CVEs
- CVE-2002-0013 CVE-2002-0012: 14
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 10
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 2
- CVE-2019-11500 CVE-2019-11500: 2

### Commands Attempted by Attackers
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 42
- ls -lh $(which ls): 42
- which ls: 42
- crontab -l: 42
- w: 42
- uname -m: 42
- cat /proc/cpuinfo | grep model | grep name | wc -l: 42
- top: 42
- uname: 42
- uname -a: 43
- whoami: 42
- lscpu | grep Model: 42
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 42
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 42
- lockr -ia .ssh: 42
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 42
- cat /proc/cpuinfo | grep name | wc -l: 41
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 41
- Enter new UNIX password: : 32
- Enter new UNIX password:": 32

### Signatures Triggered
- ET DROP Dshield Block Listed Source group 1: 437
- 2402000: 437
- ET SCAN NMAP -sS window 1024: 173
- 2009582: 173
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 98
- 2023753: 98
- ET INFO Reserved Internal IP Traffic: 57
- 2002752: 57
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 26
- 2403347: 26

### Users / Login Attempts
- cron/: 58
- 345gs5662d34/345gs5662d34: 41
- deploy/123123: 19
- admin1234/admin1234: 18
- vpn/vpnpass: 17
- holu/holu: 17
- mega/123: 15
- ftpuser/ftppassword: 14
- root/3245gs5662d34: 8
- nobody/qwerty1234: 6
- root/root2: 6
- Admin/0: 5
- ubnt/88: 6
- root/dreambox: 4
- blank/6666666666: 4
- vpn/3245gs5662d34: 4
- ftpuser/1234: 4
- root/blahblah: 4
- root/pi: 4
- blank/cable: 4

### Files Uploaded/Downloaded
- welcome.jpg): 15
- writing.jpg): 10
- tags.jpg): 10
- json: 1

### HTTP User-Agents
- No user agents recorded in this period.

### SSH Clients
- No SSH clients recorded in this period.

### SSH Servers
- No SSH servers recorded in this period.

### Top Attacker AS Organizations
- No AS organizations recorded in this period.

---

## Key Observations and Anomalies

- A significant amount of automated reconnaissance activity was observed, with attackers frequently using commands to identify system architecture, memory, and CPU details (`uname`, `lscpu`, `free`, `cat /proc/cpuinfo`).
- A recurring command sequence attempts to remove existing SSH keys, create a new `.ssh` directory, and install a malicious public key for persistent access.
- The high number of events on port 5060 suggests widespread scanning for vulnerable VoIP (SIP) services.
- There were multiple attempts to exploit older vulnerabilities, as evidenced by the CVEs detected.
