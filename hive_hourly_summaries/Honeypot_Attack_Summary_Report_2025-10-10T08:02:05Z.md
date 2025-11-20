Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-10T08:01:37Z
**Timeframe:** 2025-10-10T07:20:01Z to 2025-10-10T08:00:02Z
**Files Used:**
- agg_log_20251010T072001Z.json
- agg_log_20251010T074001Z.json
- agg_log_20251010T080002Z.json

### Executive Summary

This report summarizes 17,296 events recorded across three honeypot log files. The majority of malicious activity was captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet brute-force attempts. Attackers predominantly targeted port 445 (SMB) and port 22 (SSH). A significant number of commands were executed, primarily for system reconnaissance and attempts to disable security and add a malicious SSH key. Several CVEs were targeted, with a focus on older vulnerabilities.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7658
- Honeytrap: 3100
- Dionaea: 1947
- Suricata: 2144
- Ciscoasa: 1762
- Sentrypeer: 388
- Tanner: 97
- H0neytr4p: 88
- Redishoneypot: 47
- Dicompot: 18
- Mailoney: 22
- ElasticPot: 10
- Honeyaml: 7
- Heralding: 3
- ConPot: 3
- Adbhoney: 2

**Top Attacking IPs:**
- 167.250.224.25: 1045
- 77.79.150.127: 1035
- 221.121.100.32: 583
- 193.24.123.88: 366
- 113.30.191.232: 273
- 192.227.194.3: 279
- 88.210.63.16: 258
- 185.113.139.51: 258
- 103.10.45.57: 248
- 45.134.26.3: 248
- 141.11.167.206: 263
- 65.109.4.113: 332
- 191.13.244.160: 227
- 190.128.241.2: 228
- 36.50.176.16: 213
- 207.180.229.239: 209
- 88.214.50.58: 186
- 4.211.84.189: 159

**Top Targeted Ports/Protocols:**
- 445: 1633
- 22: 1122
- 5060: 388
- 1433: 287
- TCP/1433: 217
- 5903: 208
- 80: 97
- 5908: 82
- 5909: 82
- 5901: 73
- 443: 82
- 6379: 39
- 54321: 26
- TCP/22: 18
- 25: 14

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 7
- CVE-2005-4050: 4
- CVE-1999-0183: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
- CVE-2022-27255 CVE-2022-27255: 2
- CVE-2019-11500 CVE-2019-11500: 1
- CVE-2016-20016 CVE-2016-20016: 1

**Commands Attempted by Attackers:**
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys ...: 47
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 47
- lockr -ia .ssh: 47
- Enter new UNIX password: : 34
- Enter new UNIX password:": 34
- cat /proc/cpuinfo | grep name | wc -l: 34
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 34
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 34
- which ls: 34
- ls -lh $(which ls): 34
- crontab -l: 34
- w: 34
- uname -m: 34
- top: 34
- uname -a: 35
- whoami: 34
- uname: 34
- tftp; wget; /bin/busybox YWACD: 1

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 499
- 2402000: 499
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 404
- 2023753: 404
- ET HUNTING RDP Authentication Bypass Attempt: 188
- 2034857: 188
- ET SCAN Suspicious inbound to MSSQL port 1433: 209
- 2010935: 209
- ET SCAN NMAP -sS window 1024: 166
- 2009582: 166
- ET INFO Reserved Internal IP Traffic: 61
- 2002752: 61

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 43
- pi/test: 6
- admin/P@ssw0rd123: 6
- root/default: 6
- vpn/vpnvpn: 4
- support/support000: 4
- guest/guest: 4
- operator/operator22: 4
- vpn/vpn321: 4
- supervisor/supervisor99: 4

**Files Uploaded/Downloaded:**
- rondo.qpu.sh||wget: 1
- rondo.qpu.sh)|sh&echo: 1
- ): 1

**HTTP User-Agents:**
- (None Recorded)

**SSH Clients and Servers:**
- (None Recorded)

**Top Attacker AS Organizations:**
- (None Recorded)

### Key Observations and Anomalies

- **Consistent SSH Key Attack:** A recurring command pattern was observed across all log files where attackers attempt to remove the existing `.ssh` directory and add a specific public SSH key (`ssh-rsa AAAAB3... mdrfckr`). This indicates a coordinated campaign to maintain persistent access.
- **System Reconnaissance:** Attackers consistently run a series of commands (`uname`, `lscpu`, `whoami`, `cat /proc/cpuinfo`) to gather information about the compromised system's architecture and configuration before deploying further payloads.
- **Anomalous TFTP/Wget Command:** A unique command `tftp; wget; /bin/busybox YWACD` was observed. This suggests an attempt to download a payload using multiple methods (TFTP and Wget) and execute it using `busybox`, a common tool in embedded systems and malware.
- **High Volume of SMB Scans:** Port 445 was the most frequently targeted port, suggesting widespread scanning for SMB vulnerabilities like EternalBlue.

This concludes the Honeypot Attack Summary Report.