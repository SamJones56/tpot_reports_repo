
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T18:01:38Z
**Timeframe Covered:** 2025-10-13T17:20:01Z to 2025-10-13T18:00:02Z
**Files Used:**
- agg_log_20251013T172001Z.json
- agg_log_20251013T174001Z.json
- agg_log_20251013T180002Z.json

---

## Executive Summary

This report summarizes 17,764 malicious events recorded across the honeypot network. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force and command-injection attempts. A significant number of attacks originated from the IP address `8.219.248.7`. The most frequently targeted port was `5060/UDP` (SIP), followed closely by `445/TCP` (SMB) and `22/TCP` (SSH). Attackers were observed attempting to exploit several vulnerabilities, with a notable focus on CVE-2022-27255 (Realtek eCos RSDK/MSDK Stack-based Buffer Overflow). A recurring command pattern involved attempts to download and execute malicious scripts and add unauthorized SSH keys to `authorized_keys`.

---

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 9521
- **Sentrypeer:** 2868
- **Dionaea:** 1901
- **Suricata:** 1501
- **Honeytrap:** 973
- **Mailoney:** 831
- **Tanner:** 57
- **H0neytr4p:** 29
- **Redishoneypot:** 17
- **Ciscoasa:** 15
- **Honeyaml:** 14
- **ConPot:** 10
- **Adbhoney:** 9
- **ElasticPot:** 7
- **Ipphoney:** 3
- **Dicompot:** 3
- **Heralding:** 3
- **ssh-rsa:** 2

### Top Attacking IPs
- **8.219.248.7:** 1124
- **45.171.150.123:** 906
- **185.243.5.146:** 1078
- **45.236.188.4:** 1030
- **223.100.22.69:** 850
- **86.54.42.238:** 820
- **185.243.5.148:** 715
- **186.123.101.50:** 306
- **154.203.166.161:** 311
- **103.160.37.151:** 291
- **196.204.240.61:** 307
- **62.141.43.183:** 215
- **172.86.95.115:** 314
- **172.86.95.98:** 209
- **202.8.127.134:** 263
- **158.69.210.167:** 257
- **37.221.66.149:** 188
- **180.101.226.115:** 173
- **115.21.183.150:** 171
- **186.7.30.18:** 167

### Top Targeted Ports/Protocols
- **5060:** 2868
- **445:** 1752
- **22:** 1470
- **25:** 828
- **UDP/5060:** 126
- **TCP/21:** 122
- **80:** 61
- **23:** 57
- **TCP/1433:** 37
- **TCP/22:** 39
- **443:** 29
- **TCP/5432:** 28
- **6379:** 14
- **UDP/161:** 25
- **21:** 19
- **9200:** 7

### Most Common CVEs
- **CVE-2022-27255 CVE-2022-27255:** 42
- **CVE-2002-0013 CVE-2002-0012:** 15
- **CVE-2006-0189:** 24
- **CVE-2002-0013 CVE-2002-0012 CVE-1999-0517:** 12
- **CVE-2005-4050:** 12
- **CVE-2023-26801 CVE-2023-26801:** 1
- **CVE-2006-3602 CVE-2006-4458 CVE-2006-4542:** 1
- **CVE-1999-0517:** 1

### Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 42
- `lockr -ia .ssh`: 42
- `cd ~ && rm -rf .ssh && ...`: 42
- `cat /proc/cpuinfo | grep name | wc -l`: 38
- `ls -lh $(which ls)`: 38
- `which ls`: 38
- `crontab -l`: 38
- `w`: 38
- `uname -m`: 38
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 38
- `top`: 38
- `uname -a`: 38
- `whoami`: 38
- `lscpu | grep Model`: 38
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 37
- `uname`: 37
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 37
- `cat /proc/cpuinfo | grep name | head -n 1 | awk ...`: 37
- `rm -rf /tmp/secure.sh; ...`: 18
- `Enter new UNIX password: `: 14

### Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 325
- **ET SCAN NMAP -sS window 1024:** 148
- **ET FTP FTP STOR command attempt without login:** 87
- **ET INFO Reserved Internal IP Traffic:** 57
- **ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255):** 42
- **ET CINS Active Threat Intelligence Poor Reputation IP group 44:** 24
- **ET SCAN Sipsak SIP scan:** 22
- **ET SCAN Suspicious inbound to MSSQL port 1433:** 14
- **ET SCAN Suspicious inbound to PostgreSQL port 5432:** 14
- **ET CINS Active Threat Intelligence Poor Reputation IP group 48:** 13
- **GPL SNMP request udp:** 12
- **ET VOIP SIP UDP Softphone INVITE overflow:** 8

### Users / Login Attempts
- **345gs5662d34/345gs5662d34:** 37
- **root/Qaz123qaz:** 26
- **root/123@@@:** 22
- **root/3245gs5662d34:** 17
- **root/Password@2025:** 16
- **ftpuser/ftppassword:** 8
- **supervisor/supervisor2002:** 6
- **centos/Passw@rd:** 6
- **unknown/1234:** 6
- **root/Lofasz2:** 6
- **user/555:** 6
- **root/77:** 6
- **blank/abcd1234:** 4
- **haha/123:** 4

### Files Uploaded/Downloaded
- **wget.sh;**: 4
- **ip:** 2
- **w.sh;**: 1
- **c.sh;**: 1
- **soap-envelope:** 1
- **addressing:** 1
- **discovery:** 1
- **env:Envelope>:** 1
- **11:** 1
- **fonts.gstatic.com:** 1
- **css?family=Libre+Franklin...:** 1
- **ie8.css?ver=1.0:** 1
- **html5.js?ver=3.7.3:** 1

### HTTP User-Agents
- N/A

### SSH Clients and Servers
- **SSH Clients:** N/A
- **SSH Servers:** N/A

### Top Attacker AS Organizations
- N/A

---

## Key Observations and Anomalies

- **Repetitive SSH Key Insertion:** A significant number of command executions were aimed at removing existing SSH configurations and inserting a specific public SSH key (`ssh-rsa AAAAB3... mdrfckr`). This indicates a widespread campaign to gain persistent access to compromised systems.
- **System Reconnaissance:** Attackers consistently ran a series of commands (`uname -a`, `lscpu`, `cat /proc/cpuinfo`, `free -m`, `df -h`) to gather detailed information about the system's architecture, CPU, memory, and storage. This is a typical precursor to deploying tailored malware.
- **SIP and SMB Scanning:** The high volume of traffic to ports 5060 (SIP) and 445 (SMB) suggests large-scale, automated scanning for vulnerabilities in VoIP and file-sharing services.
- **Malware Download Attempts:** Several commands attempted to download and execute shell scripts (`w.sh`, `c.sh`, `wget.sh`) from a specific IP address (`194.238.26.136`), a clear indicator of attempts to install malware or backdoors.
- **Realtek Vulnerability Exploitation:** The consistent triggering of the `ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255)` signature points to targeted attempts to exploit this known vulnerability.
