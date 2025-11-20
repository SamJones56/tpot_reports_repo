
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-21 08:05:01 UTC
**Timeframe of Analysis:** 2025-10-21 07:20:01 UTC to 2025-10-21 08:00:01 UTC
**Log Files Analyzed:**
- `agg_log_20251021T072001Z.json`
- `agg_log_20251021T074001Z.json`
- `agg_log_20251021T080001Z.json`

## Executive Summary

This report summarizes 6,661 recorded attacks across multiple honeypots. The majority of attacks were captured by the `Cowrie` honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. The most prolific attacking IP address was `72.146.232.13`. Network scans and brute-force activity were prevalent, with ports `22` (SSH) and `5060` (SIP) being the most targeted. Several CVEs were noted, primarily related to vulnerabilities in Realtek SDK and older web server technologies. A significant number of reconnaissance and system manipulation commands were attempted, including efforts to add a malicious SSH key to `authorized_keys`.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 3,069
- **Honeytrap:** 1,941
- **Suricata:** 1,099
- **Sentrypeer:** 334
- **Dionaea:** 60
- **Miniprint:** 33
- **ConPot:** 23
- **Tanner:** 28
- **Mailoney:** 18
- **Adbhoney:** 12
- **H0neytr4p:** 12
- **Honeyaml:** 9
- **Ciscoasa:** 10
- **Dicompot:** 6
- **Redishoneypot:** 3
- **Ipphoney:** 2
- **ssh-rsa:** 2

### Top 10 Attacking IPs
- **72.146.232.13:** 717
- **198.23.190.58:** 302
- **186.118.142.216:** 297
- **103.82.240.194:** 277
- **152.32.135.139:** 199
- **203.228.30.198:** 210
- **216.10.242.161:** 229
- **152.42.165.179:** 204
- **107.170.36.5:** 160
- **185.243.5.158:** 160

### Top 10 Targeted Ports/Protocols
- **22:** 555
- **5060:** 334
- **UDP/5060:** 139
- **8333:** 136
- **TCP/445:** 86
- **5905:** 79
- **5904:** 77
- **5903:** 48
- **33252:** 46
- **33264:** 45

### Most Common CVEs
- CVE-2022-27255
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2021-3449
- CVE-2006-2369
- CVE-2005-4050

### Top 10 Commands Attempted by Attackers
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 12
- `lockr -ia .ssh`: 12
- `cd ~ && rm -rf .ssh && ...`: 12
- `cat /proc/cpuinfo | grep name | wc -l`: 12
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{...}'`: 12
- `free -m | grep Mem | awk '{...}'`: 12
- `ls -lh $(which ls)`: 12
- `which ls`: 12
- `crontab -l`: 12
- `w`: 12

### Top 10 Signatures Triggered
- **ET DROP Dshield Block Listed Source group 1:** 264
- **2402000:** 264
- **ET SCAN Sipsak SIP scan:** 118
- **2008598:** 118
- **ET SCAN NMAP -sS window 1024:** 104
- **2009582:** 104
- **ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication:** 86
- **2024766:** 86
- **ET SCAN MS Terminal Server Traffic on Non-standard Port:** 67
- **2023753:** 67

### Top 10 Users / Login Attempts (user/password)
- **345gs5662d34/345gs5662d34:** 12
- **user01/Password01:** 8
- **root/3245gs5662d34:** 4
- **deploy/1234:** 4
- **root/admin888:** 3
- **root/Alpha9498927827:** 3
- **root/adminHW:** 3
- **root/LeitboGi0ro:** 3
- **root/123@@@:** 3
- **root/alpha2015delta:** 3

### Files Uploaded/Downloaded
- **wget.sh;**: 4
- **w.sh;**: 1
- **c.sh;**: 1

### HTTP User-Agents
- None observed

### SSH Clients and Servers
- **Clients:** None observed
- **Servers:** None observed

### Top Attacker AS Organizations
- None observed

## Key Observations and Anomalies

1.  **High Volume of Automated Scans:** The consistent targeting of common ports like 22 (SSH), 5060 (SIP), and 445 (SMB) across a wide range of IPs suggests large-scale, automated scanning campaigns rather than targeted attacks.
2.  **Repetitive Command Execution:** Attackers who successfully logged into the `Cowrie` honeypot executed a nearly identical script of reconnaissance commands (`uname -a`, `lscpu`, `free -m`, etc.) followed by an attempt to install a persistent SSH key. This indicates the use of a common attack toolkit.
3.  **Realtek Vulnerability Exploitation:** The repeated triggering of the signature for CVE-2022-27255 (`Realtek eCos RSDK/MSDK Stack-based Buffer Overflow`) suggests active exploitation of this IoT-related vulnerability.
4.  **SIP Protocol Scanning:** A significant portion of traffic targeted port 5060, which is used for Session Initiation Protocol (SIP), indicating widespread scanning for vulnerabilities in VoIP systems. The `Sentrypeer` honeypot, which emulates a SIP server, logged 334 of these events.
