Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T11:01:34Z
**Timeframe:** 2025-10-17T10:20:01Z to 2025-10-17T11:00:01Z
**Files Used:**
- agg_log_20251017T102001Z.json
- agg_log_20251017T104001Z.json
- agg_log_20251017T110001Z.json

### Executive Summary

This report summarizes 24,908 events collected from the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Dionaea honeypots. A significant portion of the traffic originated from IP address 115.79.222.84. The most targeted services were SMB (port 445), SSH (port 22), and SIP (port 5060). Attackers were observed attempting to gain access via brute-force attacks and exploiting known vulnerabilities. Several commands were executed upon successful entry, primarily focused on reconnaissance and establishing further persistence.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 9294
- Honeytrap: 4730
- Dionaea: 4498
- Suricata: 2467
- Ciscoasa: 1470
- Sentrypeer: 1244
- Mailoney: 895
- Adbhoney: 36
- H0neytr4p: 69
- ConPot: 37
- Tanner: 39
- Redishoneypot: 26
- Dicompot: 20
- Heralding: 59
- Miniprint: 13
- Honeyaml: 8
- ElasticPot: 2
- Ipphoney: 1

**Top Attacking IPs:**
- 115.79.222.84
- 193.22.146.182
- 101.46.70.12
- 47.243.13.66
- 50.6.225.98
- 213.149.166.133
- 45.5.23.3
- 176.65.141.119
- 172.86.95.115
- 172.86.95.98
- 196.251.80.29
- 190.60.48.194
- 91.107.118.186
- 185.31.160.29
- 36.255.3.203
- 107.172.252.231
- 173.249.52.138
- 152.32.191.75
- 192.40.58.3

**Top Targeted Ports/Protocols:**
- 445
- 22
- 5060
- 25
- TCP/445
- TCP/21
- 8333
- 1956
- 5903
- 5901
- 21
- TCP/22

**Most Common CVEs:**
- CVE-2019-11500
- CVE-2021-3449
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-2019-16920
- CVE-2024-12856
- CVE-2024-12885
- CVE-2014-6271
- CVE-2023-52163
- CVE-2023-47565
- CVE-2023-31983
- CVE-2024-10914
- CVE-2009-2765
- CVE-2015-2051
- CVE-2019-10891
- CVE-2024-33112
- CVE-2025-11488
- CVE-2022-37056
- CVE-2024-3721
- CVE-2006-3602
- CVE-2006-4458
- CVE-2006-4542
- CVE-2021-42013
- CVE-2001-0414
- CVE-2021-35394
- CVE-1999-0517
- CVE-2005-3296

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo ... >> .ssh/authorized_keys
- cat /proc/cpuinfo | grep name | wc -l
- free -m | grep Mem
- uname -a
- whoami
- crontab -l
- w
- top
- Enter new UNIX password:

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET FTP FTP PWD command attempt without login
- 2010735
- ET FTP FTP CWD command attempt without login
- 2010731
- ET SCAN Potential SSH Scan
- 2001219
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET INFO CURL User Agent
- 2002824

**Users / Login Attempts (user/password):**
- 345gs5662d34/345gs5662d34
- guest/guest2023
- nobody/nobody2002
- admin/333333
- user/user2001
- ubnt/6
- ftpuser/ftppassword
- root/3245gs5662d34
- unknown/logon
- user/user
- config/config2021
- elastic/elastic123
- user/123123
- root/120415QTYWFC
- root/1211564
- config/config2003

**Files Uploaded/Downloaded:**
- busybox
- curl
- apply.cgi
- cfg_system_time.htm
- server.cgi
- trinity
- nohup
- ohsitsvegawellrip.sh

**HTTP User-Agents:**
- Not observed in this period.

**SSH Clients and Servers:**
- Not observed in this period.

**Top Attacker AS Organizations:**
- Not observed in this period.

### Key Observations and Anomalies

- **SSH Key Manipulation:** A large number of commands are dedicated to modifying the `.ssh/authorized_keys` file. This is a common technique for attackers to maintain persistent access to a compromised machine.
- **DoublePulsar Activity:** The signature for the DoublePulsar backdoor was triggered a significant number of times, indicating attempts to exploit the SMB vulnerability (likely related to EternalBlue).
- **Reconnaissance Commands:** Attackers frequently run commands to gather system information, such as `uname -a`, `lscpu`, and `free -m`. This is typical post-exploitation behavior to understand the environment they are in.
- **High Volume Scans:** The high number of events from signatures like "ET SCAN NMAP" and "ET SCAN Potential SSH Scan" suggest that the honeypot is being actively scanned for open ports and services.
- The IP address `115.79.222.84` has been consistently aggressive across all three time-windows.
