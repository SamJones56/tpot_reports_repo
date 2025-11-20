Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T12:01:37Z
**Timeframe:** 2025-10-19T11:20:01Z to 2025-10-19T12:00:02Z
**Files Used:**
- agg_log_20251019T112001Z.json
- agg_log_20251019T114001Z.json
- agg_log_20251019T120002Z.json

**Executive Summary:**
This report summarizes 24,791 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were captured by the Cowrie, Heralding, and Honeytrap honeypots. The most frequent attacks targeted VNC (port 5900) and SMB (port 445). The top attacking IP address was 185.243.96.105, which was responsible for a significant portion of the VNC scans. A notable CVE, CVE-2005-4050, related to a SIP UDP overflow, was triggered frequently.

**Detailed Analysis:**

**Attacks by Honeypot:**
- Cowrie: 8,108
- Heralding: 4,720
- Honeytrap: 3,256
- Suricata: 2,558
- Sentrypeer: 2,294
- Dionaea: 2,736
- Ciscoasa: 889
- Tanner: 114
- ConPot: 22
- Redishoneypot: 21
- Mailoney: 28
- Miniprint: 19
- H0neytr4p: 16
- Dicompot: 6
- ElasticPot: 3
- Honeyaml: 1

**Top Attacking IPs:**
- 185.243.96.105
- 93.124.63.121
- 194.50.16.73
- 72.146.232.13
- 198.23.190.58
- 23.94.26.58
- 31.58.144.28
- 198.12.68.114
- 157.92.145.135
- 72.167.220.12

**Top Targeted Ports/Protocols:**
- vnc/5900
- 445
- 5060
- 22
- UDP/5060
- 5903
- 8333
- TCP/22
- 5901
- 5905

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2002-0013 CVE-2002-0012
- CVE-2019-11500 CVE-2019-11500
- CVE-2021-3449 CVE-2021-3449
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-1999-0183
- CVE-2001-0414

**Commands Attempted by Attackers:**
- uname -s -v -n -r -m
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..." >> .ssh/authorized_keys
- cat /proc/cpuinfo | grep name | wc -l
- echo -e "..."|passwd|bash
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

**Signatures Triggered:**
- ET VOIP MultiTech SIP UDP Overflow
- 2003237
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN NMAP -sS window 1024
- 2009582
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN Potential SSH Scan
- 2001219
- ET INFO Reserved Internal IP Traffic
- 2002752
- ET HUNTING RDP Authentication Bypass Attempt
- 2034857
- ET INFO CURL User Agent
- 2002824

**Users / Login Attempts:**
- /Passw0rd
- /1q2w3e4r
- /passw0rd
- admin/5555
- config/config2016
- debian/debian2022
- debian/debian2015
- centos/666
- unknown/333
- test/test2008
- nobody/passwd
- /1qaz2wsx
- root/5770658589
- root/57HyUj9\xfeO

**Files Uploaded/Downloaded:**
- binary.sh
- binary.sh;
- )

**HTTP User-Agents:**
- No user agents recorded in this period.

**SSH Clients:**
- No SSH clients recorded in this period.

**SSH Servers:**
- No SSH servers recorded in this period.

**Top Attacker AS Organizations:**
- No AS organizations recorded in this period.

**Key Observations and Anomalies:**
- **High-Volume Scanning:** A small number of IP addresses are responsible for a large percentage of the total traffic, indicating automated scanning campaigns.
- **VNC and SMB Focus:** The most targeted services were VNC (5900) and SMB (445), which are common targets for remote access and file-sharing exploits.
- **SSH Key Manipulation:** Several attackers attempted to add their own SSH public key to the `authorized_keys` file, a common technique for establishing persistent access.
- **Credential Stuffing:** A wide variety of usernames and passwords were attempted, suggesting credential stuffing attacks against SSH and other services.
- **Reconnaissance Commands:** Attackers frequently used commands like `uname`, `cat /proc/cpuinfo`, and `free -m` to gather information about the system architecture and resources.
