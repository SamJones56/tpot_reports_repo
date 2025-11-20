Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T13:01:36Z
**Timeframe of Report:** 2025-10-19T12:20:01Z to 2025-10-19T13:00:01Z
**Files Used to Generate Report:**
- agg_log_20251019T122001Z.json
- agg_log_20251019T124001Z.json
- agg_log_20251019T130001Z.json

**Executive Summary**

This report summarizes 27,305 events collected from the honeypot network over a period of approximately 40 minutes. The most active honeypot was Cowrie, logging 13,232 events, primarily related to SSH and Telnet brute-force attacks. A significant number of attacks also targeted VNC (port 5900) and SIP (port 5060). Suricata detected a large volume of malicious traffic, including the installation of the DoublePulsar backdoor. Attackers were observed attempting to install a persistent SSH key and downloading malicious shell scripts.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 13,232
- Suricata: 4,193
- Honeytrap: 4,076
- Sentrypeer: 2,463
- Heralding: 2,282
- Ciscoasa: 901
- Dionaea: 34
- ssh-rsa: 32
- Mailoney: 20
- H0neytr4p: 16
- Redishoneypot: 12
- Adbhoney: 9
- Tanner: 19
- ElasticPot: 3
- ConPot: 3
- Honeyaml: 3
- Wordpot: 2
- Ipphoney: 4
- Miniprint: 1

***Top Attacking IPs***
- 185.243.96.105: 2,282
- 194.50.16.73: 2,019
- 181.40.114.54: 1,460
- 188.166.223.182: 1,252
- 198.23.190.58: 1,196
- 72.146.232.13: 1,182
- 23.94.26.58: 1,151
- 134.199.195.214: 1,002
- 198.12.68.114: 840
- 45.128.199.34: 507

***Top Targeted Ports/Protocols***
- 22: 2,593
- 5060: 2,463
- vnc/5900: 2,282
- TCP/445: 1,460
- UDP/5060: 1,381
- 5903: 224
- 8333: 137
- 5901: 110
- TCP/22: 152
- 5905: 75
- 5904: 74

***Most Common CVEs***
- CVE-2005-4050: 1,365
- CVE-2002-0013 CVE-2002-0012: 12
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 8
- CVE-2021-3449 CVE-2021-3449: 5
- CVE-2019-11500 CVE-2019-11500: 3
- CVE-1999-0183: 2
- CVE-2001-0414: 2
- CVE-2016-20016 CVE-2016-20016: 1
- CVE-2006-3602 CVE-2006-4458 CVE-2006-4542: 1
- CVE-2018-10562 CVE-2018-10561: 1
- CVE-1999-0517: 1

***Commands Attempted by Attackers***
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...": 40
- lockr -ia .ssh: 40
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 40
- cat /proc/cpuinfo | grep name | wc -l: 40
- top: 39
- uname: 39
- uname -a: 39
- whoami: 39
- lscpu | grep Model: 39
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 39
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 39
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 39
- ls -lh $(which ls): 39
- which ls: 39
- crontab -l: 39
- w: 38
- uname -m: 38
- cat /proc/cpuinfo | grep model | grep name | wc -l: 38
- Enter new UNIX password: : 31
- Enter new UNIX password:": 22
- cat /proc/uptime 2 > /dev/null | cut -d. -f1: 10
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp; ...: 1

***Signatures Triggered***
- ET VOIP MultiTech SIP UDP Overflow (2003237): 1,365
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication (2024766): 1,458
- ET DROP Dshield Block Listed Source group 1 (2402000): 262
- ET SCAN NMAP -sS window 1024 (2009582): 172
- ET SCAN Potential SSH Scan (2001219): 142
- ET SCAN MS Terminal Server Traffic on Non-standard Port (2023753): 135
- ET INFO Reserved Internal IP Traffic (2002752): 56
- ET HUNTING RDP Authentication Bypass Attempt (2034857): 46
- ET INFO CURL User Agent (2002824): 20

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 40
- root/: 30
- user01/Password01: 15
- deploy/123123: 11
- /Passw0rd: 10
- admin/maintenance: 6
- guest/654321: 6
- ubnt/555555: 6
- guest/6: 6
- ubnt/ubnt2018: 6
- centos/centos2022: 6
- root/3245gs5662d34: 5
- root/Abc12345678@: 5
- root/P@ssw0rd: 5
- root/passw0rd: 5
- root/root123: 5
- root/toor: 5
- root/123: 5
- root/1q2w3e4r: 5
- ubnt/maintenance: 5

***Files Uploaded/Downloaded***
- wget.sh;: 4
- gpon80&ipv=0: 4
- ?format=json: 4
- w.sh;: 1
- c.sh;: 1

***HTTP User-Agents***
- No HTTP user-agents were logged in this period.

***SSH Clients and Servers***
- No specific SSH clients or servers were logged in this period.

***Top Attacker AS Organizations***
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- **High Volume of VNC and SIP Attacks:** The high number of events on ports 5900 (VNC) and 5060 (SIP) suggests targeted campaigns against these services.
- **DoublePulsar Backdoor:** The detection of the DoublePulsar backdoor is a critical finding, indicating attempts to install sophisticated malware.
- **Persistent SSH Key Installation:** A recurring command sequence was observed, aiming to remove existing SSH configurations and install a new, unauthorized SSH key, allowing the attacker persistent access.
- **Malware Download Attempts:** Several commands attempted to download and execute shell scripts (e.g., w.sh, c.sh, wget.sh) from a remote server (213.209.143.62), a common tactic for malware propagation.
- **Information Gathering:** A large number of commands were focused on system information gathering, such as CPU details, memory usage, and running processes, which is typical post-compromise behavior.
