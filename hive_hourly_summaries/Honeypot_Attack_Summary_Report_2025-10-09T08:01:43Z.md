Honeypot Attack Summary Report

Report generated at: 2025-10-09T08:01:24Z
Files used for this report:
- agg_log_20251009T072002Z.json
- agg_log_20251009T074001Z.json
- agg_log_20251009T080001Z.json

Executive Summary
This report summarizes 15,689 events collected from the honeypot network. The majority of attacks were detected by the Cowrie, Honeytrap, and Suricata honeypots. The most targeted services were SSH (port 22), SMTP (port 25), and SMB (port 445). A significant number of brute-force attempts and automated scans were observed. The most notable attacker IP address was 86.54.42.238.

Detailed Analysis:

Attacks by Honeypot:
- Cowrie: 4048
- Honeytrap: 3341
- Suricata: 2571
- Dionaea: 1957
- Ciscoasa: 1639
- Mailoney: 1705
- Heralding: 191
- Sentrypeer: 61
- H0neytr4p: 68
- Tanner: 43
- ElasticPot: 9
- Honeyaml: 27
- ConPot: 10
- Redishoneypot: 9
- Adbhoney: 7
- Dicompot: 3

Top Attacking IPs:
- 86.54.42.238
- 171.42.244.192
- 120.48.1.61
- 80.94.95.238
- 114.219.56.203
- 103.130.205.82
- 77.105.182.78
- 64.188.30.242
- 27.254.149.199

Top Targeted Ports/Protocols:
- 25
- 445
- 22
- TCP/445
- vnc/5900
- 5903
- 8333
- 1028
- TCP/21
- 3306

Most Common CVEs:
- CVE-1999-0183
- CVE-2002-0013 CVE-2002-0012

Commands Attempted by Attackers:
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- uname -a
- whoami
- top

Signatures Triggered:
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET FTP FTP PWD command attempt without login
- ET FTP FTP CWD command attempt without login

Users / Login Attempts:
- root/
- 345gs5662d34/345gs5662d34
- config/config1234
- unknown/99
- support/qwerty1234
- root/sysadmin
- manager/friend

Files Uploaded/Downloaded:
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3
- w.sh;
- c.sh;

HTTP User-Agents:
- (No user agents recorded in this period)

SSH Clients and Servers:
- (No specific clients or servers recorded in this period)

Top Attacker AS Organizations:
- (No AS organizations recorded in this period)

Key Observations and Anomalies:
The most frequent commands are reconnaissance and attempts to install SSH keys for persistent access.
The high number of events on ports 25, 445, and 22 indicates widespread automated scanning and exploitation attempts for common vulnerabilities in email, file sharing, and remote access services.
The presence of the DoublePulsar signature indicates attempts to exploit systems using NSA-leaked tools.
The variety of usernames and passwords attempted suggests a mix of dictionary attacks and targeted attempts using common default credentials.
The attempt to download and execute shell scripts (w.sh, c.sh) from a remote server is a common malware installation technique.
