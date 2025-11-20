
# Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T08:01:43Z
**Timeframe:** 2025-10-17T07:20:02Z to 2025-10-17T08:00:01Z
**Files Used:**
- agg_log_20251017T072002Z.json
- agg_log_20251017T074001Z.json
- agg_log_20251017T080001Z.json

## Executive Summary
This report summarizes honeypot activity over a period of approximately 40 minutes, analyzing data from three log files. A total of 23,122 attacks were recorded. The most targeted services were SMB (port 445) and SSH (port 22). A significant amount of activity was attributed to a small number of IP addresses, with `66.181.171.136` and `2.60.243.50` being the most active. The most common attack vector appears to be the DoublePulsar backdoor, as indicated by the triggered Suricata signatures.

## Detailed Analysis

### Attacks by Honeypot
- **Cowrie:** 8200
- **Dionaea:** 4391
- **Suricata:** 3267
- **Honeytrap:** 3251
- **Ciscoasa:** 1526
- **Sentrypeer:** 1213
- **Mailoney:** 899
- **Wordpot:** 157
- **ConPot:** 103
- **ssh-rsa:** 30
- **Tanner:** 20
- **H0neytr4p:** 19
- **Adbhoney:** 13
- **Redishoneypot:** 12
- **Miniprint:** 9
- **Honeyaml:** 8
- **Dicompot:** 4

### Top Attacking IPs
- 66.181.171.136
- 2.60.243.50
- 193.193.249.106
- 176.65.141.119
- 58.181.99.73
- 34.47.232.78
- 58.181.99.75
- 72.167.220.12
- 172.86.95.115
- 172.86.95.98
- 102.88.137.80
- 91.107.118.186
- 4.211.84.189
- 27.254.235.4
- 4.224.36.103
- 193.17.92.165
- 185.225.22.80
- 119.246.15.94
- 107.170.36.5

### Top Targeted Ports/Protocols
- 445/TCP
- 22/TCP
- 5060/UDP
- 25/TCP
- 21/TCP
- 80/TCP
- 1433/TCP
- 5903/TCP
- 8333/TCP
- 1025/TCP
- 5901/TCP

### Most Common CVEs
- CVE-2002-0013, CVE-2002-0012
- CVE-2002-0013, CVE-2002-0012, CVE-1999-0517
- CVE-2021-35394
- CVE-1999-0183
- CVE-2019-11500

### Commands Attempted by Attackers
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
- cat /proc/cpuinfo | grep name | wc -l
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;
- uname -s -v -n -r -m

### Signatures Triggered
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication
- 2024766
- ET DROP Dshield Block Listed Source group 1
- 2402000
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- 2023753
- ET SCAN NMAP -sS window 1024
- 2009582
- ET FTP FTP PWD command attempt without login
- 2010735
- ET FTP FTP CWD command attempt without login
- 2010731
- ET SCAN Suspicious inbound to MSSQL port 1433
- 2010935
- ET INFO Reserved Internal IP Traffic
- 2002752

### Users / Login Attempts
- root/
- 345gs5662d34/345gs5662d34
- root/3245gs5662d34
- root/Qaz123qaz
- root/123@@@
- ftpuser/ftppassword
- debian/999999
- nobody/Passw@rd
- guest/99999
- test/test2000
- operator/1234567890
- config/7777777
- root/QWE123!@#qwe
- test/test2004
- default/default2019
- blank/6666666

### Files Uploaded/Downloaded
- ohsitsvegawellrip.sh

### HTTP User-Agents
- N/A

### SSH Clients and Servers
- **Clients:** N/A
- **Servers:** N/A

### Top Attacker AS Organizations
- N/A

## Key Observations and Anomalies
- The high number of triggers for the "DoublePulsar Backdoor" signature suggests a targeted campaign exploiting this vulnerability.
- A number of commands are repeated across multiple attacks, indicating automated scripts are in use. The commands are focused on establishing persistent access and reconnaissance.
- The file `ohsitsvegawellrip.sh` was downloaded twice, which could be a payload or a script for further attacks. Further analysis of this file is recommended.
- The credentials attempted are a mix of common default credentials and some more complex passwords, suggesting a broad-spectrum brute-force attack.
- The IP `66.181.171.136` is responsible for a large portion of the DoublePulsar related traffic. This IP should be monitored closely.
