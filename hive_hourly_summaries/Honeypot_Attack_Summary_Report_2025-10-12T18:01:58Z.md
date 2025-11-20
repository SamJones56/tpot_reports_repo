**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-12T18:01:36Z
**Timeframe:** 2025-10-12T17:20:01Z - 2025-10-12T18:00:01Z
**Files Used:**
- agg_log_20251012T172001Z.json
- agg_log_20251012T174001Z.json
- agg_log_20251012T180001Z.json

**Executive Summary**

This report summarizes 23,725 attacks recorded across our honeypot network. The majority of attacks were captured by the Dionaea and Cowrie honeypots, indicating a high volume of SMB and SSH-based threats. A single IP address, 202.88.244.34, was responsible for a significant portion of the attack traffic, primarily targeting port 445 (SMB). Analysis of Cowrie logs revealed numerous brute-force login attempts and the execution of commands aimed at reconnaissance and establishing persistence. Several CVEs were targeted, and a variety of malware samples were uploaded.

**Detailed Analysis**

**Attacks by Honeypot:**
* Dionaea: 9,347
* Cowrie: 6,148
* Honeytrap: 2,944
* Ciscoasa: 1,828
* Sentrypeer: 1,822
* Suricata: 1,374
* Mailoney: 79
* Tanner: 70
* H0neytr4p: 28
* Redishoneypot: 25
* ConPot: 21
* Honeyaml: 10
* Adbhoney: 9
* Dicompot: 8
* Ipphoney: 5
* ElasticPot: 4
* Miniprint: 3

**Top Attacking IPs:**
* 202.88.244.34: 9,144
* 45.128.199.212: 1,008
* 46.32.178.94: 928
* 182.76.204.237: 401
* 85.209.134.43: 382
* 51.178.143.200: 367
* 172.86.95.98: 336
* 62.141.43.183: 324
* 211.240.117.40: 222
* 103.171.84.217: 223
* 4.224.36.103: 223
* 34.66.72.251: 214
* 205.185.126.121: 199
* 147.78.100.99: 210
* 134.209.36.11: 183
* 103.183.75.228: 189

**Top Targeted Ports/Protocols:**
* 445: 9,150
* 5060: 1,822
* 22: 911
* 3306: 159
* 5903: 193
* 23: 87
* 80: 84
* 8333: 102
* 25: 83
* 5908: 83
* 5909: 84
* 5901: 75
* TCP/5432: 55

**Most Common CVEs:**
* CVE-2022-27255 CVE-2022-27255: 5
* CVE-2006-0189: 4
* CVE-2021-35394 CVE-2021-35394: 1
* CVE-2005-4050: 1
* CVE-2023-1389 CVE-2023-1389: 1

**Commands Attempted by Attackers:**
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}': 24
* ls -lh $(which ls): 24
* which ls: 24
* crontab -l: 24
* w: 24
* uname -m: 24
* cat /proc/cpuinfo | grep model | grep name | wc -l: 24
* top: 24
* uname: 24
* uname -a: 24
* whoami: 24
* lscpu | grep Model: 24
* df -h | head -n 2 | awk 'FNR == 2 {print $2;}': 24
* cd ~; chattr -ia .ssh; lockr -ia .ssh: 24
* lockr -ia .ssh: 24
* cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ... mdrfckr\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~: 24
* cat /proc/cpuinfo | grep name | wc -l: 24
* cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}': 24
* Enter new UNIX password: : 16
* Enter new UNIX password:": 16
* rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;: 4
* echo \"root:7Lb9fc6KwlPl\"|chpasswd|bash: 1

**Signatures Triggered:**
* ET DROP Dshield Block Listed Source group 1: 356
* 2402000: 356
* ET SCAN NMAP -sS window 1024: 153
* 2009582: 153
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 62
* 2023753: 62
* ET INFO Reserved Internal IP Traffic: 57
* 2002752: 57
* ET SCAN Suspicious inbound to PostgreSQL port 5432: 43
* 2010939: 43

**Users / Login Attempts:**
* root/: 95
* cron/: 54
* 345gs5662d34/345gs5662d34: 22
* boss/boss: 6
* root/Qwer1234: 6
* supervisor/abc123: 6
* root/root2020: 6
* root/a123456: 6
* admin/159753: 6
* ftpuser/ftppassword: 5

**Files Uploaded/Downloaded:**
* arm.urbotnetisass: 2
* arm5.urbotnetisass: 2
* arm6.urbotnetisass: 2
* arm7.urbotnetisass: 2
* x86_32.urbotnetisass: 2
* mips.urbotnetisass: 2
* mipsel.urbotnetisass: 2
* bins.sh;: 3
* json: 1

**HTTP User-Agents:**
* *No user agents recorded in this period.*

**SSH Clients and Servers:**
* *No specific SSH clients or servers recorded in this period.*

**Top Attacker AS Organizations:**
* *No AS organization data recorded in this period.*

**Key Observations and Anomalies**

- The overwhelming number of attacks from 202.88.244.34 suggests a targeted or highly aggressive scanning campaign against SMB services.
- Attackers on the Cowrie honeypot consistently used a long series of reconnaissance commands (`uname`, `lscpu`, `whoami`, etc.) before attempting to add their SSH key to `authorized_keys`, indicating a standardized attack script.
- The presence of commands to download and execute `urbotnetisass` suggests attempts to install botnet clients on compromised Android devices (via ADB honeypot).
- Multiple CVEs were targeted, including older vulnerabilities, indicating that attackers are still scanning for a wide range of unpatched systems.
- The command `echo "root:7Lb9fc6KwlPl"|chpasswd|bash` is a clear attempt to change the root password and maintain control over the compromised machine.
