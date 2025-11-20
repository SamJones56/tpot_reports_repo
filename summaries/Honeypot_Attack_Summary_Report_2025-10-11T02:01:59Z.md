**Honeypot Attack Summary Report**

**Report Generation Time:** 2025-10-11T02:01:32Z
**Timeframe:** 2025-10-11T01:20:01Z to 2025-10-11T02:00:01Z
**Files Used:**
- agg_log_20251011T012001Z.json
- agg_log_20251011T014001Z.json
- agg_log_20251011T020001Z.json

**Executive Summary**

This report summarizes 18,733 events recorded across the honeypot network. The majority of attacks were captured by the Cowrie, Honeytrap, and Dionaea honeypots, indicating a high volume of SSH and various TCP/IP service attacks. A significant number of events were also flagged by Suricata intrusion detection. Attackers were observed primarily engaging in broad scanning activities, with a focus on ports 445 (SMB) and 22 (SSH). Numerous brute-force login attempts were recorded, along with post-login activities aimed at system reconnaissance and malware download.

**Detailed Analysis**

***Attacks by Honeypot***
- Cowrie: 8565
- Honeytrap: 3260
- Dionaea: 2578
- Suricata: 2177
- Ciscoasa: 1853
- Miniprint: 74
- H0neytr4p: 30
- Sentrypeer: 41
- Adbhoney: 30
- Mailoney: 35
- Honeyaml: 21
- Tanner: 19
- Ipphoney: 21
- ConPot: 5
- ElasticPot: 2
- Dicompot: 10
- Redishoneypot: 12

***Top Attacking IPs***
- 223.100.22.69: 2111
- 185.126.217.241: 1245
- 196.251.88.103: 1007
- 167.250.224.25: 502
- 88.210.63.16: 458
- 223.100.240.9: 406
- 185.39.19.40: 328
- 154.26.135.146: 307
- 185.223.124.133: 302
- 37.59.110.4: 235
- 95.215.108.8: 243
- 4.213.160.153: 263
- 43.162.125.200: 214
- 128.1.132.137: 200
- 107.172.140.200: 180
- 103.115.24.11: 183
- 156.229.21.151: 189
- 94.182.174.231: 214
- 40.82.214.8: 179
- 103.189.234.9: 189

***Top Targeted Ports/Protocols***
- 445: 2532
- 22: 1372
- 5903: 192
- 8333: 95
- 5908: 84
- 5909: 83
- 5901: 77
- TCP/22: 63
- 23: 56
- 5060: 41
- 5907: 49
- 25: 44
- TCP/1521: 32
- 1180: 78
- 9100: 74
- 6379: 12
- 37777: 25
- 80: 13
- 9000: 13
- 8291: 12

***Most Common CVEs***
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2018-11776
- CVE-1999-0183

***Commands Attempted by Attackers***
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 29
- `lockr -ia .ssh`: 29
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 29
- `Enter new UNIX password: `: 26
- `Enter new UNIX password:`: 26
- `cat /proc/cpuinfo | grep name | wc -l`: 26
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 27
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 27
- `ls -lh $(which ls)`: 27
- `which ls`: 27
- `crontab -l`: 27
- `w`: 27
- `uname -m`: 27
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 27
- `top`: 27
- `uname`: 27
- `uname -a`: 27
- `whoami`: 27
- `lscpu | grep Model`: 27
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 27

***Signatures Triggered***
- ET DROP Dshield Block Listed Source group 1: 549
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 466
- ET HUNTING RDP Authentication Bypass Attempt: 211
- ET SCAN NMAP -sS window 1024: 150
- ET INFO Reserved Internal IP Traffic: 59
- ET SCAN Potential SSH Scan: 49
- ET SCAN Suspicious inbound to Oracle SQL port 1521: 27
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 11
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 10

***Users / Login Attempts***
- 345gs5662d34/345gs5662d34: 29
- root/nPSpP4PBW0: 20
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 17
- root/LeitboGi0ro: 8
- support/support33: 6
- admin/00000000: 6
- unknown/123321: 6
- root/123123: 6
- mysql/mysql: 5
- pi/raspberry: 4
- git/git: 3
- user/111111: 3
- user/user: 3
- root/abc123: 3
- Test/0000000: 6
- user/Aa123456: 6
- root/1234: 6
- admin/1qaz@wsx: 4
- root/T@Mohsen7337559: 5
- root/Enrike@1971: 4

***Files Uploaded/Downloaded***
- arm.urbotnetisass;
- arm.urbotnetisass
- arm5.urbotnetisass;
- arm5.urbotnetisass
- arm6.urbotnetisass;
- arm6.urbotnetisass
- arm7.urbotnetisass;
- arm7.urbotnetisass
- x86_32.urbotnetisass;
- x86_32.urbotnetisass
- mips.urbotnetisass;
- mips.urbotnetisass
- mipsel.urbotnetisass;
- mipsel.urbotnetisass
- w.sh;
- c.sh;
- 11
- fonts.gstatic.com
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

***HTTP User-Agents***
- None observed.

***SSH Clients and Servers***
- None observed.

***Top Attacker AS Organizations***
- None observed.

**Key Observations and Anomalies**

- The high number of events from Cowrie honeypot suggests that SSH brute-force attacks and subsequent command execution are a primary vector of attack.
- The command `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys` is a clear indicator of attackers attempting to install their own SSH keys for persistent access.
- Attackers are consistently using commands to profile the system (`uname`, `lscpu`, `free`, `df`), likely to tailor future attacks or malware.
- The download of files such as `arm.urbotnetisass` and other variants suggests attempts to deploy IoT botnet malware.
- The Suricata signatures triggered are consistent with widespread scanning and reconnaissance from known malicious IP addresses (Dshield, Spamhaus DROP).
- The CVEs detected are relatively old, indicating that attackers are still scanning for legacy vulnerabilities.
- There are no HTTP user-agents, SSH clients, or AS organizations in the logs. This might be a gap in the logging configuration or simply that no such data was captured in this timeframe.