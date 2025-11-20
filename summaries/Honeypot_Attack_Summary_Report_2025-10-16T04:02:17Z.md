Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-16T04:01:35Z
**Timeframe:** 2025-10-16T03:20:01Z to 2025-10-16T04:00:01Z
**Files Used:**
- `agg_log_20251016T032001Z.json`
- `agg_log_20251016T034001Z.json`
- `agg_log_20251016T040001Z.json`

**Executive Summary**

This report summarizes 17,263 events collected from the honeypot network over a period of approximately 40 minutes. The majority of attacks were captured by the Cowrie, Sentrypeer, and Honeytrap honeypots. A significant portion of the activity was directed at port 5060 (SIP) and port 22 (SSH). Attackers were observed attempting to gain access using common default credentials and executing post-exploitation commands to enumerate system information and establish persistent access.

**Detailed Analysis**

**Attacks by Honeypot**
- Cowrie: 6951
- Sentrypeer: 3485
- Honeytrap: 3164
- Suricata: 1614
- Ciscoasa: 1549
- Dionaea: 189
- Tanner: 90
- H0neytr4p: 85
- Mailoney: 56
- Adbhoney: 30
- Redishoneypot: 18
- Honeyaml: 14
- ConPot: 13
- ElasticPot: 3
- Wordpot: 1
- Ipphoney: 1

**Top Attacking IPs**
- 185.243.5.121: 1167
- 50.6.225.98: 1118
- 23.94.26.58: 829
- 20.2.136.52: 551
- 172.86.95.115: 492
- 172.86.95.98: 486
- 62.141.43.183: 322
- 87.201.127.149: 289
- 217.160.201.135: 261
- 103.10.44.105: 258
- 117.50.51.119: 269
- 118.194.228.15: 300
- 107.170.36.5: 243
- 45.200.233.125: 219
- 103.137.194.125: 199
- 103.174.115.5: 229

**Top Targeted Ports/Protocols**
- 5060: 3485
- 22: 973
- 5903: 227
- 445: 146
- 5901: 126
- 8333: 121
- UDP/5060: 116
- TCP/22: 91
- 1337: 80
- 80: 99
- 443: 83
- 5904: 74
- 5905: 74

**Most Common CVEs**
- CVE-2002-0013 CVE-2002-0012: 14
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 9
- CVE-2021-3449 CVE-2021-3449: 6
- CVE-2019-11500 CVE-2019-11500: 4

**Commands Attempted by Attackers**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 37
- `lockr -ia .ssh`: 37
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 37
- `uname -a`: 37
- `cat /proc/cpuinfo | grep name | wc -l`: 37
- `whoami`: 37
- `crontab -l`: 36
- `w`: 36
- `uname -m`: 36
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 36
- `top`: 36
- `uname`: 36
- `lscpu | grep Model`: 36
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 36
- `ls -lh $(which ls)`: 36
- `which ls`: 36
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 36
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 36
- `Enter new UNIX password: `: 19
- `Enter new UNIX password:`: 14

**Signatures Triggered**
- ET DROP Dshield Block Listed Source group 1: 453
- 2402000: 453
- ET SCAN NMAP -sS window 1024: 167
- 2009582: 167
- ET SCAN Potential SSH Scan: 71
- 2001219: 71
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 64
- 2023753: 64
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET VOIP Possible Inbound VOIP Scan/Misuse With User-Agent Zoiper: 40
- 2012297: 40
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 38
- 2403347: 38
- ET VOIP Modified Sipvicious Asterisk PBX User-Agent: 34
- 2012296: 34
- ET CINS Active Threat Intelligence Poor Reputation IP group 47: 26
- 2403346: 26
- ET SCAN Sipsak SIP scan: 26
- 2008598: 26

**Users / Login Attempts**
- `345gs5662d34/345gs5662d34`: 37
- `root/3245gs5662d34`: 18
- `root/Qaz123qaz`: 15
- `root/123@@@`: 14
- `config/6666666`: 6
- `test/7777`: 6
- `centos/1111`: 6
- `config/qwer1234`: 6
- `blank/blank2019`: 6
- `admin/6`: 6
- `config/12345`: 6
- `user/user77`: 6

**Files Uploaded/Downloaded**
- `?format=json`: 8
- `11`: 8
- `fonts.gstatic.com`: 8
- `css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext`: 8
- `ie8.css?ver=1.0`: 8
- `html5.js?ver=3.7.3`: 8
- `json`: 1

**HTTP User-Agents**
- No user agents were logged in this period.

**SSH Clients and Servers**
- No SSH clients or servers were logged in this period.

**Top Attacker AS Organizations**
- No attacker AS organizations were logged in this period.

**Key Observations and Anomalies**

- A large number of commands executed by attackers are related to system enumeration, such as checking CPU information, memory, and disk space.
- Attackers are consistently attempting to add their own SSH key to the `authorized_keys` file for persistent access.
- A significant amount of traffic is being directed towards SIP services on port 5060.
- There is a high volume of scanning activity from a small number of IP addresses.
- The CVEs being targeted are relatively old, suggesting that attackers are targeting unpatched systems.
