Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T04:01:28Z
**Timeframe:** 2025-10-07T03:20:01Z to 2025-10-07T04:00:01Z
**Files Used:**
- agg_log_20251007T032001Z.json
- agg_log_20251007T034001Z.json
- agg_log_20251007T040001Z.json

### Executive Summary
This report summarizes 20,081 events collected from the honeypot network over a 40-minute period. The most active honeypot was Cowrie, accounting for over a third of the traffic. The most common attack vector was SMB, targeting port 445. A significant number of brute-force attempts and command injections were observed.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 7543
- Dionaea: 4469
- Suricata: 2978
- Honeytrap: 2432
- Ciscoasa: 1082
- Mailoney: 889
- Sentrypeer: 481
- H0neytr4p: 52
- Tanner: 41
- Adbhoney: 37
- Honeyaml: 20
- Redishoneypot: 12
- ConPot: 13
- Dicompot: 9
- ElasticPot: 7
- Miniprint: 11
- Ipphoney: 5

**Top Attacking IPs:**
- 14.226.215.205: 3113
- 187.140.3.18: 1600
- 179.179.235.1: 1253
- 103.243.25.96: 1241
- 38.100.203.79: 540
- 62.60.218.138: 476
- 172.86.95.98: 450
- 122.166.49.42: 469
- 118.45.205.44: 381
- 186.10.86.130: 312
- 20.193.141.133: 520
- 65.254.93.52: 307
- 186.248.197.77: 288
- 181.116.220.24: 183
- 94.254.0.234: 179
- 8.243.50.114: 219
- 114.8.146.58: 172
- 103.186.19.6: 216
- 58.210.98.130: 162
- 103.182.234.219: 189

**Top Targeted Ports/Protocols:**
- 445: 4422
- TCP/445: 1598
- 22: 945
- 5060: 481
- 25: 889
- 8333: 121
- 5901: 127
- TCP/8080: 39
- TCP/443: 39
- 5903: 96
- 80: 49
- 443: 52

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517
- CVE-2019-11500 CVE-2019-11500
- CVE-2005-4050
- CVE-2016-20016 CVE-2016-20016

**Commands Attempted by Attackers:**
- A variety of shell commands were attempted, primarily focused on reconnaissance and establishing persistence.
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`
- `lockr -ia .ssh`
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys...`
- `cat /proc/cpuinfo | grep name | wc -l`
- `Enter new UNIX password:`
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`
- `ls -lh $(which ls)`
- `crontab -l`
- `uname -a`
- `whoami`

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1
- ET SCAN NMAP -sS window 1024
- ET INFO Reserved Internal IP Traffic
- ET SCAN MS Terminal Server Traffic on Non-standard Port
- ET CINS Active Threat Intelligence Poor Reputation IP group 45
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34
- ansible/3245gs5662d34
- alex/P@ssw0rd
- vpn/P@ssw0rd
- deployer/1
- monitor/monitor@1
- user/3245gs5662d34
- botuser/botuser12

**Files Uploaded/Downloaded:**
- w.sh
- c.sh
- wget.sh
- fonts.gstatic.com
- css?family=Libre+Franklin...
- ie8.css?ver=1.0
- html5.js?ver=3.7.3

**HTTP User-Agents:**
- No user agents were recorded in the logs.

**SSH Clients and Servers:**
- No specific SSH clients or servers were recorded in the logs.

**Top Attacker AS Organizations:**
- No attacker AS organizations were recorded in the logs.

### Key Observations and Anomalies
- The high number of events from a small number of IP addresses suggests targeted attacks or botnet activity.
- The prevalence of commands related to SSH key manipulation indicates a focus on establishing persistent access.
- The "DoublePulsar" signature suggests that some attackers may be attempting to exploit the EternalBlue vulnerability.
- The variety of usernames and passwords in brute-force attempts indicates that attackers are using common default credentials and password lists.
- A number of commands were observed attempting to download and execute malicious scripts.
