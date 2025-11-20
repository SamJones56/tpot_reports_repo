Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-02T21:01:22Z
**Timeframe:** 2025-10-02T20:20:01Z to 2025-10-02T21:00:01Z
**Files Used:**
- agg_log_20251002T202001Z.json
- agg_log_20251002T204001Z.json
- agg_log_20251002T210001Z.json

### Executive Summary

This report summarizes 12,079 malicious events recorded by our honeypot network. The primary attacks observed were SSH bruteforce attempts, scans for open ports, and exploitation of known vulnerabilities. The most active honeypots were Cowrie, Ciscoasa, and Suricata. A significant portion of the attacks originated from a small number of IP addresses, with a notable concentration on ports associated with email (25), VoIP (5060), and SSH (22). Several critical CVEs were targeted, and attackers attempted to download and execute malicious scripts.

### Detailed Analysis

**Attacks by Honeypot**
- Cowrie: 2783
- Ciscoasa: 2704
- Suricata: 2713
- Mailoney: 1736
- Sentrypeer: 1567
- Honeytrap: 156
- Adbhoney: 81
- Dionaea: 105
- ElasticPot: 58
- H0neytr4p: 55
- ConPot: 43
- Tanner: 27
- Honeyaml: 21
- Redishoneypot: 12
- Dicompot: 12
- Miniprint: 6

**Top Attacking IPs**
- 176.65.141.117: 1640
- 102.90.99.105: 1263
- 23.175.48.211: 1249
- 138.68.167.183: 1011
- 185.156.73.166: 362
- 92.63.197.55: 356
- 92.63.197.59: 320
- 198.23.190.58: 220
- 190.0.63.226: 188
- 119.47.90.19: 174
- 38.43.130.87: 115
- 64.23.189.160: 125
- 46.105.87.113: 120
- 128.199.33.46: 89
- 103.59.95.187: 99
- 103.174.115.196: 94
- 103.153.190.105: 89
- 45.78.226.118: 104
- 150.95.157.171: 104
- 45.234.176.18: 80

**Top Targeted Ports/Protocols**
- 25: 1736
- 5060: 1567
- TCP/445: 1297
- 22: 440
- 9200: 55
- 23: 63
- 443: 55
- TCP/80: 86
- 1025: 37
- 80: 34
- 445: 32
- 5555: 7
- 3333: 6
- 27017: 11
- TCP/22: 17
- TCP/8443: 10
- TCP/1080: 14
- TCP/1433: 4
- 6379: 7
- 7547: 6

**Most Common CVEs**
- CVE-2021-3449: 8
- CVE-2022-27255: 6
- CVE-2019-11500: 6
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2021-35394: 1
- CVE-2006-2369: 1
- CVE-2023-26801: 1
- CVE-1999-0183: 1

**Commands Attempted by Attackers**
- rm -rf /data/local/tmp; mkdir -p /data/local/tmp;...
- cd /data/local/tmp/; rm *; busybox wget...
- cd ~; chattr -ia .ssh; lockr -ia .ssh
- lockr -ia .ssh
- cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...
- cat /proc/cpuinfo | grep name | wc -l
- Enter new UNIX password:
- uname -a
- whoami
- top
- lscpu | grep Model
- df -h | head -n 2 | awk 'FNR == 2 {print $2;}'
- free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
- ls -lh $(which ls)
- which ls
- crontab -l
- w
- uname -m
- cat /proc/cpuinfo | grep model | grep name | wc -l
- tftp; wget; /bin/busybox XGBKR

**Signatures Triggered**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1291
- 2024766: 1291
- ET DROP Dshield Block Listed Source group 1: 333
- 2402000: 333
- ET SCAN NMAP -sS window 1024: 174
- 2009582: 174
- ET SCAN Sipsak SIP scan: 100
- 2008598: 100
- ET INFO Reserved Internal IP Traffic: 56
- 2002752: 56
- ET INFO curl User-Agent Outbound: 25
- 2013028: 25
- ET HUNTING curl User-Agent to Dotted Quad: 25
- 2034567: 25
- ET CINS Active Threat Intelligence Poor Reputation IP group 46: 36
- 2403345: 36
- ET CINS Active Threat Intelligence Poor Reputation IP group 42: 27
- 2403341: 27
- ET CINS Active Threat Intelligence Poor Reputation IP group 48: 31
- 2403347: 31
- ET CINS Active Threat Intelligence Poor Reputation IP group 41: 21
- 2403340: 21
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 29
- 2400031: 29

**Users / Login Attempts**
- 345gs5662d34/345gs5662d34: 7
- root/nPSpP4PBW0: 5
- root/LeitboGi0ro: 4
- agent/agent: 3
- agent/3245gs5662d34: 3
- root/2glehe5t24th1issZs: 3
- superadmin/admin123: 2
- root/1029384756: 2
- sajjad/sajjad: 2
- gera/gera123: 2
- root/: 2
- admin/Gc123456: 2
- admin/!QAZXCDE#@WS: 2
- admin/ubuntupass: 2
- admin/pass01!: 2
- admin/123@#qwe: 2
- root/user1234: 2
- root/korea123: 2
- alice/alice: 1
- solana/validator: 1

**Files Uploaded/Downloaded**
- wget.sh;: 28
- c.sh;: 6
- w.sh;: 6
- arm.urbotnetisass;: 5
- arm.urbotnetisass: 5
- arm5.urbotnetisass;: 5
- arm5.urbotnetisass: 5
- arm6.urbotnetisass;: 5
- arm6.urbotnetisass: 5
- arm7.urbotnetisass;: 5
- arm7.urbotnetisass: 5
- x86_32.urbotnetisass;: 5
- x86_32.urbotnetisass: 5
- mips.urbotnetisass;: 5
- mips.urbotnetisass: 5
- mipsel.urbotnetisass;: 5
- mipsel.urbotnetisass: 5
- 11: 2
- fonts.gstatic.com: 2
- boatnet.mpsl;: 1

**HTTP User-Agents**
- Not Available

**SSH Clients**
- Not Available

**SSH Servers**
- Not Available

**Top Attacker AS Organizations**
- Not Available

### Key Observations and Anomalies
- The high volume of attacks from a limited set of IPs suggests targeted campaigns or botnet activity.
- The prevalence of commands related to downloading and executing scripts indicates attempts to install malware or establish persistence.
- The targeting of CVE-2021-3449, a remote code execution vulnerability, is a significant concern.
- The DoublePulsar backdoor signature was triggered a large number of times, indicating attempts to exploit a known SMB vulnerability.
- There is a noticeable increase in attacks targeting mail (port 25) and VoIP (port 5060) services.
- The attackers are attempting to modify SSH authorized_keys to gain persistent access.
- Several commands are used for system reconnaissance (e.g., `lscpu`, `uname -a`, `whoami`).

This report provides a snapshot of the threat landscape as observed by our honeypot network. Continuous monitoring and analysis are recommended.
