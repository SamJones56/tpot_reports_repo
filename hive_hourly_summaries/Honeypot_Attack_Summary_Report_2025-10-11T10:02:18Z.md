Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T10:01:48Z
**Timeframe:** 2025-10-11T09:20:01Z to 2025-10-11T10:00:01Z
**Log Files:**
- agg_log_20251011T092001Z.json
- agg_log_20251011T094001Z.json
- agg_log_20251011T100001Z.json

### Executive Summary

This report summarizes honeypot activity over a 40-minute period, analyzing data from three log files. A total of 19,743 attacks were recorded. The majority of attacks were detected by the Suricata and Cowrie honeypots. The most targeted port was TCP/445, commonly associated with SMB. A significant number of attacks originated from IP address 103.91.45.100.

### Detailed Analysis

**Attacks by Honeypot:**
- Suricata: 7441
- Cowrie: 6205
- Honeytrap: 3810
- Ciscoasa: 1806
- Sentrypeer: 162
- Tanner: 77
- Dionaea: 57
- H0neytr4p: 71
- Mailoney: 29
- Adbhoney: 30
- Honeyaml: 16
- ConPot: 18
- Redishoneypot: 15
- ElasticPot: 5
- Ipphoney: 1

**Top Attacking IPs:**
- 103.91.45.100: 1605
- 182.253.188.163: 1586
- 188.71.250.136: 1370
- 124.123.167.101: 1298
- 20.46.54.49: 267
- 103.23.61.4: 237
- 195.10.205.242: 238
- 85.203.45.220: 204
- 14.103.244.250: 193
- 91.237.163.112: 154

**Top Targeted Ports/Protocols:**
- TCP/445: 5848
- 22: 829
- 5908: 82
- 5909: 81
- 80: 77
- 5901: 75
- 5038: 210
- 5903: 190
- 5060: 162
- 8333: 100
- 443: 61
- TCP/80: 52
- 23: 43
- TCP/22: 30
- TCP/5432: 30

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2006-2369: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 57
- `lockr -ia .ssh`: 57
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 57
- `cat /proc/cpuinfo | grep name | wc -l`: 32
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 32
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 32
- `ls -lh $(which ls)`: 32
- `which ls`: 32
- `crontab -l`: 32
- `w`: 32
- `uname -m`: 32
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 32
- `top`: 32
- `uname`: 32
- `uname -a`: 32
- `whoami`: 32
- `lscpu | grep Model`: 32
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 32
- `Enter new UNIX password: `: 18
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 10

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 5839
- 2024766: 5839
- ET DROP Dshield Block Listed Source group 1: 506
- 2402000: 506
- ET SCAN NMAP -sS window 1024: 150
- 2009582: 150
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 83
- 2023753: 83
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 53
- root/3245gs5662d34: 21
- root/Ahgf3487@rtjhskl854hd47893@#a4nC: 20
- root/nPSpP4PBW0: 17
- root/LeitboGi0ro: 13
- admin/admin2003: 6
- admin/admin333: 6
- 123qweASD/123qweASD: 5
- nexus/nexuspass: 5
- ubnt/123456789: 5
- webmaster/webmaster: 5

**Files Uploaded/Downloaded:**
- wget.sh;: 8
- w.sh;: 2
- c.sh;: 2
- 11: 9
- fonts.gstatic.com: 9
- css?family=Libre+Franklin%3A300%2C300i%2C400%2C400i%2C600%2C600i%2C800%2C800i&amp;subset=latin%2Clatin-ext: 9
- ie8.css?ver=1.0: 9
- html5.js?ver=3.7.3: 9

**HTTP User-Agents:**
- No user agents recorded.

**SSH Clients:**
- No SSH clients recorded.

**SSH Servers:**
- No SSH servers recorded.

**Top Attacker AS Organizations:**
- No AS organizations recorded.

### Key Observations and Anomalies

- The high volume of traffic to TCP/445 and the "DoublePulsar Backdoor" signature suggest a continuation of SMB-related worm or botnet activity.
- The commands executed on the Cowrie honeypot are consistent with reconnaissance and attempts to establish persistent access by adding SSH keys.
- A variety of commodity malware and scanners appear to be in use, with no single, sophisticated actor identified.
- The lack of HTTP User-Agents, SSH clients/servers, and AS organization data might indicate a limitation in the current honeypot configuration or that the attacks are not leveraging these protocols.
