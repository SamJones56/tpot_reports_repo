Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-07T05:01:27Z
**Timeframe Covered:** 2025-10-07T04:20:01Z to 2025-10-07T05:00:01Z
**Log Files Used:**
- agg_log_20251007T042001Z.json
- agg_log_20251007T044002Z.json
- agg_log_20251007T050001Z.json

### Executive Summary
This report summarizes 18,778 events collected from the honeypot network. The majority of attacks were detected by the Suricata IDS, followed by the Cowrie and Honeytrap honeypots. A significant number of attacks targeted SMB (port 445), likely related to exploits like EternalBlue, as suggested by the high count of DoublePulsar backdoor signatures. Attackers predominantly used SSH to attempt unauthorized access and execute reconnaissance commands.

### Detailed Analysis

**Attacks by Honeypot:**
- Suricata: 5633
- Cowrie: 4072
- Honeytrap: 3334
- Dionaea: 2891
- Mailoney: 900
- Ciscoasa: 1205
- Sentrypeer: 482
- Adbhoney: 33
- H0neytr4p: 38
- Tanner: 45
- Honeyaml: 33
- Redishoneypot: 18
- Heralding: 63
- ConPot: 13
- ElasticPot: 6
- Dicompot: 3
- Miniprint: 9

**Top Attacking IPs:**
- 125.163.36.47: 1579
- 182.10.97.48: 1518
- 42.118.158.88: 1237
- 86.54.42.238: 821
- 221.121.102.137: 802
- 118.69.3.29: 752
- 68.183.216.65: 580
- 161.132.37.66: 621
- 172.86.95.98: 470
- 103.220.207.174: 254
- 103.181.143.99: 223
- 161.132.49.155: 204
- 103.249.201.48: 204
- 185.220.101.40: 163
- 49.75.185.71: 139
- 31.57.225.31: 174
- 79.106.102.70: 174
- 122.184.55.148: 115
- 185.255.91.51: 125
- 40.160.9.156: 159

**Top Targeted Ports/Protocols:**
- TCP/445: 3092
- 445: 2805
- 25: 900
- 22: 654
- 5060: 482
- TCP/8080: 712
- 8333: 145
- 5903: 95
- 80: 47
- 23: 49
- TCP/22: 40
- vnc/5900: 63
- TCP/80: 44

**Most Common CVEs:**
- CVE-2019-11500: 3
- CVE-2021-3449: 3
- CVE-2019-12263, CVE-2019-12261, CVE-2019-12260, CVE-2019-12255: 2
- CVE-2001-0414: 1
- CVE-2016-20016: 1
- CVE-2005-4050: 1
- CVE-2002-0953: 1

**Commands Attempted by Attackers:**
- cd ~; chattr -ia .ssh; lockr -ia .ssh: 14
- lockr -ia .ssh: 14
- cd ~ && rm -rf .ssh && ...: 14
- cat /proc/cpuinfo | grep name | wc -l: 14
- Enter new UNIX password: : 14
- Enter new UNIX password::: 14
- cat /proc/cpuinfo | grep name | head ...: 14
- free -m | grep Mem ...: 14
- ls -lh $(which ls): 14
- which ls: 14
- crontab -l: 13
- w: 13
- uname -m: 13
- cat /proc/cpuinfo | grep model | ...: 13
- top: 13
- uname: 13
- uname -a: 13
- whoami: 13
- lscpu | grep Model: 14
- df -h | head -n 2 ...: 14

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 3084
- ET DROP Dshield Block Listed Source group 1: 540
- ET INFO Incoming Basic Auth Base64 HTTP Password detected unencrypted: 127
- ET SCAN NMAP -sS window 1024: 163
- ET INFO Reserved Internal IP Traffic: 55
- ET TOR Known Tor Exit Node Traffic group 92: 51
- ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 92: 48
- ET TOR Known Tor Relay/Router (Not Exit) Node Traffic group 93: 36
- ET TOR Known Tor Exit Node Traffic group 93: 43
- GPL INFO SOCKS Proxy attempt: 90
- ET INFO VNC Authentication Failure: 62
- ET CINS Active Threat Intelligence Poor Reputation IP group 45: 16
- ET SCAN Potential SSH Scan: 16
- ET INFO CURL User Agent: 14

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 13
- david/david!: 4
- admin/07101991: 3
- admin/07101979: 3
- admin/07091992: 3
- admin/07091979: 3
- admin/07061981: 3
- admin/ali12345: 3
- admin/abc...123: 3
- admin/123QWEasdf123: 3
- admin/libadmin: 3
- admin/123456@Root: 3
- oracle/1234567: 3

**Files Uploaded/Downloaded:**
- wget.sh;: 20
- config.all.php?: 30
- config.php?: 6
- cmd.txt: 4
- w.sh;: 5
- c.sh;: 5
- Xiii.php?yokyok=cat+Xiii.php&: 2
- phpversions.php?npv: 2
- PBX.php?cmd=id...: 1
- pannels_main.php?dark1=id...: 1
- woa3z.php?cmd=id...: 1

**HTTP User-Agents:**
- No user-agents were logged during this period.

**SSH Clients and Servers:**
- No specific SSH client or server versions were logged.

**Top Attacker AS Organizations:**
- No AS organization data was logged during this period.

### Key Observations and Anomalies
- The high number of "ET EXPLOIT [PTsecurity] DoublePulsar Backdoor" signatures strongly indicates widespread scanning and exploitation attempts for the EternalBlue vulnerability (MS17-010).
- A consistent pattern of SSH-based attacks was observed, where attackers, upon gaining access, attempt to secure their foothold by modifying SSH authorized_keys and then perform basic system reconnaissance.
- Multiple web-based attacks attempted to download and execute malicious scripts (`wget.sh`, `c.sh`, `w.sh`), indicating attempts to install web shells or other malware.
- The credentials attempted show a mix of default, weak, and previously breached passwords, highlighting the continued effectiveness of brute-force and dictionary attacks.
