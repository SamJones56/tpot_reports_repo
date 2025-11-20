Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-13T17:01:35Z
**Timeframe:** 2025-10-13T16:20:01Z to 2025-10-13T17:00:01Z
**Files Used:**
- agg_log_20251013T162001Z.json
- agg_log_20251013T164001Z.json
- agg_log_20251013T170001Z.json

### Executive Summary
This report summarizes 18,165 malicious activities targeting the honeypot infrastructure over the last hour. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based brute-force attempts. A significant number of attacks were also registered on SMB (port 445), likely related to attempts to exploit the EternalBlue vulnerability. The most active attacking IP was 186.67.106.14.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 9290
- Dionaea: 3059
- Sentrypeer: 2848
- Suricata: 2285
- Honeytrap: 432
- Miniprint: 48
- ConPot: 30
- Tanner: 42
- Adbhoney: 20
- Mailoney: 25
- Redishoneypot: 26
- H0neytr4p: 23
- Honeyaml: 18
- Ipphoney: 14
- Dicompot: 3
- ElasticPot: 2

**Top Attacking IPs:**
- 186.67.106.14: 2966
- 189.183.112.240: 1326
- 185.243.5.146: 1258
- 129.212.185.86: 1002
- 45.236.188.4: 1090
- 185.243.5.148: 586
- 14.225.208.97: 394
- 124.236.73.71: 376
- 95.58.255.251: 433
- 172.104.176.233: 363
- 62.141.43.183: 322
- 172.86.95.98: 314
- 172.86.95.115: 307
- 205.185.127.60: 242
- 103.172.112.192: 232
- 35.237.94.18: 211
- 182.57.16.58: 156
- 49.49.251.205: 159
- 45.159.112.173: 203
- 200.89.178.151: 169

**Top Targeted Ports/Protocols:**
- 445: 3009
- 5060: 2848
- TCP/445: 1326
- 22: 1351
- 9100: 48
- 23: 69
- 80: 44
- TCP/22: 51
- UDP/5060: 61
- TCP/80: 28
- 443: 23
- TCP/1433: 18
- TCP/5432: 22
- 631: 14
- 6379: 21
- 1025: 12
- 58000: 12
- 4433: 12
- 10001: 10

**Most Common CVEs:**
- CVE-2006-0189: 22
- CVE-2022-27255 CVE-2022-27255: 22
- CVE-2005-4050: 11
- CVE-2002-0013 CVE-2002-0012: 10
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
- CVE-2021-3449 CVE-2021-3449: 3
- CVE-2019-11500 CVE-2019-11500: 2
- CVE-2001-0414: 1
- CVE-2024-3721 CVE-2024-3721: 1
- CVE-2019-12263 CVE-2019-12261 CVE-2019-12260 CVE-2019-12255: 1

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 62
- `lockr -ia .ssh`: 62
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 62
- `cat /proc/cpuinfo | grep name | wc -l`: 41
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 41
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 41
- `crontab -l`: 40
- `w`: 40
- `uname -m`: 40
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 40
- `top`: 40
- `uname`: 40
- `uname -a`: 40
- `whoami`: 40
- `lscpu | grep Model`: 40
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 40
- `ls -lh $(which ls)`: 40
- `which ls`: 40
- `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts.deny; pkill -9 sleep;`: 22
- `Enter new UNIX password: `: 18

**Signatures Triggered:**
- ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1322
- 2024766: 1322
- ET DROP Dshield Block Listed Source group 1: 260
- 2402000: 260
- ET SCAN NMAP -sS window 1024: 128
- 2009582: 128
- ET INFO Reserved Internal IP Traffic: 60
- 2002752: 60
- ET VOIP SIP UDP Softphone INVITE overflow: 22
- 2002848: 22
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 22
- 2038669: 22
- ET CINS Active Threat Intelligence Poor Reputation IP group 2: 21
- 2403301: 21
- ET SCAN Potential SSH Scan: 23
- 2001219: 23
- ET DROP Spamhaus DROP Listed Traffic Inbound group 32: 14
- 2400031: 14
- ET SCAN Suspicious inbound to MSSQL port 1433: 13
- 2010935: 13

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 59
- root/3245gs5662d34: 30
- root/123@@@: 18
- root/Qaz123qaz: 16
- ftpuser/ftppassword: 15
- root/Password@2025: 7
- support/P@ssw0rd: 6
- centos/99: 6
- user/qwerty123: 6
- blank/Passw@rd: 6
- operator/default: 6
- blank/blank2014: 5
- ubnt/ubnt2023: 5
- chris/123: 5
- test/333333: 4
- debian/888888: 4
- root/insecure: 4
- blank/blank2024: 4
- config/config2019: 4
- bitnami/123: 4

**Files Uploaded/Downloaded:**
- arm.urbotnetisass: 4
- arm.urbotnetisass;: 4
- arm5.urbotnetisass: 4
- arm5.urbotnetisass;: 4
- arm6.urbotnetisass: 4
- arm6.urbotnetisass;: 4
- arm7.urbotnetisass: 4
- arm7.urbotnetisass;: 4
- x86_32.urbotnetisass: 4
- x86_32.urbotnetisass;: 4
- mips.urbotnetisass: 4
- mips.urbotnetisass;: 4
- mipsel.urbotnetisass: 4
- mipsel.urbotnetisass;: 4
- arc.nn;: 3
- arc.nn;cat: 3
- x86.nn;: 3
- x86.nn;cat: 3
- x86_64.nn;: 3
- x86_64.nn;cat: 3

**HTTP User-Agents:**
- No user agents were recorded in this timeframe.

**SSH Clients:**
- No SSH clients were recorded in this timeframe.

**SSH Servers:**
- No SSH servers were recorded in this timeframe.

**Top Attacker AS Organizations:**
- No AS organizations were recorded in this timeframe.

### Key Observations and Anomalies
- The high number of SMB-related attacks from 186.67.106.14 and 189.183.112.240, combined with the "DoublePulsar Backdoor" signature, strongly suggests a coordinated campaign to exploit Windows vulnerabilities.
- Attackers consistently attempt to add their SSH key to the `.ssh/authorized_keys` file, indicating a focus on establishing persistent access.
- A variety of malware payloads were downloaded, targeting different CPU architectures (ARM, x86, MIPS), which is characteristic of automated botnet activity.
- The CVEs targeted are relatively old, suggesting that attackers are targeting unpatched, legacy systems.