Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T21:01:32Z
**Timeframe:** 2025-10-20T20:20:01Z to 2025-10-20T21:00:01Z
**Files Used:**
- agg_log_20251020T202001Z.json
- agg_log_20251020T204001Z.json
- agg_log_20251020T210001Z.json

### Executive Summary
This report summarizes 20,775 events collected from the honeypot network. The majority of attacks were captured by the Cowrie honeypot, with a significant number of events also recorded by Honeytrap and Suricata. The most frequent attacks originated from IP address 72.146.232.13. The most targeted port was 22 (SSH). A notable number of attempts to exploit CVE-2022-27255 were observed.

### Detailed Analysis

**Attacks by Honeypot:**
- Cowrie: 10374
- Honeytrap: 4393
- Suricata: 2330
- Dionaea: 1622
- Sentrypeer: 571
- Mailoney: 942
- Heralding: 328
- Adbhoney: 68
- Ciscoasa: 44
- Tanner: 34
- ConPot: 14
- H0neytr4p: 17
- Dicompot: 9
- Redishoneypot: 10
- Ipphoney: 14
- ElasticPot: 3
- Honeyaml: 2

**Top Attacking IPs:**
- 72.146.232.13: 1240
- 134.199.203.121: 1004
- 129.212.189.131: 997
- 176.65.141.119: 821
- 213.149.166.133: 817
- 8.210.46.25: 771
- 198.23.190.58: 453
- 103.48.84.147: 391
- 43.229.78.35: 313
- 46.238.32.247: 316

**Top Targeted Ports/Protocols:**
- 22: 1764
- 25: 942
- 445: 866
- 5060: 571
- vnc/5900: 328
- 5903: 231
- TCP/21: 212
- UDP/5060: 216
- 21: 106
- 5901: 120

**Most Common CVEs:**
- CVE-2022-27255: 42
- CVE-2021-44228: 5
- CVE-2002-0013 CVE-2002-0012: 6
- CVE-2001-0414: 3
- CVE-2019-11500: 3
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 4
- CVE-2021-3449: 3

**Commands Attempted by Attackers:**
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 46
- `lockr -ia .ssh`: 46
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 46
- `cat /proc/cpuinfo | grep name | wc -l`: 41
- `Enter new UNIX password:`: 35
- `Enter new UNIX password: `: 35
- `uname -a`: 42
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 41
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 41
- `ls -lh $(which ls)`: 41
- `which ls`: 41
- `crontab -l`: 41
- `w`: 41
- `uname -m`: 41
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 41
- `top`: 41
- `uname`: 41
- `whoami`: 41
- `lscpu | grep Model`: 41
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 41

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 349
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 321
- ET INFO VNC Authentication Failure: 243
- ET SCAN NMAP -sS window 1024: 178
- ET SCAN Sipsak SIP scan: 171
- ET HUNTING RDP Authentication Bypass Attempt: 100
- ET FTP FTP CWD command attempt without login: 105
- ET FTP FTP PWD command attempt without login: 104
- ET EXPLOIT Realtek eCos RSDK/MSDK Stack-based Buffer Overflow Attempt Inbound (CVE-2022-27255): 41
- ET INFO Reserved Internal IP Traffic: 60

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 46
- user01/Password01: 19
- user01/3245gs5662d34: 11
- deploy/123123: 9
- root/adminvld: 4
- root/adminvoip357415963: 4
- tomcat/tomcat: 2
- ubuntu/1qazXSW@: 2
- otrs/123: 2
- web/web123: 2

**Files Uploaded/Downloaded:**
- wget.sh;: 24
- w.sh;: 6
- c.sh;: 6
- arm.urbotnetisass;: 3
- arm.urbotnetisass: 3
- arm5.urbotnetisass;: 3
- arm5.urbotnetisass: 3
- arm6.urbotnetisass;: 3
- arm6.urbotnetisass: 3
- arm7.urbotnetisass;: 3
- arm7.urbotnetisass: 3
- x86_32.urbotnetisass;: 3
- x86_32.urbotnetisass: 3
- mips.urbotnetisass;: 3
- mips.urbotnetisass: 3
- mipsel.urbotnetisass;: 3
- mipsel.urbotnetisass: 3
- Mozi.m%20dlink.mips%27$: 1

**HTTP User-Agents:**
- No user agents were logged in this timeframe.

**SSH Clients and Servers:**
- No specific SSH clients or servers were logged in this timeframe.

**Top Attacker AS Organizations:**
- No attacker AS organizations were logged in this timeframe.

### Key Observations and Anomalies
- The overwhelming majority of attacks are automated, focusing on well-known vulnerabilities and default credentials.
- The commands executed suggest a common pattern of attempting to establish persistent access by adding an SSH key to `authorized_keys`.
- A significant number of download attempts for various architectures of the `urbotnetisass` malware were observed, indicating a coordinated campaign.
- The `Mozi.m` download attempt is also noteworthy, as it is a known P2P botnet.
- The high number of VNC authentication failures suggests that many systems are still exposing VNC to the internet with weak or default credentials.
