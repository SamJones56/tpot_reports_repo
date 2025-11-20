Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-20T23:01:38Z
**Timeframe:** 2025-10-20T22:20:01Z to 2025-10-20T23:00:01Z
**Files Used to Generate Report:**
- agg_log_20251020T222001Z.json
- agg_log_20251020T224001Z.json
- agg_log_20251020T230001Z.json

### Executive Summary

This report summarizes 16,464 events collected from the T-Pot honeypot network. The majority of attacks were captured by the Cowrie honeypot. The most targeted service was SSH on port 22. A significant number of attackers attempted to download malicious shell scripts and add their SSH keys to the authorized_keys file.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 9773
* Honeytrap: 3797
* Suricata: 1783
* Dionaea: 457
* Sentrypeer: 383
* Adbhoney: 82
* Tanner: 49
* Mailoney: 29
* H0neytr4p: 28
* Heralding: 19
* Ciscoasa: 15
* Ipphoney: 14
* Redishoneypot: 18
* ElasticPot: 9
* Dicompot: 7
* ConPot: 1

**Top Attacking IPs:**
* 5.167.79.4: 1251
* 72.146.232.13: 1105
* 196.251.88.103: 1001
* 66.116.196.243: 799
* 200.89.178.151: 238
* 185.113.139.51: 192
* 107.170.36.5: 296
* 103.153.253.8: 134
* 185.158.22.150: 134
* 107.174.67.215: 129
* 103.189.208.13: 117
* 185.243.5.158: 175
* 43.229.78.35: 168
* 1.238.106.229: 125
* 157.10.252.119: 110

**Top Targeted Ports/Protocols:**
* 22: 1705
* 5060: 383
* 5903: 228
* 5901: 238
* TCP/21: 108
* TCP/80: 80
* 21: 63
* 5904: 80
* 5905: 77
* 8333: 59
* 445: 47
* TCP/22: 49

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012: 10
* CVE-2024-3721 CVE-2024-3721: 7
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 6
* CVE-2021-3449 CVE-2021-3449: 2
* CVE-2022-27255 CVE-2022-27255: 2
* CVE-2021-35394 CVE-2021-35394: 1
* CVE-2002-1149: 1
* CVE-2019-11500 CVE-2019-11500: 1

**Commands Attempted by Attackers:**
* `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 38
* `lockr -ia .ssh`: 38
* `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."`: 37
* `cat /proc/cpuinfo | grep name | wc -l`: 35
* `uname -a`: 33
* `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 34
* `ls -lh $(which ls)`: 34
* `which ls`: 34
* `crontab -l`: 34
* `w`: 34
* `uname -m`: 34
* `cat /proc/cpuinfo | grep model | grep name | wc -l`: 34
* `top`: 33
* `uname`: 33
* `whoami`: 32
* `lscpu | grep Model`: 32
* `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 31
* `Enter new UNIX password: `: 26
* `Enter new UNIX password:`: 26

**Signatures Triggered:**
* ET DROP Dshield Block Listed Source group 1: 353
* 2402000: 353
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 313
* 2023753: 313
* ET SCAN NMAP -sS window 1024: 160
* 2009582: 160
* ET HUNTING RDP Authentication Bypass Attempt: 80
* 2034857: 80
* ET FTP FTP PWD command attempt without login: 54
* 2010735: 54
* ET FTP FTP CWD command attempt without login: 54
* 2010731: 54
* ET INFO Reserved Internal IP Traffic: 54
* 2002752: 54

**Users / Login Attempts (user/password):**
* 345gs5662d34/345gs5662d34: 36
* user01/Password01: 16
* root/Admusr00: 4
* root/admxadr729: 4
* root/3245gs5662d34: 4
* deploy/123123: 4
* admin/admin123: 5
* postgres/postgres123: 3
* lighthouse/lighthouse: 3
* postgres/postgres: 3
* root/12345: 3

**Files Uploaded/Downloaded:**
* wget.sh;: 28
* w.sh;: 7
* c.sh;: 7
* arm.urbotnetisass;: 3
* arm.urbotnetisass: 3
* arm5.urbotnetisass;: 3
* arm5.urbotnetisass: 3
* arm6.urbotnetisass;: 3
* arm6.urbotnetisass: 3
* arm7.urbotnetisass;: 3
* arm7.urbotnetisass: 3
* x86_32.urbotnetisass;: 3
* x86_32.urbotnetisass: 3
* mips.urbotnetisass;: 3
* mips.urbotnetisass: 3
* mipsel.urbotnetisass;: 3
* mipsel.urbotnetisass: 3
* json: 2
* loader.sh|sh;#: 1

**HTTP User-Agents:**
* No HTTP user agents were logged in the provided data.

**SSH Clients:**
* No SSH clients were logged in the provided data.

**SSH Servers:**
* No SSH servers were logged in the provided data.

**Top Attacker AS Organizations:**
* No AS organizations were logged in the provided data.

### Key Observations and Anomalies

- A large number of commands are reconnaissance commands to understand the system's architecture (`uname -a`, `lscpu`, `cat /proc/cpuinfo`).
- Many attackers are attempting to install their SSH keys for persistent access.
- Several attackers are attempting to download and execute shell scripts, likely to install malware or DDoS bots.
- The command `cd ~; chattr -ia .ssh; lockr -ia .ssh` was seen frequently, suggesting an attempt to modify permissions and lock down the `.ssh` directory.
- There is a significant amount of scanning activity for MS Terminal Server on non-standard ports.

This concludes the Honeypot Attack Summary Report.
