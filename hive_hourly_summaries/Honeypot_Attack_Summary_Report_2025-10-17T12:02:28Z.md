Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-17T12:01:42Z
**Timeframe:** 2025-10-17T11:20:01Z - 2025-10-17T12:00:01Z
**Files Used:**
- agg_log_20251017T112001Z.json
- agg_log_20251017T114001Z.json
- agg_log_20251017T120001Z.json

**Executive Summary**
This report summarizes 18,506 events collected from the T-Pot honeypot network over a 40-minute period. The majority of attacks were SIP scanning attempts targeting port 5060, largely from a single IP address (2.57.121.61). Other significant activity includes SSH brute-force attempts and scans for vulnerabilities in FTP and other services. Several CVEs were targeted, including older vulnerabilities.

**Detailed Analysis**

**Attacks by Honeypot:**
- Sentrypeer: 8983
- Cowrie: 3784
- Honeytrap: 2116
- Ciscoasa: 1316
- Suricata: 1234
- Dionaea: 765
- Heralding: 56
- Tanner: 91
- H0neytr4p: 45
- Mailoney: 66
- Redishoneypot: 12
- Honeyaml: 12
- ElasticPot: 4
- Dicompot: 21
- ConPot: 1

**Top Attacking IPs:**
- 2.57.121.61: 7821
- 172.86.95.115: 448
- 172.86.95.98: 428
- 50.6.225.98: 294
- 20.46.54.49: 282
- 167.172.34.68: 215
- 83.229.122.23: 208
- 203.194.106.66: 218
- 185.213.174.209: 202
- 217.128.7.248: 190
- 91.107.118.186: 305
- 107.170.36.5: 223
- 42.200.78.78: 174
- 216.10.242.161: 134
- 103.70.12.139: 174
- 211.20.14.156: 169
- 41.204.63.118: 124
- 191.185.168.38: 119
- 14.127.9.45: 104
- 61.171.118.216: 97

**Top Targeted Ports/Protocols:**
- 5060: 8983
- 22: 580
- TCP/21: 207
- 5903: 202
- 8333: 160
- 21: 102
- 5901: 108
- 25: 66
- 80: 91
- 5904: 69
- 5905: 68
- 443: 42
- vnc/5900: 53
- TCP/80: 48
- 23: 20

**Most Common CVEs:**
- CVE-2002-0013 CVE-2002-0012: 4
- CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 2
- CVE-2024-4577 CVE-2024-4577: 2
- CVE-2024-4577 CVE-2002-0953: 2
- CVE-2005-4050: 1
- CVE-2009-2765: 1
- CVE-2001-0414: 1
- CVE-2021-41773 CVE-2021-41773 CVE-2021-41773 CVE-2021-41773: 1
- CVE-2021-42013 CVE-2021-42013: 1

**Commands Attempted by Attackers:**
- `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ...">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 15
- `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 15
- `lockr -ia .ssh`: 15
- `cat /proc/cpuinfo | grep name | wc -l`: 15
- `cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'`: 15
- `free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'`: 15
- `ls -lh $(which ls)`: 15
- `which ls`: 15
- `crontab -l`: 15
- `w`: 15
- `uname -m`: 15
- `cat /proc/cpuinfo | grep model | grep name | wc -l`: 15
- `top`: 15
- `uname`: 15
- `uname -a`: 15
- `whoami`: 15
- `lscpu | grep Model`: 15
- `df -h | head -n 2 | awk 'FNR == 2 {print $2;}'`: 15
- `Enter new UNIX password: `: 11
- `Enter new UNIX password:`: 10

**Signatures Triggered:**
- ET DROP Dshield Block Listed Source group 1: 242
- 2402000: 242
- ET SCAN NMAP -sS window 1024: 140
- 2009582: 140
- ET FTP FTP PWD command attempt without login: 102
- 2010735: 102
- ET FTP FTP CWD command attempt without login: 102
- 2010731: 102
- ET SCAN MS Terminal Server Traffic on Non-standard Port: 98
- 2023753: 98
- ET INFO Reserved Internal IP Traffic: 51
- 2002752: 51
- ET INFO VNC Authentication Failure: 52
- 2002920: 52
- ET SCAN Potential SSH Scan: 24
- 2001219: 24
- ET INFO CURL User Agent: 28
- 2002824: 28
- ET HUNTING RDP Authentication Bypass Attempt: 28
- 2034857: 28

**Users / Login Attempts:**
- 345gs5662d34/345gs5662d34: 15
- sa/!QAZ2wsx: 10
- support/333333: 6
- config/22: 6
- guest/guest2013: 6
- supervisor/supervisor2018: 6
- operator/operator2010: 6
- user/0: 4
- test/555: 4
- root/123hits789: 4
- default/qwerty1234: 6
- blank/0000: 4
- debian/password321: 4
- centos/8888888: 4
- root/123deoliveira4: 4
- mp/mp: 3
- training/training123: 3
- root/Aa1234567: 3
- root/123@Robert: 5
- root/123freepbxRBA8ixpisit-on-my-dickt7red2015Tftadmin: 3

**Files Uploaded/Downloaded:**
- sh: 98
- Mozi.m: 1
- ?format=json: 2

**HTTP User-Agents:**
- None Observed

**SSH Clients:**
- None Observed

**SSH Servers:**
- None Observed

**Top Attacker AS Organizations:**
- None Observed

**Key Observations and Anomalies**
- The overwhelming majority of traffic came from the Sentrypeer honeypot, with a single IP (2.57.121.61) responsible for over 7,800 events targeting the SIP port 5060. This indicates a large-scale, automated scanning campaign for VoIP vulnerabilities.
- A significant number of SSH commands were attempted to manipulate the `.ssh/authorized_keys` file, a common technique for establishing persistent access.
- The attempted logins show a wide variety of default and weak credentials, highlighting the continued use of brute-force tactics.
- The CVEs detected are a mix of recent and very old vulnerabilities, suggesting that attackers are using a broad set of exploits to maximize their chances of success.
- The `Mozi.m` file download is associated with the Mozi botnet, an IoT botnet that has been active for several years. The `sh` file downloads are likely related to the execution of malicious scripts.
