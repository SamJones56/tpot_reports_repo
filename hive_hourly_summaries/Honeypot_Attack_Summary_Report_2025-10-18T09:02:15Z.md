Honeypot Attack Summary Report

**Report Generation Time:** 2025-10-18T09:01:31Z
**Timeframe:** 2025-10-18T08:20:01Z to 2025-10-18T09:00:01Z
**Log Files:**
- agg_log_20251018T082001Z.json
- agg_log_20251018T084002Z.json
- agg_log_20251018T090001Z.json

### Executive Summary

This report summarizes 19,766 events recorded across three log files. The majority of attacks were captured by the Cowrie honeypot, indicating a high volume of SSH and Telnet-based threats. A significant portion of the activity originated from IP addresses 115.211.197.124 and 5.167.79.4. The most targeted services were SSH (port 22) and SMB (port 445). Attackers were observed attempting to gain persistence by modifying SSH authorized_keys files and exploiting known vulnerabilities, including CVE-2024-3721 and older web server vulnerabilities. Network traffic analysis revealed signatures associated with the DoublePulsar backdoor, indicating attempts to compromise systems with sophisticated malware.

### Detailed Analysis

**Attacks by Honeypot:**
*   Cowrie: 11,211
*   Suricata: 3,124
*   Honeytrap: 2,732
*   Ciscoasa: 1,244
*   Sentrypeer: 989
*   Dionaea: 131
*   Mailoney: 125
*   Tanner: 72
*   Redishoneypot: 42
*   H0neytr4p: 39
*   Adbhoney: 28
*   ConPot: 17
*   Honeyaml: 8
*   Dicompot: 3
*   Ipphoney: 1

**Top Attacking IPs:**
*   115.211.197.124: 1461
*   129.212.189.13: 992
*   5.167.79.4: 949
*   196.251.88.103: 998
*   194.135.90.141: 1261
*   72.146.232.13: 909
*   31.58.144.28: 585
*   85.198.83.143: 406
*   50.232.189.209: 307
*   50.84.211.204: 262
*   172.86.95.115: 382
*   103.51.216.210: 297
*   139.59.188.13: 288
*   72.240.125.133: 287
*   172.86.95.98: 271
*   198.23.248.151: 199
*   181.210.8.69: 199
*   103.145.145.74: 233
*   107.170.36.5: 166
*   190.129.122.12: 243

**Top Targeted Ports/Protocols:**
*   TCP/445: 1501
*   22: 1987
*   5060: 989
*   TCP/5900: 291
*   5903: 228
*   25: 127
*   80: 66
*   5901: 113
*   443: 27
*   TCP/80: 35
*   23: 39
*   TCP/22: 56
*   3128: 32
*   6379: 34

**Most Common CVEs:**
*   CVE-2024-3721: 9
*   CVE-2002-0013, CVE-2002-0012: 11
*   CVE-2002-0013, CVE-2002-0012, CVE-1999-0517: 7
*   CVE-2001-0414: 4
*   CVE-2021-3449: 3
*   CVE-2019-11500: 2
*   CVE-2021-41773: 1
*   CVE-2021-42013: 1

**Commands Attempted by Attackers:**
*   `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa ... mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~`: 31
*   `cd ~; chattr -ia .ssh; lockr -ia .ssh`: 31
*   `lockr -ia .ssh`: 31
*   System reconnaissance commands (`uname`, `whoami`, `lscpu`, `w`, `top`, `crontab -l`, `free -m`, `df -h`): High frequency
*   `Enter new UNIX password:`: 27
*   `tftp; wget; /bin/busybox ...`: Multiple variants
*   Payload download and execution scripts from IPs 94.154.35.154 and 213.209.143.167

**Signatures Triggered:**
*   ET EXPLOIT [PTsecurity] DoublePulsar Backdoor installation communication: 1455
*   ET DROP Dshield Block Listed Source group 1: 341
*   ET SCAN MS Terminal Server Traffic on Non-standard Port: 180
*   ET SCAN NMAP -sS window 1024: 125
*   ET DROP Spamhaus DROP Listed Traffic Inbound (groups 42, 41, 28): 296
*   ET HUNTING RDP Authentication Bypass Attempt: 64
*   ET INFO Reserved Internal IP Traffic: 52
*   ET SCAN Potential SSH Scan: 40
*   GPL SNMP request udp: 7
*   ET WEB_SPECIFIC_APPS TBK DVR-4104/4216 Command Injection Attempt (CVE-2024-3721): 7

**Users / Login Attempts (User/Password):**
*   345gs5662d34/345gs5662d34: 28
*   root/123@Robert: 13
*   ftpuser/ftppassword: 8
*   root/3245gs5662d34: 4
*   root/1: 4
*   root/qwerty123: 4
*   admin/1234567: 3
*   elastic/qwer1234: 3
*   dinesh/123: 3
*   dinesh/3245gs5662d34: 3
*   blank/blank2010: 3

**Files Uploaded/Downloaded:**
*   sh: 26
*   wget.sh;: 8
*   Malware binaries (e.g., `arm.urbotnetisass`, `w.sh`, `c.sh`): Multiple instances
*   Web assets (`fonts.gstatic.com`, `css?family=...`, `ie8.css`, `html5.js`): 20

**SSH Clients and Servers:**
*   SSH Clients: No data recorded.
*   SSH Servers: No data recorded.

**Top Attacker AS Organizations:**
*   No data recorded.

### Key Observations and Anomalies

1.  **High Volume of Automated Attacks:** The prevalence of common credential pairs and reconnaissance commands (`uname`, `lscpu`) suggests widespread, automated scanning and exploitation attempts rather than targeted attacks.
2.  **SSH Key Manipulation:** A frequently observed command involves deleting the `.ssh` directory and replacing `authorized_keys` with a hardcoded key. This is a clear indicator of attackers attempting to establish persistent, passwordless access to compromised machines.
3.  **DoublePulsar Activity:** The high number of "DoublePulsar Backdoor" signatures is a significant concern, pointing to attempts to exploit the EternalBlue vulnerability (associated with WannaCry) to install backdoors. This activity was heavily concentrated in the second log file.
4.  **Multi-Architecture Malware Delivery:** One interesting command string attempted to download and execute payloads for multiple architectures (ARM, x86, MIPS), indicating a sophisticated effort to infect a wide range of IoT and embedded devices.
5.  **Focus on Web Vulnerabilities:** The presence of CVEs like CVE-2024-3721 (Command Injection) and older Apache vulnerabilities (CVE-2021-41773, CVE-2021-42013) shows that attackers continue to scan for and exploit known web application flaws.